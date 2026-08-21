#!/usr/bin/env node
/**
 * dsh-netproxy engine — a dependency-free local forward proxy with a pluggable
 * EGRESS. It is the single local routing point for DSH:
 *
 *   - clients always talk to THIS engine (forward-proxy protocols: CONNECT
 *     tunnel + absolute-form HTTP), pointed to it by the host half
 *     (`HTTP(S)_PROXY` env + undici ProxyAgent => `http://127.0.0.1:<port>`);
 *   - the engine then builds the REAL connection to the target through the
 *     configured egress (`--upstream` / `UPSTREAM_URL`):
 *
 *       UPSTREAM            egress path
 *       (unset)       =>    DIRECT            (engine relays to the target itself)
 *       http://h:p    =>    tunnel via an HTTP(S) forward proxy (CONNECT +
 *                           optional Basic auth); absolute-form is re-forwarded
 *       socks4://h:p  =>    SOCKS4/SOCKS4a handshake (zero-dependency)
 *       socks5://h:p  =>    SOCKS5 handshake (no-auth or user:pass,
 *                           remote DNS, zero-dependency)
 *
 * So one engine covers direct / system / custom — including the SOCKS the
 * undici fetch layer cannot speak — and every client (fetch, curl, git, npm)
 * sees a single uniform local HTTP proxy.
 *
 * Engine protocol surface (unchanged):
 *   - CONNECT        -> blind TCP/TLS tunnel (HTTPS, wss). No MITM by default.
 *   - GET/POST …     -> absolute-form (proxy-style) HTTP forwarding.
 *   - basic auth     -> optional `Proxy-Authorization: Basic` (env AUTH=user:pass).
 *   - access log     -> JSON-lines to stdout and/or a file (LOG_FILE).
 *   - NO_PROXY       -> server-side safety net.
 *
 * Usage:
 *   node engine.js [--port 4317] [--bind 127.0.0.1] [--auth user:pass]
 *                  [--log FILE|stdout] [--no-proxy 127.0.0.1,localhost]
 *                  [--upstream socks5://[user:pass@]host:port]
 *   Env: PORT, BIND, AUTH, LOG_FILE, NO_PROXY, MAX_CONNS, UPSTREAM_URL.
 *
 * The engine is spawned as its own host-realm subprocess by the plugin's host
 * half. It has no dependencies on the DSH runtime or npm packages.
 */
import { createServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { connect as netConnect, isIP } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { createWriteStream } from "node:fs";

const HOP_BY_HOP = new Set([
  "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
  "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
]);

// ---- tiny argv/env parsing -------------------------------------------------
function opt(name, fallback) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx !== -1 && process.argv[idx + 1] !== undefined) return process.argv[idx + 1];
  const env = { port: "PORT", bind: "BIND", auth: "AUTH", log: "LOG_FILE", "no-proxy": "NO_PROXY", "max-conns": "MAX_CONNS", upstream: "UPSTREAM_URL" }[name];
  if (env && process.env[env]) return process.env[env];
  return fallback;
}
const PORT = Number(opt("port", "4317"));
const BIND = opt("bind", "127.0.0.1");
const AUTH = opt("auth", "");
const LOG_TARGET = opt("log", "stdout");
const NO_PROXY = (opt("no-proxy", "") || "").toLowerCase();
const MAX_CONNS = Number(opt("max-conns", "0")) || 0;
const UPSTREAM = opt("upstream", "") || "";

// ---- egress (unified outbound) ---------------------------------------------
function parseUpstream(u) {
  if (!u) return { kind: "direct" };
  let p;
  try { p = new URL(u); } catch { return { kind: "direct", raw: u }; }
  const proto = (p.protocol || "").replace(/:$/, "").toLowerCase();
  const host = p.hostname;
  const port = Number(p.port) || (proto === "https" ? 443 : proto === "http" ? 80 : 0);
  const user = p.username ? decodeURIComponent(p.username) : "";
  const pass = p.password ? decodeURIComponent(p.password) : "";
  if (proto === "http" || proto === "https") return { kind: proto, host, port, user, pass, raw: u };
  if (proto === "socks4" || proto === "socks4a") return { kind: "socks4", host, port, user, raw: u };
  if (proto === "socks5" || proto === "socks5h") return { kind: "socks5", host, port, user, pass, raw: u };
  return { kind: "direct", raw: u };
}
const EXIT = parseUpstream(UPSTREAM);
// A misrouted upstream pointing at our own listener would infinitely loop.
if (EXIT.host) {
  const h = String(EXIT.host).replace(/^\[|\]$/g, "").toLowerCase();
  const myself = (h === BIND.toLowerCase() || h === "127.0.0.1" || h === "localhost" || h === "::1") && EXIT.port === PORT;
  if (myself) {
    EXIT.kind = "direct"; // never self-loop; host half's excludeSelf is the primary guard
  }
}

// ---- logging ---------------------------------------------------------------
const logStream = LOG_TARGET === "stdout"
  ? process.stdout
  : createWriteStream(LOG_TARGET, { flags: "a" });

let counter = 0;
function log(entry) {
  const record = { ts: new Date().toISOString(), id: ++counter, ...entry };
  logStream.write(`${JSON.stringify(record)}\n`);
}

// ---- NO_PROXY server-side bypass (safety net, mirrors curl/undici rules) ----
function hostBypassed(hostname, port) {
  if (!NO_PROXY) return false;
  if (NO_PROXY === "*") return true;
  return [...NO_PROXY.split(/[,\s]/)].filter(Boolean).some((rule) => {
    if (!rule) return false;
    const m = rule.match(/^(.+):(\d+)$/);
    const rh = m ? m[1].toLowerCase() : rule.toLowerCase();
    const rp = m ? Number(m[2]) : 0;
    if (rp && rp !== port) return false;
    if (rh.startsWith("*.")) return hostname.endsWith(rh.slice(1));
    if (!rh.includes(".") && !isIp(rh)) return hostname === rh || hostname.endsWith(`.${rh}`);
    return hostname === rh || (rh.startsWith(".") && hostname.endsWith(rh));
  });
}
function isIp(s) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || /^\[?[0-9a-f:]+\]?$/i.test(s);
}

// ---- auth ------------------------------------------------------------------
const AUTH_HEADER = AUTH ? `Basic ${Buffer.from(AUTH, "utf8").toString("base64")}` : null;
function authorized(req) {
  if (!AUTH_HEADER) return true;
  return req.headers["proxy-authorization"] === AUTH_HEADER;
}
function send407(req, res, msg = "Proxy authentication required") {
  res.writeHead(407, {
    "proxy-authenticate": "Basic realm=\"dsh-netproxy\"",
    "content-type": "text/plain; charset=utf-8",
  });
  res.end(msg);
  log({ evt: "auth-denied", method: req.method, url: req.url, src: ipOf(req) });
}
function ipOf(req) {
  return req.socket.remoteAddress ?? "";
}

// ---- egress connection helpers ----------------------------------------------
const proxyAuthHeader = () => (EXIT.user
  ? `Proxy-Authorization: Basic ${Buffer.from(`${EXIT.user}:${EXIT.pass}`, "utf8").toString("base64")}\r\n`
  : "");

/** Open the raw connection to the egress proxy itself (TLS if `https:`). */
function connectExit() {
  if (EXIT.kind === "https") {
    const s = tlsConnect({ host: EXIT.host, port: EXIT.port, servername: isIP(EXIT.host) ? undefined : EXIT.host });
    return new Promise((resolve, reject) => {
      s.once("secureConnect", () => resolve(s));
      s.once("error", reject);
    });
  }
  const s = netConnect({ host: EXIT.host, port: EXIT.port });
  return new Promise((resolve, reject) => {
    s.once("connect", () => resolve(s));
    s.once("error", reject);
  });
}

/**
 * Persistent buffered reader for one handshake phase. A single 'data' listener
 * accumulates everything and `read(n)`/`readHead()` slice off exactly what they
 * need, so leftover bytes are never lost. `detach()` returns any unconsumed
 * bytes to the socket (via unshift) before the tunnel takes over.
 */
function makeReader(sock, label = "egress", timeout = 10000) {
  let buf = Buffer.alloc(0);
  const waiters = [];
  const onData = (c) => { buf = Buffer.concat([buf, c]); flush(); };
  const failAll = (e) => {
    for (const w of waiters.splice(0)) { clearTimeout(w.t); w.reject(e); }
  };
  const onErr = (e) => failAll(e);
  const onClose = () => failAll(new Error(`${label}: egress closed`));
  sock.on("data", onData);
  sock.on("error", onErr);
  sock.on("close", onClose);
  function flush() {
    for (let i = waiters.length - 1; i >= 0; i--) {
      const w = waiters[i];
      const headEnd = w.delim ? buf.indexOf(w.delim) : -1;
      const take = w.delim ? (headEnd === -1 ? -1 : headEnd + w.delim.length) : w.n;
      if (take === -1 || buf.length < take) continue;
      const out = buf.subarray(0, take);
      buf = buf.subarray(take);
      waiters.splice(i, 1);
      clearTimeout(w.t);
      w.resolve(w.delim ? out.toString("latin1") : out);
    }
  }
  const read = (n) => new Promise((resolve, reject) => {
    const w = { n, delim: null, resolve, reject, t: null };
    w.t = setTimeout(() => {
      const i = waiters.indexOf(w);
      if (i >= 0) { waiters.splice(i, 1); reject(new Error(`${label} timeout`)); }
    }, timeout);
    waiters.push(w);
    flush();
  });
  const readHead = () => new Promise((resolve, reject) => {
    const w = { n: 0, delim: Buffer.from("\r\n\r\n"), resolve, reject, t: null };
    w.t = setTimeout(() => {
      const i = waiters.indexOf(w);
      if (i >= 0) { waiters.splice(i, 1); reject(new Error(`${label} head timeout`)); }
    }, timeout);
    waiters.push(w);
    flush();
  });
  return {
    read,
    readHead,
    detach() {
      sock.removeListener("data", onData);
      sock.removeListener("error", onErr);
      sock.removeListener("close", onClose);
      if (waiters.length) failAll(new Error(`${label} detached with pending reads`));
      if (buf.length) sock.unshift(buf); // handshakes leave no leftovers in practice
      buf = Buffer.alloc(0);
    },
  };
}

/** CONNECT tunnel through an HTTP(S) forward-proxy egress. */
async function httpTunnel(sock, hostname, port) {
  const reader = makeReader(sock, "upstream CONNECT");
  try {
    sock.write(`CONNECT ${hostname}:${port} HTTP/1.1\r\nHost: ${hostname}:${port}\r\nProxy-Connection: keep-alive\r\n${proxyAuthHeader()}\r\n`);
    const head = await reader.readHead();
    const statusLine = head.split("\r\n")[0];
    const m = statusLine.match(/^HTTP\/\d\.\d\s+(\d{3})/);
    const status = m ? Number(m[1]) : 0;
    if (status >= 200 && status < 300) return;
    throw new Error(`upstream proxy CONNECT -> ${status} for ${hostname}:${port} (${statusLine})`);
  } finally {
    reader.detach();
  }
}

function ipv4Bytes(s) { return Buffer.from(String(s).split(".").map((n) => Number(n) & 0xff)); }
function ipv6Bytes(s) {
  const [l, r] = String(s).split("::", 2);
  const lp = l ? l.split(":").filter(Boolean) : [];
  const rp = r ? r.split(":").filter(Boolean) : [];
  const all = [...lp, ...Array(Math.max(0, 8 - lp.length - rp.length)).fill("0"), ...rp];
  const buf = Buffer.alloc(16);
  all.forEach((p, i) => { const n = parseInt(p || "0", 16) || 0; buf[i * 2] = (n >> 8) & 0xff; buf[i * 2 + 1] = n & 0xff; });
  return buf;
}

/** SOCKS5 handshake (no-auth or user:pass). Always uses remote DNS (atyp 3). */
async function socks5Handshake(sock, hostname, port) {
  const reader = makeReader(sock, "socks5");
  try {
    const methods = EXIT.user ? [0x02, 0x00] : [0x00];
    sock.write(Buffer.from([0x05, methods.length, ...methods]));
    const sel = await reader.read(2);
    if (sel[0] !== 0x05) throw new Error(`socks5 bad version ${sel[0]}`);
    const method = sel[1];
    if (method === 0xff) throw new Error("socks5: no acceptable auth method");
    if (method === 0x02) {
      const u = Buffer.from(EXIT.user, "utf8");
      const p = Buffer.from(EXIT.pass || "", "utf8");
      sock.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([p.length]), p]));
      const st = await reader.read(2);
      if (st[1] !== 0) throw new Error(`socks5 auth failed (status ${st[1]})`);
    } else if (method !== 0x00) {
      throw new Error(`socks5 unsupported method ${method}`);
    }
    const v6 = isIP(hostname) === 6;
    const v4 = isIP(hostname) === 4;
    const addr = v6
      ? Buffer.concat([Buffer.from([0x04]), ipv6Bytes(hostname)])
      : v4
        ? Buffer.concat([Buffer.from([0x01]), ipv4Bytes(hostname)])
        : Buffer.concat([Buffer.from([0x03, hostname.length]), Buffer.from(hostname, "utf8")]);
    const portB = Buffer.from([(port >> 8) & 0xff, port & 0xff]);
    sock.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addr, portB]));
    const rep = await reader.read(4);
    if (rep[0] !== 0x05) throw new Error(`socks5 bad connect version ${rep[0]}`);
    const atyp = rep[3];
    if (atyp === 0x01) await reader.read(4);
    else if (atyp === 0x04) await reader.read(16);
    else if (atyp === 0x03) { const len = (await reader.read(1))[0]; await reader.read(len); }
    await reader.read(2);
    if (rep[1] !== 0x00) throw new Error(`socks5 CONNECT failed (rep ${rep[1]})`);
  } finally {
    reader.detach();
  }
}

/** SOCKS4 / SOCKS4a handshake. Domains use the 4a marker (0.0.0.1). */
async function socks4Handshake(sock, hostname, port) {
  const reader = makeReader(sock, "socks4");
  try {
    const portB = Buffer.from([(port >> 8) & 0xff, port & 0xff]);
    const v4 = isIP(hostname) === 4;
    const head = v4
      ? Buffer.concat([Buffer.from([0x04, 0x01]), portB, ipv4Bytes(hostname)])
      : Buffer.concat([Buffer.from([0x04, 0x01]), portB, Buffer.from([0, 0, 0, 1])]);
    const req = Buffer.concat([head, Buffer.from(EXIT.user || "", "utf8"), Buffer.from([0x00])]);
    sock.write(v4 ? req : Buffer.concat([req, Buffer.from(hostname, "utf8"), Buffer.from([0x00])]));
    const rep = await reader.read(8);
    if (rep[1] !== 0x5a) throw new Error(`socks4 CONNECT failed (CD=${rep[1]} VN=${rep[0]})`);
  } finally {
    reader.detach();
  }
}

/**
 * Open a real connection to (hostname, port) through the configured egress.
 * Resolves to a ready socket; on failure destroys it and rejects.
 */
function openTarget(hostname, port) {
  if (EXIT.kind === "http" || EXIT.kind === "https") {
    return connectExit().then((sock) =>
      httpTunnel(sock, hostname, port).catch((e) => { try { sock.destroy(); } catch {} throw e; }).then(() => sock));
  }
  if (EXIT.kind === "socks4") {
    return connectExit().then((sock) =>
      socks4Handshake(sock, hostname, port).catch((e) => { try { sock.destroy(); } catch {} throw e; }).then(() => sock));
  }
  if (EXIT.kind === "socks5") {
    return connectExit().then((sock) =>
      socks5Handshake(sock, hostname, port).catch((e) => { try { sock.destroy(); } catch {} throw e; }).then(() => sock));
  }
  // DIRECT
  const sock = netConnect({ host: hostname, port });
  return new Promise((resolve, reject) => {
    sock.once("connect", () => { sock.removeListener("error", onErr); resolve(sock); });
    const onErr = (e) => reject(e);
    sock.once("error", onErr);
  });
}

// ---- CONNECT tunnel ---------------------------------------------------------
// Node's http.Server does NOT deliver CONNECT to the `request` listener: it
// emits a `connect` event instead. We must handle it there, writing the 200
// trampoline manually to the raw client socket before piping the tunnel.
function handleConnect(req, clientSocket, start, head) {
  const src = clientSocket.remoteAddress ?? "";
  const [hostnameDir, portRaw] = (req.url || "").split(":");
  const hostname = hostnameDir || "";
  const port = Number(portRaw) || 443;
  if (AUTH_HEADER && req.headers["proxy-authorization"] !== AUTH_HEADER) {
    clientSocket.write("HTTP/1.1 407 Proxy Authentication Required\r\n")
      .write(`proxy-authenticate: Basic realm="dsh-netproxy"\r\n`)
      .write("content-length: 0\r\n\r\n");
    log({ evt: "auth-denied", method: "CONNECT", url: req.url, src });
    clientSocket.destroy();
    return;
  }
  if (!hostname) return void clientSocketDestroy(clientSocket, "HTTP/1.1 400 Bad Request\r\n\r\n", { evt: "connect-bad", src });
  if (rejectsSelf(hostname, port)) return void clientSocketDestroy(clientSocket, "HTTP/1.1 400 Bad Request\r\n\r\n", { evt: "connect-loop-refused", host: hostname, port, src });
  openTarget(hostname, port).then((sock) => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    log({ evt: "connect", host: hostname, port, via: EXIT.kind, src, ms: Date.now() - start });
    clientSocket.pipe(sock);
    if (head && head.length) sock.write(head);
    sock.pipe(clientSocket);
  }).catch((err) => {
    log({ evt: "connect-error", host: hostname, port, via: EXIT.kind, error: String(err), ms: Date.now() - start });
    clientSocketDestroy(clientSocket, "HTTP/1.1 502 Bad Gateway\r\n\r\n", null);
  });
}

function clientSocketDestroy(socket, statusText, entry) {
  if (statusText) try { socket.write(statusText); } catch {}
  if (entry) log(entry);
  try { socket.destroy(); } catch {}
}

function rejectsSelf(hostname, port) {
  const h = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const sameHost = h === BIND.toLowerCase() || h === "127.0.0.1" || h === "localhost" || h === "::1";
  return sameHost && port === PORT;
}

// ---- cleaned client headers (hop-by-hop stripped, host kept as target) --------
function cleanHeaders(req, target) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP.has(key)) continue;
    if (key === "host") continue; // rewritten below
    if (v !== undefined) headers[k] = v;
  }
  headers.host = target.host;
  headers["x-forwarded-for"] = [headers["x-forwarded-for"], ipOf(req)].filter(Boolean).join(", ");
  return headers;
}

// ---- HTTP absolute-form forwarding ----------------------------------------
function handleHttp(req, res, start) {
  if (!authorized(req)) return send407(req, res);
  let target;
  try {
    target = new URL(req.url);
  } catch {
    res.writeHead(400, { "content-type": "text/plain" }).end("bad absolute-form URL; this proxy requires proxy-style requests");
    return;
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    res.writeHead(400, { "content-type": "text/plain" }).end(`unsupported scheme ${target.protocol}`);
    return;
  }
  const toPort = Number(target.port) || (target.protocol === "https:" ? 443 : 80);
  if (rejectsSelf(target.hostname, toPort)) {
    res.writeHead(400).end("refusing to loop through itself");
    return;
  }

  const headers = cleanHeaders(req, target);

  if (EXIT.kind === "direct") {
    // Delegate to Node's own HTTP(S) stack against the target.
    const send = target.protocol === "https:" ? httpsRequest : httpRequest;
    delete headers["proxy-authorization"]; // never forward proxy credentials
    const upstream = send(target, {
      method: req.method,
      headers,
      signal: req.socket.destroyed ? AbortSignal.abort() : undefined,
    }, relayUpstream(res, req, target, start, "direct"));
    upstream.on("error", (err) => onUpstreamError(err, res, req, target, start));
    req.pipe(upstream);
    return;
  }

  if (EXIT.kind === "http" || EXIT.kind === "https") {
    // Forward the absolute-form request unchanged to the upstream proxy
    // (proxy-style), adding Proxy-Authorization for the upstream itself.
    if (EXIT.user) headers["proxy-authorization"] = `Basic ${Buffer.from(`${EXIT.user}:${EXIT.pass}`, "utf8").toString("base64")}`;
    const send = EXIT.kind === "https" ? httpsRequest : httpRequest;
    const upstream = send({ host: EXIT.host, port: EXIT.port, method: req.method, path: req.url, headers, signal: req.socket.destroyed ? AbortSignal.abort() : undefined }, relayUpstream(res, req, target, start, EXIT.kind));
    upstream.on("error", (err) => onUpstreamError(err, res, req, target, start));
    req.pipe(upstream);
    return;
  }

  // SOCKS egress: tunnel to the target, then speak origin-form on it (blind
  // relay — status/headers/body are passed through verbatim).
  delete headers["proxy-authorization"];
  openTarget(target.hostname, toPort).then((sock) => {
    const originPath = (target.pathname || "/") + (target.search || "");
    let head = `${req.method} ${originPath} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(headers)) {
      if (v === undefined) continue;
      head += `${k}: ${Array.isArray(v) ? v.join(", ") : v}\r\n`;
    }
    head += "Connection: close\r\n\r\n";
    sock.write(head);
    if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS" || req.method === "DELETE") {
      sock.end();
    } else {
      req.on("end", () => sock.end());
      req.on("error", () => sock.destroy());
      req.pipe(sock, { end: false });
    }
    sock.pipe(res);
    res.on("finish", () => {
      log({ evt: "http", method: req.method, scheme: target.protocol.slice(0, -1), host: target.host, path: target.pathname, status: undefined, via: "socks", src: ipOf(req), ms: Date.now() - start });
    });
    sock.on("error", (err) => {
      log({ evt: "http-error", method: req.method, host: target.host, path: target.pathname, via: "socks", error: String(err), ms: Date.now() - start });
      try { res.destroy(); } catch {}
    });
  }).catch((err) => {
    log({ evt: "http-error", method: req.method, host: target.host, path: target.pathname, via: "socks", error: String(err), ms: Date.now() - start });
    if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain", "content-length": 15 }).end("upstream failure");
    else try { res.destroy(); } catch {}
  });
}

function relayUpstream(res, req, target, start, via) {
  return (upRes) => {
    const outHeaders = {};
    let len = 0;
    for (const [k, v] of Object.entries(upRes.headers)) {
      if (HOP_BY_HOP.has(k.toLowerCase())) continue;
      outHeaders[k] = v;
    }
    res.writeHead(upRes.statusCode ?? 502, outHeaders);
    upRes.on("data", (c) => { len += c.length; });
    upRes.pipe(res);
    res.on("finish", () => {
      log({ evt: "http", method: req.method, scheme: target.protocol.slice(0, -1), host: target.host, path: target.pathname, status: upRes.statusCode, bytes: len, via, src: ipOf(req), ms: Date.now() - start });
    });
  };
}

function onUpstreamError(err, res, req, target, start) {
  log({ evt: "http-error", method: req.method, host: target.host, path: target.pathname, error: String(err), ms: Date.now() - start });
  if (!res.headersSent) {
    // Clean 502 so strict clients (undici) read the response instead of
    // seeing the connection aborted mid-handshake as "request cancelled".
    res.writeHead(502, { "content-type": "text/plain", "content-length": 15 }).end("upstream failure");
  } else {
    res.destroy();
  }
  req.unpipe();
  res.on("close", () => req.socket.destroy());
}

// ---- server ----------------------------------------------------------------
const server = createServer((req, res) => {
  const start = Date.now();
  if (!authorized(req)) return send407(req, res);
  return handleHttp(req, res, start);
});
// CONNECT requests are delivered to the `connect` event, not `request`.
server.on("connect", (req, clientSocket, head) => {
  handleConnect(req, clientSocket, Date.now(), head);
});

let conns = 0;
server.maxConnections = MAX_CONNS || undefined;
server.on("connection", (s) => {
  conns += 1;
  s.on("close", () => { conns -= 1; });
});

server.listen(PORT, BIND, () => {
  log({ evt: "listen", bind: BIND, port: PORT, auth: !!AUTH, noProxy: NO_PROXY || "(none)", log: LOG_TARGET, upstream: UPSTREAM || "(direct)" });
  process.stdout.write(`dsh-netproxy engine listening on ${BIND}:${PORT} (auth=${!!AUTH}, egress=${EXIT.kind})${UPSTREAM ? ` via ${UPSTREAM}` : ""}\n`);
});

function shutdown(signal) {
  log({ evt: "shutdown", signal, conns });
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1500).unref();
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
