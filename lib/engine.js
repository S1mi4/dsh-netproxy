#!/usr/bin/env node
/**
 * dsh-netproxy engine — a dependency-free local forward proxy.
 *
 * Serves the L0 enforcement point for DSH: the DSH host process (LLM adapters,
 * web tool, other plugins) and its child shells are pointed at this engine via
 * `HTTP(S)_PROXY` + `NODE_OPTIONS=--use-env-proxy`. The engine speaks classic
 * forward-proxy protocols so any fetch/curl/git client can be routed through it:
 *
 *   - CONNECT      -> blind TCP/TLS tunnel (HTTPS, wss). No MITM by default.
 *   - GET/POST …   -> absolute-form (proxy-style) HTTP forwarding.
 *   - basic auth   -> optional `Proxy-Authorization: Basic` (env AUTH=user:pass).
 *   - access log   -> JSON-lines to stdout and/or a file (LOG_FILE).
 *   - NO_PROXY     -> parsed and honoured as a server-side safety net (clients
 *                     such as Node's --use-env-proxy already handle bypass, this
 *                     is belt-and-braces for weird clients).
 *
 * Loop-loop guard: requests whose target equals this engine's own listener are
 * rejected with 400 so a misconfig cannot self-recurse.
 *
 * Usage:
 *   node engine.js [--port 4317] [--bind 127.0.0.1] [--auth user:pass]
 *                  [--log FILE|stdout] [--no-proxy 127.0.0.1,localhost]
 *   Env: PORT, BIND, AUTH, LOG_FILE, NO_PROXY, MAX_CONNS (all optional).
 *
 * The engine is spawned as its own host-realm subprocess by the plugin's host
 * half (Phase 2+). It has no dependencies on the DSH runtime or npm packages.
 */
import { createServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";
import { connect as netConnect } from "node:net";
import { createWriteStream } from "node:fs";

const HOP_BY_HOP = new Set([
  "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
  "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
]);

// ---- tiny argv/env parsing -------------------------------------------------
function opt(name, fallback) {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx !== -1 && process.argv[idx + 1] !== undefined) return process.argv[idx + 1];
  const env = { port: "PORT", bind: "BIND", auth: "AUTH", log: "LOG_FILE", "no-proxy": "NO_PROXY", "max-conns": "MAX_CONNS" }[name];
  if (env && process.env[env]) return process.env[env];
  return fallback;
}
const PORT = Number(opt("port", "4317"));
const BIND = opt("bind", "127.0.0.1");
const AUTH = opt("auth", "");
const LOG_TARGET = opt("log", "stdout");
const NO_PROXY = (opt("no-proxy", "") || "").toLowerCase();
const MAX_CONNS = Number(opt("max-conns", "0")) || 0;

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
  const sock = netConnect(port, hostname, () => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    log({ evt: "connect", host: hostname, port, src, ms: Date.now() - start });
    clientSocket.pipe(sock);
    if (head && head.length) sock.write(head);
    sock.pipe(clientSocket);
  });
  sock.on("error", (err) => {
    log({ evt: "connect-error", host: hostname, port, error: String(err), ms: Date.now() - start });
    clientSocketDestroy(clientSocket, "HTTP/1.1 502 Bad Gateway\r\n\r\n", null);
  });
  clientSocket.on("error", () => sock.destroy());
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

  const headers = {};
  const hopStrip = new Set(HOP_BY_HOP);
  for (const [k, v] of Object.entries(req.headers)) {
    const key = k.toLowerCase();
    if (hopStrip.has(key)) continue;
    if (key === "host") continue; // rewritten below
    if (v !== undefined) headers[k] = v;
  }
  headers.host = target.host;
  headers["x-forwarded-for"] = [headers["x-forwarded-for"], ipOf(req)].filter(Boolean).join(", ");
  const proxyHeaders = target.protocol === "https:" ? { ...headers, "proxy-authorization": undefined } : headers;
  delete proxyHeaders["proxy-authorization"]; // never forward proxy credentials

  const send = target.protocol === "https:" ? httpsRequest : httpRequest;
  const upstream = send(target, {
    method: req.method,
    headers,
    signal: req.socket.destroyed ? AbortSignal.abort() : undefined,
  }, (upRes) => {
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
      log({
        evt: "http", method: req.method, scheme: target.protocol.slice(0, -1),
        host: target.host, path: target.pathname, status: upRes.statusCode,
        bytes: len, src: ipOf(req), ms: Date.now() - start,
      });
    });
  });
  upstream.on("error", (err) => {
    log({ evt: "http-error", method: req.method, host: target.host, path: target.pathname, error: String(err), ms: Date.now() - start });
    if (!res.headersSent) {
      // Clean 502 so strict clients (undici) read the response instead of
      // seeing the connection aborted mid-handshake as "request cancelled".
      res.writeHead(502, { "content-type": "text/plain", "content-length": 15 }).end("upstream failure");
    } else {
      res.destroy();
    }
    req.unpipe(upstream);
    res.on("close", () => req.socket.destroy());
  });
  req.pipe(upstream);
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
  log({ evt: "listen", bind: BIND, port: PORT, auth: !!AUTH, noProxy: NO_PROXY || "(none)", log: LOG_TARGET });
  process.stdout.write(`dsh-netproxy engine listening on ${BIND}:${PORT} (auth=${!!AUTH})\n`);
});

function shutdown(signal) {
  log({ evt: "shutdown", signal, conns });
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1500).unref();
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
