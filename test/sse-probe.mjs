/**
 * sse-probe — reproduces "external proxy + LLM SSE → DSH retry" in isolation.
 *
 * Uses the SAME hot-routing mechanism as lib/index.js (undici ProxyAgent +
 * requestTls.ca + per-call target) with loopback bypass OFF, so a local TLS SSE
 * origin exercises the exact proxied-streaming path the live plugin uses.
 *
 * Scenarios:
 *   A) CONNECT passthrough engine (our lib/engine.js) — baseline.
 *   B) "Burp-like" MITM proxy: terminates client TLS with its own CA, reopens
 *      upstream TLS to the origin (trusting the origin CA), streams back.
 *
 * Each run issues N sequential SSE requests and reports per-request success,
 * first-byte latency, event count, and any failure reason (+ simulated retry,
 * i.e. DSH would mark the request for retry on failure/abort).
 */
import { spawn, execSync } from 'node:child_process';
import { createServer as createHttpsServer, request as httpsRequest } from 'node:https';
import { createServer as createHttpServer } from 'node:http';
import { TLSSocket } from 'node:tls';
import { createServer as createNetServer } from 'node:net';
import zlib from 'node:zlib';
import { readFile, rm, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ProxyAgent } from 'undici';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE = join(HERE, '..', 'lib', 'engine.js');
const TMP = join(HERE, '.sse-tmp');
const ok = (c, m) => console.log(`${c ? '  ok -' : '  FAIL -'} ${m}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const run = (cmd) => execSync(cmd, { stdio: 'pipe' });

const ORIGIN_PORT = 8444;
const ENGINE_PORT = 4435;
const MITM_PORT = 4436;
const GZIP_PORT = 4437;
const BUFFER_PORT = 4438;
const EVENTS = 12;
const EVENT_INTERVAL = 120; // ms between SSE events
const N_REQUESTS = 5;

// ---- SSE origin (TLS, cert signed by our CA) -------------------------------
const sseHandler = (req, res) => {
  let iv = EVENT_INTERVAL;
  try { iv = Number(new URL(req.url, 'http://x').searchParams.get('iv')) || EVENT_INTERVAL; } catch {}
  res.writeHead(200, {
    'content-type': 'text/event-stream; charset=utf-8',
    'cache-control': 'no-cache',
    connection: 'keep-alive',
  });
  let i = 0;
  const t = setInterval(() => {
    i += 1;
    res.write(`data: ${JSON.stringify({ i, ts: Date.now() })}\n\n`);
    if (i >= EVENTS) {
      clearInterval(t);
      res.write('data: [DONE]\n\n');
      res.end();
    }
  }, iv);
  req.on('close', () => clearInterval(t));
};

// ---- "Burp-like" MITM forward proxy ------------------------------------------
// Terminates client TLS with `certPem` (signed by our proxy CA), reopens an
// upstream TLS to (host, port) trusting `originCa`, and pipes HTTP/1.1
// bidirectionally. `respMode` controls how the response is delivered:
//   'stream' -> pass through untouched (a compliant proxy),
//   'gzip'   -> if the client accepted gzip, re-encode the SSE stream with a
//               non-flushed gzip writer (≈ Burp re-encoding; undici/DSH see a
//               delayed first byte until the gzip buffer/stream fills),
//   'buffer' -> hold the whole response, send it at once (≈ response buffering).
function startMitmProxy({ caPem, certPem, keyPem }, { originCa, respMode = 'stream', port = MITM_PORT }) {
  const tunnels = [];
  const debug = process.env.SSE_DEBUG === '1';
  const log = (...a) => { if (debug) console.log('   [mitm]', ...a); };
  const server = createNetServer((raw) => {
    raw.once('data', (chunk) => {
      const head = chunk.toString('latin1');
      const m = head.match(/^CONNECT ([^\s:]+):(\d+) HTTP\/1\.1/i);
      if (!m) { try { raw.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch {} return; }
      const host = m[1]; const port = Number(m[2]);
      const breakAt = head.indexOf('\r\n\r\n');
      const leftover = breakAt >= 0 ? chunk.slice(breakAt + 4) : Buffer.alloc(0);
      log('CONNECT', host, port, 'leftover', leftover.length);
      // 1) answer CONNECT, 2) put any early TLS bytes back, 3) wrap in TLS.
      try { raw.write('HTTP/1.1 200 Connection established\r\n\r\n'); } catch {}
      if (leftover.length) raw.unshift(leftover);
      const secure = new TLSSocket(raw, { isServer: true, key: keyPem, cert: certPem, ca: caPem });
      secure.on('tlsClientError', (e) => log('tlsClientError', e.code || e.message));
      let buf = '', parsed = false, upHead = null;
      secure.on('secure', () => {
        log('secure OK', host, port);
        const started = Date.now();
        const tryParse = () => {
          if (parsed) return;
          const at = buf.indexOf('\r\n\r\n');
          if (at === -1) return;
          parsed = true;
          const headPart = buf.slice(0, at);
          const lines = headPart.split('\r\n');
          const [method, path] = (lines[0] || '').split(' ');
          const hdrs = {};
          for (const l of lines.slice(1)) { const i = l.indexOf(':'); if (i > 0) hdrs[l.slice(0, i).toLowerCase()] = l.slice(i + 1).trim(); }
          delete hdrs['proxy-connection'];
          log('parsed request', method, path, 'hdrLen', Object.keys(hdrs).length);
          secure.removeAllListeners('data');
          secure.on('data', (d) => upHead.write(d));
          const up = httpsRequest({ host, port, method, path, servername: host, rejectUnauthorized: true, ca: originCa, headers: hdrs });
          upHead = up;
          up.on('socket', () => log('upstream socket opened'));
          up.on('response', (upRes) => {
            log('upstream response', upRes.statusCode, path, 'respMode', respMode);
            const statusLine = `HTTP/1.1 ${upRes.statusCode || 502} ${upRes.statusMessage || ''}\r\n`;
            let h = '';
            for (const [k, v] of Object.entries(upRes.headers)) {
              if (k === 'transfer-encoding' || k === 'connection' || k === 'content-length') continue;
              h += `${k}: ${v}\r\n`;
            }
            const acceptedGzip = ((hdrs['accept-encoding'] || '').toLowerCase().includes('gzip'));
            const useGzip = respMode === 'gzip' && acceptedGzip;
            if (useGzip) h += 'content-encoding: gzip\r\n';
            secure.write(statusLine + h + '\r\n');
            if (respMode === 'buffer') {
              const chunks = [];
              upRes.on('data', (c) => chunks.push(c));
              upRes.on('end', () => {
                tunnels.push({ host, port, ms: Date.now() - started });
                secure.write(Buffer.concat(chunks));
                try { secure.end(); } catch {}
              });
            } else if (useGzip) {
              const gz = zlib.createGzip(); // default flush → output withheld until ~32KB or end
              upRes.pipe(gz);
              gz.pipe(secure, { end: false });
              gz.on('end', () => { tunnels.push({ host, port, ms: Date.now() - started }); try { secure.end(); } catch {} });
            } else {
              upRes.pipe(secure, { end: false });
              upRes.on('end', () => { tunnels.push({ host, port, ms: Date.now() - started }); try { secure.end(); } catch {} });
            }
          });
          up.on('error', (e) => { log('upstream error', e.code || e.message); try { secure.write('HTTP/1.1 502 Bad Gateway\r\n\r\n'); secure.end(); } catch {} });
          const body = Buffer.from(buf.slice(at + 4), 'utf8');
          if (body.length) up.write(body);
          up.end(); // finalize the request so the origin responds
        };
        secure.on('data', (d) => { if (!parsed) { log('inner bytes', d.length); buf += d.toString('latin1'); tryParse(); } else { log('inner body bytes', d.length); } });
      });
    });
  });
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => resolve({
      server, close: () => new Promise((r) => server.close(r)), tunnels,
    }));
  });
}

// ---- consumer (replicates hot wrapper) ----------------------------------------
async function runConsumer({ proxyUrl, caPem, targetUrl, plainStream = true }) {
  const orig = globalThis.fetch;
  const cache = new Map();
  const dispatcherFor = (u, ca) => {
    const key = `${u}|${ca ? 'ca' : ''}`;
    if (!cache.has(key)) cache.set(key, ca ? new ProxyAgent({ uri: u, requestTls: { ca: [ca] } }) : new ProxyAgent(u));
    return cache.get(key);
  };
  globalThis.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url);
    if (!url || !proxyUrl) return orig(input, init);
    if (init && init.dispatcher) return orig(input, init);
    let init2 = { ...(init || {}), dispatcher: dispatcherFor(proxyUrl, caPem) };
    if (plainStream) {
      const h = new Headers(init && init.headers);
      h.set('accept-encoding', 'identity');
      init2.headers = h;
    }
    return orig.call(this, input, init2);
  };

  const results = [];
  const REQUEST_TIMEOUT = 20000;
  for (let n = 1; n <= N_REQUESTS; n++) {
    const t0 = Date.now();
    let firstByte = 0, firstEventAt = -1, events = 0, done = false, error = '', lastEventAt = 0, maxGap = 0;
    const ctl = new AbortController();
    const guard = setTimeout(() => ctl.abort(new Error('request-timeout')), REQUEST_TIMEOUT);
    try {
      const res = await globalThis.fetch(targetUrl, { method: 'POST', signal: ctl.signal });
      firstByte = Date.now() - t0;
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      while (true) {
        const { value, done: d } = await reader.read();
        if (d) break;
        buf += dec.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf('\n\n')) !== -1) {
          const chunk = buf.slice(0, idx); buf = buf.slice(idx + 2);
          if (chunk.startsWith('data:')) {
            const now = Date.now();
            if (events === 0) firstEventAt = now - t0; else { const gap = now - lastEventAt; if (gap > maxGap) maxGap = gap; }
            lastEventAt = now;
            events += 1;
            if (chunk.includes('[DONE]')) done = true;
          }
        }
      }
      if (events === 0) firstEventAt = -1;
    } catch (e) {
      error = (e.cause && (e.cause.code || e.cause.message)) || String(e.message || e) || String(e);
    } finally {
      clearTimeout(guard);
    }
    results.push({
      n, firstByte, firstEventAt, maxGap, events, done, error,
      retry: error ? true : (!done || firstEventAt < 0 || firstEventAt > 2000 || maxGap > 2000),
    });
  }
  globalThis.fetch = orig;
  return results;
}

// ---- main ----------------------------------------------------------------------
let pass = true, fails = [];
const record = (c, m) => { ok(c, m); if (!c) { pass = false; fails.push(m); } };

try {
  await rm(TMP, { recursive: true, force: true });
  await mkdir(TMP, { recursive: true });
  run(`openssl req -x509 -newkey rsa:2048 -keyout ${TMP}/ca.key -out ${TMP}/ca.pem -days 2 -nodes -subj "/C=CN/O=np-test/CN=np-test-ca"`);
  run(`openssl req -newkey rsa:2048 -keyout ${TMP}/origin.key -out ${TMP}/origin.csr -nodes -subj "/C=CN/O=np-test/CN=127.0.0.1"`);
  run(`printf "subjectAltName=IP:127.0.0.1\\n" > ${TMP}/san.cnf`);
  run(`openssl x509 -req -in ${TMP}/origin.csr -CA ${TMP}/ca.pem -CAkey ${TMP}/ca.key -CAcreateserial -out ${TMP}/origin.pem -days 2 -extfile ${TMP}/san.cnf`);
  // proxy cert = same CA signs a CN=proxy.127.0.0.1 cert
  run(`openssl req -newkey rsa:2048 -keyout ${TMP}/mitm.key -out ${TMP}/mitm.csr -nodes -subj "/C=CN/O=np-test/CN=proxy.test"`);
  run(`printf "subjectAltName=IP:127.0.0.1,DNS:proxy.test\\n" > ${TMP}/mitm-san.cnf`);
  run(`openssl x509 -req -in ${TMP}/mitm.csr -CA ${TMP}/ca.pem -CAkey ${TMP}/ca.key -CAcreateserial -out ${TMP}/mitm.pem -days 2 -extfile ${TMP}/mitm-san.cnf`);

  const [caPem, originKey, originCert, mitmKey, mitmCert] = await Promise.all([
    readFile(join(TMP, 'ca.pem'), 'utf8'),
    readFile(join(TMP, 'origin.key'), 'utf8'),
    readFile(join(TMP, 'origin.pem'), 'utf8'),
    readFile(join(TMP, 'mitm.key'), 'utf8'),
    readFile(join(TMP, 'mitm.pem'), 'utf8'),
  ]);

  // origin HTTPS server
  const origin = createHttpsServer({ key: originKey, cert: originCert }, sseHandler);
  await new Promise((r) => origin.listen(ORIGIN_PORT, '127.0.0.1', r));

  // engine (CONNECT passthrough)
  const engine = spawn(process.execPath, [ENGINE, '--port', String(ENGINE_PORT), '--log', join(TMP, 'engine.log')], { cwd: dirname(ENGINE), stdio: 'ignore' });
  // mitm proxy (streaming by default)
  const mitm = await startMitmProxy({ caPem, certPem: mitmCert, keyPem: mitmKey }, { originCa: caPem, respMode: 'stream' });
  await sleep(800);

  console.log('== A) SSE through CONNECT passthrough engine (same wrapper) ==');
  const rA = await runConsumer({ proxyUrl: `http://127.0.0.1:${ENGINE_PORT}`, caPem, targetUrl: `https://127.0.0.1:${ORIGIN_PORT}/sse?iv=120` });
  for (const r of rA) console.log(`  req#${r.n}: firstEvent=${r.firstEventAt}ms maxGap=${r.maxGap}ms events=${r.events} done=${r.done}${r.error ? ' ERROR=' + r.error : ''}${r.retry ? ' => RETRY' : ''}`);
  record(rA.every((r) => !r.error && r.done && r.events >= EVENTS), `engine passthrough: ${N_REQUESTS}/${N_REQUESTS} SSE OK, no errors`);

  console.log('== B) SSE through streaming MITM proxy (well-behaved) ==');
  const rB = await runConsumer({ proxyUrl: `http://127.0.0.1:${MITM_PORT}`, caPem, targetUrl: `https://127.0.0.1:${ORIGIN_PORT}/sse?iv=120` });
  for (const r of rB) console.log(`  req#${r.n}: firstEvent=${r.firstEventAt}ms maxGap=${r.maxGap}ms events=${r.events} done=${r.done}${r.error ? ' ERROR=' + r.error : ''}${r.retry ? ' => RETRY' : ''}`);
  record(rB.every((r) => !r.error && r.done && r.events >= EVENTS), `mitm stream: ${rB.filter((r) => !r.error && r.done).length}/${N_REQUESTS} SSE OK`);

  // ---- C) gzip re-encoding MITM: the "Burp receives SSE but DSH retries" repro --
  const mitmGzip = await startMitmProxy({ caPem, certPem: mitmCert, keyPem: mitmKey }, { originCa: caPem, respMode: 'gzip', port: GZIP_PORT });
  await sleep(300);
  const slowTarget = `https://127.0.0.1:${ORIGIN_PORT}/sse?iv=450`; // ~5.4s stream
  console.log('== C1) gzip MITM + client accepts gzip (plainStream OFF) — should stall/retry ==');
  const rC1 = await runConsumer({ proxyUrl: `http://127.0.0.1:${GZIP_PORT}`, caPem, targetUrl: slowTarget, plainStream: false });
  for (const r of rC1) console.log(`  req#${r.n}: firstEvent=${r.firstEventAt}ms maxGap=${r.maxGap}ms events=${r.events} done=${r.done}${r.error ? ' ERROR=' + r.error : ''}${r.retry ? ' => RETRY' : ''}`);
  const c1Retry = rC1.some((r) => r.retry);
  record(c1Retry, `gzip + client accepts gzip ⇒ first event stalled (firstEventAt ${rC1.map((r) => r.firstEventAt).join('/')}ms), DSH would retry`);

  console.log('== C2) same gzip MITM + plainStream ON (identity) — smooth ==');
  const rC2 = await runConsumer({ proxyUrl: `http://127.0.0.1:${GZIP_PORT}`, caPem, targetUrl: slowTarget, plainStream: true });
  for (const r of rC2) console.log(`  req#${r.n}: firstEvent=${r.firstEventAt}ms maxGap=${r.maxGap}ms events=${r.events} done=${r.done}${r.error ? ' ERROR=' + r.error : ''}${r.retry ? ' => RETRY' : ''}`);
  record(rC2.every((r) => !r.error && r.done && r.firstEventAt >= 0 && r.firstEventAt < 1200 && r.maxGap < 1200), `plainStream ON ⇒ first event streams promptly (firstEventAt ${rC2.map((r) => r.firstEventAt).join('/')}ms), no retry`);
  await mitmGzip.close();

  // ---- D) buffering MITM (informational; needs Burp-side settings) ----
  const mitmBuf = await startMitmProxy({ caPem, certPem: mitmCert, keyPem: mitmKey }, { originCa: caPem, respMode: 'buffer', port: BUFFER_PORT });
  await sleep(300);
  console.log('== D) response-buffering MITM (information only, not fixed by plainStream) ==');
  const rD = await runConsumer({ proxyUrl: `http://127.0.0.1:${BUFFER_PORT}`, caPem, targetUrl: slowTarget, plainStream: true });
  for (const r of rD) console.log(`  req#${r.n}: firstEvent=${r.firstEventAt}ms maxGap=${r.maxGap}ms events=${r.events} done=${r.done}${r.error ? ' ERROR=' + r.error : ''}`);
  console.log('  (buffer mode: firstByte ≈ 整段流时长，需在 Burp 关闭响应缓冲/对目标开 TLS pass-through)');
  await mitmBuf.close();

  origin.close(); engine.kill('SIGTERM'); await mitm.close();
} catch (e) {
  pass = false; fails.push(String((e && e.stack) || e));
  console.log('THREW:', (e && e.stack) || e);
} finally {
  await sleep(500);
  rm(TMP, { recursive: true, force: true }).catch(() => {});
}
console.log(fails.length === 0 ? '\nSSE PROBE PASS' : `\nSSE PROBE FAIL:\n- ` + fails.join('\n- '));
process.exit(pass ? 0 : 1);
