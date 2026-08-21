/**
 * socks-probe — validates the engine's UNIFIED EGRESS (the new Postman-style
 * model): no matter which protocol the user picks, one local engine is the
 * routing point and builds the real connection through that egress.
 *
 * Covered here (engine-level, zero-dependency handshakes):
 *   1) SOCKS5 (no-auth)  : absolute-form HTTP through a socks5 egress.
 *   2) SOCKS5 (no-auth)  : CONNECT tunnel through socks5 (echo relay).
 *   3) SOCKS5 user:pass  : CONNECT tunnel through an authenticated socks5.
 *   4) SOCKS4            : CONNECT tunnel through socks4 (incl. socks4a domain).
 *   5) HTTP proxy chain  : engine -> http upstream engine -> origin (both logs).
 *   6) HTTPS upstream    : engine egress https:// — CONNECT via TLS upstream.
 *
 * A minimal in-probe SOCKS5/SOCKS4 server (node:net only) acts as the upstream.
 */
import { spawn } from 'node:child_process';
import { createServer as httpServer } from 'node:http';
import { createServer as netServer, connect as netConnect } from 'node:net';
import { createServer as tlsServer } from 'node:tls';
import { readFile, rm } from 'node:fs/promises';
import { execSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ProxyAgent } from 'undici';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE = join(HERE, '..', 'lib', 'engine.js');
const TMP = join(HERE, '.tmp-socks');
const failures = [];
const ok = (c, m) => { if (c) console.log('  ok -', m); else { failures.push(m); console.log('  FAIL -', m); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const listen = (srv, port, host = '127.0.0.1') => new Promise((r) => srv.listen(port, host, r));

/** Sequential byte reader: returns exactly n bytes, keeping leftovers queued. */
class SeqReader {
  constructor(sock) {
    this.buf = Buffer.alloc(0);
    this.waiting = [];
    sock.on('data', (c) => { this.buf = Buffer.concat([this.buf, c]); this._flush(); });
    sock.on('error', (e) => this._err(e));
    sock.on('close', () => this._err(new Error('socket closed')));
  }
  _flush() {
    for (let i = this.waiting.length - 1; i >= 0; i--) {
      const w = this.waiting[i];
      if (this.buf.length >= w.n) {
        const out = this.buf.subarray(0, w.n);
        this.buf = this.buf.subarray(w.n);
        this.waiting.splice(i, 1);
        clearTimeout(w.t);
        w.resolve(out);
      }
    }
  }
  _err(e) { for (const w of this.waiting) { clearTimeout(w.t); w.reject(e); } this.waiting = []; }
  read(n, timeout = 8000) {
    return new Promise((resolve, reject) => {
      const w = { n, resolve, reject, t: null };
      w.t = setTimeout(() => {
        const i = this.waiting.indexOf(w);
        if (i >= 0) { this.waiting.splice(i, 1); reject(new Error('reader timeout')); }
      }, timeout);
      this.waiting.push(w);
      this._flush();
    });
  }
}

// ---- minimal SOCKS5 server (no-auth + user/pass 'u1':'p1') ----
function socks5Server() {
  const srv = netServer((sock) => {
    const reader = new SeqReader(sock);
    (async () => {
      const hdr = await reader.read(2);
      const nm = hdr[1];
      const methods = await reader.read(nm);
      const list = [...methods];
      const mode = list.includes(0x00) ? 'noauth' : list.includes(0x02) ? 'auth' : null;
      if (!mode) { sock.write(Buffer.from([0x05, 0xff])); sock.destroy(); return; }
      sock.write(Buffer.from([0x05, mode === 'auth' ? 0x02 : 0x00]));
      if (mode === 'auth') {
        const [v, ulen] = [...(await reader.read(2))];
        const user = (await reader.read(ulen)).toString('utf8');
        const plen = (await reader.read(1))[0];
        const pass = (await reader.read(plen)).toString('utf8');
        if (user !== 'u1' || pass !== 'p1') { sock.write(Buffer.from([0x01, 0x01])); sock.destroy(); return; }
        sock.write(Buffer.from([0x01, 0x00]));
      }
      const h = await reader.read(4);
      const cmd = h[1]; const atyp = h[3];
      let host = '';
      if (atyp === 0x01) host = [...(await reader.read(4))].join('.');
      else if (atyp === 0x04) { host = '::1'; await reader.read(16); }
      else if (atyp === 0x03) { const len = (await reader.read(1))[0]; host = (await reader.read(len)).toString('utf8'); }
      const pb = await reader.read(2);
      const port = pb[0] * 256 + pb[1];
      const replyHead = (code) => Buffer.concat([Buffer.from([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])]);
      if (cmd !== 0x01) { sock.write(replyHead(0x07)); sock.destroy(); return; }
      const up = netConnect(port, host, () => { sock.write(replyHead(0x00)); sock.pipe(up); up.pipe(sock); });
      up.on('error', () => { try { sock.write(replyHead(0x05)); sock.destroy(); } catch {} });
    })().catch(() => sock.destroy());
  });
  return srv;
}

// ---- minimal SOCKS4 / SOCKS4a server ----
function socks4Server() {
  const srv = netServer((sock) => {
    const reader = new SeqReader(sock);
    (async () => {
      const head = await reader.read(8);
      const port = head[2] * 256 + head[3];
      const ipv4 = [...head.subarray(4, 8)];
      let user = Buffer.alloc(0);
      for (;;) { const b = await reader.read(1); if (b[0] === 0) break; user = Buffer.concat([user, b]); }
      let host;
      const isDomain = ipv4[0] === 0 && ipv4[1] === 0 && ipv4[2] === 0 && ipv4[3] !== 0;
      if (isDomain) {
        let dom = Buffer.alloc(0);
        for (;;) { const b = await reader.read(1); if (b[0] === 0) break; dom = Buffer.concat([dom, b]); }
        host = dom.toString('utf8');
      } else {
        host = ipv4.join('.');
      }
      const ok8 = Buffer.from([0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      const fail8 = Buffer.from([0x00, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
      const up = netConnect(port, host, () => { sock.write(ok8); sock.pipe(up); up.pipe(sock); });
      up.on('error', () => { try { sock.write(fail8); sock.destroy(); } catch {} });
    })().catch(() => sock.destroy());
  });
  return srv;
}

const startEngine = async (port, upstream, extraEnv = {}) => {
  const args = ['--port', String(port), '--log', join(TMP, `eng-${port}.log`)];
  if (upstream) args.push('--upstream', upstream);
  const child = spawn(process.execPath, [ENGINE, ...args], { cwd: dirname(ENGINE), stdio: 'ignore', env: { ...process.env, ...extraEnv } });
  await sleep(500);
  return child;
};

/** Raw CONNECT through an engine; sends `payload`, expects it echoed back. */
function tunnelVia(enginePort, host, port, payload) {
  return new Promise((resolve, reject) => {
    const sock = netConnect(enginePort, '127.0.0.1', () => {
      sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);
    });
    let buf = '';
    let tunneled = false;
    const timer = setTimeout(() => { sock.destroy(); reject(new Error('tunnel timeout')); }, 10000);
    sock.on('data', (c) => {
      buf += c.toString('latin1');
      if (!tunneled) {
        const i = buf.indexOf('\r\n\r\n');
        if (i === -1) return;
        const head = buf.slice(0, i);
        if (/^HTTP\/1\.[01] 200/.test(head)) {
          tunneled = true;
          const leftover = buf.slice(i + 4);
          buf = '';
          sock.write(payload);
          if (leftover) sock.emit('data', Buffer.from(leftover, 'latin1'));
        } else {
          clearTimeout(timer);
          sock.destroy();
          resolve({ error: head.split('\r\n')[0] });
        }
        return;
      }
      if (buf.includes(payload)) {
        clearTimeout(timer);
        sock.destroy();
        resolve({ ok: true, echo: buf.slice(0, payload.length) });
      }
    });
    sock.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

const S5 = 4601, S5A = 4602, S4 = 4603, ORIGIN = 4604, ECHO = 4605;
const ENG5 = 4606, ENG5A = 4607, ENG4 = 4608, ENGB = 4609, ENGC = 4610;
const TLSUP = 4611, ENGHTTPS = 4612;

const engines = [];
try {
  await rm(TMP, { recursive: true, force: true }).catch(() => {});
  const { mkdir } = await import('node:fs/promises');
  await mkdir(TMP, { recursive: true });

  // ---- origins ----
  const origin = httpServer((req, res) => res.end(`origin-ok:${req.url}`));
  await listen(origin, ORIGIN);
  const echo = netServer((s) => s.on('data', (d) => s.write(d)));
  await listen(echo, ECHO);

  const s5 = socks5Server(); await listen(s5, S5);
  const s5a = socks5Server(); await listen(s5a, S5A);
  const s4 = socks4Server(); await listen(s4, S4);

  // ---- 1) SOCKS5 no-auth, absolute-form HTTP ----
  console.log('== 1) socks5 (no-auth) absolute-form ==');
  const e5 = await startEngine(ENG5, `socks5://127.0.0.1:${S5}`);
  engines.push(e5);
  const r1 = await fetch(`http://127.0.0.1:${ORIGIN}/hello`, { dispatcher: new ProxyAgent(`http://127.0.0.1:${ENG5}`) });
  const b1 = await r1.text();
  ok(r1.status === 200 && b1 === `origin-ok:/hello`, `http via socks5 egress → 200 "${b1}"`);

  // ---- 2) SOCKS5 no-auth CONNECT tunnel ----
  console.log('== 2) socks5 (no-auth) CONNECT ==');
  const t2 = await tunnelVia(ENG5, '127.0.0.1', ECHO, 'ping');
  ok(t2.ok && t2.echo === 'ping', `CONNECT through socks5 → echo "${t2.echo || t2.error}"`);

  // ---- 3) SOCKS5 user:pass CONNECT ----
  console.log('== 3) socks5 (user:pass) CONNECT ==');
  const e5a = await startEngine(ENG5A, `socks5://u1:p1@127.0.0.1:${S5A}`);
  engines.push(e5a);
  const t3 = await tunnelVia(ENG5A, '127.0.0.1', ECHO, 'pong');
  ok(t3.ok && t3.echo === 'pong', `CONNECT through authenticated socks5 → echo "${t3.echo || t3.error}"`);

  // ---- 4) SOCKS4 CONNECT (socks4a domain) ----
  console.log('== 4) socks4 CONNECT ==');
  const e4 = await startEngine(ENG4, `socks4://127.0.0.1:${S4}`);
  engines.push(e4);
  const t4 = await tunnelVia(ENG4, '127.0.0.1', ECHO, 's4ping');
  ok(t4.ok && t4.echo === 's4ping', `CONNECT through socks4 → echo "${t4.echo || t4.error}"`);

  // ---- 5) HTTP proxy chain (engine -> engine) ----
  console.log('== 5) http upstream chain ==');
  const eC = await startEngine(ENGC); // direct engine
  engines.push(eC);
  const eB = await startEngine(ENGB, `http://127.0.0.1:${ENGC}`);
  engines.push(eB);
  const r5 = await fetch(`http://127.0.0.1:${ORIGIN}/chain`, { dispatcher: new ProxyAgent(`http://127.0.0.1:${ENGB}`) });
  const b5 = await r5.text();
  ok(r5.status === 200 && b5 === `origin-ok:/chain`, `http via chain engineB→engineC → 200 "${b5}"`);
  const logB = await readFile(join(TMP, `eng-${ENGB}.log`), 'utf8').catch(() => '');
  const logC = await readFile(join(TMP, `eng-${ENGC}.log`), 'utf8').catch(() => '');
  ok(logB.includes(`"port":${ORIGIN}`), 'engineB (upstream) logged the chain request');
  ok(logC.includes(`"port":${ORIGIN}`), 'engineC (final) logged the same request');

  // ---- 6) HTTPS upstream (TLS to upstream proxy, trusted via NODE_EXTRA_CA_CERTS) ----
  console.log('== 6) https upstream ==');
  const { writeFile } = await import('node:fs/promises');
  execSync(`openssl req -x509 -newkey rsa:2048 -keyout ${TMP}/u.key -out ${TMP}/u.pem -days 1 -nodes -subj "/C=CN/O=np-test/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1"`, { stdio: 'pipe' });
  const uCerts = await Promise.all([readFile(join(TMP, 'u.key')), readFile(join(TMP, 'u.pem'))]);
  const tlsUp = tlsServer({ key: uCerts[0], cert: uCerts[1] }, (sock) => {
    // TLS-terminating forward proxy: parse CONNECT, relay to target.
    let buf = '';
    sock.on('data', (c) => {
      buf += c.toString('latin1');
      const i = buf.indexOf('\r\n\r\n');
      if (i === -1) return;
      const [line] = buf.split('\r\n');
      const m = line.match(/^CONNECT\s+([^:]+):(\d+)\s+HTTP/);
      const head = buf.slice(0, i + 4);
      buf = buf.slice(i + 4);
      if (!m) { sock.end('HTTP/1.1 400 Bad Request\r\n\r\n'); return; }
      const up = netConnect(Number(m[2]), m[1], () => {
        sock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (buf) up.write(Buffer.from(buf, 'latin1'));
        sock.pipe(up); up.pipe(sock);
      });
      up.on('error', () => sock.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'));
    });
  });
  await listen(tlsUp, TLSUP);
  const eH = await startEngine(ENGHTTPS, `https://127.0.0.1:${TLSUP}`, { NODE_EXTRA_CA_CERTS: join(TMP, 'u.pem') });
  engines.push(eH);
  const t6 = await tunnelVia(ENGHTTPS, '127.0.0.1', ECHO, 'tlsup');
  ok(t6.ok && t6.echo === 'tlsup', `CONNECT through https upstream (TLS) → echo "${t6.echo || t6.error}"`);

  // ---- cleanup ----
  origin.close(); echo.close(); s5.close(); s5a.close(); s4.close(); tlsUp.close();
} catch (e) {
  failures.push(String((e && e.stack) || e));
  console.log('THREW:', (e && e.stack) || e);
} finally {
  for (const e of engines) { try { e.kill('SIGTERM'); } catch {} }
  await sleep(300);
  rm(TMP, { recursive: true, force: true }).catch(() => {});
}
console.log(failures.length === 0 ? '\nSOCKS PROBE PASS' : `\nSOCKS PROBE FAIL (${failures.length}):\n- ` + failures.join('\n- '));
process.exit(failures.length === 0 ? 0 : 1);
