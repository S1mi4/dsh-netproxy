/**
 * ca-probe — validates the caFile / error-reporting machinery in isolation.
 *
 * 1) Tunnel-through-proxy HTTPS with a CA-signed origin cert (a faithful stand-in
 *    for "Burp MITM with its own CA"):
 *      - without requestTls.ca  -> TLS rejected (unknown CA)
 *      - with    requestTls.ca  -> 200 (the caFile mechanism works)
 * 2) Error codes the plugin's classifyError() maps to user hints:
 *      - proxy unreachable       -> ECONNREFUSED  (PROXY_UNREACHABLE)
 *      - upstream DNS/5xx        -> engine 502    (HTTP_502)
 *      - unknown CA / self-sigh  -> SELF_SIGNED_CERT_IN_CHAIN (TLS_CA)
 */
import { spawn, execSync } from 'node:child_process';
import { createServer } from 'node:https';
import { readFile, rm, writeFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ProxyAgent } from 'undici';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE = join(HERE, '..', 'lib', 'engine.js');
const TMP = join(HERE, '.tmp-certs');
const failures = [];
const ok = (c, m) => { if (c) console.log('  ok -', m); else { failures.push(m); console.log('  FAIL -', m); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const run = (cmd) => execSync(cmd, { stdio: 'pipe' });

try {
  // ---- generate CA + server cert (openssl) ----
  await rm(TMP, { recursive: true, force: true });
  await mkdir(TMP, { recursive: true });
  run(`openssl req -x509 -newkey rsa:2048 -keyout ${TMP}/ca.key -out ${TMP}/ca.pem -days 2 -nodes -subj "/C=CN/O=np-test/CN=np-test-ca"`);
  run(`openssl req -newkey rsa:2048 -keyout ${TMP}/srv.key -out ${TMP}/srv.csr -nodes -subj "/C=CN/O=np-test/CN=127.0.0.1"`);
  run(`printf "subjectAltName=IP:127.0.0.1\\n" > ${TMP}/san.cnf`);
  run(`openssl x509 -req -in ${TMP}/srv.csr -CA ${TMP}/ca.pem -CAkey ${TMP}/ca.key -CAcreateserial -out ${TMP}/srv.pem -days 2 -extfile ${TMP}/san.cnf`);

  const [caPem, srvKey, srvCert] = await Promise.all([
    readFile(join(TMP, 'ca.pem'), 'utf8'),
    readFile(join(TMP, 'srv.key'), 'utf8'),
    readFile(join(TMP, 'srv.pem'), 'utf8'),
  ]);

  // ---- origin HTTPS server (cert signed by our CA) ----
  const origin = createServer({ key: srvKey, cert: srvCert }, (_req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('secure-ok');
  });
  await new Promise((r) => origin.listen(8443, '127.0.0.1', r));

  // ---- forward engine (CONNECT passthrough) ----
  const engine = spawn(process.execPath, [ENGINE, '--port', '4417', '--log', join(TMP, 'engine.log')], { cwd: dirname(ENGINE), stdio: 'ignore' });
  await sleep(800);

  const agentPlain = new ProxyAgent('http://127.0.0.1:4417');
  const agentCa = new ProxyAgent({ uri: 'http://127.0.0.1:4417', requestTls: { ca: [caPem] } });

  console.log('== caFile mechanism (HTTPS through proxy w/ custom CA) ==');
  let t1Code = '';
  try { await fetch('https://127.0.0.1:8443/secure', { dispatcher: agentPlain }); t1Code = '(no error!)'; }
  catch (e) { t1Code = (e.cause && e.cause.code) || String(e.message); }
  ok(/CERT|SELF_SIGNED|UNABLE_TO_VERIFY/i.test(t1Code), `without requestTls.ca → rejected (${t1Code}) [maps to TLS_CA hint]`);

  const r2 = await fetch('https://127.0.0.1:8443/secure', { dispatcher: agentCa });
  const body2 = await r2.text();
  ok(r2.status === 200 && body2 === 'secure-ok', `with requestTls.ca(caFile) → 200 "secure-ok" (got ${r2.status})`);

  console.log('== error classification codes ==');
  const blind = new ProxyAgent('http://127.0.0.1:9');
  let c1 = '';
  try { await fetch('https://example.com/', { dispatcher: blind }); c1 = '(no error!)'; }
  catch (e) { c1 = (e.cause && e.cause.code) || String(e.message); }
  ok(c1 === 'ECONNREFUSED', `proxy unreachable → ECONNREFUSED (got ${c1}) [→ PROXY_UNREACHABLE]`);

  let r3Rejected = false, r3Code = '';
  try { await fetch('http://neverssl.example/', { dispatcher: agentPlain }); }
  catch (e) { r3Rejected = true; r3Code = (e.cause && (e.cause.code || e.cause.status)) || String(e.message); }
  ok(r3Rejected, `upstream DNS failure → tunnel rejected (engine connect-error/502; undici: ${r3Code}) [→ PROXY_502 / TARGET_DNS hint]`);
  await sleep(200);
  let r4 = null;
  try { r4 = await fetch('https://127.0.0.1:8443/secure2', { dispatcher: agentCa }); }
  catch (e) { console.log('  DEBUG r4 cause:', e.cause && (e.cause.code || e.cause.message), JSON.stringify(e.message).slice(0, 120)); }
  ok(r4 && r4.status === 200, `sanity: another tunnel fetch via engine+ca (got ${r4 && r4.status})`);

  console.log('  DEBUG engine alive:', engine.exitCode === null);
  try { console.log('  DEBUG engine.log tail:\n' + (await readFile(join(TMP, 'engine.log'), 'utf8')).split('\n').filter(Boolean).slice(-6).join('\n')); } catch (e) { console.log('  DEBUG log read fail', String(e)); }

  await agentPlain.close(); await agentCa.close(); await blind.close();
  origin.close(); engine.kill('SIGTERM');
  await sleep(300);
} catch (e) {
  failures.push(String((e && e.stack) || e));
  console.log('THREW:', (e && e.stack) || e);
} finally {
  await sleep(400);
  rm(TMP, { recursive: true, force: true }).catch(() => {});
}
console.log(failures.length === 0 ? '\nCA PROBE PASS' : `\nCA PROBE FAIL (${failures.length}):\n- ` + failures.join('\n- '));
process.exit(failures.length === 0 ? 0 : 1);
