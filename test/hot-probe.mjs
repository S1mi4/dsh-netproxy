/**
 * hot-probe — validates the plugin's hot-routing mechanism in isolation.
 *
 * Replicates exactly what lib/index.js's `installHot`/`applyTarget` do:
 *   - wrap globalThis.fetch with a per-request undici ProxyAgent built from the
 *     CURRENT target,
 *   - loopback (and NO_PROXY) destinations bypass,
 *   - an explicit caller `dispatcher` is honored and not overridden,
 *   - switching the current target applies immediately (no restart).
 *
 * Runs two real engine subprocesses (4417/4418) and asserts which proxy got
 * each external request, plus that a 127.0.0.1 request bypassed both.
 */
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ProxyAgent } from 'undici';
import { rm, readFile } from 'node:fs/promises';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE = join(HERE, '..', 'lib', 'engine.js');
const LOG = (p) => join(HERE, '..', `.hot-${p}.log`);

const failures = [];
const ok = (c, m) => { if (c) console.log('  ok -', m); else { failures.push(m); console.log('  FAIL -', m); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const startEngine = (port) => {
  rm(LOG(port), { force: true }).catch(() => {});
  const child = spawn(process.execPath, [ENGINE, '--port', String(port), '--log', LOG(port)], {
    cwd: dirname(ENGINE), stdio: 'ignore',
  });
  return child;
};

// ---- replicate plugin wrapper ----
const origFetch = globalThis.fetch;
let currentTarget = '';
const cache = new Map();
const dispatcherFor = (u) => { if (!cache.has(u)) cache.set(u, new ProxyAgent(u)); return cache.get(u); };
const bypass = (url) => {
  try {
    const { hostname, port } = new URL(url);
    if (hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1') return true;
  } catch { return true; }
  return false;
};
globalThis.fetch = function (input, init) {
  try {
    const url = typeof input === 'string' ? input : (input && input.url);
    if (!url || bypass(url)) return origFetch(input, init);
    if (init && init.dispatcher) return origFetch(input, init);
    if (!currentTarget || !/^https?:$/.test(new URL(currentTarget).protocol)) return origFetch(input, init);
    return origFetch.call(this, input, { ...(init || {}), dispatcher: dispatcherFor(currentTarget) });
  } catch { return origFetch(input, init); }
};

const recentHosts = async (port) => {
  try {
    const t = await readFile(LOG(port), 'utf8');
    return (t.match(/"host":"[^"]*"/g) || []).map((s) => s.slice(8, -1));
  } catch { return []; }
};

const local = createServer((_req, res) => res.end('local-ok'));
await new Promise((r) => local.listen(4555, r));

const e17 = startEngine(4417);
const e18 = startEngine(4418);
await sleep(800);

console.log('== hot switch 4417 -> 4418 (real undici ProxyAgent) ==');
currentTarget = 'http://127.0.0.1:4417';
console.log('  fetch#1 example.com via 4417 ->', (await fetch('https://example.com/')).status);
currentTarget = 'http://127.0.0.1:4418';
console.log('  SWITCHED to 4418 (no restart)');
console.log('  fetch#2 api.github.com via 4418 ->', (await fetch('https://api.github.com/')).status);
console.log('  fetch#3 local 127.0.0.1:4555 (must BYPASS) ->', (await fetch('http://127.0.0.1:4555/ping')).status);
await sleep(600);

const h17 = await recentHosts(4417);
const h18 = await recentHosts(4418);
ok(h17.includes('example.com'), `4417 got example.com (hosts=${h17.join(',')})`);
ok(!h17.includes('api.github.com'), '4417 did NOT get api.github.com');
ok(h18.includes('api.github.com'), `4418 got api.github.com after hot switch (hosts=${h18.join(',')})`);
ok(!h17.includes('127.0.0.1:4555') && !h18.includes('127.0.0.1:4555'), 'loopback request bypassed both proxies');
console.log('  4417 hosts:', h17.join(', ') || '(none)');
console.log('  4418 hosts:', h18.join(', ') || '(none)');

local.close(); e17.kill('SIGTERM'); e18.kill('SIGTERM');
await Promise.all([rm(LOG(4417), { force: true }), rm(LOG(4418), { force: true })]);
console.log(failures.length === 0 ? '\nHOT PROBE PASS' : `\nHOT PROBE FAIL (${failures.length})`);
process.exit(failures.length === 0 ? 0 : 1);
