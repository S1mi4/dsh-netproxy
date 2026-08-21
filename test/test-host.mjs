/**
 * Host-half smoke test for dsh-netproxy (runs OUTSIDE the harness).
 *
 * Two scenarios:
 *   A) settings provider present at apply() time.
 *   B) settings provider binds LATE (the live web profile showed host plugins
 *      can mount before the settings service) — attaches via
 *      'internal/service'('settings'), then /set must work.
 *
 * Postman-style model: `source` (direct|system|custom) drives a local engine
 * whose egress is the resolved custom/system URL. Uses a mock ctx, real
 * schemastery (junctioned into node_modules), and a real spawned engine. Asserts
 * registration, route registration, engine liftoff, /state, /detect, /log, /set
 * round-trip, and teardown.
 */
import { apply, Config, name } from '../lib/index.js';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const failures = [];
const ok = (cond, msg) => { if (cond) console.log('  ok -', msg); else { failures.push(msg); console.log('  FAIL -', msg); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const DEFAULTS = { source: 'direct', customProtocol: 'http', customHost: '', customPort: 0, customAuth: '', enginePort: 4317, engineBind: '127.0.0.1', logFile: '', noProxy: '', caFile: '', skipVerify: false, observe: true, restartOnCrash: true, watchMs: 0, hot: false };

function makeCtx({ lateSettings = false, base = {} } = {}) {
  const registrations = { settings: null, routes: [], effects: [], on: [], watchers: [] };
  let settingsAvailable = !lateSettings;
  const settingsSection = {};
  const baseConfig = { ...base };
  const scope = {
    get() { return { ...DEFAULTS, ...baseConfig, ...settingsSection }; },
    watch(cb) { registrations.watchers.push(cb); return () => {}; },
    update(patch) { Object.assign(settingsSection, patch); for (const w of registrations.watchers) w(this.get(), this.get()); return Promise.resolve(); },
  };
  const ctx = {
    registrations,
    settingsSection,
    logger: { debug: () => {}, warn: (...a) => console.log('  [warn]', ...a), info: () => {} },
    get(service) {
      if (service === 'settings') return settingsAvailable ? { register(_ns, schema, opts) { registrations.settings = { schema, opts }; return scope; } } : undefined;
      if (service === 'webServer') return { register(route) { registrations.routes.push(route); return () => {}; } };
      if (service === 'llm') return { stream: () => {} };
      return undefined;
    },
    on(event, cb) { registrations.on.push({ event, cb }); return () => {}; },
    effect(cb) { const disposer = cb(); registrations.effects.push({ disposer }); return disposer; },
    timeout(cb, ms) { const t = setTimeout(() => cb(), ms); return () => clearTimeout(t); },
    interval(cb, ms) { const t = setInterval(cb, ms); return () => clearInterval(t); },
  };
  return { ctx, settingsSection, emitService(_n) { settingsAvailable = true; for (const h of registrations.on.filter((x) => x.event === 'internal/service')) h.cb(_n); } };
}

const fakeRes = () => { let status = 200, body = ''; return { writeHead(s) { status = s; }, end(b) { body = String(b); }, get status() { return status; }, get body() { return body; } }; };
const fakeReq = (url, body) => {
  const handlers = {};
  const req = { url, on(ev, cb) { handlers[ev] = cb; }, emit(ev, data) { if (handlers[ev]) handlers[ev](data); }, destroy() {} };
  if (body !== undefined) { req.emit('data', JSON.stringify(body)); req.emit('end'); } else req.emit('end');
  return req;
};
const byPath = (regs, p) => regs.routes.find((r) => r.path === p);

async function runScenario(label, { lateSettings }) {
  console.log(`\n== ${label} ==`);
  const port = lateSettings ? 4398 : 4399;
  const appCfg = { source: 'custom', customProtocol: 'http', customHost: '127.0.0.1', customPort: 39999, enginePort: port, logFile: join(tmpdir(), `np-smoke-${Date.now()}.log`), hot: false };
  const { ctx, emitService, settingsSection } = makeCtx({ lateSettings, base: appCfg });
  apply(ctx, appCfg);
  const regs = ctx.registrations;

  if (!lateSettings) {
    ok(regs.settings !== null, 'settings registered upfront');
  } else {
    ok(regs.settings === null, 'settings NOT registered before service binds (expected late)');
    ok(regs.routes.filter((r) => r.path.includes('dsh-netproxy')).length === 4, 'routes registered even without settings');
    const preRes = fakeRes();
    await byPath(regs, '/plugins/dsh-netproxy/set').handler(fakeReq('/x', { source: 'custom' }), preRes);
    ok(preRes.status === 400, '/set before settings → 400');
    emitService('settings');
    await sleep(20);
    ok(regs.settings !== null, 'settings attached after internal/service');
  }

  await sleep(700); // engine liftoff
  const stateRes = fakeRes();
  await byPath(regs, '/plugins/dsh-netproxy/state').handler(fakeReq('/x'), stateRes);
  ok(stateRes.status === 200, 'state 200');
  const s1 = JSON.parse(stateRes.body);
  ok(s1.name === name, 'state.name');
  ok(s1.source === 'custom', `state.source=custom (got ${s1.source})`);
  ok(s1.egress === 'http://127.0.0.1:39999', `state.egress resolved (got ${s1.egress})`);
  ok(s1.engine.running === true, `engine.running (pid=${s1.engine.pid})`);
  ok(s1.engine.upstream === 'http://127.0.0.1:39999', `engine.upstream=${s1.engine.upstream}`);
  const detectRes = fakeRes();
  await byPath(regs, '/plugins/dsh-netproxy/detect').handler(fakeReq('/x'), detectRes);
  ok(detectRes.status === 200, '/detect 200');
  const logRes = fakeRes();
  await byPath(regs, '/plugins/dsh-netproxy/log').handler(fakeReq('/plugins/dsh-netproxy/log?n=5'), logRes);
  const logResJson = JSON.parse(logRes.body);
  ok(Array.isArray(logResJson.lines) && logResJson.lines.length >= 1, `log route returns ${logResJson.lines.length} line(s)`);

  const setRes = fakeRes();
  const sink = { handlers: {}, url: '/plugins/dsh-netproxy/set', on(e, cb) { this.handlers[e] = cb; }, destroy() {} };
  const setPromise = byPath(regs, '/plugins/dsh-netproxy/set').handler(sink, setRes);
  sink.handlers.data?.(JSON.stringify({ source: 'direct' }));
  sink.handlers.end?.();
  await setPromise;
  ok(setRes.status === 200 && JSON.parse(setRes.body).source === 'direct', '/set {source:direct} → 200, source direct');
  ok(settingsSection.source === 'direct', 'settings section updated (persisted)');

  for (const e of regs.effects) { try { e.disposer(); } catch {} }
  await sleep(400);
  console.log('  ok - teardown ran (no throw)');
}

console.log('plugin name =', name);
try {
  await runScenario('A: settings upfront', { lateSettings: false });
  await runScenario('B: settings late', { lateSettings: true });
} catch (e) {
  failures.push(String((e && e.stack) || e));
  console.log('THREW:', (e && e.stack) || e);
}

console.log(failures.length === 0 ? '\nSMOKE PASS' : `\nSMOKE FAIL (${failures.length}):\n- ` + failures.join('\n- '));
process.exit(failures.length === 0 ? 0 : 1);
