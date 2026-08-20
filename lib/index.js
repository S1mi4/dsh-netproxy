/**
 * dsh-netproxy — persistent host-half plugin for routing DSH outbound traffic
 * through a configurable proxy (decisions: D1=L0 env enforcement, D2=E2
 * built-in engine, D3=A persistent plugin, D4=all incl. child shells).
 *
 * Responsibilities of this host half:
 *   - owns the `netProxy` settings namespace (composition row config = base),
 *   - supervises the built-in forward-proxy engine subprocess (`lib/engine.js`),
 *     spawning it on demand and restarting it on crash (terminated on dispose),
 *   - observes every streaming model call via the `llm/stream` waterfall to
 *     attribute calls to provider/model (metrics only; traffic bytes come from
 *     the engine access log),
 *   - validates the L0 enforcement environment (`HTTP(S)_PROXY`/`NO_PROXY` +
 *     `NODE_OPTIONS=--use-env-proxy`) and reports readiness to the UI,
 *   - serves `/plugins/dsh-netproxy/*` web routes for the browser client
 *     (state, engine log, runtime toggle).
 *
 * Enforcement note: this plugin manages the proxy and its configuration; the
 * actual interception happens at process launch through the L0 environment
 * (see docs/np-env.ps1). `--use-env-proxy` only takes effect at DSH start, so
 * the plugin surfaces "restart required" guidance when the environment is not
 * in place.
 *
 * @module dsh-netproxy
 */
import z from '@deepseek-ai/schemastery';
import { ProxyAgent } from 'undici';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const name = 'netproxy';
export const inject = ['timer'];

/** Streams stdout/stderr ring of the engine subprocess for diagnostics. */
const PROC_RING_LIMIT = 40;
const WEB_SERVER_KEYS = ['webServer', 'httpServer'];

export const Config = z.object({
  // Master switch: run the engine and attach observers.
  enabled: z.boolean().default(false),
  // engine transport: 'builtin' | 'external'
  mode: z.string().default('builtin'),
  // external mode: the HTTP(S) proxy URL to route through (e.g. http://127.0.0.1:7890).
  proxyUrl: z.string().default(''),
  // built-in engine listener.
  enginePort: z.number().default(4317),
  engineBind: z.string().default('127.0.0.1'),
  // optional 'user:pass' for the built-in engine (empty = no auth).
  auth: z.string().default(''),
  // engine access log file; empty => $DSH_HOME/netproxy-engine.log
  logFile: z.string().default(''),
  // server-side NO_PROXY safety net (comma list) applied by the engine.
  noProxy: z.string().default(''),
  // Optional CA file (PEM) trusted for the ORIGIN TLS when tunneling through a
  // MITM-capable proxy (e.g. Burp's CA). Passed as `requestTls.ca` to the
  // undici ProxyAgent, so HTTPS over Burp works without OS-level CA install.
  // Applies to the hot wrapper path; children/workers still need their own
  // CA trust (e.g. NODE_EXTRA_CA_CERTS).
  caFile: z.string().default(''),
  // SSE/stream friendliness through proxies: force `Accept-Encoding: identity`
  // on routed requests. MITM proxies (Burp) may re-encode a streaming response
  // as gzip, and undici's decompressor then buffers ~32 KB or the whole stream
  // before yielding the first byte — DSH's stream watchdog treats that as a
  // stall and retries. identity keeps SSE flowing immediately (and the proxy
  // records plaintext). Apply to the hot wrapper path; default on.
  plainStream: z.boolean().default(true),
  // Fresh proxy tunnel per routed request (no pooled keep-alive reuse through
  // external proxies). Some proxies close CONNECT tunnels after a response or
  // on idle; a reused/stale tunnel then delays the next LLM request and causes
  // retries. A fresh tunnel per call is robust and cheap for LLM-frequency
  // traffic. Default on for the hot path.
  freshTunnel: z.boolean().default(true),
  // attach the llm/stream observer.
  observe: z.boolean().default(true),
  // restart the engine if it exits unexpectedly.
  restartOnCrash: z.boolean().default(true),
  // health-check + restart polling interval (ms).
  watchMs: z.number().default(5000),
  // hot routing: wrap globalThis.fetch with an undici ProxyAgent driven by the
  // CURRENT config, so proxy/target changes apply immediately (no restart).
  // Falls back to the original fetch on any internal error, and honors an
  // explicit caller-provided `dispatcher` (never overrides it).
  hot: z.boolean().default(true),
});

export function apply(ctx, config) {
  const logger = ctx.logger;

  // Owner scope for the `netProxy` settings namespace: schema defaults -> row
  // config (base) -> user settings layer. The settings service can bind AFTER
  // this bundle row mounts (layer/provider ordering), so it is attached
  // lazily — now and again on each 'internal/service' bind — and we fall back
  // to the row config when no settings provider exists (webless profiles).
  let scope = undefined;
  const readConfig = () => ((scope !== undefined ? scope.get() : config));
  const attachSettings = () => {
    if (scope !== undefined) return;
    const settings = ctx.get('settings');
    if (settings === undefined) return;
    try {
      scope = settings.register('netProxy', Config, { base: config });
    } catch (error) {
      logger.warn(`netproxy: settings register failed: ${String(error)}`);
      return;
    }
    scope.watch((next) => {
      state.enabled = !!next.enabled;
      state.mode = next.mode;
      state.externalProxyUrl = next.proxyUrl;
      updateEnvFacts();
      applyTarget();
    });
  };

  // ---- runtime state (lossless JSON only) ----------------------------------
  const state = {
    enabled: false,
    mode: 'builtin',
    externalProxyUrl: '',
    engine: { running: false, pid: -1, bind: '127.0.0.1', port: 4317, auth: false, spawnedAt: 0, lastExit: null },
    env: { httpProxy: '', httpsProxy: '', noProxy: '', nodeOptions: '', useEnvProxy: false },
    envReady: false,
    envHint: '',
    stats: { llmCalls: 0, providers: {} },
    lastError: null,
    engineLogCount: 0,
    hot: { installed: false, active: false, target: '' },
    ca: { file: '', loaded: false, error: null },
    routeOk: true,
    lastRouteError: null,
    routeErrors: [],
    engineLoop: { detected: false, count: 0, lastExit: null },
    startedAt: Date.now(),
  };

  let child = null;          // engine child process handle
  let restartDisposer = null;
  let watchDisposer = null;
  let procRing = [];
  let crashTimes = [];       // recent engine exits, for the crash-loop guard
  const startedAt = state.startedAt;

  // ---- hot routing (runtime, restart-free) ------------------------------------
  // Wraps globalThis.fetch so every call is routed through an undici ProxyAgent
  // pointing at the CURRENT target. Because the dispatcher is chosen per call
  // from `currentProxyUrl`, switching mode/port/external URL applies
  // immediately. Explicit caller-provided `dispatcher`s and loopback/NO_PROXY
  // destinations are never overridden; any internal error falls back to the
  // original fetch so the harness can never be broken by this wrapper.
  //
  // Error reporting: every routed call's outcome is observed. Rejections and
  // 5xx responses are classified into a user-facing reason (proxy unreachable,
  // target DNS, TLS/CA, timeout, upstream error) and recorded in
  // `routeErrors`/`lastRouteError` so the panel can tell the user WHY the proxy
  // could not reach the target — nothing is silently retried.
  let origFetch = null;
  let hotInstalled = false;
  let currentProxyUrl = '';
  const hotCache = new Map();
  let caPem = null;
  let caGen = 0;
  let lastCaFile = null;

  const trackError = (entry) => {
    const item = { ts: Date.now(), ...entry };
    state.routeErrors.push(item);
    if (state.routeErrors.length > 40) state.routeErrors.splice(0, state.routeErrors.length - 40);
    state.lastRouteError = item;
    if (state.lastError === null) state.lastError = `route: ${item.hint || item.error}`;
  };

  const classifyError = (error) => {
    const cause = error && error.cause && (error.cause.cause || error.cause);
    const code = cause?.code || error?.code || '';
    const msg = String(cause?.message || error?.message || error);
    // Proxy-level failure that came back with a status (e.g. engine CONNECT 502
    // for an unreachable target, or a rejecting upstream proxy).
    if (cause && typeof cause.status === 'number') {
      return { code: `PROXY_${cause.status}`, hint: `代理建立到目标的连接失败（上游返回 ${cause.status}）——目标不可达、DNS 失败或代理拒绝` };
    }
    const CL = code.toUpperCase();
    if (/ECONNREFUSED/.test(CL)) return { code: 'PROXY_UNREACHABLE', hint: `代理地址无法连接（${code}）——代理未启动/端口未监听，或模式/URL 配错` };
    if (/ENOTFOUND|EAI_AGAIN/.test(CL)) return { code: 'TARGET_DNS', hint: `目标地址 DNS 解析失败（${code}）` };
    if (/ETIMEDOUT|TIMEOUT|UND_ERR_CONNECT_TIMEOUT/.test(CL)) return { code: 'TIMEOUT', hint: `连接超时（${code}）` };
    if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|CERT_UNTRUSTED/.test(CL)) {
      const caState = state.ca.loaded ? `（已加载 CA ${state.ca.file}）` : '（未配置 caFile）';
      return { code: 'TLS_CA', hint: `TLS 证书校验失败（${code}）${caState}——经 Burp 等 MITM 代理时，请在设置填写「CA 文件」为导出的代理 CA` };
    }
    if (/EPROTO|ERR_SSL|HANDSHAKE/.test(CL)) return { code: 'TLS_HANDSHAKE', hint: `TLS 握手失败（${code}）` };
    if (/ECONNRESET|EPIPE|ETIMEDOUT/.test(CL)) return { code: 'CONN_RESET', hint: `连接被重置（${code}）` };
    if (/ERR_HTTP2|PROTOCOL/.test(CL)) return { code: 'PROTOCOL', hint: `协议错误（${code}）` };
    return { code: CL || 'UNKNOWN', hint: `代理路由失败：${msg.slice(0, 200)}` };
  };

  const hostOf = (url) => { try { return new URL(url).host; } catch { return String(url).slice(0, 200); } };

  const observeRoute = (promise, input, target) => {
    const url = typeof input === 'string' ? input : (input && (input.url || ''));
    const host = hostOf(url);
    if (promise && typeof promise.then === 'function') {
      promise.then(
        (res) => {
          if (res && typeof res.status === 'number') {
            if (res.status >= 500) trackError({ host, target, code: `HTTP_${res.status}`, hint: `目标经代理返回 ${res.status}（上游无法完成请求）` });
            else state.routeOk = true;
          }
          return res;
        },
        (error) => {
          state.routeOk = false;
          trackError({ host, target, error: error instanceof Error ? error.message : String(error), ...classifyError(error) });
          throw error;
        },
      ).then(() => {}, () => {});
    }
  };

  const dispatcherFor = (url) => {
    const key = `${url}#${caGen}`;
    let d = hotCache.get(key);
    if (!d) {
      d = buildAgent(url);
      hotCache.set(key, d);
    }
    return d;
  };
  /** Build one ProxyAgent (pooled or fresh) honoring ca + tunnel reuse policy. */
  const buildAgent = (url, fresh) => {
    const opts = { uri: url };
    if (caPem !== null) opts.requestTls = { ca: [caPem] };
    if (fresh) {
      // per-request tunnel: let the agent abandon/reap its socket quickly so a
      // flaky proxy (closes tunnels after response / idle) never poisons the
      // next LLM stream with a reused dead tunnel.
      opts.keepAliveTimeout = 300;
      opts.connections = 1;
    }
    return new ProxyAgent(opts);
  };
  /** Merge `Accept-Encoding: identity` so SSE streams aren't gzip-buffered by MITM proxies. */
  const withIdentityHeaders = (input, init) => {
    const headers = new Headers(init && init.headers);
    if (!headers.has('accept-encoding')) headers.set('accept-encoding', 'identity');
    return headers;
  };
  const proxySchemeAllowed = (url) => {
    try { const p = new URL(url).protocol; return p === 'http:' || p === 'https:'; } catch { return false; }
  };
  const shouldBypassUrl = (url) => {
    try {
      const parsed = new URL(url);
      const host = parsed.hostname.toLowerCase();
      if (host === 'localhost' || host === '::1' || host === '127.0.0.1' || host.startsWith('127.')) return true;
      const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
      const rules = (readConfig().noProxy || '').split(/[,\s]/).filter(Boolean);
      for (const ruleRaw of rules) {
        const rule = ruleRaw.toLowerCase().replace(/^\./, '');
        const m = rule.match(/^(.+):(\d+)$/);
        const rh = (m ? m[1] : rule).replace(/^\*\./, '');
        const rp = m ? m[2] : null;
        if (rp && rp !== port) continue;
        if (host === rh || host.endsWith('.' + rh)) return true;
      }
      return false;
    } catch { return true; }
  };
  /** (Re)load the optional CA file for MITM proxies; failures are surfaced, never silent. */
  const maybeReloadCa = () => {
    const file = (readConfig().caFile || '').trim();
    if (file === lastCaFile) return;
    lastCaFile = file;
    if (!file) {
      caPem = null;
      caGen += 1;
      state.ca = { file: '', loaded: false, error: null };
      for (const d of hotCache.values()) { try { d.close(); } catch {} }
      hotCache.clear();
      return;
    }
    try {
      caPem = readFileSync(file, 'utf8');
      if (!/-----BEGIN CERTIFICATE-----/.test(caPem)) throw new Error('不是有效的 PEM 证书内容');
      caGen += 1;
      state.ca = { file, loaded: true, error: null };
      for (const d of hotCache.values()) { try { d.close(); } catch {} }
      hotCache.clear();
      state.lastError = null;
    } catch (error) {
      caPem = null;
      state.ca = { file, loaded: false, error: error instanceof Error ? error.message : String(error) };
      state.lastError = `CA 文件读取失败：${state.ca.error}`;
      logger.warn(state.lastError);
    }
  };
  const installHot = () => {
    if (hotInstalled) return;
    if (typeof globalThis.fetch !== 'function') return;
    origFetch = globalThis.fetch;
    hotInstalled = true;
    globalThis.fetch = function (input, init) {
      try {
        const url = typeof input === 'string' ? input : (input && (input.url || ''));
        if (!url || shouldBypassUrl(url)) return origFetch(input, init);
        if (init && init.dispatcher) return origFetch(input, init);
        const target = currentProxyUrl;
        if (!target || !proxySchemeAllowed(target)) return origFetch(input, init);
        const cfg = readConfig();
        const fresh = cfg.freshTunnel !== false;
        const dispatcher = fresh ? buildAgent(target, true) : dispatcherFor(target);
        let init2 = { ...(init || {}), dispatcher };
        if (cfg.plainStream !== false) init2.headers = withIdentityHeaders(input, init2);
        const out = origFetch.call(this, input, init2);
        observeRoute(out, input, target);
        return out;
      } catch {
        return origFetch(input, init);
      }
    };
    state.hot.installed = true;
  };
  const uninstallHot = () => {
    if (hotInstalled && origFetch) {
      try { if (typeof globalThis.fetch === 'function') globalThis.fetch = origFetch; } catch {}
      hotInstalled = false;
    }
    for (const d of hotCache.values()) { try { d.close(); } catch {} }
    hotCache.clear();
    state.hot.installed = false;
    state.hot.active = false;
    state.hot.target = '';
  };
  const hotActive = () => hotInstalled && !!currentProxyUrl && !!readConfig().enabled;

  /** Keep child processes (curl/git/npm) on the same target as the fetch patch. */
  const syncProcessEnv = (target) => {
    try {
      if (target) {
        process.env.HTTP_PROXY = target; process.env.http_proxy = target;
        process.env.HTTPS_PROXY = target; process.env.https_proxy = target;
        const extra = readConfig().noProxy || '';
        const merged = ['127.0.0.1', 'localhost', '::1', ...extra.split(/[,\s]/).filter(Boolean)];
        process.env.NO_PROXY = merged.join(',');
        process.env.no_proxy = merged.join(',');
      } else {
        for (const k of ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'NO_PROXY', 'no_proxy']) delete process.env[k];
      }
    } catch { /* env mutation must never throw */ }
  };

  /** Reconcile the routing target from the CURRENT config (hot, no restart). */
  const applyTarget = () => {
    const cfg = readConfig();
    // A configuration change is a fresh start for crash-loop recovery.
    state.engineLoop.detected = false;
    maybeReloadCa();
    if (!cfg.enabled) {
      stopEngine();
      currentProxyUrl = '';
      syncProcessEnv('');
      state.hot.target = currentProxyUrl;
      state.hot.active = hotActive();
      return;
    }
    if ((cfg.mode || 'builtin') === 'external') {
      stopEngine();
      currentProxyUrl = (cfg.proxyUrl || '').trim() || '';
      syncProcessEnv(currentProxyUrl);
      state.hot.target = currentProxyUrl;
      state.hot.active = hotActive();
      return;
    }
    // builtin: (re)start engine to the configured port first, then route to it.
    const port = cfg.enginePort || 4317;
    const bind = cfg.engineBind || '127.0.0.1';
    if (!isRunning() || state.engine.port !== port || state.engine.bind !== bind) {
      stopEngine();
      startEngine();
    }
    currentProxyUrl = `http://${bind}:${port}`;
    syncProcessEnv(currentProxyUrl);
    state.hot.target = currentProxyUrl;
    state.hot.active = hotActive();
    void ensureEngine();
  };

  const pushProc = (line) => { procRing.push(line); if (procRing.length > PROC_RING_LIMIT) procRing.splice(0, procRing.length - PROC_RING_LIMIT); };
  const ringLines = (chunk) => String(chunk).split(/\r?\n/).filter(Boolean).forEach(pushProc);

  // ---- engine subprocess lifecycle ------------------------------------------
  const engineFile = fileURLToPath(new URL('./engine.js', import.meta.url));
  const dshHome = process.env.DSH_HOME || join(homedir(), '.dsh');
  const defaultLogFile = join(dshHome, 'netproxy-engine.log');

  /** The engine is the proxy — never let it inherit proxy env or node flags. */
  const engineEnv = () => {
    const env = { ...process.env };
    for (const k of ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy', 'NODE_OPTIONS']) delete env[k];
    return env;
  };

  const isRunning = () => child !== null && child.exitCode === null && child.signalCode === null;

  const startEngine = () => {
    const cfg = readConfig();
    const mode = cfg.mode || 'builtin';
    const port = cfg.enginePort || 4317;
    const bind = cfg.engineBind || '127.0.0.1';
    if (mode !== 'builtin' || !cfg.enabled) return;
    if (isRunning()) return;
    const args = ['--port', String(port), '--bind', bind];
    if (cfg.auth) args.push('--auth', cfg.auth);
    args.push('--log', cfg.logFile || defaultLogFile);
    if (cfg.noProxy) args.push('--no-proxy', cfg.noProxy);
    const spawned = spawn(process.execPath, [engineFile, ...args], {
      cwd: dirname(engineFile),
      stdio: ['ignore', 'pipe', 'pipe'],
      env: engineEnv(),
      windowsHide: true,
    });
    child = spawned;
    state.engine.running = true;
    state.engine.pid = spawned.pid ?? -1;
    state.engine.bind = bind;
    state.engine.port = port;
    state.engine.auth = !!cfg.auth;
    state.engine.spawnedAt = Date.now();
    spawned.stdout?.on('data', ringLines);
    spawned.stderr?.on('data', ringLines);
    spawned.on('error', (error) => {
      state.lastError = `engine process error: ${String(error)}`;
      logger.warn(state.lastError);
    });
    spawned.on('exit', (code, signal) => {
      // A later engine may have replaced this child (applyTarget restart);
      // ignore the stale exit of an old process so it never clears the running
      // flag of the current child. Intentional stops already set running=false
      // inside stopEngine().
      if (child !== spawned) return;
      state.engine.running = false;
      state.engine.lastExit = { code, signal, at: Date.now() };
      logger.warn(`netproxy: engine exited code=${code} signal=${signal}`);
      const cfgNow = readConfig();
      // Crash-loop guard: 3+ exits within 60s stops auto-restart so the panel
      // can surface the root cause instead of hammering a broken setup.
      const now = Date.now();
      crashTimes.push(now);
      crashTimes = crashTimes.filter((t) => now - t < 60000);
      if (crashTimes.length >= 3) {
        state.engineLoop.detected = true;
        state.engineLoop.count = crashTimes.length;
        state.engineLoop.lastExit = { code, signal };
        state.lastError = `引擎在 60 秒内退出 ${crashTimes.length} 次（最近 code=${code} signal=${signal}）：已暂停自动重启。请检查端口占用/配置（改配置会自动解除）`;
        logger.warn(state.lastError);
        return; // no restart
      }
      // Only auto-restart an unexpected crash of the current child; stopEngine()
      // already set child = null, so an intentionally-stopped engine never restarts.
      if (cfgNow.restartOnCrash && cfgNow.enabled && (cfgNow.mode || 'builtin') === 'builtin') {
        if (restartDisposer === null) restartDisposer = ctx.timeout(() => { restartDisposer = null; startEngine(); }, 1000);
      }
    });
    // Boot diagnostics: a bind failure surfaces as a fast exit, which the exit
    // handler above restarts/logs. Explicit early log so the panel can show why.
  };

  const stopEngine = () => {
    if (restartDisposer !== null) { restartDisposer(); restartDisposer = null; }
    if (child === null) {
      state.engine.running = false;
      return;
    }
    const target = child;
    child = null;
    state.engine.running = false;
    try { target.kill('SIGTERM'); } catch { /* already gone */ }
    // SIGKILL escalation, fiber-owned; does not hold teardown open.
    ctx.timeout(() => { try { target.kill('SIGKILL'); } catch {} }, 1500);
  };

  // ---- health probes ----------------------------------------------------------
  const pingEngine = () => new Promise((resolve) => {
    const cfg = readConfig();
    const sock = connect({ host: cfg.engineBind, port: cfg.enginePort });
    const done = (ok) => { try { sock.destroy(); } catch {} resolve(ok); };
    sock.setTimeout(1200);
    sock.once('connect', () => done(true));
    sock.once('timeout', () => done(false));
    sock.once('error', () => done(false));
  });

  const ensureEngine = async () => {
    const cfg = readConfig();
    const mode = cfg.mode || 'builtin';
    if (mode !== 'builtin' || !cfg.enabled) return;
    if (isRunning()) {
      const bind = cfg.engineBind || '127.0.0.1';
      const port = cfg.enginePort || 4317;
      // A freshly spawned engine may not have bound the socket yet; killing and
      // re-spawning it within a second of liftoff is a race, not a recovery.
      if (Date.now() - (state.engine.spawnedAt || 0) < 1500) return;
      // A long-stable engine clears the crash-loop latch (clear recovery).
      if (Date.now() - (state.engine.spawnedAt || 0) > 10000) {
        crashTimes = [];
        state.engineLoop.detected = false;
      }
      const alive = await pingEngine();
      if (!alive) {
        state.lastError = `engine pid ${state.engine.pid} alive but ${bind}:${port} not answering; restarting`;
        logger.warn(state.lastError);
        stopEngine();
        startEngine();
      }
      return;
    }
    // Do not auto-respawn while a crash loop is latched; surface the cause and
    // wait for a config change (applyTarget resets the latch).
    if (state.engineLoop.detected) {
      if (state.lastError === null) state.lastError = '引擎已因反复崩溃暂停自动重启；请检查配置/端口后修改任意设置恢复';
      return;
    }
    startEngine();
  };

  // ---- routing/env facts -------------------------------------------------------
  const updateEnvFacts = () => {
    const cfg = readConfig();
    const httpProxy = process.env.HTTP_PROXY || process.env.http_proxy || '';
    const httpsProxy = process.env.HTTPS_PROXY || process.env.https_proxy || '';
    const noProxy = process.env.NO_PROXY || process.env.no_proxy || '';
    const nodeOptions = process.env.NODE_OPTIONS || '';
    const useEnvProxy = /(?:^|\s|;)--use-env-proxy(?:\s|$|;)/.test(` ${nodeOptions} `);
    state.env = { httpProxy, httpsProxy, noProxy, nodeOptions, useEnvProxy };
    const enabled = !!cfg.enabled;
    const routing = hotActive();
    if (!enabled) {
      state.envReady = false;
      state.envHint = '代理已关闭。';
    } else if (routing) {
      state.envReady = true;
      state.envHint = `${state.hot.target || ''} 路由已生效（热切换，改配置无需重启）。${useEnvProxy ? '' : '（建议启动时带 --use-env-proxy，以覆盖子进程/工作线程）'}`;
    } else if (useEnvProxy && httpsProxy) {
      state.envReady = true;
      state.envHint = `L0 环境就绪：${httpsProxy}。要免重启热切换，请开启「热切换」并在下次重启后生效。`;
    } else {
      state.envReady = false;
      state.envHint = '未检测到可用路由：开启「热切换」可立即生效；或用 docs/np-env.ps1 启动 DSH（需重启）。';
    }
  };

  // ---- llm/stream observer (metrics only; lossless pass-through) ---------------
  const observeHandler = (options, next) => {
    const provider = (options && typeof options.provider === 'string') ? options.provider : 'unknown';
    const model = (options && typeof options.model === 'string') ? options.model : '';
    const started = Date.now();
    let stream;
    try {
      stream = next();
    } catch (error) {
      logger.warn(`netproxy: llm/stream next() failed: ${String(error)}`);
      return [];
    }
    const key = model ? `${provider}/${model}` : provider;
    return (async function* wrap() {
      try {
        for await (const chunk of stream) yield chunk;
      } finally {
        state.stats.llmCalls += 1;
        const entry = state.stats.providers[key] ?? { calls: 0, totalMs: 0 };
        entry.calls += 1;
        entry.totalMs += Date.now() - started;
        state.stats.providers[key] = entry;
      }
    })();
  };

  // ---- web surface ---------------------------------------------------------------
  const sendJson = (res, payload, status = 200) => {
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    });
    res.end(JSON.stringify(payload));
  };

  const buildState = async () => {
    const cfg = readConfig();
    updateEnvFacts();
    // `readConfig` is the source of truth for the switch: the engine may have
    // been started by the watchdog before a settings commit (late service
    // bind), so never report a stale cached enabled flag.
    state.enabled = !!cfg.enabled;
    state.mode = cfg.mode || 'builtin';
    state.externalProxyUrl = cfg.proxyUrl;
    return {
      name,
      startedAt,
      now: Date.now(),
      enabled: state.enabled,
      mode: state.mode,
      externalProxyUrl: state.externalProxyUrl,
      engine: state.engine,
      hot: state.hot,
      ca: state.ca,
      routeOk: state.routeOk,
      lastRouteError: state.lastRouteError,
      routeErrors: state.routeErrors,
      engineLoop: state.engineLoop,
      env: state.env,
      envReady: state.envReady,
      envHint: state.envHint,
      stats: state.stats,
      lastError: state.lastError,
      engineLogCount: state.engineLogCount,
      config: {
        enginePort: cfg.enginePort,
        engineBind: cfg.engineBind,
        auth: !!cfg.auth,
        logFile: cfg.logFile || defaultLogFile,
        noProxy: cfg.noProxy,
        caFile: cfg.caFile,
        plainStream: cfg.plainStream,
        freshTunnel: cfg.freshTunnel,
        observe: cfg.observe,
        restartOnCrash: cfg.restartOnCrash,
      },
    };
  };

  const readLogTail = async (n) => {
    const result = await buildState();
    const logFile = result.config.logFile;
    try {
      const text = await readFile(logFile, 'utf8');
      return { file: logFile, lines: text.split(/\r?\n/).filter(Boolean).slice(-n) };
    } catch (error) {
      return { file: logFile, lines: procRing.slice(-n), error: String(error) };
    }
  };

  const readBody = (req) => new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => { data += c; if (data.length > 1e5) req.destroy(); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });

  let webRegistered = false;
  const registerWebSurface = () => {
    if (webRegistered) return;
    const webServer = ctx.get(WEB_SERVER_KEYS[0]) ?? ctx.get(WEB_SERVER_KEYS[1]);
    if (webServer === undefined) return;
    webRegistered = true;
    const route = (path, handler) => ctx.effect(() => webServer.register({ kind: 'exact', path, handler }), `netproxy route ${path}`);
    route('/plugins/dsh-netproxy/state', async (_req, res) => sendJson(res, await buildState()));
    route('/plugins/dsh-netproxy/log', async (req, res) => {
      const url = new URL(req.url, 'http://local');
      const n = Number(url.searchParams.get('n')) || 50;
      sendJson(res, await readLogTail(Math.max(1, Math.min(500, n))));
    });
    route('/plugins/dsh-netproxy/set', async (req, res) => {
      if (scope === undefined) return sendJson(res, { ok: false, error: 'no settings provider' }, 400);
      try {
        const patch = await readBody(req);
        await scope.update(patch);
        applyTarget();
        sendJson(res, await buildState());
      } catch (error) {
        sendJson(res, { ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
      }
    });
  };
  registerWebSurface();
  ctx.on('internal/service', (serviceName) => {
    if (WEB_SERVER_KEYS.includes(serviceName)) registerWebSurface();
    if (serviceName === 'settings') attachSettings();
  });

  // ---- boot -------------------------------------------------------------------
  attachSettings();
  const cfg0 = readConfig();
  state.enabled = !!cfg0.enabled;
  state.mode = cfg0.mode;
  state.externalProxyUrl = cfg0.proxyUrl;
  updateEnvFacts();
  if (cfg0.hot !== false) installHot();
  applyTarget();
  if (cfg0.observe !== false && ctx.get('llm') !== undefined) {
    ctx.on('llm/stream', observeHandler, { global: true, prepend: true });
  }
  if (cfg0.watchMs > 0) watchDisposer = ctx.interval(() => { updateEnvFacts(); applyTarget(); }, cfg0.watchMs);

  // ---- teardown ---------------------------------------------------------------
  ctx.effect(() => () => {
    uninstallHot();
    if (watchDisposer !== null) watchDisposer();
    if (restartDisposer !== null) restartDisposer();
    stopEngine();
  }, 'netproxy: teardown');
}
