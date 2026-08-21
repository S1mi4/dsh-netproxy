/**
 * dsh-netproxy — persistent host-half plugin for routing DSH outbound traffic.
 *
 * Model (Postman-style):
 *   - `source`: 'direct' | 'system' | 'custom'
 *       direct  = no proxying (fetch untouched, child env cleared)
 *       system  = follow the OS system proxy (env vars + Windows registry)
 *       custom  = explicit host:port with protocol http|https|socks4|socks5
 *   - whenever a proxy is active, ALL clients (undici global fetch + child
 *     shells) talk to ONE local engine (`http://127.0.0.1:<enginePort>`); the
 *     engine builds the real connection through the configured egress —
 *     including SOCKS4/5, which undici cannot speak itself.
 *   - certificates are NOT a precondition: TLS follows the SYSTEM certificate
 *     chain by default; `caFile` remains an optional extra for MITM proxies
 *     (Burp), and `skipVerify` is the Postman-style "ignore certificate
 *     verification" switch for self-signed/internal environments.
 *
 * Responsibilities of this host half:
 *   - owns the `netProxy` settings namespace (composition row config = base),
 *   - supervises the engine subprocess, spawning it on demand with the current
 *     egress and restarting it on crash (terminated on dispose),
 *   - detects the system proxy (env + Windows registry) with caching,
 *   - hot-switches globalThis.fetch via undici ProxyAgent (per-request choice
 *     from the CURRENT config), syncs `HTTP(S)_PROXY`/`NO_PROXY` for children,
 *   - observes every streaming model call via `llm/stream` (metrics only),
 *   - validates the L0 enforcement environment and reports readiness,
 *   - serves `/plugins/dsh-netproxy/*` web routes for the browser client.
 *
 * Enforcement note: hot routing needs no restart. The L0 `--use-env-proxy`
 * environment (see scripts/np-env.ps1) additionally covers worker threads and
 * anything reading the process environment at boot; when absent the plugin
 * only nudges the user to restart once with it.
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
import { detectSystemProxy, parseProxyServer } from './sysproxy.js';

export const name = 'netproxy';
export const inject = ['timer'];

/** Streams stdout/stderr ring of the engine subprocess for diagnostics. */
const PROC_RING_LIMIT = 40;
const WEB_SERVER_KEYS = ['webServer', 'httpServer'];
const PROTOCOLS = ['http', 'https', 'socks4', 'socks5'];

export const Config = z.object({
  // Proxy source (Postman-style): direct = none, system = OS proxy, custom = explicit.
  source: z.string().default('direct'),
  // custom protocol: http | https | socks4 | socks5
  customProtocol: z.string().default('http'),
  // custom proxy host (hostname or IP)
  customHost: z.string().default(''),
  // custom proxy port
  customPort: z.number().default(0),
  // optional 'user:pass' for the custom proxy (and socks5/h-http auth)
  customAuth: z.string().default(''),
  // built-in engine listener — the single local routing point when active.
  enginePort: z.number().default(4317),
  engineBind: z.string().default('127.0.0.1'),
  // engine access log file; empty => $DSH_HOME/netproxy-engine.log
  logFile: z.string().default(''),
  // server-side NO_PROXY safety net (comma list) applied per routed request.
  noProxy: z.string().default(''),
  // Optional CA file (PEM) — extra trust on top of the SYSTEM chain for MITM
  // proxies (e.g. Burp's CA). Not a precondition; leave empty to follow the
  // system certificate chain.
  caFile: z.string().default(''),
  // Postman-style "ignore certificate verification": skip TLS validation for
  // routed traffic (self-signed / internal / unusual proxies).
  skipVerify: z.boolean().default(false),
  // SSE/stream friendliness through proxies: force `Accept-Encoding: identity`
  // on routed requests so MITM proxies cannot gzip-buffer the stream.
  plainStream: z.boolean().default(true),
  // Fresh proxy tunnel per routed request (no pooled keep-alive reuse through
  // external proxies). On for the hot path by default.
  freshTunnel: z.boolean().default(true),
  // attach the llm/stream observer.
  observe: z.boolean().default(true),
  // restart the engine if it exits unexpectedly.
  restartOnCrash: z.boolean().default(true),
  // health-check + restart polling interval (ms).
  watchMs: z.number().default(5000),
  // hot routing: wrap globalThis.fetch with an undici ProxyAgent driven by the
  // CURRENT config, so source/protocol/target changes apply immediately.
  hot: z.boolean().default(true),
  // ---- legacy fields (kept for settings.yaml compatibility; ignored) ----
  enabled: z.boolean().default(false),
  mode: z.string().default('builtin'),
  proxyUrl: z.string().default(''),
  auth: z.string().default(''),
});

/** Normalize a raw config value; migrates the legacy proxyUrl into `custom`. */
const normalizeConfig = (raw) => {
  const cfg = { ...raw };
  const legacyUrl = String(raw && raw.proxyUrl || '').trim();
  if (legacyUrl && (cfg.source === 'direct')) {
    const m = legacyUrl.match(/^(https?|socks4|socks4a|socks5|socks5h):\/\/(?:([^:@/]+)(?::([^@/]*))?@)?(\[?[0-9a-fA-F:.]+\]?)(?::(\d+))?/i);
    if (m) {
      cfg.source = 'custom';
      cfg.customProtocol = String(m[1]).toLowerCase().replace(/a$/, '').replace(/h$/, '');
      cfg.customHost = m[4] || '';
      cfg.customPort = Number(m[5]) || 0;
      cfg.customAuth = m[2] ? `${m[2]}${m[3] !== undefined ? `:${m[3]}` : ''}` : '';
    }
  }
  return cfg;
};

export function apply(ctx, config) {
  const logger = ctx.logger;

  // Owner scope for the `netProxy` settings namespace: schema defaults -> row
  // config (base) -> user settings layer. The settings service can bind AFTER
  // this bundle row mounts, so it is attached lazily and on every
  // 'internal/service' bind; we fall back to the row config when webless.
  let scope = undefined;
  const readConfig = () => normalizeConfig(scope !== undefined ? scope.get() : config);
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
      const cfg = normalizeConfig(next);
      state.source = cfg.source;
      updateEnvFacts();
      applyTarget();
    });
  };

  // ---- runtime state (lossless JSON only) ----------------------------------
  const state = {
    source: 'direct',
    // routeKind: 'direct' | 'upstream' (undici talks straight to the proxy,
    // no local engine) | 'engine' (SOCKS egress needs the local engine bridge).
    routeKind: 'direct',
    egress: '',                      // final outbound (custom URL / system URL / socks URL)
    system: { url: null, source: 'none', from: '', checkedAt: 0 }, // detected system proxy
    engine: { running: false, pid: -1, bind: '127.0.0.1', port: 4317, auth: false, upstream: '', spawnedAt: 0, lastExit: null },
    env: { httpProxy: '', httpsProxy: '', noProxy: '', nodeOptions: '', useEnvProxy: false },
    envReady: false,
    envHint: '',
    stats: { llmCalls: 0, providers: {} },
    lastError: null,
    engineLogCount: 0,
    hot: { installed: false, active: false, target: '' },
    ca: { file: '', loaded: false, error: null },
    skipVerify: false,
    routeOk: true,
    lastRouteError: null,
    routeErrors: [],
    engineLoop: { detected: false, count: 0, lastExit: null },
    startedAt: Date.now(),
  };

  let child = null;          // engine child process handle (SOCKS bridge only)
  let restartDisposer = null;
  let watchDisposer = null;
  let procRing = [];
  let crashTimes = [];       // recent engine exits, for the crash-loop guard
  const startedAt = state.startedAt;

  // ---- system-proxy detection (cached; kicks on demand, self-heals) ----------
  let sysPromise = null;
  let sysRes = { url: null, source: 'none', from: '' };
  const ensureSystemDetected = (cfg) => {
    if (sysPromise) return sysPromise;
    const selfExclude = (u) => {
      try {
        const hp = Number(u.port || (u.protocol === 'https:' ? 443 : 80));
        const h = (u.hostname || '').toLowerCase();
        const b = (cfg.engineBind || '127.0.0.1').toLowerCase();
        return (h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === b) && hp === (cfg.enginePort || 4317);
      } catch { return false; }
    };
    sysPromise = detectSystemProxy({ excludeSelf: selfExclude })
      .then((r) => {
        sysRes = { url: r.url, source: r.source, from: r.from || '' };
        return r;
      })
      .catch(() => {
        sysRes = { url: null, source: 'none', from: '' };
        return sysRes;
      })
      .finally(() => { sysPromise = null; });
    return sysPromise;
  };

  /**
   * Decide HOW to route from the CURRENT config. http/https (including the
   * detected system proxy) go straight to the upstream via undici — no local
   * engine. Only SOCKS4/5 egress needs the local engine bridge (undici cannot
   * speak SOCKS).
   * @returns {{kind:'direct'} | {kind:'upstream', url:string} | {kind:'engine', upstream:string}}
   */
  const identifyRoute = (cfg) => {
    if (!cfg || cfg.source === 'direct') return { kind: 'direct' };
    if (cfg.source === 'custom') {
      const host = String(cfg.customHost || '').trim();
      const port = Number(cfg.customPort) || 0;
      const proto = String(cfg.customProtocol || 'http').toLowerCase();
      if (!host || !port || !PROTOCOLS.includes(proto)) return { kind: 'direct', configIncomplete: true };
      const auth = String(cfg.customAuth || '').trim();
      const url = `${proto}://${auth ? `${auth}@` : ''}${host}:${port}`;
      if (proto === 'socks4' || proto === 'socks5') return { kind: 'engine', upstream: url };
      return { kind: 'upstream', url };
    }
    // system
    if (sysRes.url) {
      if (/^socks/i.test(sysRes.url)) return { kind: 'engine', upstream: sysRes.url };
      return { kind: 'upstream', url: sysRes.url };
    }
    // kick detection so the next applyTarget/watch tick can use the result
    void ensureSystemDetected(cfg);
    return { kind: 'direct', sysPending: true };
  };
  const routeTarget = (route) => (route.kind === 'engine' ? route.upstream : route.kind === 'upstream' ? route.url : '');

  // ---- hot routing (runtime, restart-free) ------------------------------------
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
    if (cause && typeof cause.status === 'number') {
      let hint = `代理建立到目标的连接失败（上游返回 ${cause.status}）——目标不可达、DNS 失败或代理拒绝`;
      if (/socks/i.test(state.egress)) hint = `SOCKS 代理建立到目标的连接失败（上游返回 ${cause.status}）——代理不可达/目标连接被拒`;
      return { code: `PROXY_${cause.status}`, hint };
    }
    const CL = code.toUpperCase();
    if (/ECONNREFUSED/.test(CL)) return { code: 'PROXY_UNREACHABLE', hint: `代理地址无法连接（${code}）——代理未启动/端口未监听，或来源/地址配错` };
    if (/ENOTFOUND|EAI_AGAIN/.test(CL)) return { code: 'TARGET_DNS', hint: `目标地址 DNS 解析失败（${code}）` };
    if (/ETIMEDOUT|TIMEOUT|UND_ERR_CONNECT_TIMEOUT/.test(CL)) return { code: 'TIMEOUT', hint: `连接超时（${code}）` };
    if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY|CERT_UNTRUSTED/.test(CL)) {
      if (state.skipVerify) return { code: 'TLS_CA', hint: `TLS 证书校验失败（${code}）——已开启「忽略证书校验」仍报错，请检查是否为代理 MITM/时间偏差` };
      const caState = state.ca.loaded ? `（已加载 CA ${state.ca.file}）` : `（未配置 caFile）`;
      return { code: 'TLS_CA', hint: `TLS 证书校验失败（${code}）${caState}——本插件默认跟随系统证书链；若是 Burp 等 MITM 代理请填「CA 文件」，自签环境可开启「忽略证书校验」` };
    }
    if (/EPROTO|ERR_SSL|HANDSHAKE/.test(CL)) return { code: 'TLS_HANDSHAKE', hint: `TLS 握手失败（${code}）` };
    if (/ECONNRESET|EPIPE/.test(CL)) return { code: 'CONN_RESET', hint: `连接被重置（${code}）` };
    if (/socks/.test(String(cause?.message || '').toLowerCase())) return { code: 'SOCKS', hint: `SOCKS 协商失败：${msg.slice(0, 200)}` };
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
    const key = `${url}#${caGen}${readConfig().skipVerify ? ':nv' : ''}`;
    let d = hotCache.get(key);
    if (!d) {
      d = buildAgent(url);
      hotCache.set(key, d);
    }
    return d;
  };
  /** Build one ProxyAgent (pooled or fresh) honoring ca + skipVerify + tunnel reuse. */
  const buildAgent = (url, fresh) => {
    const opts = { uri: url };
    const tls = {};
    if (caPem !== null) tls.ca = [caPem];
    if (readConfig().skipVerify) tls.rejectUnauthorized = false;
    if (Object.keys(tls).length > 0) opts.requestTls = tls;
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
  /** (Re)load the optional CA file for MITM proxies; failures surfaced, never silent. */
  const maybeReloadCa = () => {
    const file = (readConfig().caFile || '').trim();
    if (file === lastCaFile) return;
    lastCaFile = file;
    if (!file) {
      caPem = null;
      caGen += 1;
      state.ca = { file: '', loaded: false, error: null };
      invalidateHotAgents();
      return;
    }
    try {
      caPem = readFileSync(file, 'utf8');
      if (!/-----BEGIN CERTIFICATE-----/.test(caPem)) throw new Error('不是有效的 PEM 证书内容');
      caGen += 1;
      state.ca = { file, loaded: true, error: null };
      invalidateHotAgents();
      state.lastError = null;
    } catch (error) {
      caPem = null;
      state.ca = { file, loaded: false, error: error instanceof Error ? error.message : String(error) };
      state.lastError = `CA 文件读取失败：${state.ca.error}`;
      logger.warn(state.lastError);
    }
  };
  const invalidateHotAgents = () => {
    for (const d of hotCache.values()) { try { d.close(); } catch {} }
    hotCache.clear();
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
    invalidateHotAgents();
    state.hot.installed = false;
    state.hot.active = false;
    state.hot.target = '';
  };
  const hotActive = () => hotInstalled && !!currentProxyUrl && (readConfig().source || 'direct') !== 'direct';

  /** Keep child processes (curl/git/npm) on the same local engine as the fetch patch. */
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
    const route = identifyRoute(cfg);
    state.source = cfg.source;
    state.routeKind = route.kind;
    state.egress = routeTarget(route);
    state.skipVerify = !!cfg.skipVerify;
    if (route.kind === 'direct') {
      if (cfg.source === 'system') void ensureSystemDetected(cfg); // keep probing for display
      stopEngine();
      currentProxyUrl = '';
      syncProcessEnv('');
      state.hot.target = '';
      state.hot.active = hotActive();
      return;
    }
    if (route.kind === 'upstream') {
      // http/https: undici + children talk straight to the proxy; no local engine.
      stopEngine();
      currentProxyUrl = route.url;
      syncProcessEnv(currentProxyUrl);
      state.hot.target = currentProxyUrl;
      state.hot.active = hotActive();
      return;
    }
    // engine (SOCKS egress): local engine bridges undici's CONNECT to the socks proxy.
    const port = cfg.enginePort || 4317;
    const bind = cfg.engineBind || '127.0.0.1';
    if (!isRunning() || state.engine.port !== port || state.engine.bind !== bind || state.engine.upstream !== route.upstream) {
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

  /** The engine is the proxy — never inherit proxy env or node flags. */
  const engineEnv = (cfg, egress) => {
    const env = { ...process.env };
    for (const k of ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy', 'NODE_OPTIONS', 'UPSTREAM_URL', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_EXTRA_CA_CERTS']) delete env[k];
    if (egress) env.UPSTREAM_URL = egress;
    if (cfg.caFile) env.NODE_EXTRA_CA_CERTS = cfg.caFile.trim();
    if (cfg.skipVerify) env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    return env;
  };

  const isRunning = () => child !== null && child.exitCode === null && child.signalCode === null;

  const startEngine = () => {
    const cfg = readConfig();
    const route = identifyRoute(cfg);
    if (route.kind !== 'engine' || !route.upstream) return;
    if (isRunning()) return;
    const port = cfg.enginePort || 4317;
    const bind = cfg.engineBind || '127.0.0.1';
    const args = ['--port', String(port), '--bind', bind];
    if (cfg.noProxy) args.push('--no-proxy', cfg.noProxy);
    args.push('--log', cfg.logFile || defaultLogFile);
    const spawned = spawn(process.execPath, [engineFile, ...args], {
      cwd: dirname(engineFile),
      stdio: ['ignore', 'pipe', 'pipe'],
      env: engineEnv(cfg, route.upstream),
      windowsHide: true,
    });
    child = spawned;
    state.engine.running = true;
    state.engine.pid = spawned.pid ?? -1;
    state.engine.bind = bind;
    state.engine.port = port;
    state.engine.auth = false;
    state.engine.upstream = route.upstream;
    state.engine.spawnedAt = Date.now();
    spawned.stdout?.on('data', ringLines);
    spawned.stderr?.on('data', ringLines);
    spawned.on('error', (error) => {
      state.lastError = `engine process error: ${String(error)}`;
      logger.warn(state.lastError);
    });
    spawned.on('exit', (code, signal) => {
      if (child !== spawned) return;
      state.engine.running = false;
      state.engine.lastExit = { code, signal, at: Date.now() };
      logger.warn(`netproxy: engine exited code=${code} signal=${signal}`);
      const cfgNow = readConfig();
      const now = Date.now();
      crashTimes.push(now);
      crashTimes = crashTimes.filter((t) => now - t < 60000);
      if (crashTimes.length >= 3) {
        state.engineLoop.detected = true;
        state.engineLoop.count = crashTimes.length;
        state.engineLoop.lastExit = { code, signal };
        state.lastError = `引擎在 60 秒内退出 ${crashTimes.length} 次（最近 code=${code} signal=${signal}）：已暂停自动重启。请检查端口占用/配置（改配置会自动解除）`;
        logger.warn(state.lastError);
        return;
      }
      if (cfgNow.restartOnCrash && identifyRoute(cfgNow).kind === 'engine') {
        if (restartDisposer === null) restartDisposer = ctx.timeout(() => { restartDisposer = null; startEngine(); }, 1000);
      }
    });
  };

  const stopEngine = () => {
    if (restartDisposer !== null) { restartDisposer(); restartDisposer = null; }
    if (child === null) {
      state.engine.running = false;
      state.engine.upstream = '';
      return;
    }
    const target = child;
    child = null;
    state.engine.running = false;
    state.engine.upstream = '';
    try { target.kill('SIGTERM'); } catch { /* already gone */ }
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
    if (identifyRoute(cfg).kind !== 'engine') return;
    if (isRunning()) {
      const bind = cfg.engineBind || '127.0.0.1';
      const port = cfg.enginePort || 4317;
      if (Date.now() - (state.engine.spawnedAt || 0) < 1500) return;
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
    const routing = hotActive();
    if (cfg.source === 'direct') {
      state.envReady = false;
      state.envHint = '直连：不代理任何出站流量。';
    } else if (routing && state.egress) {
      const via = state.routeKind === 'engine'
        ? `（经本地引擎 ${state.hot.target} 桥接 → ${state.egress}，仅 SOCKS 需要）`
        : `（直接 → ${state.egress}，无需本地引擎）`;
      state.envReady = true;
      state.envHint = `${state.hot.target || ''} 出口已生效${via}；热切换无需重启。${useEnvProxy ? '' : '（建议启动时带 --use-env-proxy，以覆盖子进程/工作线程）'}`;
    } else if (cfg.source === 'system') {
      state.envReady = false;
      state.envHint = `系统代理：${sysRes.source === 'none' ? (sysRes.from ? '检测中…' : '未检测到系统代理') : `检测到 ${sysRes.url}（${sysRes.source}）`}；当前按直连处理。`;
    } else if (cfg.source === 'custom' && !state.egress) {
      state.envReady = false;
      state.envHint = '自定义代理配置不完整（缺少主机/端口或协议无效），当前按直连处理。';
    } else if (useEnvProxy && httpsProxy) {
      state.envReady = true;
      state.envHint = `L0 环境就绪：${httpsProxy}。要免重启热切换，请开启「热切换」并在下次重启后生效。`;
    } else {
      state.envReady = false;
      state.envHint = '未检测到可用路由：开启「热切换」可立即生效；或用 scripts/np-env.ps1 启动 DSH（需重启）。';
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
    const route = identifyRoute(cfg);
    state.source = cfg.source;
    state.routeKind = route.kind;
    state.egress = routeTarget(route) || state.egress;
    state.skipVerify = !!cfg.skipVerify;
    if (cfg.source === 'system' && sysRes.source === 'none') void ensureSystemDetected(cfg);
    state.system = { ...state.system, url: sysRes.url, source: sysRes.source, from: sysRes.from, checkedAt: sysRes.url ? Date.now() : state.system.checkedAt };
    return {
      name,
      startedAt,
      now: Date.now(),
      source: state.source,
      routeKind: state.routeKind,
      egress: state.egress,
      system: state.system,
      skipVerify: state.skipVerify,
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
        source: cfg.source,
        customProtocol: cfg.customProtocol,
        customHost: cfg.customHost,
        customPort: cfg.customPort,
        customAuth: !!cfg.customAuth,
        enginePort: cfg.enginePort,
        engineBind: cfg.engineBind,
        logFile: cfg.logFile || defaultLogFile,
        noProxy: cfg.noProxy,
        caFile: cfg.caFile,
        skipVerify: cfg.skipVerify,
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
    route('/plugins/dsh-netproxy/detect', async (_req, res) => {
      sysRes = { url: null, source: 'none', from: '' };
      void ensureSystemDetected(readConfig());
      await new Promise((r) => setTimeout(r, 250)); // one sweep
      sendJson(res, await buildState());
    });
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
  state.source = cfg0.source;
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
