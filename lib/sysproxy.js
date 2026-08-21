/**
 * dsh-sysproxy — system-proxy detection for the dsh-netproxy host half.
 *
 * Postman-style "Use system proxy": the plugin picks up whatever proxy the OS
 * current user has configured and routes through it. Detection order:
 *
 *   1. environment  — HTTP(S)_PROXY / http(s)_proxy / ALL_PROXY (process.env).
 *   2. Windows      — registry `Internet Settings` (ProxyEnable + ProxyServer),
 *                     read via `reg query` (zero extra dependencies).
 *
 * Both are async/cheap and cached by the caller (`detectSystemProxy` itself
 * performs one read). `excludeSelf` lets the caller veto proxy settings that
 * point at dsh-netproxy's own local engine (an L0 environment variable from
 * the previous model would otherwise create a loop).
 *
 * Zero npm dependencies on purpose: the engine's "zero-dependency" promise is
 * a feature, and this module uses only node built-ins.
 */
import { execFile } from 'node:child_process';

const WIN_REG_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

/** Parse a Windows registry `ProxyServer` value into `{ url, host, port, kind }` or null. */
export function parseProxyServer(value) {
  const s = (value || '').trim();
  if (!s) return null;
  // addr -> { host, port }; host may be a domain, an IPv4, or a bracketed IPv6.
  const hostPort = (addr) => {
    let a = String(addr || '').trim().replace(/^(?:https?|socks5h?:)\/\//i, '');
    const m = a.match(/^(.*?):(\d{1,5})$/);
    if (!m || !m[1]) return null;
    return { host: m[1], port: Number(m[2]) };
  };
  const entry = (hp, kind) => ({
    url: `${kind === 'socks' ? 'socks5' : 'http'}://${hp.host}:${hp.port}`,
    host: hp.host, port: hp.port, kind,
  });
  // Single server form: "host:port"  (or "socks=host:port" style).
  if (!s.includes('=')) {
    const hp = hostPort(s);
    if (!hp) return null;
    const kind = /^socks/i.test(s) ? 'socks' : 'http';
    return entry(hp, kind);
  }
  // Per-protocol form: "http=host:81;https=host:443;ftp=host:21;socks=..."
  let chosen = null;
  for (const part of s.split(';')) {
    const m = part.match(/^\s*([A-Za-z0-9]+)=(.+)$/);
    if (!m) continue;
    const kind = m[1].toLowerCase();
    const hp = hostPort(m[2]);
    if (!hp) continue;
    if (kind === 'socks') { if (!chosen) chosen = entry(hp, 'socks'); continue; }
    // HTTPS http-over-CONNECT target is what DSH mostly needs; prefer it.
    if (kind === 'https') { chosen = entry(hp, 'http'); break; }
    if (kind === 'http' && !chosen) chosen = entry(hp, 'http');
  }
  return chosen;
}

const ENV_NAMES = ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy'];

/**
 * Detect the current system proxy.
 * @param {{ excludeSelf?: (u: URL) => boolean }} [opts]
 * @returns {Promise<{url: string|null, host: string, port: number, source: 'env'|'registry'|'none', from?: string}>}
 */
export async function detectSystemProxy({ excludeSelf } = {}) {
  // 1) environment variables — the most portable source.
  for (const name of ENV_NAMES) {
    const v = (process.env[name] || '').trim();
    if (!v) continue;
    if (!/^https?:\/\//i.test(v)) continue; // ignore non-http(s) (e.g. socks= URLs in env)
    let u;
    try { u = new URL(v); } catch { /* malformed */ continue; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
    if (excludeSelf && excludeSelf(u)) continue; // never loop into our own engine
    return { url: v, host: u.hostname, port: Number(u.port || (u.protocol === 'https:' ? 443 : 80)), source: 'env', from: name };
  }

  // 2) Windows registry (IE/系统代理).
  if (process.platform === 'win32') {
    try {
      const out = await new Promise((resolve, reject) => {
        execFile('reg', ['query', WIN_REG_KEY], { windowsHide: true, timeout: 4000 }, (err, stdout, stderr) =>
          err ? reject(new Error(stderr || String(err))) : resolve(stdout));
      });
      let enabled = false;
      let server = '';
      for (const line of out.split(/\r?\n/)) {
        const em = line.match(/^\s*ProxyEnable\s+REG_DWORD\s+0x([0-9a-f]+)/i);
        if (em) enabled = parseInt(em[1], 16) === 1;
        const sm = line.match(/^\s*ProxyServer\s+REG_SZ\s+(.+)$/i);
        if (sm) server = sm[1].trim();
      }
      if (enabled && server) {
        const parsed = parseProxyServer(server);
        if (parsed) {
          let u = null;
          try { u = new URL(parsed.url); } catch { /* keep null */ }
          if (!(u && excludeSelf && excludeSelf(u))) return { ...parsed, source: 'registry', from: '注册表 Internet Settings' };
        }
      }
    } catch { /* registry unavailable (non-Windows / blocked) — treated as no system proxy */ }
  }

  return { url: null, host: '', port: 0, source: 'none', from: '' };
}
