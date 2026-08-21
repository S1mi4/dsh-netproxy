/**
 * dsh-netproxy — type surface.
 * The host half registers the `netProxy` settings namespace and serves
 * `/plugins/dsh-netproxy/*` web routes; the client half mounts a Settings page.
 */
import type { Schema } from '@deepseek-ai/schemastery';

export interface NetProxyConfig {
  /** Postman-style proxy source: direct (none) | system (OS proxy) | custom. */
  source: 'direct' | 'system' | 'custom';
  /** custom proxy protocol: http | https | socks4 | socks5. */
  customProtocol: 'http' | 'https' | 'socks4' | 'socks5';
  customHost: string;
  customPort: number;
  customAuth: string;
  enginePort: number;
  engineBind: string;
  logFile: string;
  noProxy: string;
  /** Optional extra CA (PEM) for MITM proxies; empty = follow system chain. */
  caFile: string;
  /** Postman-style "ignore certificate verification" switch. */
  skipVerify: boolean;
  plainStream: boolean;
  freshTunnel: boolean;
  observe: boolean;
  restartOnCrash: boolean;
  watchMs: number;
  hot: boolean;
  /** @deprecated legacy fields kept for settings.yaml compatibility. */
  enabled?: boolean;
  mode?: string;
  proxyUrl?: string;
  auth?: string;
}

export interface NetProxyRouteError {
  ts: number;
  host: string;
  target?: string;
  code: string;
  hint?: string;
  error?: string;
}

export interface NetProxyState {
  name: string;
  startedAt: number;
  now: number;
  source: 'direct' | 'system' | 'custom';
  /** direct | upstream (undici speaks straight to the proxy) | engine (SOCKS bridge). */
  routeKind: 'direct' | 'upstream' | 'engine';
  /** Resolved outbound target (e.g. socks5://127.0.0.1:1080 or system proxy). */
  egress: string;
  system: { url: string | null; source: 'env' | 'registry' | 'none' | 'loading'; from: string; checkedAt: number };
  skipVerify: boolean;
  engine: {
    running: boolean;
    pid: number;
    bind: string;
    port: number;
    auth: boolean;
    upstream: string;
    spawnedAt: number;
    lastExit: { code: number | null; signal: string | null; at: number } | null;
  };
  hot: { installed: boolean; active: boolean; target: string };
  ca: { file: string; loaded: boolean; error: string | null };
  routeOk: boolean;
  lastRouteError: NetProxyRouteError | null;
  routeErrors: NetProxyRouteError[];
  engineLoop: { detected: boolean; count: number; lastExit: { code: number | null; signal: string | null } | null };
  env: {
    httpProxy: string;
    httpsProxy: string;
    noProxy: string;
    nodeOptions: string;
    useEnvProxy: boolean;
  };
  envReady: boolean;
  envHint: string;
  stats: { llmCalls: number; providers: Record<string, { calls: number; totalMs: number }> };
  lastError: string | null;
  engineLogCount: number;
  config: {
    source: 'direct' | 'system' | 'custom';
    customProtocol: 'http' | 'https' | 'socks4' | 'socks5';
    customHost: string;
    customPort: number;
    customAuth: boolean;
    enginePort: number;
    engineBind: string;
    logFile: string;
    noProxy: string;
    caFile: string;
    skipVerify: boolean;
    plainStream: boolean;
    freshTunnel: boolean;
    observe: boolean;
    restartOnCrash: boolean;
  };
}

export const Config: Schema<NetProxyConfig>;
export const name: 'netproxy';
export const inject: ['timer'];
export function apply(ctx: unknown, config: Partial<NetProxyConfig>): void;
