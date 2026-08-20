/**
 * dsh-netproxy — type surface.
 * The host half registers the `netProxy` settings namespace and serves
 * `/plugins/dsh-netproxy/*` web routes; the client half mounts a Settings page.
 */
import type { Schema } from '@deepseek-ai/schemastery';

export interface NetProxyConfig {
  enabled: boolean;
  mode: 'builtin' | 'external';
  proxyUrl: string;
  enginePort: number;
  engineBind: string;
  auth: string;
  logFile: string;
  noProxy: string;
  caFile: string;
  plainStream: boolean;
  freshTunnel: boolean;
  observe: boolean;
  restartOnCrash: boolean;
  watchMs: number;
  hot: boolean;
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
  enabled: boolean;
  mode: string;
  externalProxyUrl: string;
  engine: {
    running: boolean;
    pid: number;
    bind: string;
    port: number;
    auth: boolean;
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
  config: Omit<NetProxyConfig, 'enabled' | 'mode'> & { logFile: string; auth: boolean };
}

export const Config: Schema<NetProxyConfig>;
export const name: 'netproxy';
export const inject: ['timer'];
export function apply(ctx: unknown, config: NetProxyConfig): void;
