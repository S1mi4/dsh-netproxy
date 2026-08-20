# np-env.ps1 — L0 enforcement environment for dsh-netproxy
#
# Sets the process environment so the DSH host process and its child shells
# route ALL outbound HTTP(S) through the configured proxy:
#   - HTTP(S)_PROXY   -> proxy address (default the built-in engine 127.0.0.1:<Port>)
#   - NO_PROXY        -> loopback (+ your own bypasses) are never proxied
#   - NODE_OPTIONS    -> --use-env-proxy makes Node's global fetch honour the
#                        proxy env (must be present at DSH process start).
#   - NODE_EXTRA_CA_CERTS -> optional CA for MITM proxies (Burp) so worker
#                        threads / subprocesses also trust it (hot wrapper on
#                        the main thread already uses the plugin's caFile).
#
# IMPORTANT: --use-env-proxy only takes effect at DSH launch, so run dsh via
# this script (or bake the same vars into your user/system environment) and
# RESTART DSH after changing any proxy setting. Once running, the plugin's hot
# routing makes further config changes apply instantly (no restart needed).
#
# Usage:
#   powershell -File scripts/np-env.ps1                    # start dsh web with proxy env
#   powershell -File scripts/np-env.ps1 -Port 4317 -CaCert C:\burp\ca.pem
#   powershell -File scripts/np-env.ps1 -Profile headless -Args "run tests"
#   powershell -File scripts/np-env.ps1 -PrintOnly         # just print the env block

param(
  [int]$Port = 4317,
  [string]$CaCert = "",
  [switch]$PrintOnly,
  [string]$Profile = "web",
  [string]$Extra = ""
)

$env:HTTP_PROXY  = "http://127.0.0.1:$Port"
$env:HTTPS_PROXY = "http://127.0.0.1:$Port"
$env:NO_PROXY    = "127.0.0.1,localhost,::1"
# Merge any pre-existing NO_PROXY entries so the user's own bypasses survive.
if ($env:NO_PROXY_OLD) { $env:NO_PROXY = "$env:NO_PROXY,$env:NO_PROXY_OLD" }
# Node v24: --use-env-proxy is allowed inside NODE_OPTIONS.
$env:NODE_OPTIONS = "--use-env-proxy"
if ($CaCert -ne "" -and (Test-Path $CaCert)) { $env:NODE_EXTRA_CA_CERTS = (Resolve-Path $CaCert).Path }

Write-Host "dsh-netproxy L0 env:"
Write-Host "  HTTP_PROXY   = $env:HTTP_PROXY"
Write-Host "  HTTPS_PROXY  = $env:HTTPS_PROXY"
Write-Host "  NO_PROXY     = $env:NO_PROXY"
Write-Host "  NODE_OPTIONS = $env:NODE_OPTIONS"
if ($env:NODE_EXTRA_CA_CERTS) { Write-Host "  NODE_EXTRA_CA_CERTS = $env:NODE_EXTRA_CA_CERTS" }

if ($PrintOnly) { return }

Write-Host "Starting: dsh --profile $Profile $Extra ..."
& dsh --profile $Profile $Extra.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
