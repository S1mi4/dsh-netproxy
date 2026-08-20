# dsh-netproxy

> DSH（DeepSeek Harness）网络代理插件：让 **LLM 推理、web 搜索/抓取、其他插件的网络请求，以及 curl/git/npm 等子进程** 的所有出站 HTTP(S) 流量，统一走一个可配置的代理——并支持**热切换（改配置无需重启）**、**逐请求可读报错**、**可选信任 MITM 代理 CA（如 Burp）**。

## 项目作用（它能做什么）

DSH 的 LLM 请求由宿主进程的全局 `fetch` 发出（pi-ai/deepseek 适配器 → 上游），浏览器 GUI 只连本机 `127.0.0.1:3080` 回环。因此**只要管住“宿主全局 fetch + 子进程环境变量”两条路径，就能覆盖 DSH 的全部出站流量**。本插件：

- **自带 forward 代理引擎**（`lib/engine.js`，零依赖子进程）：HTTP 转发 + HTTPS `CONNECT` 隧道 + 可选 Basic 认证 + JSON 访问日志 + `NO_PROXY` 安全网，监听 `127.0.0.1:<port>`。
- **也可指向你已有的外置代理**（Clash / v2ray / 公司网关 / Burp 等）。
- **热切换**：宿主插件在运行时用 undici `ProxyAgent` 包装 `globalThis.fetch`，**每次请求按当前配置选代理**——改模式/端口/外置 URL/开关即时生效，无需重启；同时同步 `process.env` 覆盖新起的子进程。
- **可观测**：`llm/stream` 挂钩统计每次模型调用（provider/model/耗时）；引擎访问日志可回读。
- **报错归因**：任何“代理到不了目标”的原因（代理连不上、目标 DNS、TLS/CA、超时、上游 5xx、代理 CONNECT 失败、引擎反复崩溃）都会归类成用户可读原因并展示在设置页，不再无声重试。
- **MITM 代理 CA**：填 `caFile` 让 HTTPS 经 Burp 等 MITM 代理正常完成（否则 Node 不信任其 CA 会握手失败）。
- 官方设置页「网络代理」：开关/模式/端口/认证/NO_PROXY/CA/状态/流量/错误，随主题亮暗切换。

```
DSH 宿主进程 (host realm)
  LLM(pi-ai/deepseek) ─┐
  其他插件 fetch ───────┼─→ 全局 fetch ──→ [热切换包装: undici ProxyAgent] ──→ 代理引擎(内置 or 外置) ──→ 目标
  curl/git 子进程 ──────┘  (进程环境变量同步)
  浏览器 GUI ──────────→ 127.0.0.1:3080（回环，NO_PROXY 豁免，不代理）
```

## 目录结构

```
dsh-netproxy/
├─ lib/
│  ├─ engine.js      # 自带 forward 代理引擎（HTTP + CONNECT + 鉴权 + JSON 日志），零依赖，可独立运行
│  ├─ index.js       # 宿主插件：settings、引擎启停/崩溃熔断、热切换、报错归因、观测、web 路由
│  ├─ client.js      # 浏览器端设置页「网络代理」
│  └─ types/         # 类型声明
├─ scripts/
│  └─ np-env.ps1     # L0 拦截环境辅助脚本（设置代理环境变量并以该环境启动 dsh）
├─ test/             # 隔离测试（mock 宿主通不过真机则说明缺失）：smoke / hot / ca
├─ cordis.patch.yml  # bundle 行（id: netproxy, name: dsh-netproxy）
├─ package.json
└─ README.md
```

## 安装（安装方法）

> 前置：本机已有 DSH（Node ≥ 22.19 或 ≥ 24）。

方式 A —— 从 GitHub 安装（本仓库）：

```powershell
dsh plugin --profile web add git+https://github.com/S1mi4/dsh-netproxy.git
```

方式 B —— 克隆后本地安装（便于改代码，pnpm 会以 `link:` 方式装入，改动即时可调试）：

```powershell
git clone https://github.com/S1mi4/dsh-netproxy.git
dsh plugin --profile web add <克隆下来的绝对路径>
```

`dsh plugin` 会把包 pnpm 装入 profile 的 `node_modules` 并按 `dsh.bundle.patch` 自动加入 `dsh.profile.bundles`。安装后**重启一次 dsh** 使插件挂载（配置层 L0 环境见下）。

## 使用方法

### 1) 启动 DSH（带 L0 拦截环境）—— 只需做一次，此后重启都用它

> `--use-env-proxy` 只在进程启动时读取，所以 DSH 必须用下面脚本（或等效环境变量）启动一次；之后插件内的热切换就能让配置改动即时生效。

```powershell
powershell -File scripts/np-env.ps1
# 常用参数：
#   -Port 4317               代理端口（默认 4317，与设置里 enginePort 一致）
#   -CaCert C:\burp\ca.pem   经 MITM 代理时信任其 CA（子进程/工作线程也用）
#   -Profile web             启动的 profile（默认 web）
#   -PrintOnly               只打印环境变量不启动
```

### 2) 在设置页配置

打开 **设置 → 网络代理**，核心字段：

| 字段 | 说明 |
|---|---|
| 启用 | 主开关。关闭=直连（引擎停、热切换失效）。 |
| 传输模式 | **内置引擎**：用自带引擎（推荐，零依赖）；**外置代理**：走 `外置代理 URL`（Clash/公司/Burp 等）。 |
| 外置代理 URL | 外置模式下目标地址，如 `http://127.0.0.1:8080`、`http://user:pass@host:port`。 |
| 监听端口 / 基本认证 / 引擎访问日志 / NO_PROXY | 内置引擎参数；NO_PROXY 为服务端豁免名单（默认含回环）。 |
| CA 文件 | MITM 代理（Burp）导出的根证书 PEM 路径，见下方“接 Burp”。 |
| SSE 明文流 (plainStream) | 默认开：经代理的请求强制 `Accept-Encoding: identity`，避免 MITM 代理把 SSE 再编码成 gzip 导致“首事件被缓冲、DSH 误判卡住而重试”，也便于抓取明文。 |
| 独立隧道 (freshTunnel) | 默认开：每请求新建代理连接（短 keep-alive 自动回收），规避代理侧关闭隧道的复用竞态。 |
| 热切换 | 默认开启；关闭则退化为“仅 L0 环境、改配置需重启”。 |

也可直接写 `~/.dsh/settings.yaml`：

```yaml
netProxy:
  enabled: true
  mode: builtin        # 或 external
  enginePort: 4317
  # proxyUrl: http://127.0.0.1:8080   # external 时必填
  # caFile: C:\burp\ca.pem            # MITM 代理时填
  plainStream: true    # SSE 明文流（防 gzip 缓冲导致重试）
  freshTunnel: true    # 每请求独立代理隧道
```

### 3) 验证

- 设置页 → 面板显示「热切换路由：已生效 → http://127.0.0.1:4317」「L0 环境就绪」。
- 引擎访问日志：`$env:USERPROFILE\.dsh\netproxy-engine.log`（或你设置的文件），能看到 `connect opencode.ai:443`（LLM）与各工具/curl 域名。
- 现在改端口/模式/开关 → **立即生效，无需重启**（热切换）。

### 4) 接 Burp（外置代理 + 抓 HTTPS）

1. 传输模式=**外置代理**，URL=`http://127.0.0.1:8080`。
2. 导出 Burp 根证书为 PEM：`Proxy → Options → Import/Export CA certificate` → `Copy`（PEM 文本，存成 `.pem`）；或导出 DER 后转：`openssl x509 -inform DER -in burp.cer -out burp.pem`。
3. CA 文件=该 `.pem` 路径（并对子进程/工作线程用 `scripts/np-env.ps1 -CaCert ...` 启动，或设 `NODE_EXTRA_CA_CERTS`）。
4. 完成后 HTTPS 请求能经 Burp 完成，Burp `HTTP history` 可见正文；否则面板会报 `TLS_CA` 并提示填 CA。

### 5) LLM 流式（SSE）经 Burp 时而“收到却重试”？—— 本插件已内置对策

**根因**：LLM 是 SSE 长连接。若客户端带 `Accept-Encoding: gzip`，MITM 代理（Burp）会把响应流再编码成 gzip；undici 的解压器为大窗口/整段缓冲，**首个 SSE 事件被推迟数秒**，DSH 的流式看门狗判定“卡住”→ 自动重试，形成“Burp 收到了、DSH 却重试”。

**内置对策（默认开启，无需你操作）**：
- `plainStream`（SSE 明文流）：经远端代理的请求强制 `Accept-Encoding: identity` → 上游/代理不再 gzip → SSE 即时逐事件下发（实测首事件 465ms vs 5.4s，重试消失）。
- `freshTunnel`（独立隧道）：每条请求新建代理连接，规避代理侧关闭/闲置隧道的复用竞态。

**如仍异常，请在 Burp 侧配合**：
- `Proxy → Options` 关闭对这些流量的响应缓冲/重写；或对该 LLM 主机 `TLS pass through`（直通，仅记连接）；或关闭对 SSE 的 gzip 再编码。
- 说明：若代理是“整段缓冲后才转发”（不属压缩），客户端无法解决，属代理配置问题（见探针 D 模式）。

## 报错与排查（报错机制）

| 代码 | 含义 / 处置 |
|---|---|
| `PROXY_UNREACHABLE` | 代理地址连不上（端口没监听/代理没启动/URL 配错） |
| `TARGET_DNS` | 目标地址 DNS 解析失败 |
| `TLS_CA` | 证书校验失败；经 MITM 代理请填 `caFile` |
| `TIMEOUT` / `CONN_RESET` | 连接超时 / 连接被重置 |
| `HTTP_5xx` | 目标/上游返回 5xx |
| `PROXY_5xx` | 代理建立连接失败（目标不可达/代理拒绝） |
| `CA 文件读取失败` | `caFile` 路径不存在或不是 PEM |
| 引擎循环熔断 | 引擎 60 秒内退出 ≥3 次：自动暂停重启并写明根因；改任意配置即解除 |

所有失败都会记录在设置页「代理错误 / CA 状态」卡片（时间/主机/原因），顶部横幅变红。

## 测试

```powershell
npm run check                              # 语法检查
node test/test-host.mjs                    # 宿主逻辑（settings 晚绑定/引擎启停//set）
node test/hot-probe.mjs                    # 热切换 + 回环豁免（需网络）
node test/ca-probe.mjs                     # caFile/错误分类（需 openssl，自签 CA 隧道）
node test/sse-probe.mjs                    # SSE 经代理流式（gzip 重编码复现+plainStream 修复证明，需 openssl）
```

## 边界

- 回环（127.0.0.1/localhost/::1）默认不代理（`NO_PROXY` 含之），DSH 自身 3080、本地 MCP 不受影响。
- 内置引擎为 CONNECT 直通，默认不做 TLS 中间人；要抓 HTTPS 正文请用带 `caFile` 的外置 MITM 代理。
- 热切换覆盖主线程全局 fetch 与新起的子进程；工作线程兜底需启动时带 L0 环境（`scripts/np-env.ps1`）。
- 个别用自建 agent 的第三方库可能不读代理环境；DSH 主链路（LLM/工具）均走 fetch，不受影响。

## License

MIT © S1mi4
