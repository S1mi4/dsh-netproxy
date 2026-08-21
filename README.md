# dsh-netproxy

> DSH（DeepSeek Harness）网络代理插件：像 **Postman** 一样选代理来源 —— **直连 / 系统代理 / 自定义代理**，自定义时可选 **HTTP / HTTPS / SOCKS4 / SOCKS5** 协议；让 **LLM 推理、web 搜索/抓取、其他插件的网络请求，以及 curl/git/npm 等子进程** 的所有出站 HTTP(S) 流量统一走一个可配置的代理。证书**天然跟随系统证书链**，不再是使用条件；同时支持**热切换**、**逐请求可读报错**、可选信任 MITM 代理 CA（Burp）。

## 项目作用（它能做什么）

DSH 的 LLM 请求由宿主进程的全局 `fetch` 发出（pi-ai/deepseek 适配器 → 上游），浏览器 GUI 只连本机 `127.0.0.1:3080` 回环。因此**只要管住“宿主全局 fetch + 子进程环境变量”两条路径，就能覆盖 DSH 的全部出站流量**。本插件：

- **代理来源三选一（Postman 风格）**：
  - **直连** —— 不代理任何流量，环境变量清空；
  - **系统代理** —— 自动跟随系统代理（环境变量 `HTTP(S)_PROXY`/`ALL_PROXY` + Windows 注册表 `Internet Settings`），带缓存与“重新探测”；
  - **自定义代理** —— 填主机/端口（可带认证），**协议可选 http / https / socks4 / socks5**。
- **能直连就直连，本地引擎只在必须时启用**：
  - **HTTP / HTTPS 代理（含系统代理、自定义 http/https）**：undici 与子进程**直接**连上游代理，**不经过本地引擎**（少一跳，报错也更直观）；
  - **SOCKS4/5**（undici 本身不会说 socks 协议）：才启用本地引擎（`lib/engine.js`，零依赖）做桥 —— fetch/子进程连 `http://127.0.0.1:<port>`，由引擎完成 socks 握手（no-auth / user:pass、IPv4/IPv6/域名、socks4a）。
- **证书不再卡使用，天然跟随系统证书链**：默认就用 Node 信任的系统根证书做校验，无需任何配置；
  - `caFile`（可选）：额外信任一个 PEM CA —— 只有接 Burp 等 **MITM 抓包代理**才需要；
  - `skipVerify`（可选）：Postman 的“SSL certificate verification”开关，一键忽略证书校验（自签内部服务/个别代理）。
- **热切换**：宿主运行时用 undici `ProxyAgent` 包装 `globalThis.fetch`，**每次请求按当前配置选代理** —— 改来源/协议/主机/开关即时生效，无需重启；同时同步 `process.env` 覆盖新起的子进程。
- **可观测**：`llm/stream` 挂钩统计每次模型调用（provider/model/耗时）；引擎访问日志可回读（仅 socks 场景运行）。
- **报错归因**：代理连不上、目标 DNS、TLS/CA、超时、上游 5xx、SOCKS 协商失败、引擎反复崩溃……都会归类成用户可读原因并展示在设置页，不再无声重试。
- 官方设置页「网络代理」：来源/协议/证书/NO_PROXY/状态/流量/错误，随主题亮暗切换。

```
DSH 宿主进程 (host realm)
  LLM(pi-ai/deepseek) ─┐
  其他插件 fetch ───────┼─→ 全局 fetch ──→ [热切换: undici ProxyAgent]
  curl/git 子进程 ──────┘  (HTTP(S)_PROXY env)                          │
  浏览器 GUI ──────────→ 127.0.0.1:3080（回环，NO_PROXY 豁免）            │
                                                                        ▼
           http/https / 系统代理        ── 直连上游（不经本地引擎）
                                                                        ▼
              socks4 / socks5           ── 本地引擎 http://127.0.0.1:<port>（socks 握手桥）
```

## 目录结构

```
dsh-netproxy/
├─ lib/
│  ├─ engine.js      # 本地 SOCKS 桥引擎（仅 socks egress 才启用）：HTTP+CONNECT 转发 + socks4/5 零依赖握手 + http/https 上游转发 + 访问日志 + NO_PROXY
│  ├─ index.js       # 宿主插件：settings、路由决策（直连/上游/引擎桥）、系统代理探测缓存、引擎启停/熔断、热切换、报错归因、观测、web 路由
│  ├─ client.js      # 浏览器端设置页「网络代理」（Postman 风格）
│  ├─ sysproxy.js    # 系统代理探测（环境变量 + Windows 注册表；零依赖）
│  └─ types/         # 类型声明
├─ scripts/
│  └─ np-env.ps1     # L0 拦截环境辅助脚本（设置代理环境变量并以该环境启动 dsh，可选）
├─ test/             # 隔离测试：smoke / hot / ca / sse / socks（egress 探针）
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

`dsh plugin` 会把包 pnpm 装入 profile 的 `node_modules` 并按 `dsh.bundle.patch` 自动加入 `dsh.profile.bundles`。安装后**重启一次 dsh** 使插件挂载。

## 使用方法

### 1) 设置页配置（推荐）

打开 **设置 → 网络代理**：

| 字段（卡片） | 说明 |
|---|---|
| **代理来源（类型）** | **直连**（不代理）/ **系统代理**（跟随系统：环境变量 + Windows 注册表，可「重新探测」）/ **自定义代理**。 |
| **协议**（自定义时） | **HTTP / HTTPS / SOCKS4 / SOCKS5**。SOCKS5 支持无认证或 user:pass；域名为远端解析。 |
| 代理主机 / 代理端口 | 自定义代理地址；端口如 7890（Clash）/ 1080（socks）等。 |
| 认证（可选） | `user:pass`，同时用于 HTTP 上游 Basic 认证与 SOCKS5 用户认证。 |
| 本地引擎端口 | 统一出口引擎监听端口（默认 4317）。 |
| **MITM 代理 CA（可选）** | 只有接 Burp 等 MITM 代理才填（导出的根证书 PEM）；留空 = 跟随系统证书链。 |
| **忽略证书校验** | Postman 风格开关：跳过 TLS 证书校验（自签内部环境）。默认关闭。 |
| NO_PROXY（服务端） | 豁免名单（默认含回环）。 |
| SSE 明文流(plainStream) / 独立隧道(freshTunnel) | 见下文“SSE 流式经代理”。 |

也可直接写 `~/.dsh/settings.yaml`：

```yaml
netProxy:
  source: custom            # direct | system | custom
  customProtocol: socks5    # http | https | socks4 | socks5
  customHost: 127.0.0.1
  customPort: 1080
  # customAuth: user:pass   # 可选
  # caFile: C:\burp\ca.pem  # 可选：仅 MITM 代理（Burp）需要；留空=系统证书链
  # skipVerify: false        # 可选：忽略证书校验
  plainStream: true         # SSE 明文流（防 gzip 缓冲导致重试）
  freshTunnel: true         # 每请求独立代理隧道
```

> 兼容：老配置里的 `enabled`/`mode`/`proxyUrl` 会被自动迁移成新模型（有 `proxyUrl` 时映射为 `custom`）。

### 2) 验证

- 设置页 → 面板显示当前来源与出口路由，如「自定义代理 → socks5://127.0.0.1:1080（经本地引擎桥接）」；若是 **http/https 或系统代理**则显示「直连上游 http://…」，**本地引擎不会启动**。
- 引擎访问日志：`$env:USERPROFILE\.dsh\netproxy-engine.log`（仅 SOCKS 场景运行；http/https 直连时无此进程）。
- 现在改来源/协议/主机/开关 → **立即生效，无需重启**（热切换）；开「忽略证书校验」或填 CA 后 → 同样即时生效。
- 系统代理模式下若显示「未检测到系统代理」，点「重新探测」或确认系统代理（设置 → 网络 → 代理）已开启。

### 3) L0 环境（进阶，可选）

热切换只覆盖主线程全局 fetch 与新起的子进程。若要**工作线程/进程启动时就注入环境**，可用脚本以代理环境启动 DSH（L0 拦截层），之后仍可热切换：

```powershell
powershell -File scripts/np-env.ps1
#   -Port 4317    -Profile web   -CaCert <MITM.CA.pem>   -PrintOnly
```

未带 L0 时插件只提示“建议重启时带 --use-env-proxy”，不影响热切换路由。

### 4) 接 Burp（外置 MITM 代理 + 抓 HTTPS）

1. 代理来源=**自定义代理**，协议=**HTTP**，主机=`127.0.0.1`，端口=`8080`（Burp 的 Proxy listener）。
2. 导出 Burp 根证书为 PEM：`Proxy → Options → Import/Export CA certificate → Copy`（PEM 文本存 `.pem`）；或导出 DER 转：`openssl x509 -inform DER -in burp.cer -out burp.pem`。
3. **MITM 代理 CA** 填该 `.pem` 路径。完成后 HTTPS 请求能经 Burp 完成，Burp `HTTP history` 可见明文/正文；否则面板会报 `TLS_CA` 提示填 CA。
4. 若只是本机自签/内部服务，也可以不填 CA，直接开 **忽略证书校验**。

### 5) LLM 流式（SSE）经 Burp 时而“收到却重试”？—— 本插件已内置对策

**根因**：LLM 是 SSE 长连接。若客户端带 `Accept-Encoding: gzip`，MITM 代理（Burp）会把响应流再编码成 gzip；undici 的解压器为大窗口/整段缓冲，**首个 SSE 事件被推迟数秒**，DSH 的流式看门狗判定“卡住”→ 自动重试。

**内置对策（默认开启，无需操作）**：
- `plainStream`（SSE 明文流）：经代理的请求强制 `Accept-Encoding: identity` → 上游/代理不再 gzip → SSE 即时逐事件下发（实测首事件 5.4s → ~465ms）。
- `freshTunnel`（独立隧道）：每请求新建代理连接，规避代理侧关闭/闲置隧道的复用竞态。

**如仍异常，请在 Burp 侧配合**：`Proxy → Options` 关闭对这些流量的响应缓冲/重写；或对该 LLM 主机 `TLS pass through`；或关闭对 SSE 的 gzip 再编码。若代理是“整段缓冲后才转发”（不属压缩），客户端无法解决，属代理配置问题。

## 报错与排查（报错机制）

| 代码 | 含义 / 处置 |
|---|---|
| `PROXY_UNREACHABLE` | 代理地址连不上（代理未启动/端口没监听/地址配错） |
| `TARGET_DNS` | 目标地址 DNS 解析失败 |
| `TLS_CA` | 证书校验失败。默认跟随系统证书链：若代理是 MITM（Burp）请填「CA 文件」；自签环境可开「忽略证书校验」 |
| `TIMEOUT` / `CONN_RESET` | 连接超时 / 连接被重置 |
| `HTTP_5xx` / `PROXY_5xx` | 目标/上游返回 5xx；代理建立连接失败 |
| `SOCKS` | SOCKS 协商失败（不可达/认证失败/目标拒绝），注意自定义代理的协议与端口是否匹配 |
| CA 文件读取失败 | `caFile` 路径不存在或不是 PEM |
| 引擎循环熔断 | 引擎 60 秒内退出 ≥3 次：自动暂停重启并写明根因；改任意配置即解除 |

所有失败都会记录在设置页「代理错误 / CA 状态」卡片（时间/主机/原因），顶部横幅变红。

## 测试

```powershell
npm install
npm run check                              # 语法检查（engine/index/client/sysproxy）
node test/test-host.mjs                    # 宿主逻辑（settings 晚绑定 / 引擎启停 / source/egress / set）
node test/sysproxy-parse.mjs               # 系统代理 ProxyServer 解析（域名/IPv6/多协议条目）
node test/hot-probe.mjs                    # 热切换 + 回环豁免（需网络）
node test/ca-probe.mjs                     # caFile/错误分类（需 openssl，自签 CA 隧道）
node test/sse-probe.mjs                    # SSE 经代理流式（gzip 重编码复现+plainStream 修复证明，需 openssl）
node test/socks-probe.mjs                  # 统一出口：socks5(无认证/带认证)/socks4/http 链式/https 上游（需 openssl）
```

## 边界

- 回环（127.0.0.1/localhost/::1）默认不代理（`NO_PROXY` 含之），DSH 自身 3080、本地 MCP 不受影响；系统代理探测也会自动排除指向本插件自身引擎的环路。
- **本地引擎端口（4317）只有 SOCKS 场景才使用**：http/https（含系统代理）直连上游，引擎不会启动、也不会有 4317 报错。若在 socks 场景仍见 4317 报错 `fetch failed … tried through http://127.0.0.1:4317`，说明 socks 代理不可达/握手失败——查看设置页「代理错误」卡片的 `SOCKS`/`PROXY_*` 归类原因。
- 引擎做 CONNECT 直通，不做 TLS 中间人；要抓 HTTPS 正文请用带 `caFile` 的外置 MITM 代理（或临时开「忽略证书校验」做纯转发）。
- 系统代理通常为 HTTP 上游；若系统配置了 SOCKS（注册表 `socks=` 条目或 socks:// 环境变量），引擎会自动启用桥接。
- 个别用自建 agent 的第三方库可能不读代理环境；DSH 主链路（LLM/工具）均走 fetch，不受影响。

## License

MIT © S1mi4
