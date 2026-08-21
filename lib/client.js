/**
 * dsh-netproxy — browser client half.
 *
 * Mounts one Settings page ("网络代理") into the `settings.section` slot. The
 * page reads the host-half state from `/plugins/dsh-netproxy/state`, writes
 * configuration via `/plugins/dsh-netproxy/set` (and re-probes the system
 * proxy via `/detect`), and shows:
 *   - proxy source picker (直连 / 系统代理 / 自定义代理) + protocol for custom,
 *   - certificate handling: system-chain by default, optional MITM CA file,
 *     Postman-style "忽略证书校验" switch,
 *   - engine subprocess health / last exit / access-log tail,
 *   - LLM call attribution statistics.
 *
 * Communication is same-origin fetch to the DSH webserver routes; no host RPC.
 */
window.__ModuleLoader__.load({
	id: "dsh-netproxy",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

		const react = require("react");

		const STATE_URL = "/plugins/dsh-netproxy/state";
		const SET_URL = "/plugins/dsh-netproxy/set";
		const DETECT_URL = "/plugins/dsh-netproxy/detect";
		const LOG_URL = "/plugins/dsh-netproxy/log?n=12";

		async function getJson(url, body) {
			const res = await fetch(url, body === undefined ? {} : {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(body),
			});
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			return res.json();
		}

		/** One labelled row of key/value display text. */
		function Field({ label, children }) {
			return react.createElement("div", { style: rowStyle() },
				react.createElement("span", { style: cellStyle("label") }, label),
				react.createElement("span", { style: cellStyle("value") }, children),
			);
		}
		function rowStyle() { return { display: "flex", justifyContent: "space-between", gap: "12px", padding: "6px 0", borderBottom: "1px solid var(--dsw-alias-border-l1, rgba(120,120,120,0.3))", fontSize: 13 }; }
		function cellStyle(kind) { return kind === "label" ? { color: "var(--dsw-alias-label-secondary, #5f6b7a)", whiteSpace: "nowrap" } : { wordBreak: "break-all", textAlign: "right", color: "var(--dsw-alias-label-primary, inherit)" }; }

		/** Text input control wired to a draft object. */
		function Input({ draft, setDraft, field, placeholder, width }) {
			return react.createElement("input", {
				style: {
					flex: 1, minWidth: 0, padding: "4px 8px", borderRadius: 6,
					border: "1px solid var(--dsw-alias-border-l2, rgba(120,120,120,0.4))",
					background: "var(--dsw-alias-bg-layer-2, #f0f1f3)", color: "var(--dsw-alias-label-primary, inherit)",
					...(width ? { width } : {}),
				},
				value: draft[field] ?? "",
				placeholder: placeholder || "",
				onChange: (e) => setDraft({ ...draft, [field]: e.target.value }),
			});
		}

		/** Boolean toggle row: shows the state and flips the draft field. */
		function CheckToggle({ draft, setDraft, field, yes, no }) {
			const on = !!draft[field];
			return react.createElement("label", { style: { display: "inline-flex", alignItems: "center", gap: 8, fontSize: 13, cursor: "pointer" } },
				react.createElement("input", {
					type: "checkbox", checked: on,
					onChange: (e) => setDraft({ ...draft, [field]: e.target.checked }),
				}),
				on ? yes : no,
			);
		}

		const SOURCE_NAMES = { direct: "直连", system: "系统代理", custom: "自定义代理" };
		const PROTO_NAMES = { http: "HTTP", https: "HTTPS", socks4: "SOCKS4", socks5: "SOCKS5" };

		function NetProxyPage() {
			const [state, setState] = react.useState(null);
			const [error, setError] = react.useState(null);
			const [draft, setDraft] = react.useState(null);
			const [saving, setSaving] = react.useState(false);
			const [savedMsg, setSavedMsg] = react.useState("");
			const [log, setLog] = react.useState([]);
			const [detecting, setDetecting] = react.useState(false);
			const [refreshKey, setRefreshKey] = react.useState(0);

			react.useEffect(() => {
				let alive = true;
				const tick = async () => {
					try {
						const s = await getJson(STATE_URL);
						if (!alive) return;
						setState(s);
						setError(null);
						setDraft((d) => (d === null ? {
							source: s.source || "direct",
							customProtocol: s.config.customProtocol || "http",
							customHost: s.config.customHost || "",
							customPort: s.config.customPort || "",
							customAuth: "",
							enginePort: s.config.enginePort,
							noProxy: s.config.noProxy,
							caFile: s.config.caFile || "",
							skipVerify: !!s.config.skipVerify,
							plainStream: s.config.plainStream !== false,
							freshTunnel: s.config.freshTunnel !== false,
						} : d)); // keep user's in-progress edits across polls
					} catch (e) {
						if (alive) setError(String(e));
					}
				};
				void tick();
				const id = window.setInterval(tick, 3000);
				return () => { alive = false; window.clearInterval(id); };
			}, [refreshKey]);

			react.useEffect(() => {
				let alive = true;
				getJson(LOG_URL).then((r) => { if (alive) setLog(r.lines ?? []); }).catch(() => {});
				return () => { alive = false; };
			}, [refreshKey]);

			const save = async () => {
				if (draft === null) return;
				setSaving(true);
				setSavedMsg("");
				try {
					const payload = {
						source: draft.source,
						customProtocol: draft.customProtocol,
						customHost: String(draft.customHost || "").trim(),
						customPort: Number(draft.customPort) || 0,
						customAuth: draft.customAuth || "",
						enginePort: Number(draft.enginePort) || 4317,
						noProxy: draft.noProxy || "",
						caFile: draft.caFile || "",
						skipVerify: !!draft.skipVerify,
						plainStream: !!draft.plainStream,
						freshTunnel: !!draft.freshTunnel,
					};
					await getJson(SET_URL, payload);
					setSavedMsg("已保存（热切换即时生效）");
					setTimeout(() => setSavedMsg(""), 4000);
					setRefreshKey((k) => k + 1);
				} catch (e) {
					setError(String(e));
				} finally {
					setSaving(false);
				}
			};

			const redetect = async () => {
				setDetecting(true);
				try { await getJson(DETECT_URL); setRefreshKey((k) => k + 1); }
				catch (e) { setError(String(e)); }
				finally { setDetecting(false); }
			};

			const s = state;
			const providers = s ? Object.entries(s.stats.providers) : [];

			return react.createElement("div", { style: { maxWidth: 720, display: "flex", flexDirection: "column", gap: 14 } },

				// -- status banner --
				react.createElement("div", { style: bannerStyle(error, s) }, error
					? `状态读取失败：${error}`
					: s === null ? "正在读取…"
					: s.source === "direct" ? "代理当前：直连（不代理）"
					: `代理当前：${SOURCE_NAMES[s.source] || s.source}${s.egress ? ` → ${s.egress}` : ""}${s.envReady ? "" : "（未生效）"}`),

				(draft === null) ? null : react.createElement("div", { style: cardStyle() },

					react.createElement("h3", { style: titleStyle() }, "代理来源"),
					react.createElement(Field, { label: "类型" },
						react.createElement("select", {
							value: draft.source,
							onChange: (e) => setDraft({ ...draft, source: e.target.value }),
							style: selectStyle(),
						},
							react.createElement("option", { value: "direct" }, "直连（不代理）"),
							react.createElement("option", { value: "system" }, "系统代理"),
							react.createElement("option", { value: "custom" }, "自定义代理")),
					),

					draft.source === "custom"
						? react.createElement(react.Fragment, {},
							react.createElement(Field, { label: "协议" },
								react.createElement("select", {
									value: draft.customProtocol,
									onChange: (e) => setDraft({ ...draft, customProtocol: e.target.value }),
									style: selectStyle(),
								},
									react.createElement("option", { value: "http" }, "HTTP"),
									react.createElement("option", { value: "https" }, "HTTPS"),
									react.createElement("option", { value: "socks4" }, "SOCKS4"),
									react.createElement("option", { value: "socks5" }, "SOCKS5")),
							),
							react.createElement(Field, { label: "代理主机" }, react.createElement(Input, { draft, setDraft, field: "customHost", placeholder: "如 127.0.0.1 或 proxy.example.com" })),
							react.createElement(Field, { label: "代理端口" }, react.createElement(Input, { draft, setDraft, field: "customPort", placeholder: "如 7890 / 1080", width: 110 })),
							react.createElement(Field, { label: "认证(可选)" }, react.createElement(Input, { draft, setDraft, field: "customAuth", placeholder: "user:pass（socks5/HTTP）" })),
						)
						: draft.source === "system"
							? react.createElement(react.Fragment, {},
								react.createElement(Field, { label: "检测结果" },
									s === null ? "…" : s.system && s.system.url
										? `${s.system.url}（${s.system.source === "registry" ? "Windows 系统设置" : "环境变量 " + (s.system.from || "")}）`
										: (s.system && (s.system.source === "loading" || !s.system.source) ? "探测中…" : "未检测到系统代理（当前按直连处理）")),
								react.createElement("div", { style: { display: "flex", alignItems: "center", gap: 10, marginTop: 4 } },
									react.createElement("button", { style: btnStyle("secondary"), onClick: redetect, disabled: detecting }, detecting ? "探测中…" : "重新探测系统代理")),
							)
							: react.createElement("p", { style: { fontSize: 12, color: "var(--dsw-alias-label-secondary, #5f6b7a)", margin: "4px 0 0" } },
								"直连：所有出站流量（LLM / 工具 / curl / git）都不经代理。"),

					react.createElement(Field, { label: "本地引擎端口" }, react.createElement(Input, { draft, setDraft, field: "enginePort", placeholder: "4317", width: 96 })),

					react.createElement("h3", { style: titleStyle() }, "证书（默认跟随系统证书链）"),
					react.createElement(Field, { label: "MITM 代理 CA(可选)" }, react.createElement(Input, { draft, setDraft, field: "caFile", placeholder: "如 Burp 导出的 cacert.pem（留空=系统证书链）" })),
					react.createElement(Field, { label: "忽略证书校验" },
						react.createElement(CheckToggle, { draft, setDraft, field: "skipVerify", yes: "开启：跳过 TLS 证书校验（自签/内部）", no: "关闭：按系统证书链校验" })),

					react.createElement("h3", { style: titleStyle() }, "流式与范围"),
					react.createElement(Field, { label: "NO_PROXY(服务端)" }, react.createElement(Input, { draft, setDraft, field: "noProxy", placeholder: "127.0.0.1,localhost" })),
					react.createElement(Field, { label: "SSE 明文流(plainStream)" },
						react.createElement(CheckToggle, { draft, setDraft, field: "plainStream", yes: "强制 identity，流式即时", no: "允许压缩" })),
					react.createElement(Field, { label: "独立隧道(freshTunnel)" },
						react.createElement(CheckToggle, { draft, setDraft, field: "freshTunnel", yes: "每请求新建代理连接", no: "复用连接池" })),

					react.createElement("div", { style: { display: "flex", alignItems: "center", gap: 12, marginTop: 8 } },
						react.createElement("button", { style: btnStyle("primary"), onClick: save, disabled: saving }, saving ? "保存中…" : "保存配置"),
						savedMsg ? react.createElement("span", { style: { fontSize: 13, color: "var(--dsw-alias-state-success-primary, #2e7d32)" } }, savedMsg) : null,
					),
				),

				// -- enforcement status --
				react.createElement("div", { style: cardStyle() },
					react.createElement("h3", { style: titleStyle() }, "强制层（L0 环境）"),
					s === null ? null : react.createElement(react.Fragment, {},
						react.createElement(Field, { label: "热切换路由" }, s.hot && s.hot.active ? `已生效 → ${s.hot.target}${s.egress ? "（出口 " + s.egress + "）" : ""}` : "未生效（直连或待开启）"),
						react.createElement(Field, { label: "NODE_OPTIONS" }, s.env.nodeOptions || "(空)"),
						react.createElement(Field, { label: "HTTP_PROXY" }, s.env.httpProxy || "(空)"),
						react.createElement(Field, { label: "HTTPS_PROXY" }, s.env.httpsProxy || "(空)"),
						react.createElement(Field, { label: "NO_PROXY" }, s.env.noProxy || "(空)"),
						react.createElement("p", { style: { fontSize: 13, color: s.envReady ? "var(--dsw-alias-state-success-primary, #2e7d32)" : "var(--dsw-alias-state-warn-primary, #b26a00)", margin: "8px 0 0" } }, s.envHint),
					),
				),

				// -- engine + traffic --
				react.createElement("div", { style: cardStyle() },
					react.createElement("h3", { style: titleStyle() }, "引擎状态"),
					s === null ? null : react.createElement(react.Fragment, {},
						react.createElement(Field, { label: "引擎进程" }, `${s.engine.running ? "运行中" : "未运行"}${s.engine.running ? ` · pid ${s.engine.pid} · ${s.engine.bind}:${s.engine.port}` : ""}`),
						s.engine.upstream ? react.createElement(Field, { label: "引擎出口" }, s.engine.upstream) : null,
						s.engine.lastExit ? react.createElement(Field, { label: "上次退出" }, `code=${s.engine.lastExit.code} signal=${s.engine.lastExit.signal} @ ${new Date(s.engine.lastExit.at).toLocaleString()}`) : null,
						s.lastError ? react.createElement(Field, { label: "错误" }, s.lastError) : null,
						react.createElement("h3", { style: titleStyle() }, "LLM 调用统计（llm/stream）"),
						react.createElement(Field, { label: "调用次数" }, String(s.stats.llmCalls)),
						providers.map(([key, v]) => react.createElement(Field, { key, label: key }, `${v.calls} 次 · 平均 ${Math.round(v.totalMs / v.calls)}ms`)),
						react.createElement("h3", { style: titleStyle() }, "引擎访问日志（最近）"),
						log.length === 0 ? react.createElement("p", { style: { fontSize: 12, color: "var(--dsw-alias-label-secondary, #5f6b7a)" } }, "暂无访问记录") : log.map((line, i) => {
							let parsed = null;
							try { parsed = JSON.parse(line); } catch {}
							return react.createElement("pre", { key: i, style: { fontSize: 11, whiteSpace: "pre-wrap", margin: 0, padding: "3px 0", borderBottom: "1px solid var(--dsw-alias-border-l1, rgba(120,120,120,0.2))" } },
								parsed ? `${parsed.ts.slice(11, 19)}  [${parsed.evt}] ${parsed.host ?? ""}${parsed.method ? " " + parsed.method : ""}${parsed.status ? " → " + parsed.status : ""}${parsed.via ? " · via " + parsed.via : ""}${parsed.bytes != null ? " · " + parsed.bytes + "B" : ""}${parsed.src ? " · " + parsed.src : ""}` : line);
						}),
					),
				),

				// -- route errors / CA --
				react.createElement("div", { style: cardStyle() },
					react.createElement("h3", { style: titleStyle() }, "代理错误 / CA 状态"),
					s === null ? null : react.createElement(react.Fragment, {},
						s.ca ? react.createElement(Field, { label: "CA 文件" },
							s.ca.loaded ? `已加载 ${s.ca.file}` : (s.ca.file ? `加载失败：${s.ca.error || '未知'}` : "(未设置，跟随系统证书链)")) : null,
						react.createElement(Field, { label: "最近路由" }, s.routeOk ? "正常" : "最近失败"),
						s.engineLoop && s.engineLoop.detected ? react.createElement(Field, { label: "引擎循环" }, `已暂停自动重启（60 秒内 ${s.engineLoop.count} 次）`) : null,
						s.lastRouteError ? react.createElement(Field, { label: "最近错误" }, `${s.lastRouteError.hint || s.lastRouteError.error}（${s.lastRouteError.code}）`) : null,
						(s.routeErrors || []).slice(-5).map((e, i) => react.createElement("pre", { key: i, style: { fontSize: 11, whiteSpace: "pre-wrap", margin: 0, padding: "3px 0", borderBottom: "1px solid var(--dsw-alias-border-l1, rgba(120,120,120,0.2))", color: "var(--dsw-alias-state-error-primary, #c62828)" } },
							`${new Date(e.ts).toLocaleTimeString()}  ${e.host || ''} → ${e.hint || e.error || e.code}`)),
					),
				),
			);
		}

		function bannerStyle(error, s) {
			const base = { padding: "8px 12px", borderRadius: 8, fontSize: 13, fontWeight: 600, background: "var(--dsw-alias-bg-layer-1, transparent)" };
			if (error) return { ...base, color: "var(--dsw-alias-state-error-primary, #c62828)", borderLeft: "3px solid var(--dsw-alias-state-error-primary, #c62828)" };
			if (!s) return { ...base, color: "var(--dsw-alias-label-secondary, #5f6b7a)" };
			if (s.source === "direct") return { ...base, color: "var(--dsw-alias-label-secondary, #5f6b7a)" };
			const trouble = !s.routeOk || (s.engineLoop && s.engineLoop.detected) || !!s.lastError || !s.egress || (s.ca && !!s.ca.error);
			if (trouble) return { ...base, color: "var(--dsw-alias-state-error-primary, #c62828)", borderLeft: "3px solid var(--dsw-alias-state-error-primary, #c62828)" };
			const tone = s.envReady ? "var(--dsw-alias-state-success-primary, #2e7d32)" : "var(--dsw-alias-state-warn-primary, #b26a00)";
			return { ...base, color: tone, borderLeft: `3px solid ${tone}` };
		}

		function cardStyle() { return { padding: "12px 14px", borderRadius: 10, background: "var(--dsw-alias-bg-layer-1, #f7f8fa)", border: "1px solid var(--dsw-alias-border-l1, rgba(120,120,120,0.25))" }; }
		function titleStyle() { return { fontSize: 13, fontWeight: 700, margin: "10px 0 6px", color: "var(--dsw-alias-label-primary, inherit)" }; }
		function selectStyle() { return { padding: "4px 8px", borderRadius: 6, border: "1px solid var(--dsw-alias-border-l2, rgba(120,120,120,0.4))", background: "var(--dsw-alias-bg-layer-2, #f0f1f3)", color: "var(--dsw-alias-label-primary, inherit)" }; }
		function btnStyle(kind) {
			const base = { padding: "6px 14px", borderRadius: 8, fontSize: 13, cursor: "pointer" };
			if (kind === "primary") return { ...base, background: "var(--dsw-alias-brand-primary, #2f6fed)", color: "#fff", border: "none" };
			return { ...base, background: "var(--dsw-alias-bg-layer-2, #f0f1f3)", border: "1px solid var(--dsw-alias-border-l2, rgba(120,120,120,0.4))", color: "var(--dsw-alias-label-primary, inherit)" };
		}

		// ---- registration --------------------------------------------------------
		const inject = [];
		function apply(ctx) {
			const slots = ctx.get("slots");
			if (slots === undefined) return;
			slots.inject("settings.section", () => slots.register(
				{ name: "settings.section", id: "netproxy", order: 50, label: "网络代理" },
				(props) => react.createElement(NetProxyPage, props),
			));
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
