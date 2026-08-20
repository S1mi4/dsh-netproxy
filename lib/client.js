/**
 * dsh-netproxy — browser client half.
 *
 * Mounts one Settings page ("网络代理") into the `settings.section` slot. The
 * page reads the host-half state from `/plugins/dsh-netproxy/state`, writes
 * configuration via `/plugins/dsh-netproxy/set`, and shows:
 *   - master enable toggle + enforcement (L0 env) readiness with guidance,
 *   - engine transport choice (built-in vs external) and listener config,
 *   - engine subprocess health, last exit, access-log tail,
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

		const YES = { true: "启用", false: "关闭" };

		function NetProxyPage() {
			const [state, setState] = react.useState(null);
			const [error, setError] = react.useState(null);
			const [draft, setDraft] = react.useState(null);
			const [saving, setSaving] = react.useState(false);
			const [savedMsg, setSavedMsg] = react.useState("");
			const [log, setLog] = react.useState([]);
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
							enabled: s.enabled,
							mode: s.mode,
							proxyUrl: s.externalProxyUrl,
							enginePort: s.config.enginePort,
							auth: "",
							logFile: "",
							noProxy: s.config.noProxy,
							caFile: s.config.caFile || "",
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
						enabled: !!draft.enabled,
						mode: draft.mode,
						proxyUrl: draft.proxyUrl,
						enginePort: Number(draft.enginePort) || 4317,
						auth: draft.auth || "",
						logFile: draft.logFile || "",
						noProxy: draft.noProxy || "",
						caFile: draft.caFile || "",
					};
					await getJson(SET_URL, payload);
					setSavedMsg("已保存" + (draft.enabled ? "；L0 环境若未就绪请重启 DSH 生效" : ""));
					setTimeout(() => setSavedMsg(""), 4000);
					setRefreshKey((k) => k + 1);
				} catch (e) {
					setError(String(e));
				} finally {
					setSaving(false);
				}
			};

			const s = state;
			const providers = s ? Object.entries(s.stats.providers) : [];

			return react.createElement("div", { style: { maxWidth: 720, display: "flex", flexDirection: "column", gap: 14 } },

				// -- status banner --
				react.createElement("div", { style: bannerStyle(error, s) }, error
					? `状态读取失败：${error}`
					: s === null ? "正在读取…"
					: (s.enabled ? `代理已启用（${s.mode === "external" ? "外置代理" : "内置引擎"}）· ${s.envReady ? "L0 环境就绪" : "L0 环境未就绪（见下方说明）"}` : "代理当前关闭")),

				(draft === null) ? null : react.createElement("div", { style: cardStyle() },

					react.createElement("h3", { style: titleStyle() }, "开关"),
					react.createElement("div", {},
						react.createElement("label", { style: { display: "inline-flex", alignItems: "center", gap: 8, fontSize: 14, cursor: "pointer" } },
							react.createElement("input", {
								type: "checkbox", checked: !!draft.enabled,
								onChange: (e) => setDraft({ ...draft, enabled: e.target.checked }),
							}),
							`启用网络代理（${YES[draft.enabled ? "true" : "false"]}）`)),

					react.createElement("h3", { style: titleStyle() }, "引擎"),
					react.createElement(Field, { label: "传输模式" },
						react.createElement("select", {
							value: draft.mode,
							onChange: (e) => setDraft({ ...draft, mode: e.target.value }),
							style: selectStyle(),
						},
							react.createElement("option", { value: "builtin" }, "内置引擎（HTTP+CONNECT）"),
							react.createElement("option", { value: "external" }, "外置代理（Clash/公司代理）")),
					),
					draft.mode === "external"
						? react.createElement(Field, { label: "外置代理 URL" }, react.createElement(Input, { draft, setDraft, field: "proxyUrl", placeholder: "http://127.0.0.1:7890" }))
						: react.createElement(react.Fragment, {},
							react.createElement(Field, { label: "监听端口" }, react.createElement(Input, { draft, setDraft, field: "enginePort", placeholder: "4317", width: 96 })),
							react.createElement(Field, { label: "基本认证(可选)" }, react.createElement(Input, { draft, setDraft, field: "auth", placeholder: "user:pass" })),
						),
					react.createElement(Field, { label: "引擎访问日志" },
						react.createElement("span", {}, s ? (s.config.logFile || "(使用默认)") : "")),
					react.createElement(Field, { label: "NO_PROXY(服务端)" }, react.createElement(Input, { draft, setDraft, field: "noProxy", placeholder: "127.0.0.1,localhost" })),
					react.createElement(Field, { label: "CA 文件(代理MITM)" }, react.createElement(Input, { draft, setDraft, field: "caFile", placeholder: "如 Burp 导出的 cacert.pem" })),

					react.createElement("div", { style: { display: "flex", alignItems: "center", gap: 12, marginTop: 8 } },
						react.createElement("button", { style: btnStyle("primary"), onClick: save, disabled: saving }, saving ? "保存中…" : "保存配置"),
						savedMsg ? react.createElement("span", { style: { fontSize: 13, color: "var(--dsw-alias-state-success-primary, #2e7d32)" } }, savedMsg) : null,
					),
				),

				// -- enforcement status --
				react.createElement("div", { style: cardStyle() },
					react.createElement("h3", { style: titleStyle() }, "强制层（L0 环境）"),
					s === null ? null : react.createElement(react.Fragment, {},
						react.createElement(Field, { label: "热切换路由" }, s.hot && s.hot.active ? `已生效 → ${s.hot.target}` : "未生效（改配置后需重启或有待开启）"),
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
								parsed ? `${parsed.ts.slice(11, 19)}  [${parsed.evt}] ${parsed.host ?? ""}${parsed.method ? " " + parsed.method : ""}${parsed.status ? " → " + parsed.status : ""}${parsed.bytes != null ? " · " + parsed.bytes + "B" : ""}${parsed.src ? " · " + parsed.src : ""}` : line);
						}),
					),
				),

				// -- route errors / CA --
				react.createElement("div", { style: cardStyle() },
					react.createElement("h3", { style: titleStyle() }, "代理错误 / CA 状态"),
					s === null ? null : react.createElement(react.Fragment, {},
						s.ca ? react.createElement(Field, { label: "CA 文件" },
							s.ca.loaded ? `已加载 ${s.ca.file}` : (s.ca.file ? `加载失败：${s.ca.error || '未知'}` : "(未设置)")) : null,
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
			if (!s.enabled) return { ...base, color: "var(--dsw-alias-label-secondary, #5f6b7a)" };
			const trouble = !s.routeOk || (s.engineLoop && s.engineLoop.detected) || !!s.lastError || (s.ca && !!s.ca.error);
			if (trouble) return { ...base, color: "var(--dsw-alias-state-error-primary, #c62828)", borderLeft: "3px solid var(--dsw-alias-state-error-primary, #c62828)" };
			const tone = s.envReady ? "var(--dsw-alias-state-success-primary, #2e7d32)" : "var(--dsw-alias-state-warn-primary, #b26a00)";
			return { ...base, color: tone, borderLeft: `3px solid ${tone}` };
		}

		function cardStyle() { return { padding: "12px 14px", borderRadius: 10, background: "var(--dsw-alias-bg-layer-1, #f7f8fa)", border: "1px solid var(--dsw-alias-border-l1, rgba(120,120,120,0.25))" }; }
		function titleStyle() { return { fontSize: 13, fontWeight: 700, margin: "10px 0 6px", color: "var(--dsw-alias-label-primary, inherit)" }; }
		function selectStyle() { return { padding: "4px 8px", borderRadius: 6, border: "1px solid var(--dsw-alias-border-l2, rgba(120,120,120,0.4))", background: "var(--dsw-alias-bg-layer-2, #f0f1f3)", color: "var(--dsw-alias-label-primary, inherit)" }; }
		function btnStyle(kind) {
			const primary = { background: "var(--dsw-alias-brand-primary, #2f6fed)", color: "#fff", border: "none" };
			return { ...primary, padding: "6px 14px", borderRadius: 8, fontSize: 13, cursor: "pointer", opacity: 1 };
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
