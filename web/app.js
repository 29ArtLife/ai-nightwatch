/* AI 守夜人监控台：原生 JS，无构建、无 CDN */
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "");
let TOKEN = localStorage.getItem("nw_token") || "";
let lastId = 0;
let USE_SSE = true;
let errors = 0;
let es = null;
let pollTimer = null;

const params = new URLSearchParams(location.search);
if (params.get("token")) {
  TOKEN = params.get("token");
  localStorage.setItem("nw_token", TOKEN);
  history.replaceState(null, "", location.pathname);
}

async function api(path, opts = {}) {
  const sep = path.includes("?") ? "&" : "?";
  const url = path + (TOKEN ? sep + "token=" + encodeURIComponent(TOKEN) : "");
  const r = await fetch(url, { ...opts, headers: { "Content-Type": "application/json", ...(opts.headers || {}) } });
  if (r.status === 401) {
    const t = prompt("请输入监控台 token（服务器 data/token.txt）");
    if (t) { TOKEN = t.trim(); localStorage.setItem("nw_token", TOKEN); location.reload(); }
    throw new Error("unauthorized");
  }
  return r;
}

/* ---------- 状态条 ---------- */
async function refreshStatus() {
  try {
    const r = await api("/api/status");
    if (!r.ok) return;
    const s = await r.json();
    $("#c-status").textContent = s.guarding ? "守护中" : "已停止";
    $("#c-status").className = "chip " + (s.guarding ? "ok" : "bad");
    $("#c-events").textContent = "事件 " + s.events;
    $("#c-bans").textContent = "封禁 " + s.bans;
    $("#c-osv").textContent = "OSV " + (s.osv_mode === "offline" ? "离线快照" : "在线");
    $("#c-chain").textContent = "链 " + (s.chain_ok ? "完整" : "异常");
    $("#c-chain").className = "chip " + (s.chain_ok ? "ok" : "bad");
    const off = s.sources.filter((x) => !x.online).map((x) => x.name);
    if (off.length) $("#c-status").textContent += " · 源离线:" + off.join(",");
    $("#auto").checked = s.auto_response;
  } catch (e) { /* 401 已处理 */ }
}

/* ---------- 事件 ---------- */
const KIND_LABEL = {
  login_fail: "登录失败", login_success: "登录成功",
  http_404: "404 探测", http_request: "HTTP 请求",
  decision: "裁决", rollback: "人工回滚", parse_error: "解析错误",
};

function ruleShort(r) {
  return (r || "").replace(".v1", "");
}

function renderEvent(row, prepend = false) {
  const ev = row.evidence || {};
  const action = ev.action || "";
  const cls = action === "ban" ? "ban" : action === "observe" || action === "no_action" ? "observe"
    : action === "alert" ? "alert" : row.kind === "rollback" ? "rollback" : "";
  const el = document.createElement("div");
  el.className = "ev " + cls + " fade-in";
  el.dataset.id = row.id;

  const row1 = document.createElement("div");
  row1.className = "row1";
  const mk = (tag, cls2, text) => {
    const n = document.createElement(tag);
    if (cls2) n.className = cls2;
    n.textContent = text;
    return n;
  };
  row1.append(mk("span", "id", "#" + row.id));
  row1.append(mk("span", "ip", row.ip));
  row1.append(mk("span", "kind", KIND_LABEL[row.kind] || row.kind));
  if (row.rule_id) row1.append(mk("span", "badge", ruleShort(row.rule_id)));
  if (action) row1.append(mk("span", "badge " + cls, action.toUpperCase() +
    (ev.reason_code ? " · " + ev.reason_code : "")));
  if (ev.counts) {
    const c = ev.counts;
    let t = "";
    if (c.fail !== undefined) t += `失败 ${c.fail}`;
    if (c.success) t += ` · 成功 ${c.success}`;
    if (c.s404 !== undefined) t += ` · 404 ${c.s404} · 敏感路径 ${(c.sensitive_paths || []).length}`;
    if (t) row1.append(mk("span", "kind", t));
  }
  row1.append(mk("span", "id", new Date(row.ts).toLocaleTimeString()));
  el.append(row1);

  const detail = document.createElement("div");
  detail.className = "detail";
  const pre = document.createElement("pre");
  pre.textContent = JSON.stringify({ evidence: ev, raw_line: row.raw_line,
    source: `${row.source_file || ""}:${row.source_offset || 0}`,
    prev_hash: (row.prev_hash || "").slice(0, 24) + "…",
    hash: (row.hash || "").slice(0, 24) + "…" }, null, 2);
  detail.append(pre);
  el.append(detail);
  el.addEventListener("click", () => el.classList.toggle("open"));

  const stream = $("#stream");
  if (!stream) return;
  if (prepend) stream.prepend(el); else stream.append(el);
  while (stream.children.length > 300) stream.lastChild.remove();
  stream.scrollTop = stream.scrollHeight;
}

function isObserve(row) {
  return row.kind === "decision" && ["observe", "no_action", "alert"].includes(row.evidence?.action);
}

function renderObserve(row) {
  const box = $("#observes");
  if (!box) return;
  const ev = row.evidence || {};
  const item = document.createElement("div");
  item.className = "obs-item fade-in";
  const g = document.createElement("div");
  g.className = "grow";
  const a = document.createElement("div");
  a.className = "mono";
  a.textContent = `${row.ip} · ${ev.reason_code || ""}`;
  const b = document.createElement("div");
  b.className = "hint";
  b.textContent = (ev.negatives && ev.negatives[0]) || ev.observation || "";
  g.append(a, b);
  item.append(g);
  box.prepend(item);
  while (box.children.length > 12) box.lastChild.remove();
}

/* ---------- 封禁名单 ---------- */
async function refreshBans() {
  try {
    const r = await api("/api/bans");
    if (!r.ok) return;
    const bans = await r.json();
    const box = $("#bans");
    box.innerHTML = "";
    if (!bans.length) {
      const e = document.createElement("div");
      e.className = "empty";
      e.textContent = "当前无封禁";
      box.append(e);
      return;
    }
    for (const b of bans) {
      const item = document.createElement("div");
      item.className = "ban-item";
      const g = document.createElement("div");
      g.className = "grow";
      const ip = document.createElement("div");
      ip.className = "mono";
      ip.textContent = b.ip;
      const meta = document.createElement("div");
      meta.className = "hint";
      meta.textContent = `${b.reason} · 解封于 ${new Date(b.until_ts).toLocaleTimeString()}`;
      g.append(ip, meta);
      const cd = document.createElement("span");
      cd.className = "count";
      cd.dataset.until = b.until_ts;
      const btn = document.createElement("button");
      btn.className = "danger";
      btn.textContent = "解封";
      btn.addEventListener("click", async () => {
        const operator = prompt("操作人", "demo") || "demo";
        await api(`/api/bans/${encodeURIComponent(b.ip)}/rollback`, {
          method: "POST", body: JSON.stringify({ operator, reason: "手动解封" }),
        });
        refreshBans(); refreshStatus();
      });
      item.append(g, cd, btn);
      box.append(item);
    }
  } catch (e) { /* ignore */ }
}

function tickCountdowns() {
  document.querySelectorAll(".count[data-until]").forEach((el) => {
    const left = Math.max(0, Math.floor((new Date(el.dataset.until) - Date.now()) / 1000));
    el.textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
    if (left === 0) el.textContent = "已到期";
  });
}

/* ---------- SSE / 轮询 ---------- */
function startStream() {
  if (!USE_SSE) return startPolling();
  const q = `since=${lastId}` + (TOKEN ? `&token=${encodeURIComponent(TOKEN)}` : "");
  es = new EventSource(`/api/stream?${q}`);
  es.onopen = () => { errors = 0; };
  es.onmessage = (e) => {
    try {
      const row = JSON.parse(e.data);
      if (row.id <= lastId) return;
      lastId = row.id;
      renderEvent(row);
      if (isObserve(row)) renderObserve(row);
      if (row.kind === "decision" && row.evidence?.action === "ban") refreshBans();
      if (row.kind === "rollback") refreshBans();
      refreshStatus();
    } catch (_) { /* ignore */ }
  };
  es.onerror = () => {
    errors += 1;
    if (errors >= 3) {
      USE_SSE = false;
      try { es.close(); } catch (_) {}
      startPolling();
    }
  };
}

function startPolling() {
  const tick = async () => {
    try {
      const r = await api(`/api/events?since=${lastId}&limit=200`);
      if (!r.ok) return;
      const rows = await r.json();
      for (const row of rows) {
        if (row.id <= lastId) continue;
        lastId = row.id;
        renderEvent(row);
        if (isObserve(row)) renderObserve(row);
      }
      if (rows.length) { refreshStatus(); refreshBans(); }
    } catch (_) {}
  };
  tick();
  pollTimer = setInterval(tick, 2000);
}

async function bootstrap() {
  await refreshStatus();
  try {
    const r = await api("/api/events?since=0&limit=200");
    if (r.ok) {
      (await r.json()).forEach((row) => { renderEvent(row); lastId = Math.max(lastId, row.id); });
    }
  } catch (_) { return; }
  refreshBans();
  startStream();
  setInterval(() => { refreshStatus(); tickCountdowns(); }, 3000);
  setInterval(refreshBans, 5000);
}

/* ---------- 体检 ---------- */
const VERDICT = {
  CONFIRMED: ["确认", "bad"], VERSION_MISMATCH: ["版本不符", "warn"],
  UNREACHABLE: ["未引用", "warn"], DEV_ONLY: ["仅开发", "warn"], UNDETERMINED: ["待定", "warn"],
};

async function runAudit() {
  const btn = $("#run-audit");
  btn.disabled = true; btn.textContent = "核验中…";
  try {
    const r = await api("/api/audit/run", { method: "POST", body: "{}" });
    renderAudit(await r.json());
  } finally { btn.disabled = false; btn.textContent = "运行漏洞验真"; }
}

function renderAudit(run) {
  const box = $("#audit-summary");
  const list = $("#findings");
  if (!run || !run.summary) { box.innerHTML = '<div class="empty">尚未运行体检</div>'; return; }
  const s = run.summary;
  box.innerHTML = "";
  const stats = [
    ["依赖", s.deps, ""], ["清单", s.total, ""],
    ["确认", s.confirmed, "bad"], ["版本不符", s.version_mismatch, "warn"],
    ["未引用", s.unreachable, "warn"], ["仅开发", s.dev_only, "warn"],
  ];
  for (const [label, value, cls] of stats) {
    const d = document.createElement("div");
    d.className = "stat " + (cls || "");
    const b = document.createElement("b"); b.textContent = value ?? 0;
    const sp = document.createElement("span"); sp.textContent = label;
    d.append(b, sp); box.append(d);
  }
  list.innerHTML = "";
  for (const f of run.findings) {
    const [label, cls] = VERDICT[f.verdict] || [f.verdict, ""];
    const card = document.createElement("div");
    card.className = "finding";
    const h = document.createElement("h3");
    h.append(document.createTextNode(`${f.pkg} ${f.version || ""}`));
    const badge = document.createElement("span"); badge.className = "badge " + (f.verdict === "CONFIRMED" ? "ban" : "alert");
    badge.textContent = label; h.append(badge);
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = `${f.cve} · ${f.scope} · ${f.reason_code}`;
    const ev2 = document.createElement("div");
    ev2.className = "ev2";
    const e = f.evidence || {};
    const sites = (e.import_site || []).slice(0, 3).map((x) => `${x.file}:${x.line}`).join(", ");
    ev2.textContent = `范围 ${(e.affected_range || []).join(" / ") || "无可比对范围"}` +
      (sites ? ` · import ${sites}` : (e.import_site ? " · 未 import" : " · 无模块映射"));
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify({ aliases: e.aliases, matched_records: e.matched_records,
      dynamic_imports_uncovered: e.dynamic_imports_uncovered }, null, 1);
    card.append(h, meta, ev2, pre);
    list.append(card);
  }
}

async function loadAudit() {
  try {
    const r = await api("/api/audit/latest");
    if (r.ok) renderAudit(await r.json());
  } catch (_) {}
}

/* ---------- 资产 ---------- */
async function runAssets() {
  const btn = $("#run-assets");
  btn.disabled = true; btn.textContent = "探测中…";
  try {
    const r = await api("/api/assets");
    renderAssets(await r.json());
  } finally { btn.disabled = false; btn.textContent = "探测授权资产"; }
}

function renderAssets(list) {
  const box = $("#assets");
  box.innerHTML = "";
  if (!Array.isArray(list) || !list.length) {
    box.innerHTML = '<div class="empty">无探测结果</div>';
    return;
  }
  for (const a of list) {
    const card = document.createElement("div");
    card.className = "asset";
    const h = document.createElement("h3");
    h.textContent = `${a.label || a.id} · ${a.target}:${a.port}`;
    const badge = document.createElement("span");
    badge.className = "badge " + (a.state === "SUSPECTED" ? "alert" : a.state === "UNREACHABLE" ? "ban" : "observe");
    badge.textContent = a.state;
    h.append(" ", badge);
    const kv = document.createElement("div");
    kv.className = "kv";
    const rows = [
      ["banner", a.banner || "（无）"], ["产品/版本", `${a.product || "?"} ${a.version || ""}`],
      ["协议握手", a.handshake], ["引擎", a.engine],
      ["关联 CVE", String(a.cve_linked)], ["结论", a.note],
    ];
    for (const [k, v] of rows) {
      const kk = document.createElement("span"); kk.textContent = k;
      const vv = document.createElement("span"); vv.className = "mono"; vv.textContent = v;
      kv.append(kk, vv);
    }
    card.append(h, kv); box.append(card);
  }
}

/* ---------- 日报 / 留痕 ---------- */
async function runReport() {
  const r = await api("/api/report");
  $("#report").textContent = await r.text();
}

async function verifyChain() {
  const r = await api("/api/chain/verify");
  const v = await r.json();
  $("#chain-result").textContent = v.ok
    ? `链上 ${v.count} 条，校验通过`
    : `校验失败：${v.reason || ""}（id=${v.broken_at ?? "?"}）`;
  $("#chain-result").style.color = v.ok ? "var(--green)" : "var(--red)";
}

/* ---------- AI 调查员 ---------- */
let AGENT_INFO = null;
let AGENT_HISTORY = [];

function agentBubble(role, text) {
  const box = $("#agent-log");
  if (box.querySelector(".empty")) box.innerHTML = "";
  const el = document.createElement("div");
  el.className = "msg " + (role === "user" ? "user" : "ai");
  const who = document.createElement("div");
  who.className = "who";
  who.textContent = role === "user" ? "你" : "AI 调查员";
  const body = document.createElement("div");
  body.className = "body";
  body.textContent = text;
  el.append(who, body);
  box.append(el);
  box.scrollTop = box.scrollHeight;
  return el;
}

function renderTrace(el, trace) {
  if (!trace || !trace.length) return;
  const det = document.createElement("details");
  const sum = document.createElement("summary");
  sum.textContent = `工具调用 ${trace.length} 次（点击查看）`;
  const box = document.createElement("div");
  box.className = "trace";
  for (const t of trace) {
    const row = document.createElement("div");
    row.className = "t";
    const n = document.createElement("span"); n.className = "n"; n.textContent = `#${t.step} ${t.tool}`;
    const ok = document.createElement("span"); ok.className = t.ok ? "ok" : "bad";
    ok.textContent = t.ok ? "OK" : "ERROR";
    const ms = document.createElement("span"); ms.textContent = `${t.duration_ms}ms`;
    row.append(n, ok, ms);
    box.append(row);
    const pre = document.createElement("pre");
    pre.style.margin = "2px 0 6px 14px";
    pre.textContent = JSON.stringify(t.args) + "\n" + (t.result_preview || "");
    box.append(pre);
  }
  det.append(sum, box);
  el.append(det);
}

async function loadAgentInfo() {
  try {
    const r = await api("/api/agent/info");
    AGENT_INFO = await r.json();
    $("#agent-model").textContent = `${AGENT_INFO.model} · ${AGENT_INFO.tools.length} 个工具`;
    if (!AGENT_INFO.enabled) $("#agent-status").textContent = "AI 调查已在配置中关闭；确定性守卫仍在运行。";
    else if (!AGENT_INFO.key_present) $("#agent-status").textContent = "未配置 DEEPSEEK_API_KEY，AI 调查不可用；确定性守卫仍在运行。";
    else $("#agent-status").textContent = "";
  } catch (_) {}
}

async function sendAgent(text) {
  text = (text || "").trim();
  if (!text) return;
  if (AGENT_INFO && (!AGENT_INFO.enabled || !AGENT_INFO.key_present)) {
    $("#agent-status").textContent = AGENT_INFO.enabled ? "模型密钥未配置" : "AI 调查已关闭";
    return;
  }
  agentBubble("user", text);
  $("#agent-msg").value = "";
  const btn = $("#agent-send");
  btn.disabled = true;
  $("#agent-status").innerHTML = '<span class="spin"></span> 调查中，可能需要几十秒…';
  try {
    const r = await api("/api/agent/chat", {
      method: "POST",
      body: JSON.stringify({ message: text, history: AGENT_HISTORY.slice(-6) }),
    });
    const d = await r.json();
    if (d.ok) {
      const el = agentBubble("ai", d.answer);
      renderTrace(el, d.trace);
      AGENT_HISTORY.push({ role: "user", content: text },
                         { role: "assistant", content: d.answer });
      if (AGENT_HISTORY.length > 12) AGENT_HISTORY = AGENT_HISTORY.slice(-12);
      $("#agent-status").textContent = `完成：${d.steps} 步 · ${d.trace.length} 次工具调用`;
      refreshStatus();
      loadAgentActions();
    } else {
      agentBubble("ai", "调查失败：" + (d.error || "未知错误"));
      $("#agent-status").textContent = "调用失败";
    }
  } catch (e) {
    agentBubble("ai", "请求失败：" + e.message);
  } finally {
    btn.disabled = false;
  }
}

async function loadAgentActions() {
  try {
    const r = await api("/api/agent/actions");
    if (!r.ok) return;
    const list = await r.json();
    const box = $("#agent-actions");
    box.innerHTML = "";
    if (!list.length) {
      const e = document.createElement("div"); e.className = "empty";
      e.textContent = "暂无"; box.append(e); return;
    }
    for (const a of list) {
      const item = document.createElement("div");
      item.className = "ban-item";
      const g = document.createElement("div"); g.className = "grow";
      const ip = document.createElement("div"); ip.className = "mono"; ip.textContent = a.ip;
      const meta = document.createElement("div"); meta.className = "hint";
      meta.textContent = `${a.reason} · 证据 ${a.evidence_event_ids.map((x) => "#" + x).join(",")}`;
      g.append(ip, meta);
      const ok = document.createElement("button"); ok.className = "danger"; ok.textContent = "批准封禁";
      ok.addEventListener("click", async () => {
        const operator = prompt("批准人", "demo") || "demo";
        await api(`/api/agent/actions/${a.id}/approve`, {
          method: "POST", body: JSON.stringify({ operator }),
        });
        loadAgentActions(); refreshBans(); refreshStatus();
      });
      const no = document.createElement("button"); no.textContent = "拒绝";
      no.addEventListener("click", async () => {
        await api(`/api/agent/actions/${a.id}/reject`, {
          method: "POST", body: JSON.stringify({ operator: "demo" }),
        });
        loadAgentActions();
      });
      item.append(g, ok, no);
      box.append(item);
    }
  } catch (_) {}
}

/* ---------- 交互 ---------- */
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
  document.querySelectorAll(".tabpane").forEach((x) => x.classList.remove("active"));
  t.classList.add("active");
  $("#tab-" + t.dataset.tab).classList.add("active");
  if (t.dataset.tab === "audit") loadAudit();
  if (t.dataset.tab === "report") runReport();
  if (t.dataset.tab === "agent") { loadAgentInfo(); loadAgentActions(); }
}));

$("#run-audit").addEventListener("click", runAudit);
$("#run-assets").addEventListener("click", runAssets);
$("#run-report").addEventListener("click", runReport);
$("#verify-chain").addEventListener("click", verifyChain);
$("#auto").addEventListener("change", async (e) => {
  await api("/api/control", { method: "POST", body: JSON.stringify({ auto_response: e.target.checked }) });
  refreshStatus();
});
$("#agent-send").addEventListener("click", () => sendAgent($("#agent-msg").value));
$("#agent-msg").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) sendAgent($("#agent-msg").value);
});
document.querySelectorAll(".quick button").forEach((b) => b.addEventListener("click", () => {
  const q = b.dataset.q;
  $("#agent-msg").value = q;
  sendAgent(q);
}));
loadAgentInfo();
setInterval(loadAgentActions, 10000);

bootstrap();
