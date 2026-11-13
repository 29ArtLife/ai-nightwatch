"""Agent 工具层：唯一发包/执行入口，目标一律从配置的 asset_id 解析。

模型拿不到 host/port/命令，只能选工具与参数；白名单在这里硬校验。
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass, field

from verify.assets import probe_http, probe_ssh, verdict

ANSI = re.compile(r"\x1b\[[0-9;]*m")


class ToolError(RuntimeError):
    pass


@dataclass
class Ctx:
    cfg: dict
    store: object
    worker: object
    service: object
    pending: dict = field(default_factory=dict)
    last_scan: dict = field(default_factory=dict)


def _assets(cfg: dict) -> dict:
    return {a["id"]: a for a in cfg["asset"]["assets"]}


def _allowed(cfg: dict) -> set[str]:
    return {str(ipaddress.ip_address(x)) for x in cfg["asset"]["allowed_targets"]}


def resolve_asset(cfg: dict, asset_id: str) -> dict:
    a = _assets(cfg).get(asset_id)
    if not a:
        raise ToolError(f"未知资产 id：{asset_id}（可用：{', '.join(_assets(cfg))}）")
    try:
        ip = str(ipaddress.ip_address(str(a["target"])))
    except ValueError as e:
        raise ToolError("配置中的资产地址不是合法 IP") from e
    if ip not in _allowed(cfg):
        raise ToolError(f"拒绝：{ip} 不在授权资产白名单")
    return {**a, "ip": ip}


def _rate(ctx: Ctx, key: str):
    gap = int(ctx.cfg["agent"].get("scan_cooldown_sec", 60))
    last = ctx.last_scan.get(key, 0)
    if time.time() - last < gap:
        raise ToolError(f"扫描过于频繁，请 {gap - int(time.time() - last)} 秒后再试")
    ctx.last_scan[key] = time.time()


def _run(ctx: Ctx, cmd: list[str], timeout: int | None = None) -> dict:
    if not shutil.which(cmd[0]):
        return {"ok": False, "error": f"工具未安装：{cmd[0]}"}
    t = timeout or int(ctx.cfg["agent"].get("tool_timeout_sec", 45))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=t,
                           errors="replace")
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"命令超时（{t}s）", "cmd": cmd}
    except OSError as e:
        return {"ok": False, "error": str(e), "cmd": cmd}
    out = ANSI.sub("", (p.stdout or "") + (p.stderr or "")).strip()
    cap = int(ctx.cfg["agent"].get("max_output_bytes", 12000))
    truncated = len(out.encode("utf-8")) > cap
    if truncated:
        out = out.encode("utf-8")[:cap].decode("utf-8", "ignore")
    return {"ok": p.returncode == 0, "rc": p.returncode, "cmd": cmd,
            "output": out, "truncated": truncated}


# ---------------- 工具实现 ----------------

def guard_status(ctx: Ctx, **_) -> dict:
    v = ctx.store.verify_chain()
    bans = ctx.store.active_bans()
    sources = [{"name": s.source_name, "online": s.online} for s in ctx.worker.sources]
    if not sources:  # CLI 一次性进程没有启动 tailer，用文件存在性代替
        sources = [{"name": s["name"], "online": os.path.exists(s["path"])}
                   for s in ctx.cfg.get("ingest", {}).get("sources", [])]
    return {
        "events": v.get("count", 0),
        "chain_ok": v.get("ok", False),
        "auto_response": ctx.worker.auto_enabled,
        "active_bans": [{"ip": b["ip"], "reason": b["reason"], "until": b["until_ts"]}
                        for b in bans],
        "sources": sources,
        "assets": [{"id": a["id"], "kind": a.get("kind", "ssh"), "port": a["port"],
                    "label": a.get("label", a["id"])} for a in ctx.cfg["asset"]["assets"]],
    }


def query_events(ctx: Ctx, ip: str = "", kind: str = "", rule_prefix: str = "",
                 limit: int = 20, **_) -> dict:
    limit = max(1, min(int(limit), 50))
    rows = ctx.store.query_events(ip=ip, kind=kind, rule_prefix=rule_prefix, limit=limit)
    return {"count": len(rows), "events": [{
        "id": r["id"], "ts": r["ts"], "ip": r["ip"], "kind": r["kind"],
        "rule_id": r["rule_id"],
        "action": r["evidence"].get("action"),
        "reason_code": r["evidence"].get("reason_code"),
        "counts": r["evidence"].get("counts"),
        "path": r["evidence"].get("path"),
    } for r in rows]}


def get_event(ctx: Ctx, event_id: int, **_) -> dict:
    r = ctx.store.event(int(event_id))
    if not r:
        raise ToolError(f"事件 #{event_id} 不存在")
    return {k: r[k] for k in ("id", "ts", "ip", "kind", "rule_id", "evidence",
                              "raw_line", "source_file", "source_offset",
                              "prev_hash", "hash")}


def verify_chain(ctx: Ctx, **_) -> dict:
    return ctx.store.verify_chain()


def audit_dependencies(ctx: Ctx, **_) -> dict:
    run = ctx.service.audit()
    return {"run_id": run["run_id"], "summary": run["summary"],
            "findings": [{"pkg": f["pkg"], "version": f["version"], "cve": f["cve"],
                          "verdict": f["verdict"], "reason": f["reason_code"],
                          "import_site": f["evidence"].get("import_site")}
                         for f in run["findings"]]}


def probe_asset(ctx: Ctx, asset_id: str, **_) -> dict:
    a = resolve_asset(ctx.cfg, asset_id)
    fn = probe_http if a.get("kind") == "http" else probe_ssh
    obs = fn(a["ip"], int(a["port"]), _allowed(ctx.cfg),
             float(ctx.cfg["asset"].get("timeout_sec", 2.0)))
    obs.update(verdict(obs))
    obs["asset_id"] = asset_id
    obs["label"] = a.get("label", asset_id)
    return obs


def nmap_scan(ctx: Ctx, asset_id: str, **_) -> dict:
    if not ctx.cfg["agent"].get("allow_active_scans", True):
        raise ToolError("主动扫描已在配置中关闭")
    a = resolve_asset(ctx.cfg, asset_id)
    _rate(ctx, f"nmap:{asset_id}")
    t = int(ctx.cfg["agent"].get("tool_timeout_sec", 45)) - 5
    return _run(ctx, ["nmap", "-sT", "-sV", "-Pn", "-T4", "-p", str(a["port"]),
                      "--host-timeout", f"{max(10, t)}s", a["ip"]])


def nikto_scan(ctx: Ctx, asset_id: str, **_) -> dict:
    if not ctx.cfg["agent"].get("allow_active_scans", True):
        raise ToolError("主动扫描已在配置中关闭")
    a = resolve_asset(ctx.cfg, asset_id)
    if a.get("kind") != "http":
        raise ToolError("nikto 只能用于 kind=http 的资产")
    _rate(ctx, f"nikto:{asset_id}")
    return _run(ctx, ["nikto", "-h", f"http://{a['ip']}:{a['port']}/",
                      "-Tuning", "123b", "-maxtime", "12s", "-nointeractive"],
                timeout=25)


def whatweb_scan(ctx: Ctx, asset_id: str, **_) -> dict:
    if not ctx.cfg["agent"].get("allow_active_scans", True):
        raise ToolError("主动扫描已在配置中关闭")
    a = resolve_asset(ctx.cfg, asset_id)
    if a.get("kind") != "http":
        raise ToolError("whatweb 只能用于 kind=http 的资产")
    _rate(ctx, f"whatweb:{asset_id}")
    return _run(ctx, ["whatweb", f"http://{a['ip']}:{a['port']}/"], timeout=30)


def host_audit(ctx: Ctx, **_) -> dict:
    cmds = {"listening": ["ss", "-lntp"], "uptime": ["uptime"],
            "memory": ["free", "-h"], "disk": ["df", "-h", "/"]}
    return {k: _run(ctx, v, timeout=10) for k, v in cmds.items()}


def propose_ban(ctx: Ctx, ip: str, reason: str, evidence_event_ids: list[int], **_) -> dict:
    try:
        ip_n = str(ipaddress.ip_address(ip))
    except ValueError as e:
        raise ToolError("ip 不是合法地址") from e
    from app.config import ip_allowed, whitelist_nets
    nets, _ = whitelist_nets(ctx.cfg)
    if ip_allowed(ip_n, nets):
        raise ToolError("该 IP 在白名单中，不能建议封禁")
    for eid in evidence_event_ids or []:
        if not ctx.store.event(int(eid)):
            raise ToolError(f"证据事件 #{eid} 不存在")
    rid = secrets.token_hex(4)
    ctx.service.pending[rid] = {
        "id": rid, "ip": ip_n, "reason": str(reason)[:300],
        "evidence_event_ids": [int(x) for x in (evidence_event_ids or [])],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "pending",
    }
    if hasattr(ctx.service, "save_pending"):
        ctx.service.save_pending()
    return {"recommendation_id": rid,
            "note": "仅为建议，必须在监控台由人工点击确认后才会执行封禁"}


def list_pending(ctx: Ctx, **_) -> dict:
    return {"actions": list(ctx.service.pending.values())}


STRONG_EVIDENCE = {"net_alert", "waf_alert", "decision"}


def execute_ban(ctx: Ctx, ip: str, reason: str, ttl: int = 600,
                evidence_event_ids: list[int] | None = None, **_) -> dict:
    """AI 自主封禁：仅在 autonomy=auto 时可用，护栏全部在此强制。"""
    if getattr(ctx.service, "agent_autonomy", "approve") != "auto":
        raise ToolError("AI 自主处置未开启（监控台 AI 页签可切换）")
    if not getattr(ctx.worker, "auto_enabled", True):
        raise ToolError("全局自动处置已暂停，AI 不得封禁")

    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError as e:
        raise ToolError("ip 不是合法地址") from e
    if a.version != 4 or a.is_unspecified or a.is_multicast or a.is_link_local or a.is_reserved:
        raise ToolError("拒绝封禁保留/组播/链路本地地址")
    ip_n = str(a)

    from app.config import ip_allowed, whitelist_nets
    nets, _ = whitelist_nets(ctx.cfg)
    if ip_allowed(ip_n, nets):
        raise ToolError("目标在白名单/管理网段，AI 不得封禁")

    ids = [int(x) for x in (evidence_event_ids or [])]
    if not ids:
        raise ToolError("必须提供至少一个证据事件号")
    strong = False
    for eid in ids:
        ev = ctx.store.event(eid)
        if not ev:
            raise ToolError(f"证据事件 #{eid} 不存在")
        if ev["ip"] != ip_n:
            raise ToolError(f"证据事件 #{eid} 的 IP 与目标不一致")
        if ev["kind"] in STRONG_EVIDENCE:
            strong = True
    if not strong:
        raise ToolError("证据不足：需要 net_alert / waf_alert / decision 事件")

    ttl = max(60, min(3600, int(ttl or ctx.cfg["agent"].get("auto_ban_ttl", 600))))
    now = time.time()
    times = [t for t in getattr(ctx.service, "_auto_ban_times", []) if now - t < 60]
    limit = int(ctx.cfg["agent"].get("max_auto_bans_per_min", 3))
    if len(times) >= limit:
        raise ToolError(f"AI 自动封禁频率超限（{limit}/分钟）")
    if ctx.store.is_banned(ip_n):
        return {"ok": True, "already_banned": True, "ip": ip_n}

    from app.store import now_iso
    ts = now_iso()
    sig = {"ip": ip_n, "rule_id": "AI_AUTO_BAN.v1",
           "window": {"start": ts, "end": ts, "sec": 0},
           "counts": {}, "thresholds": {},
           "sample_raw": [str(reason)[:300]], "ua": "ai-agent"}
    verdict = {"action": "ban", "reason_code": "AI_AUTO_BAN", "ttl_sec": ttl,
               "evidence": {"rule_id": "AI_AUTO_BAN.v1", "actor": "ai-agent",
                            "autonomy": "auto", "reason": str(reason)[:300],
                            "evidence_event_ids": ids, "counts": {},
                            "negatives": []}}
    row = ctx.worker.enforcer.handle(sig, verdict, ts)
    times.append(now)
    ctx.service._auto_ban_times = times
    return {"ok": True, "event_id": row["id"], "ip": ip_n, "ttl": ttl,
            "until": row.get("until_ts"),
            "note": "已由 AI 直接执行封禁；人工可在监控台回滚"}


def firewall_status(ctx: Ctx, **_) -> dict:
    st = ctx.service.fw_status()
    bans = ctx.store.active_bans()
    return {"backend": "nftables", "status": st,
            "ledger_bans": [{"ip": b["ip"], "reason": b["reason"],
                             "until": b["until_ts"]} for b in bans]}


def profile_attacker(ctx: Ctx, ip: str, limit: int = 200, **_) -> dict:
    from app.profile import identify
    rows = ctx.store.query_events(ip=ip, limit=min(int(limit), 200))
    return identify(ip, rows)


def escalate_ban(ctx: Ctx, ip: str, reason: str, ttl: int = 3600,
                 evidence_event_ids: list[int] | None = None, **_) -> dict:
    """对重复攻击者延长封禁；必须已有生效封禁且引用同 IP 强证据。"""
    if getattr(ctx.service, "agent_autonomy", "approve") != "auto":
        raise ToolError("AI 自主处置未开启")
    if not getattr(ctx.worker, "auto_enabled", True):
        raise ToolError("全局自动处置已暂停")
    try:
        ip_n = str(ipaddress.ip_address(ip))
    except ValueError as e:
        raise ToolError("ip 不是合法地址") from e
    from app.config import ip_allowed, whitelist_nets
    nets, _ = whitelist_nets(ctx.cfg)
    if ip_allowed(ip_n, nets):
        raise ToolError("目标在白名单/管理网段")
    ids = [int(x) for x in (evidence_event_ids or [])]
    if not ids:
        raise ToolError("必须提供证据事件号")
    strong = False
    for eid in ids:
        ev = ctx.store.event(eid)
        if not ev or ev["ip"] != ip_n:
            raise ToolError(f"证据 #{eid} 不存在或 IP 不一致")
        if ev["kind"] in STRONG_EVIDENCE:
            strong = True
    if not strong:
        raise ToolError("需要 net_alert / waf_alert / decision 证据")
    cur = next((b for b in ctx.store.active_bans() if b["ip"] == ip_n), None)
    if not cur:
        raise ToolError("当前没有生效封禁；请用 execute_ban")
    from app.store import now_iso
    from datetime import datetime, timezone
    until = datetime.fromisoformat(cur["until_ts"].replace("Z", "+00:00"))
    remaining = max(0, int((until - datetime.now(timezone.utc)).total_seconds()))
    ttl = max(int(ttl), remaining + 600)
    ttl = max(3600, min(86400, ttl))
    ts = now_iso()
    sig = {"ip": ip_n, "rule_id": "AI_ESCALATE.v1",
           "window": {"start": ts, "end": ts, "sec": 0},
           "counts": {}, "thresholds": {}, "sample_raw": [str(reason)[:300]],
           "ua": "ai-agent"}
    verdict = {"action": "ban", "reason_code": "AI_ESCALATE", "ttl_sec": ttl,
               "evidence": {"rule_id": "AI_ESCALATE.v1", "actor": "ai-agent",
                            "reason": str(reason)[:300],
                            "evidence_event_ids": ids, "counts": {},
                            "negatives": []}}
    row = ctx.worker.enforcer.handle(sig, verdict, ts)
    return {"ok": True, "event_id": row["id"], "ip": ip_n, "ttl": ttl,
            "until": row.get("until_ts"), "note": "已延长封禁"}


def deploy_waf_rule(ctx: Ctx, match: str, value: str, note: str = "", **_) -> dict:
    """AI 现场写一条模板化 WAF 规则（UA 包含 / 路径前缀），最多 3 条。"""
    if getattr(ctx.service, "agent_autonomy", "approve") != "auto":
        raise ToolError("AI 自主处置未开启")
    if match not in ("ua", "path"):
        raise ToolError("match 必须是 ua 或 path")
    if not re.fullmatch(r"[A-Za-z0-9._:/%+\-]{2,64}", value or ""):
        raise ToolError("value 仅允许字母数字 . _ : / % + -，2-64 字符")
    sub = "add-ua" if match == "ua" else "add-path"
    try:
        p = subprocess.run(
            ["sudo", "-n", "/usr/local/sbin/nw-waf", sub, value],
            capture_output=True, text=True, timeout=25)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ToolError(f"nw-waf 调用失败: {e}") from e
    ok = p.returncode == 0
    from app.store import now_iso
    row = ctx.store.append_event(
        now_iso(), "firewall", "0.0.0.0",
        {"action": "waf_rule", "match": match, "value": value,
         "note": str(note)[:200], "ok": ok,
         "output": ((p.stdout or "") + (p.stderr or ""))[-300:]})
    pub = getattr(ctx.worker, "publish", None)
    if pub:
        pub(row)
    if not ok:
        raise ToolError(((p.stdout or "") + (p.stderr or ""))[-300:])
    return {"ok": True, "match": match, "value": value,
            "event_id": row["id"], "note": "WAF 规则已校验并 reload"}


def attack_chain(ctx: Ctx, ip: str, limit: int = 30, **_) -> dict:
    """把某个 IP 的网络/WAF/应用层事件串成一条链。"""
    rows = ctx.store.query_events(ip=ip, limit=max(1, min(int(limit), 100)))
    return {"ip": ip, "count": len(rows), "events": [{
        "id": r["id"], "ts": r["ts"], "kind": r["kind"], "rule_id": r["rule_id"],
        "action": r["evidence"].get("action"),
        "reason_code": r["evidence"].get("reason_code"),
        "signature": r["evidence"].get("signature"),
        "crs_rule": r["evidence"].get("crs_rule"),
        "path": r["evidence"].get("path"),
    } for r in rows]}


IMPL = {
    "guard_status": guard_status, "query_events": query_events, "get_event": get_event,
    "verify_chain": verify_chain, "audit_dependencies": audit_dependencies,
    "probe_asset": probe_asset, "nmap_scan": nmap_scan, "nikto_scan": nikto_scan,
    "whatweb_scan": whatweb_scan, "host_audit": host_audit,
    "propose_ban": propose_ban, "list_pending": list_pending,
    "firewall_status": firewall_status, "attack_chain": attack_chain,
    "execute_ban": execute_ban, "escalate_ban": escalate_ban,
    "profile_attacker": profile_attacker, "deploy_waf_rule": deploy_waf_rule,
}


def _fn(name, desc, props=None, required=None):
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "properties": props or {},
                       "required": required or []}}}


def build_specs(cfg: dict) -> list[dict]:
    ids = list(_assets(cfg))
    return [
        _fn("guard_status", "读取守夜人状态：事件总数、哈希链是否完整、当前封禁、采集源、可用资产"),
        _fn("query_events", "按 IP/类型查询事件账本（只读）", {
            "ip": {"type": "string", "description": "精确 IP，可留空"},
            "kind": {"type": "string", "enum": ["login_fail", "login_success", "http_404",
                                                "http_request", "http_429", "net_alert",
                                                "waf_alert", "decision", "rollback",
                                                "agent_tool", "agent_run", "parse_error",
                                                "enforce_error"]},
            "rule_prefix": {"type": "string", "description": "如 NET_ / WAF_ / BRUTE"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        }),
        _fn("get_event", "取单条事件的完整证据与原始日志行", {
            "event_id": {"type": "integer"}} , ["event_id"]),
        _fn("verify_chain", "校验事件哈希链完整性"),
        _fn("audit_dependencies", "运行依赖漏洞验真（OSV 版本范围/作用域/可达性）"),
        _fn("probe_asset", "内置探测单个授权资产（SSH banner+握手 / HTTP 响应）", {
            "asset_id": {"type": "string", "enum": ids}}, ["asset_id"]),
        _fn("nmap_scan", "对单个授权资产做服务/版本识别（仅配置端口）", {
            "asset_id": {"type": "string", "enum": ids}}, ["asset_id"]),
        _fn("nikto_scan", "对单个授权 HTTP 资产做 Web 配置检查", {
            "asset_id": {"type": "string", "enum": ids}}, ["asset_id"]),
        _fn("whatweb_scan", "对单个授权 HTTP 资产做指纹识别", {
            "asset_id": {"type": "string", "enum": ids}}, ["asset_id"]),
        _fn("host_audit", "本机只读巡检：监听端口、负载、内存、磁盘"),
        _fn("propose_ban", "提交封禁建议（不会直接封禁，需人工确认）", {
            "ip": {"type": "string"},
            "reason": {"type": "string"},
            "evidence_event_ids": {"type": "array", "items": {"type": "integer"}},
        }, ["ip", "reason", "evidence_event_ids"]),
        _fn("list_pending", "列出待人工确认的处置建议"),
        _fn("firewall_status", "读取 nftables 活跃封禁与账本中的封禁"),
        _fn("attack_chain", "把一个 IP 的网络/WAF/应用层事件串成攻击链", {
            "ip": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        }, ["ip"]),
        _fn("execute_ban",
            "直接执行封禁（仅 autonomy=auto；必须引用同 IP 的强证据事件；TTL 60-3600）", {
                "ip": {"type": "string"},
                "reason": {"type": "string"},
                "ttl": {"type": "integer", "minimum": 60, "maximum": 3600},
                "evidence_event_ids": {"type": "array", "items": {"type": "integer"}},
            }, ["ip", "reason", "evidence_event_ids"]),
        _fn("escalate_ban",
            "对已被封禁的重复攻击者延长封禁（TTL 1h-24h，需同 IP 证据）", {
                "ip": {"type": "string"},
                "reason": {"type": "string"},
                "ttl": {"type": "integer", "minimum": 3600, "maximum": 86400},
                "evidence_event_ids": {"type": "array", "items": {"type": "integer"}},
            }, ["ip", "reason", "evidence_event_ids"]),
        _fn("profile_attacker", "识别攻击者使用的工具（nmap/nikto/sqlmap/hydra 等）", {
            "ip": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200},
        }, ["ip"]),
        _fn("deploy_waf_rule", "现场生成并部署一条 WAF 规则（UA 包含/路径前缀，最多 3 条）", {
            "match": {"type": "string", "enum": ["ua", "path"]},
            "value": {"type": "string"},
            "note": {"type": "string"},
        }, ["match", "value"]),
    ]


def execute(ctx: Ctx, name: str, args: dict) -> dict:
    fn = IMPL.get(name)
    if not fn:
        return {"error": f"未知工具：{name}"}
    try:
        return fn(ctx, **(args or {}))
    except ToolError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
