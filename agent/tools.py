"""Agent 工具层：唯一发包/执行入口，目标一律从配置的 asset_id 解析。

模型拿不到 host/port/命令，只能选工具与参数；白名单在这里硬校验。
"""
from __future__ import annotations

import ipaddress
import json
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
    return {
        "events": v.get("count", 0),
        "chain_ok": v.get("ok", False),
        "auto_response": ctx.worker.auto_enabled,
        "active_bans": [{"ip": b["ip"], "reason": b["reason"], "until": b["until_ts"]}
                        for b in bans],
        "sources": [{"name": s.source_name, "online": s.online} for s in ctx.worker.sources],
        "assets": [{"id": a["id"], "kind": a.get("kind", "ssh"), "port": a["port"],
                    "label": a.get("label", a["id"])} for a in ctx.cfg["asset"]["assets"]],
    }


def query_events(ctx: Ctx, ip: str = "", kind: str = "", limit: int = 20, **_) -> dict:
    limit = max(1, min(int(limit), 50))
    rows = ctx.store.events_since(0, 100000)
    if ip:
        rows = [r for r in rows if r["ip"] == ip]
    if kind:
        rows = [r for r in rows if r["kind"] == kind]
    rows = rows[-limit:]
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
    return {"recommendation_id": rid,
            "note": "仅为建议，必须在监控台由人工点击确认后才会执行封禁"}


def list_pending(ctx: Ctx, **_) -> dict:
    return {"actions": list(ctx.service.pending.values())}


IMPL = {
    "guard_status": guard_status, "query_events": query_events, "get_event": get_event,
    "verify_chain": verify_chain, "audit_dependencies": audit_dependencies,
    "probe_asset": probe_asset, "nmap_scan": nmap_scan, "nikto_scan": nikto_scan,
    "whatweb_scan": whatweb_scan, "host_audit": host_audit,
    "propose_ban": propose_ban, "list_pending": list_pending,
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
                                                "http_request", "decision", "rollback",
                                                "agent_tool", "agent_run", "parse_error"]},
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
