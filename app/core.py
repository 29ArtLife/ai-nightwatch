"""业务核心：CLI 与 daemon 共用；不依赖 HTTP/SSE。"""
from __future__ import annotations

import json
import os
import threading

from .report import build as build_report
from .store import now_iso
from verify.assets import probe_all
from verify.findings import run_audit


def _flag(name: str, default: str) -> str:
    try:
        with open(os.path.join("data", name), encoding="utf-8") as f:
            return f.read().strip() or default
    except OSError:
        return default


def _write_flag(name: str, value: str) -> None:
    os.makedirs("data", exist_ok=True)
    with open(os.path.join("data", name), "w", encoding="utf-8") as f:
        f.write(value + "\n")


def _key_present() -> bool:
    if os.environ.get("DEEPSEEK_API_KEY"):
        return True
    try:
        with open(os.path.join("data", "agent.env"), encoding="utf-8") as f:
            return "DEEPSEEK_API_KEY=" in f.read()
    except OSError:
        return False


class Core:
    def __init__(self, cfg: dict, store, worker):
        self.cfg = cfg
        self.store = store
        self.worker = worker
        self.pending: dict[str, dict] = {}
        self._plock = threading.Lock()
        self._auto_ban_times: list[float] = []
        self.autopilot = None
        self._load_pending()

    # ---------- 运行控制 ----------
    @property
    def agent_autonomy(self) -> str:
        return _flag("autonomy.flag",
                     str(self.cfg.get("agent", {}).get("autonomy", "approve")))

    def set_autonomy(self, mode: str, operator: str = "cli") -> str:
        if mode not in ("auto", "approve"):
            raise ValueError("mode 必须是 auto 或 approve")
        _write_flag("autonomy.flag", mode)
        row = self.store.append_event(
            now_iso(), "agent_autonomy", "0.0.0.0",
            {"mode": mode, "operator": operator})
        self._publish(row)
        return mode

    def autopilot_enabled(self) -> bool:
        return _flag("autopilot.flag",
                     "on" if self.cfg["agent"].get("autopilot") else "off") == "on"

    def set_autopilot(self, enabled: bool, operator: str = "cli") -> bool:
        _write_flag("autopilot.flag", "on" if enabled else "off")
        if self.autopilot:
            self.autopilot.enabled = bool(enabled)
        row = self.store.append_event(
            now_iso(), "agent_autonomy", "0.0.0.0",
            {"autopilot": bool(enabled), "operator": operator})
        self._publish(row)
        return bool(enabled)

    def set_auto_response(self, enabled: bool, operator: str = "cli") -> bool:
        _write_flag("auto_response.flag", "on" if enabled else "off")
        row = self.store.append_event(
            now_iso(), "agent_autonomy", "0.0.0.0",
            {"auto_response": bool(enabled), "operator": operator})
        self._publish(row)
        return bool(enabled)

    def _publish(self, row):
        """CLI 无 SSE；daemon 里 broker 已移除。"""
        return row

    # ---------- 状态/查询 ----------
    def daemon_alive(self) -> bool:
        try:
            with open(os.path.join("data", "daemon.pid"), encoding="utf-8") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            return False

    def status(self) -> dict:
        v = self.store.verify_chain()
        sources = []
        for s in self.cfg.get("ingest", {}).get("sources", []):
            sources.append({"name": s["name"], "path": s["path"],
                            "online": os.path.exists(s["path"])})
        return {
            "daemon": self.daemon_alive(),
            "auto_response": self.worker.auto_enabled,
            "events": v.get("count", 0),
            "bans": len(self.store.active_bans(now_iso())),
            "sources": sources,
            "chain_ok": v.get("ok", False),
            "osv_mode": self.cfg["osv"]["mode"],
            "agent_autonomy": self.agent_autonomy,
            "autopilot": self.autopilot_enabled(),
            "key_present": _key_present(),
        }

    def events(self, since: int = 0, limit: int = 50, latest: bool = True,
               ip: str = "", kind: str = "", rule_prefix: str = "") -> list[dict]:
        if ip or kind or rule_prefix:
            return self.store.query_events(ip=ip, kind=kind,
                                           rule_prefix=rule_prefix, limit=limit)
        if latest:
            return self.store.recent_events(min(int(limit), 500))
        return self.store.events_since(since, min(int(limit), 500))

    def event(self, eid: int) -> dict | None:
        return self.store.event(eid)

    def bans(self) -> list[dict]:
        return self.store.active_bans(now_iso())

    def chain(self) -> dict:
        return self.store.verify_chain()

    def report(self) -> str:
        return build_report(self.store, self.cfg)

    # ---------- 处置 ----------
    def ban_manual(self, ip: str, ttl: int, reason: str,
                   operator: str = "cli") -> dict:
        sig = {"ip": ip, "rule_id": "CLI_MANUAL.v1",
               "window": {"start": now_iso(), "end": now_iso(), "sec": 0},
               "counts": {}, "thresholds": {}, "sample_raw": [reason[:300]],
               "ua": "cli"}
        verdict = {"action": "ban", "reason_code": "MANUAL_BAN", "ttl_sec": ttl,
                   "evidence": {"rule_id": "CLI_MANUAL.v1", "actor": operator,
                                "reason": reason[:300], "counts": {},
                                "negatives": []}}
        return self.worker.enforcer.handle(sig, verdict, now_iso())

    def unban(self, ip: str, operator: str = "cli", reason: str = "manual") -> dict | None:
        return self.worker.enforcer.rollback(ip, operator, reason, now_iso())

    def fw_status(self) -> dict:
        return self.worker.enforcer.fw_status()

    def fw_flush(self, operator: str = "cli") -> dict:
        res = self.worker.enforcer.fw.flush()
        row = self.store.append_event(
            now_iso(), "firewall", "0.0.0.0",
            {"action": "flush", "operator": operator,
             "ok": bool(res.get("ok")), "error": res.get("error")})
        self._publish(row)
        return {"ok": bool(res.get("ok")), "event_id": row["id"],
                "output": res.get("output") or res.get("error")}

    def fw_reconcile(self) -> dict:
        res = self.worker.enforcer.reconcile(now_iso())
        return {"ok": all(x.get("ok") for x in res), "count": len(res),
                "results": res}

    # ---------- 体检/资产 ----------
    def audit(self) -> dict:
        result = run_audit(self.cfg["reach"]["project_dir"], self.cfg)
        run_id = self.store.save_audit(result["project"], result["source"],
                                       result["snapshot_ts"], result["summary"],
                                       result["findings"])
        return {"run_id": run_id, **self.store.latest_audit()}

    def assets(self) -> list[dict]:
        return probe_all(self.cfg)

    # ---------- AI ----------
    def agent_info(self) -> dict:
        from agent.tools import build_specs
        return {
            "enabled": bool(self.cfg.get("agent", {}).get("enabled")),
            "model": self.cfg.get("agent", {}).get("model"),
            "autonomy": self.agent_autonomy,
            "autopilot": self.autopilot_enabled(),
            "key_present": _key_present(),
            "assets": [{"id": a["id"], "kind": a.get("kind", "ssh"),
                        "label": a.get("label", a["id"])}
                       for a in self.cfg["asset"]["assets"]],
            "tools": [s["function"]["name"] for s in build_specs(self.cfg)],
        }

    def agent_chat(self, message: str) -> dict:
        from agent.runner import run_agent
        from agent.tools import Ctx
        ctx = Ctx(cfg=self.cfg, store=self.store, worker=self.worker,
                  service=self, pending=self.pending)
        return run_agent(message, self.cfg, ctx)

    # ---------- 待确认建议 ----------
    def _pending_file(self) -> str:
        return os.path.join("data", "pending.json")

    def _load_pending(self):
        try:
            with open(self._pending_file(), encoding="utf-8") as f:
                self.pending = json.load(f)
        except (OSError, json.JSONDecodeError):
            self.pending = {}

    def save_pending(self):
        with self._plock:
            os.makedirs("data", exist_ok=True)
            with open(self._pending_file(), "w", encoding="utf-8") as f:
                json.dump(self.pending, f, ensure_ascii=False, indent=1)

    def agent_actions(self) -> list[dict]:
        return [a for a in self.pending.values() if a.get("status") == "pending"]

    def agent_approve(self, rid: str, operator: str = "cli") -> dict | None:
        a = self.pending.get(rid)
        if not a or a.get("status") != "pending":
            return None
        sig = {"ip": a["ip"], "rule_id": "AI_RECOMMENDED.v1",
               "window": {"start": a["created_at"], "end": now_iso(), "sec": 0},
               "counts": {}, "thresholds": {}, "sample_raw": [a["reason"]],
               "ua": "ai-agent"}
        verdict = {"action": "ban", "reason_code": "AI_RECOMMENDED",
                   "ttl_sec": int(self.cfg["enforce"]["default_ttl_sec"]),
                   "evidence": {"rule_id": "AI_RECOMMENDED.v1",
                                "recommendation_id": rid,
                                "approved_by": operator,
                                "evidence_event_ids": a["evidence_event_ids"],
                                "reason": a["reason"], "counts": {},
                                "negatives": []}}
        row = self.worker.enforcer.handle(sig, verdict, now_iso())
        a["status"] = "approved"
        a["approved_by"] = operator
        self.save_pending()
        return row

    def agent_reject(self, rid: str, operator: str = "cli") -> bool:
        a = self.pending.get(rid)
        if not a or a.get("status") != "pending":
            return False
        a["status"] = "rejected"
        a["rejected_by"] = operator
        self.save_pending()
        return True
