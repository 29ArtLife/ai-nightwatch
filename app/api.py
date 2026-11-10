"""业务服务层：只返回 dict/str，不碰 HTTP。"""
from __future__ import annotations

import os

from .report import build as build_report
from .store import now_iso
from verify.assets import probe_all
from verify.findings import run_audit


class Service:
    def __init__(self, cfg: dict, store, broker, worker):
        self.cfg = cfg
        self.store = store
        self.broker = broker
        self.worker = worker
        self.pending: dict[str, dict] = {}

    def status(self) -> dict:
        v = self.store.verify_chain()
        return {
            "guarding": True,
            "auto_response": self.worker.auto_enabled,
            "events": v.get("count", 0),
            "bans": len(self.store.active_bans(now_iso())),
            "sources": [{"name": s.source_name, "online": s.online} for s in self.worker.sources],
            "chain_ok": v.get("ok", False),
            "osv_mode": self.cfg["osv"]["mode"],
        }

    def events(self, since: int = 0, limit: int = 500) -> list[dict]:
        return self.store.events_since(since, min(int(limit), 500))

    def bans(self) -> list[dict]:
        return self.store.active_bans(now_iso())

    def rollback(self, ip: str, operator: str, reason: str) -> dict | None:
        row = self.worker.enforcer.rollback(ip, operator or "operator", reason or "manual",
                                            now_iso())
        return row

    def audit(self) -> dict:
        result = run_audit(self.cfg["reach"]["project_dir"], self.cfg)
        run_id = self.store.save_audit(result["project"], result["source"],
                                       result["snapshot_ts"], result["summary"],
                                       result["findings"])
        return {"run_id": run_id, **self.store.latest_audit()}

    def latest_audit(self) -> dict | None:
        return self.store.latest_audit()

    def assets(self) -> list[dict]:
        return probe_all(self.cfg)

    def chain(self) -> dict:
        return self.store.verify_chain()

    def report(self) -> str:
        return build_report(self.store, self.cfg)

    def set_auto(self, enabled: bool) -> bool:
        self.worker.auto_enabled = bool(enabled)
        return self.worker.auto_enabled

    # ---------- AI 调查员 ----------
    def agent_info(self) -> dict:
        from agent.tools import build_specs
        return {
            "enabled": bool(self.cfg.get("agent", {}).get("enabled")),
            "model": self.cfg.get("agent", {}).get("model"),
            "key_present": bool(os.environ.get("DEEPSEEK_API_KEY")),
            "assets": [{"id": a["id"], "kind": a.get("kind", "ssh"),
                        "label": a.get("label", a["id"])}
                       for a in self.cfg["asset"]["assets"]],
            "tools": [s["function"]["name"] for s in build_specs(self.cfg)],
        }

    def agent_chat(self, message: str, history: list[dict] | None = None) -> dict:
        from agent.runner import run_agent
        from agent.tools import Ctx
        ctx = Ctx(cfg=self.cfg, store=self.store, worker=self.worker,
                  service=self, pending=self.pending)
        return run_agent(message, self.cfg, ctx, history=history)

    def agent_actions(self) -> list[dict]:
        return [a for a in self.pending.values() if a.get("status") == "pending"]

    def agent_approve(self, rid: str, operator: str) -> dict | None:
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
                                "approved_by": operator or "operator",
                                "evidence_event_ids": a["evidence_event_ids"],
                                "reason": a["reason"], "counts": {},
                                "negatives": []}}
        row = self.worker.enforcer.handle(sig, verdict, now_iso())
        a["status"] = "approved"
        a["approved_by"] = operator or "operator"
        return row

    def agent_reject(self, rid: str, operator: str) -> bool:
        a = self.pending.get(rid)
        if not a or a.get("status") != "pending":
            return False
        a["status"] = "rejected"
        a["rejected_by"] = operator or "operator"
        return True
