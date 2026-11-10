import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent import runner as runner_mod  # noqa: E402
from agent.tools import Ctx, ToolError, execute, resolve_asset  # noqa: E402
from app.config import load  # noqa: E402
from app.enforce import Enforcer  # noqa: E402
from app.store import Store, now_iso  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = load(os.path.join(ROOT, "config.toml"))


class FakeWorker:
    def __init__(self, store):
        self.store = store
        self.auto_enabled = True
        self.sources = []
        self.enforcer = Enforcer(store, CFG)

    def enqueue_event(self, kind, ip, evidence):
        self.store.append_event(now_iso(), kind, ip, evidence)


class FakeService:
    def __init__(self):
        self.pending = {}


def ctx():
    s = Store(os.path.join(tempfile.mkdtemp(), "a.db"))
    w = FakeWorker(s)
    svc = FakeService()
    return Ctx(cfg=CFG, store=s, worker=w, service=svc, pending=svc.pending)


def test_asset_allowlist():
    assert resolve_asset(CFG, "sshd")["ip"] == "127.0.0.1"
    with pytest.raises(ToolError):
        resolve_asset(CFG, "1.2.3.4")
    with pytest.raises(ToolError):
        resolve_asset(CFG, "../../etc/passwd")


def test_scan_tool_rejects_unknown_asset_no_exec():
    c = ctx()
    r = execute(c, "nmap_scan", {"asset_id": "8.8.8.8"})
    assert "error" in r


def test_propose_ban_does_not_ban_and_whitelist_rejected():
    c = ctx()
    r = execute(c, "propose_ban", {"ip": "127.0.0.1", "reason": "x",
                                   "evidence_event_ids": []})
    assert "error" in r and not c.store.active_bans()
    ev = c.store.append_event(now_iso(), "decision", "127.0.0.2", {"action": "ban"})
    r = execute(c, "propose_ban", {"ip": "127.0.0.2", "reason": "爆破",
                                   "evidence_event_ids": [ev["id"]]})
    assert "recommendation_id" in r and not c.store.active_bans()
    rid = r["recommendation_id"]
    assert c.pending[rid]["status"] == "pending"


def test_runner_loop_with_mocked_model(monkeypatch):
    c = ctx()
    ev = c.store.append_event(now_iso(), "decision", "127.0.0.2", {"action": "observe"})

    def fake_chat(cfg, messages, tools):
        if not any(m.get("role") == "tool" for m in messages):
            return {"choices": [{"message": {
                "role": "assistant", "content": "",
                "tool_calls": [{"id": "c1", "type": "function",
                                "function": {"name": "guard_status", "arguments": "{}"}}]}}]}
        return {"choices": [{"message": {
            "role": "assistant", "content": f"结论：链完整，见事件 #{ev['id']}"}}]}

    monkeypatch.setattr(runner_mod, "_chat", fake_chat)
    r = runner_mod.run_agent("看一下状态", CFG, c)
    assert r["ok"] and r["steps"] == 2 and len(r["trace"]) == 1
    assert not r["citations_invalid"]
    kinds = [x["kind"] for x in c.store.events_since(0, 100)]
    assert "agent_tool" in kinds and "agent_run" in kinds
    assert c.store.verify_chain()["ok"]


def test_citation_validation(monkeypatch):
    c = ctx()
    monkeypatch.setattr(runner_mod, "_chat", lambda *a: {"choices": [{"message": {
        "role": "assistant", "content": "结论：见事件 #99999"}}]})
    r = runner_mod.run_agent("胡编一个引用", CFG, c)
    assert r["ok"] and r["citations_invalid"] == [99999]
