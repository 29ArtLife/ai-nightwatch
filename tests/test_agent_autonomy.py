import copy
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.tools import Ctx, execute  # noqa: E402
from app.config import load  # noqa: E402
from app.enforce import Enforcer  # noqa: E402
from app.store import Store, now_iso  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = copy.deepcopy(load(os.path.join(ROOT, "config.toml")))
CFG["agent"]["autonomy"] = "auto"


class W:
    def __init__(self, store):
        self.store = store
        self.auto_enabled = True
        self.enforcer = Enforcer(store, CFG)

    def enqueue_event(self, kind, ip, ev):
        self.store.append_event(now_iso(), kind, ip, ev)


class S:
    def __init__(self, mode="auto"):
        self.pending = {}
        self.agent_autonomy = mode
        self._auto_ban_times = []


def ctx(mode="auto"):
    s = Store(os.path.join(tempfile.mkdtemp(), "a.db"))
    w = W(s)
    return Ctx(cfg=CFG, store=s, worker=w, service=S(mode), pending={})


def strong(store, ip="10.0.0.2"):
    return store.append_event(now_iso(), "waf_alert", ip,
                              {"rule_id": "942100", "message": "SQLi"})


def test_approve_mode_rejects():
    c = ctx("approve")
    ev = strong(c.store)
    r = execute(c, "execute_ban", {"ip": "10.0.0.2", "reason": "x",
                                   "evidence_event_ids": [ev["id"]]})
    assert "error" in r and not c.store.active_bans()


def test_whitelist_and_mismatch_rejected():
    c = ctx()
    ev = strong(c.store, "10.2.102.143")
    r = execute(c, "execute_ban", {"ip": "10.2.102.143", "reason": "x",
                                   "evidence_event_ids": [ev["id"]]})
    assert "error" in r
    ev2 = strong(c.store, "10.0.0.2")
    r = execute(c, "execute_ban", {"ip": "10.0.0.3", "reason": "x",
                                   "evidence_event_ids": [ev2["id"]]})
    assert "error" in r


def test_valid_ban_and_chain():
    c = ctx()
    ev = strong(c.store)
    r = execute(c, "execute_ban", {"ip": "10.0.0.2", "reason": "SQLi",
                                   "ttl": 600, "evidence_event_ids": [ev["id"]]})
    assert r.get("ok") and r["event_id"]
    assert c.store.is_banned("10.0.0.2")
    row = c.store.event(r["event_id"])
    assert row["evidence"]["actor"] == "ai-agent"
    assert c.store.verify_chain()["ok"]


def test_ttl_clamped_and_rate_limited():
    c = ctx()
    for i in range(3):
        ip = f"10.0.1.{i + 1}"
        ev = strong(c.store, ip)
        r = execute(c, "execute_ban", {"ip": ip, "reason": "x", "ttl": 99999,
                                       "evidence_event_ids": [ev["id"]]})
        assert r.get("ok"), r
        assert r["ttl"] == 3600
    ev = strong(c.store, "10.0.1.9")
    r = execute(c, "execute_ban", {"ip": "10.0.1.9", "reason": "x",
                                   "evidence_event_ids": [ev["id"]]})
    assert "error" in r and "频率" in r["error"]
