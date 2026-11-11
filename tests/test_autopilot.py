import copy
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent import autopilot as ap_mod  # noqa: E402
from agent.autopilot import Autopilot  # noqa: E402
from app.config import load  # noqa: E402
from app.store import Store, now_iso  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = copy.deepcopy(load(os.path.join(ROOT, "config.toml")))
CFG["agent"]["autopilot"] = True
CFG["agent"]["autonomy"] = "auto"


class W:
    def __init__(self, store):
        self.store = store
        self.auto_enabled = True

    def enqueue_event(self, kind, ip, ev):
        self.store.append_event(now_iso(), kind, ip, ev)


class S:
    def __init__(self):
        self.agent_autonomy = "auto"
        self.pending = {}


def setup():
    s = Store(os.path.join(tempfile.mkdtemp(), "ap.db"))
    w = W(s)
    svc = S()
    ap = Autopilot(CFG, s, w, svc)
    ap.last_id = 0
    return s, ap


def alert(store, ip, sig="NW TEST"):
    return store.append_event(now_iso(), "net_alert", ip,
                              {"signature": sig, "category": "test"})


def test_select_filters_banned_and_ignores_normal(monkeypatch):
    s, ap = setup()
    a = alert(s, "10.0.0.2")
    b = alert(s, "10.0.0.3")
    s.ban("10.0.0.3", "2099-01-01T00:00:00.000Z", decision_event=0)
    c = s.append_event(now_iso(), "decision", "10.0.0.4",
                       {"action": "observe", "reason_code": "SUCCESS_AFTER_THRESHOLD"})
    s.append_event(now_iso(), "http_request", "10.0.0.5",
                   {"path": "/"})
    rows = ap.select()
    ids = {r["id"] for r in rows}
    assert a["id"] in ids and c["id"] in ids
    assert b["id"] not in ids


def test_tick_dedup_and_new_alert(monkeypatch):
    s, ap = setup()
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test")
    calls = []

    def fake_agent(msg, cfg, ctx, history=None, source="chat"):
        calls.append(source)
        return {"ok": True, "answer": "done"}

    monkeypatch.setattr(ap_mod, "run_agent", fake_agent)
    alert(s, "10.0.0.2")
    assert ap.tick() is True
    assert calls == ["autopilot"]
    assert ap.tick() is False          # 同一批告警不重复调用
    alert(s, "10.0.0.6", "NW NEW")
    assert ap.tick() is True
    assert len(calls) == 2


def test_rate_limit(monkeypatch):
    s, ap = setup()
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test")
    monkeypatch.setattr(ap_mod, "run_agent",
                        lambda *a, **k: {"ok": True, "answer": "x"})
    import time
    ap.calls = [time.time()] * ap.max_calls
    alert(s, "10.0.0.2")
    assert ap.tick() is False
    assert "上限" in ap.last_error


def test_backoff_on_model_error(monkeypatch):
    s, ap = setup()
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test")
    monkeypatch.setattr(ap_mod, "run_agent",
                        lambda *a, **k: {"ok": False, "error": "boom"})
    alert(s, "10.0.0.2")
    assert ap.tick() is True
    assert ap.backoff_until > 0
    assert ap.last_error == "boom"
