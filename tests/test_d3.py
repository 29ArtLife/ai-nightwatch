import copy
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.tools import Ctx, execute  # noqa: E402
from app.config import load  # noqa: E402
from app.decide import decide  # noqa: E402
from app.detect import Detector  # noqa: E402
from app.enforce import Enforcer  # noqa: E402
from app.parsers import ParsedEvent, parse_jsonl_http  # noqa: E402
from app.profile import identify  # noqa: E402
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
        self.agent_autonomy = mode
        self.pending = {}
        self._auto_ban_times = []


def ctx(mode="auto"):
    s = Store(os.path.join(tempfile.mkdtemp(), "d3.db"))
    return Ctx(cfg=CFG, store=s, worker=W(s), service=S(mode), pending={})


def test_honeypot_parser_and_ban():
    e = parse_jsonl_http('{"ts":"2026-11-13T00:00:00Z","ip":"10.0.0.2",'
                         '"path":"/admin","status":200,"honeypot":"admin"}')
    assert e.kind == "honeypot" and e.extra["honeypot"] == "admin"
    d = Detector(CFG)
    sig = d.feed(e)
    assert sig and sig["rule_id"] == "HONEYPOT.v1"
    v = decide(sig, CFG, "x", whitelisted=False, already_banned=False,
               auto_enabled=True)
    assert v["action"] == "ban" and v["ttl_sec"] == 3600
    assert v["reason_code"] == "HONEYPOT"


def test_profile_identifies_sqlmap():
    rows = [{"ts": "2026-11-13T00:00:00Z", "rule_id": "WAF_SQLI.v1",
             "evidence": {"ua": "sqlmap/1.8", "crs_message": "SQL Injection",
                          "path": "/lab/item"}}]
    r = identify("10.0.0.2", rows)
    assert r["tool"] == "sqlmap" and r["confidence"] >= 0.9


def test_escalate_extends_existing_ban():
    c = ctx()
    ev = c.store.append_event(now_iso(), "waf_alert", "10.0.0.2",
                              {"rule_id": "942100", "message": "SQLi"})
    sig = {"ip": "10.0.0.2", "rule_id": "WAF_SQLI.v1", "counts": {},
           "thresholds": {}, "sample_raw": [""]}
    v = {"action": "ban", "reason_code": "WAF_SQLI", "ttl_sec": 600,
         "evidence": {"rule_id": "WAF_SQLI.v1", "counts": {}}}
    c.worker.enforcer.handle(sig, v, now_iso())
    before = c.store.active_bans()[0]["until_ts"]
    r = execute(c, "escalate_ban", {
        "ip": "10.0.0.2", "reason": "repeat", "ttl": 3600,
        "evidence_event_ids": [ev["id"]]})
    assert r.get("ok"), r
    after = c.store.active_bans()[0]["until_ts"]
    assert after > before
    assert c.store.verify_chain()["ok"]
