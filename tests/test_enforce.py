import copy
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config import load  # noqa: E402
from app.enforce import Enforcer  # noqa: E402
from app.store import Store, now_iso  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make():
    cfg = copy.deepcopy(load(os.path.join(ROOT, "config.toml")))
    cfg["enforce"]["default_ttl_sec"] = 1
    s = Store(os.path.join(tempfile.mkdtemp(), "t.db"))
    return s, Enforcer(s, cfg)


def test_ban_ttl_and_expire_event():
    s, e = make()
    sig = {"ip": "127.0.0.9", "rule_id": "BRUTE_FORCE.v1", "sample_raw": ["x"]}
    v = {"action": "ban", "reason_code": "BRUTE_FORCE", "ttl_sec": 1,
         "evidence": {"rule_id": "BRUTE_FORCE.v1", "counts": {"fail": 5},
                      "thresholds": {"fail": 5}}}
    e.handle(sig, v, now_iso())
    assert s.is_banned("127.0.0.9")
    time.sleep(1.2)
    assert not s.is_banned("127.0.0.9")
    e.sweep(now_iso())
    kinds = [r["evidence"].get("action") for r in s.events_since(0, 100)]
    assert "expire" in kinds
    assert s.verify_chain()["ok"]
    s.close()


def test_rollback_idempotent():
    s, e = make()
    sig = {"ip": "127.0.0.10", "rule_id": "PATH_SCAN.v1", "sample_raw": [""]}
    v = {"action": "ban", "reason_code": "PATH_SCAN", "ttl_sec": 600,
         "evidence": {"rule_id": "PATH_SCAN.v1", "counts": {}}}
    e.handle(sig, v, now_iso())
    assert e.rollback("127.0.0.10", "op", "test", now_iso()) is not None
    assert e.rollback("127.0.0.10", "op", "test", now_iso()) is None
    assert not s.is_banned("127.0.0.10")
    assert s.verify_chain()["ok"]
    s.close()
