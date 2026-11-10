import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config import load  # noqa: E402
from app.decide import decide  # noqa: E402
from app.detect import Detector  # noqa: E402
from app.parsers import ParsedEvent  # noqa: E402

CFG = load(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.toml"))
T0 = datetime(2026, 11, 10, 5, 0, 0, tzinfo=timezone.utc)


def ev(kind, ip, sec=0, path="/", user="demo"):
    ts = (T0 + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return ParsedEvent(ts=ts, ip=ip, kind=kind, path=path, user=user)


def test_brute_fifth_fail():
    d = Detector(CFG)
    sigs = [d.feed(ev("login_fail", "127.0.0.2", i), T0 + timedelta(seconds=i))
            for i in range(1, 6)]
    assert sigs[-1] is not None
    assert sigs[-1]["rule_id"] == "BRUTE_FORCE.v1"
    assert sigs[-1]["counts"]["fail"] == 5


def test_success_negative_evidence():
    d = Detector(CFG)
    d.feed(ev("login_fail", "127.0.0.3", 1), T0 + timedelta(seconds=1))
    d.feed(ev("login_fail", "127.0.0.3", 2), T0 + timedelta(seconds=2))
    sig = d.feed(ev("login_success", "127.0.0.3", 3), T0 + timedelta(seconds=3))
    assert sig and sig["observation"] == "SUCCESS_IN_WINDOW"
    v = decide(sig, CFG, "2026-11-10T05:00:03.000Z", whitelisted=False,
               already_banned=False, auto_enabled=True)
    assert v["action"] == "observe" and v["reason_code"] == "SUCCESS_IN_WINDOW"
    assert v["evidence"]["negatives"]


def test_whitelist_never_ban():
    d = Detector(CFG)
    sig = None
    for i in range(1, 8):
        sig = d.feed(ev("login_fail", "127.0.0.1", i), T0 + timedelta(seconds=i)) or sig
    v = decide(sig, CFG, "x", whitelisted=True, already_banned=False, auto_enabled=True)
    assert v["action"] == "no_action" and v["reason_code"] == "WHITELIST"


def test_scan_rule():
    d = Detector(CFG)
    paths = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/a", "/admin.php",
             "/.aws/x", "/backup.zip", "/actuator/env"]
    sig = None
    for i, p in enumerate(paths):
        sig = d.feed(ev("http_404", "127.0.0.12", i, p), T0 + timedelta(seconds=i)) or sig
    assert sig and sig["rule_id"] == "PATH_SCAN.v1"
    v = decide(sig, CFG, "x", whitelisted=False, already_banned=False, auto_enabled=True)
    assert v["action"] == "ban"


def test_window_expiry():
    d = Detector(CFG)
    for i in range(4):
        d.feed(ev("login_fail", "127.0.0.9", i), T0 + timedelta(seconds=i))
    assert d.last_counts["127.0.0.9"]["fail"] == 4
    d.feed(ev("login_fail", "127.0.0.9", 90), T0 + timedelta(seconds=90))
    assert d.last_counts["127.0.0.9"]["fail"] == 1


def test_auto_disabled():
    v = decide({"ip": "1.1.1.1", "rule_id": "BRUTE_FORCE.v1", "window": {}, "counts": {},
                "thresholds": {}}, CFG, "x", whitelisted=False, already_banned=False,
               auto_enabled=False)
    assert v["action"] == "alert" and v["reason_code"] == "AUTO_DISABLED"
