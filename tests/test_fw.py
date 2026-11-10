import copy
import os
import platform
import subprocess
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config import load  # noqa: E402
from app.enforce import Enforcer  # noqa: E402
from app.fw import FwBackend, FwError  # noqa: E402
from app.store import Store, now_iso  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = load(os.path.join(ROOT, "config.toml"))


class FakeFw:
    def __init__(self, ok=True):
        self.ok = ok
        self.calls = []

    def ban(self, ip, ttl):
        self.calls.append(("ban", ip, ttl))
        return {"ok": self.ok, "error": None if self.ok else "boom"}

    def unban(self, ip):
        self.calls.append(("unban", ip))
        return {"ok": self.ok}

    def status(self):
        return {"ok": True, "count": 0, "entries": []}

    def flush(self):
        return {"ok": True}

    def reconcile(self, pairs):
        return {"ok": True, "count": len(pairs)}


def make(fw=None, ttl=600):
    cfg = copy.deepcopy(CFG)
    cfg["enforce"]["default_ttl_sec"] = ttl
    s = Store(os.path.join(tempfile.mkdtemp(), "f.db"))
    return s, Enforcer(s, cfg, fw=fw or FakeFw())


def sig(ip="127.0.0.9"):
    return {"ip": ip, "rule_id": "BRUTE_FORCE.v1", "sample_raw": [""]}


def verdict(ttl=600):
    return {"action": "ban", "reason_code": "BRUTE_FORCE", "ttl_sec": ttl,
            "evidence": {"rule_id": "BRUTE_FORCE.v1", "counts": {}}}


def test_validate_ip_and_ttl():
    assert FwBackend.validate_ip("8.8.8.8") == "8.8.8.8"
    assert FwBackend.validate_ttl(600) == 600
    for bad in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "not-ip"):
        with pytest.raises(FwError):
            FwBackend.validate_ip(bad)
    for bad in (59, 86401):
        with pytest.raises(FwError):
            FwBackend.validate_ttl(bad)


def test_backend_command_shape(monkeypatch):
    calls = []

    class P:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return P()

    monkeypatch.setattr("app.fw.subprocess.run", fake_run)
    b = FwBackend({"fw": {"enabled": True, "wrapper": "/usr/local/sbin/nw-fw"}})
    assert b.ban("8.8.8.8", 600)["ok"]
    assert calls[0] == ["sudo", "-n", "/usr/local/sbin/nw-fw", "ban", "8.8.8.8", "600"]
    assert b.unban("8.8.8.8")["ok"]
    assert calls[1][3:] == ["unban", "8.8.8.8"]


def test_enforce_calls_fw_and_records_failure():
    fw = FakeFw(ok=True)
    s, e = make(fw)
    e.handle(sig(), verdict(), now_iso())
    assert fw.calls == [("ban", "127.0.0.9", 600)]
    assert s.verify_chain()["ok"]
    s.close()

    fw2 = FakeFw(ok=False)
    s2, e2 = make(fw2)
    e2.handle(sig("127.0.0.10"), verdict(), now_iso())
    kinds = [r["kind"] for r in s2.events_since(0, 100)]
    assert "enforce_error" in kinds
    assert s2.verify_chain()["ok"]
    s2.close()


def test_sweep_and_rollback_unban():
    fw = FakeFw()
    s, e = make(fw, ttl=1)
    e.handle(sig("127.0.0.11"), verdict(1), now_iso())
    time.sleep(1.1)
    e.sweep(now_iso())
    assert ("unban", "127.0.0.11") in fw.calls
    e.rollback("127.0.0.11", "op", "test", now_iso())
    assert s.verify_chain()["ok"]
    s.close()


@pytest.mark.skipif(platform.system() != "Linux", reason="wrapper selftest is Linux-only")
def test_wrapper_selftest_dry():
    env = dict(os.environ, NW_FW_DRY="1",
               NW_FW_ALLOW_FILE=os.path.join(ROOT, "deploy/fw-allow"))
    p = subprocess.run(["bash", os.path.join(ROOT, "deploy/nw-fw"), "selftest"],
                       capture_output=True, text=True, env=env, timeout=30)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "SELFTEST OK" in p.stdout
