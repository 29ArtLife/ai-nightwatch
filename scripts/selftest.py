"""端到端自检：假设监控台与演示站已启动。只在 Linux 上运行。"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASS, FAIL = [], []


def check(name, fn):
    try:
        fn()
        PASS.append(name)
        print(f"PASS {name}", flush=True)
    except Exception as e:
        FAIL.append((name, str(e)))
        print(f"FAIL {name}: {e}", flush=True)


def http(url, method="GET", data=None, token=None):
    req = urllib.request.Request(url, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(data).encode()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def sim(*args, expect=None):
    p = subprocess.run([sys.executable, "demo/sim.py", *args], cwd=ROOT,
                       capture_output=True, text=True, timeout=120)
    if expect is not None and p.returncode != expect:
        raise AssertionError(f"sim 退出码 {p.returncode} != {expect}: {p.stderr}")
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dash", default="http://127.0.0.1:8080")
    ap.add_argument("--site", default="http://127.0.0.1:8081")
    ap.add_argument("--token", default="")
    a = ap.parse_args()
    if platform.system() != "Linux":
        print("SKIP：selftest 依赖 Linux（tail -F / 源地址绑定 / 进程管理）")
        return 0
    token = a.token
    if not token:
        try:
            token = open(os.path.join(ROOT, "data/token.txt"), encoding="utf-8").read().strip()
        except FileNotFoundError:
            pass
    os.chdir(ROOT)

    def health():
        s, b = http(a.dash + "/api/health")
        assert s == 200 and json.loads(b)["ok"]

    def normal_not_banned():
        sim("normal", "--src", "127.0.0.3", "--interval", "0.2")
        time.sleep(1.5)
        s, b = http(a.dash + "/api/bans", token=token)
        assert all(x["ip"] != "127.0.0.3" for x in json.loads(b)), "正常用户被误封"

    def brute_banned():
        p = sim("brute", "--src", "127.0.0.2", "--n", "5", "--interval", "0.5")
        lines = p.stdout.strip().splitlines()
        assert lines[-1].endswith("403"), f"封禁后正确密码未被拦截: {lines[-1]}"
        time.sleep(1.5)
        s, b = http(a.dash + "/api/bans", token=token)
        assert any(x["ip"] == "127.0.0.2" for x in json.loads(b))

    def scan_banned():
        sim("scan", "--src", "127.0.0.12", "--n", "10", "--interval", "0.15")
        time.sleep(1.5)
        s, b = http(a.dash + "/api/bans", token=token)
        assert any(x["ip"] == "127.0.0.12" for x in json.loads(b))

    def rollback():
        s, b = http(a.dash + "/api/bans/127.0.0.2/rollback", "POST",
                    {"operator": "selftest", "reason": "自检"}, token)
        assert s == 200, b
        time.sleep(0.3)
        lines = sim("brute", "--src", "127.0.0.2", "--n", "1", "--interval", "0.1").stdout
        assert "401" in lines, f"回滚后仍被封: {lines}"

    def audit_counts():
        s, b = http(a.dash + "/api/audit/run", "POST", {}, token)
        d = json.loads(b)
        sm = d["summary"]
        assert (sm["total"], sm["confirmed"], sm["version_mismatch"],
                sm["unreachable"], sm["dev_only"]) == (12, 5, 5, 1, 1), sm
        assert sm["source_mode"] == "offline"

    def assets():
        s, b = http(a.dash + "/api/assets", token=token)
        d = {x["id"]: x for x in json.loads(b)}
        assert d["fake-ssh"]["state"] == "SUSPECTED" and d["fake-ssh"]["cve_linked"] == 0
        assert d["sshd"]["state"] == "PROTOCOL_CONFIRMED"

    def chain():
        s, b = http(a.dash + "/api/chain/verify", token=token)
        assert json.loads(b)["ok"]

    def no_unauthorized():
        sim("brute", "--src", "127.0.0.2", "--target", "8.8.8.8:80", expect=2)

    def report_ok():
        s, b = http(a.dash + "/api/report", token=token)
        assert "证据完整性" in b and "校验通过" in b

    def rollback_scan():
        http(a.dash + "/api/bans/127.0.0.12/rollback", "POST",
             {"operator": "selftest", "reason": "清理"}, token)

    for name, fn in [("health", health), ("normal-user-not-banned", normal_not_banned),
                     ("brute-banned-at-5th", brute_banned), ("scan-banned", scan_banned),
                     ("rollback-restores", rollback), ("audit-12-5-5-1-1", audit_counts),
                     ("asset-fake-suspected", assets), ("chain-verify-ok", chain),
                     ("no-unauthorized-target", no_unauthorized),
                     ("report-generated", report_ok)]:
        check(name, fn)
    rollback_scan()
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
