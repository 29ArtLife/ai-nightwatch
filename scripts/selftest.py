"""端到端自检：CLI 版，假设 daemon 与演示站已启动。只在 Linux 上运行。"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = [sys.executable, "-m", "app.cli"]
PASS, FAIL, SKIP = [], [], []


class Skip(Exception):
    pass


def check(name, fn):
    try:
        fn()
        PASS.append(name)
        print(f"PASS {name}", flush=True)
    except Skip as e:
        SKIP.append(name)
        print(f"SKIP {name}: {e}", flush=True)
    except Exception as e:
        FAIL.append((name, str(e)))
        print(f"FAIL {name}: {e}", flush=True)


def run(*args):
    return subprocess.run([*CLI, *args], cwd=ROOT, capture_output=True, text=True,
                          timeout=120)


def cj(*args):
    p = run(*args)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        raise AssertionError(f"CLI {' '.join(args)} 输出不是 JSON: {p.stdout[:200]} {p.stderr[:200]}")


def sim(*args, expect=None):
    p = subprocess.run([sys.executable, "demo/sim.py", *args], cwd=ROOT,
                       capture_output=True, text=True, timeout=120)
    if expect is not None and p.returncode != expect:
        raise AssertionError(f"sim 退出码 {p.returncode} != {expect}: {p.stderr}")
    return p


def main():
    if platform.system() != "Linux":
        print("SKIP：selftest 依赖 Linux")
        return 0
    os.chdir(ROOT)

    def status():
        d = cj("status", "--json")
        assert d["chain_ok"] and d["events"] >= 0, d

    def sources_online():
        d = cj("status", "--json")
        names = {s["name"]: s["online"] for s in d["sources"]}
        assert names.get("suricata") and names.get("waf") and names.get("nginx"), names

    def fw_status():
        d = cj("fw-status", "--json")
        assert d.get("ok") and "entries" in d, d

    def nft_roundtrip():
        r = subprocess.run(["sudo", "-n", "/usr/local/sbin/nw-fw", "ban",
                            "10.255.255.1", "120"], capture_output=True, text=True)
        if r.returncode != 0:
            raise Skip(f"nw-fw 不可用: {r.stderr.strip()[:120]}")
        try:
            d = cj("fw-status", "--json")
            assert any(e.get("ip") == "10.255.255.1" for e in d["entries"]), d
        finally:
            subprocess.run(["sudo", "-n", "/usr/local/sbin/nw-fw", "unban",
                            "10.255.255.1"], capture_output=True)

    def normal_not_banned():
        sim("normal", "--src", "127.0.0.3", "--interval", "0.2")
        time.sleep(1.5)
        bans = cj("bans", "--json")
        assert all(x["ip"] != "127.0.0.3" for x in bans), "正常用户被误封"

    def brute_banned():
        p = sim("brute", "--src", "127.0.0.2", "--n", "5", "--interval", "0.5")
        lines = p.stdout.strip().splitlines()
        assert lines[-1].endswith("403"), f"封禁后正确密码未被拦截: {lines[-1]}"
        time.sleep(1.5)
        bans = cj("bans", "--json")
        assert any(x["ip"] == "127.0.0.2" for x in bans)

    def scan_banned():
        sim("scan", "--src", "127.0.0.12", "--n", "10", "--interval", "0.15")
        time.sleep(1.5)
        bans = cj("bans", "--json")
        assert any(x["ip"] == "127.0.0.12" for x in bans)

    def rollback():
        p = run("unban", "127.0.0.2")
        assert p.returncode == 0, p.stdout + p.stderr
        time.sleep(0.3)
        lines = sim("brute", "--src", "127.0.0.2", "--n", "1",
                    "--interval", "0.1").stdout
        assert "401" in lines, f"回滚后仍被封: {lines}"

    def audit_counts():
        d = cj("audit", "--json")
        sm = d["summary"]
        assert (sm["total"], sm["confirmed"], sm["version_mismatch"],
                sm["unreachable"], sm["dev_only"]) == (12, 5, 5, 1, 1), sm
        assert sm["source_mode"] == "offline"

    def assets():
        rows = cj("probe", "--json")
        d = {x["id"]: x for x in rows}
        assert d["fake-ssh"]["state"] == "SUSPECTED" and d["fake-ssh"]["cve_linked"] == 0
        assert d["sshd"]["state"] == "PROTOCOL_CONFIRMED"

    def chain():
        assert cj("chain", "--json")["ok"]

    def no_unauthorized():
        sim("brute", "--src", "127.0.0.2", "--target", "8.8.8.8:80", expect=2)

    def waf_blocks():
        p = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--interface", "127.0.0.8", "--max-time", "6",
             "http://127.0.0.1:8081/lab/item?id=1%20OR%201=1"],
            capture_output=True, text=True)
        assert p.stdout.strip() == "403", p.stdout + p.stderr
        rows = cj("events", "--json", "--kind", "waf_alert", "--limit", "10")
        assert any(r["ip"] == "127.0.0.8" for r in rows), rows

    def kill_switch():
        run("unban", "127.0.0.7")
        assert run("auto-response", "off").returncode == 0
        try:
            sim("brute", "--src", "127.0.0.7", "--n", "5", "--interval", "0.2")
            time.sleep(1)
            bans = cj("bans", "--json")
            assert all(x["ip"] != "127.0.0.7" for x in bans), "自动处置已暂停但仍封禁"
        finally:
            run("auto-response", "on")

    def net_scan():
        if not os.path.exists("/run/netns/nw-attacker"):
            raise Skip("netns 未建立")
        p = subprocess.run(
            ["sudo", "-n", "ip", "netns", "exec", "nw-attacker",
             "nmap", "-sS", "-Pn", "-p", "1-200", "--min-rate", "50",
             "--max-retries", "1", "10.200.0.1"],
            capture_output=True, text=True, timeout=60)
        if p.returncode != 0:
            raise Skip(f"nmap 失败: {p.stderr[:120]}")
        time.sleep(2.5)
        bans = cj("bans", "--json")
        assert any(x["ip"] == "10.200.0.2" for x in bans), bans

    def report_ok():
        p = run("report")
        assert "证据完整性" in p.stdout and "校验通过" in p.stdout

    def cleanup():
        for ip in ("127.0.0.2", "127.0.0.7", "127.0.0.8", "127.0.0.12",
                   "10.200.0.2", "10.255.255.1"):
            run("unban", ip)
        run("flush")
        subprocess.run(["sudo", "-n", "/usr/local/sbin/nw-fw", "unban",
                        "10.255.255.1"], capture_output=True)

    for name, fn in [("status", status), ("sources-online", sources_online),
                     ("fw-status-ok", fw_status), ("nft-ban-roundtrip", nft_roundtrip),
                     ("normal-user-not-banned", normal_not_banned),
                     ("brute-banned-at-5th", brute_banned), ("scan-banned", scan_banned),
                     ("rollback-restores", rollback), ("audit-12-5-5-1-1", audit_counts),
                     ("asset-fake-suspected", assets), ("chain-verify-ok", chain),
                     ("no-unauthorized-target", no_unauthorized),
                     ("waf-blocks-sqli", waf_blocks), ("kill-switch", kill_switch),
                     ("net-scan-banned", net_scan), ("report-generated", report_ok)]:
        check(name, fn)
    cleanup()
    print(f"\n{len(PASS)} passed, {len(SKIP)} skipped, {len(FAIL)} failed")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
