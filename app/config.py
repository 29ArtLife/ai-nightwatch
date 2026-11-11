"""配置加载：tomllib 只读，白名单规范化为 ipaddress 网段。"""
from __future__ import annotations

import ipaddress
import tomllib
from pathlib import Path


def load(path: str | Path = "config.toml") -> dict:
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
    cfg.setdefault("mode", {}).setdefault("demo", False)
    cfg.setdefault("mode", {}).setdefault("auto_response", True)
    cfg.setdefault("server", {})
    cfg["server"].setdefault("host", "127.0.0.1")
    cfg["server"].setdefault("port", 8080)
    cfg["server"].setdefault("token", "")
    cfg.setdefault("enforce", {}).setdefault("default_ttl_sec", 600)
    cfg["enforce"].setdefault("cooldown_sec", 30)
    cfg["enforce"].setdefault("whitelist_ips", [])
    cfg.setdefault("detect", {}).setdefault("brute", {}).setdefault("window_sec", 60)
    cfg["detect"]["brute"].setdefault("fail_threshold", 5)
    cfg.setdefault("detect", {}).setdefault("scan", {}).setdefault("window_sec", 60)
    cfg["detect"]["scan"].setdefault("status_404_threshold", 8)
    cfg["detect"]["scan"].setdefault("distinct_sensitive_paths", 5)
    cfg["detect"]["scan"].setdefault("sensitive_prefixes", [])
    cfg.setdefault("osv", {}).setdefault("mode", "offline")
    cfg["osv"].setdefault("snapshot_dir", "osv")
    cfg["osv"].setdefault("api", "https://api.osv.dev")
    cfg["osv"].setdefault("include_querybatch", False)
    cfg.setdefault("asset", {}).setdefault("timeout_sec", 2.0)
    cfg.setdefault("reach", {}).setdefault("project_dir", "demo/demo_project")
    cfg["reach"].setdefault("aliases_file", "demo/demo_project/module_aliases.json")
    cfg.setdefault("agent", {})
    cfg["agent"].setdefault("autonomy", "approve")
    cfg["agent"].setdefault("auto_ban_ttl", 600)
    cfg["agent"].setdefault("max_auto_bans_per_min", 3)
    cfg["agent"].setdefault("autopilot", False)
    cfg["agent"].setdefault("autopilot_interval_sec", 120)
    cfg["agent"].setdefault("autopilot_max_calls_per_hour", 20)
    cfg["agent"].setdefault("autopilot_max_alerts", 8)
    cfg.setdefault("fw", {})
    cfg["fw"].setdefault("enabled", False)
    cfg["fw"].setdefault("wrapper", "/usr/local/sbin/nw-fw")
    cfg["fw"].setdefault("timeout_sec", 5)
    return cfg


def whitelist_nets(cfg: dict):
    """字符串白名单 → 规范化网段集合。非法项直接丢掉并保留原文以便报警。"""
    nets, bad = [], []
    for raw in cfg["enforce"]["whitelist_ips"]:
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            bad.append(raw)
    return nets, bad


def ip_allowed(ip: str, nets) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)
