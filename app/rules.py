"""外部告警 → 内部规则映射。不锁 Suricata sid，按类别 + 签名正则；CRS 按 rule id 段。"""
from __future__ import annotations

import re

SURICATA = [
    (re.compile(r"scan|nmap|nikto|masscan|vulnerability scanner", re.I),
     "NET_SCAN.v1", 1800, 3, 60, True),
    # Suricata 规则自身已做 count/seconds 阈值，这里只按“命中即处置”
    (re.compile(r"flood|denial of service|\bdos\b", re.I),
     "NET_DOS.v1", 600, 1, 10, True),
    (re.compile(r"exploit|web application attack|privilege gain", re.I),
     "NET_EXPLOIT.v1", 3600, 1, 60, True),
    (re.compile(r"trojan|malware|cins|command and control", re.I),
     "NET_C2.v1", 3600, 1, 60, True),
]

CRS = {
    913: ("WAF_SCANNER.v1", 3600, True),
    920: ("WAF_PROTOCOL.v1", 600, False),
    921: ("WAF_PROTOCOL.v1", 600, False),
    930: ("WAF_LFI.v1", 3600, True),
    931: ("WAF_RFI.v1", 3600, True),
    932: ("WAF_RCE.v1", 3600, True),
    933: ("WAF_RCE.v1", 3600, True),
    934: ("WAF_RCE.v1", 3600, True),
    944: ("WAF_RCE.v1", 3600, True),
    941: ("WAF_XSS.v1", 1800, True),
    942: ("WAF_SQLI.v1", 3600, True),
    949: ("WAF_BLOCK.v1", 600, True),
}


def map_suricata(category: str, signature: str, severity=None) -> dict:
    text = f"{category or ''} {signature or ''}"
    for rx, rule, ttl, threshold, window, auto in SURICATA:
        if rx.search(text):
            return {"rule": rule, "ttl": ttl, "threshold": threshold,
                    "window": window, "auto": auto}
    return {"rule": "NET_ALERT.v1", "ttl": 0, "threshold": 0,
            "window": 60, "auto": False}


def map_crs(rule_id) -> dict:
    try:
        n = int(rule_id)
    except (TypeError, ValueError):
        return {"rule": "WAF_ALERT.v1", "ttl": 0, "auto": False}
    seg = n // 1000
    rule, ttl, auto = CRS.get(seg, ("WAF_ALERT.v1", 0, False))
    return {"rule": rule, "ttl": ttl, "auto": auto}
