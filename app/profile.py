"""攻击者画像：从 UA / 签名 / CRS 规则 / 路径节奏识别工具。"""
from __future__ import annotations

import re

PATTERNS = [
    ("sqlmap", re.compile(r"sqlmap|libinjection|sql injection|942\d{3}", re.I), 0.95),
    ("nikto", re.compile(r"nikto|\b913\d{3}\b", re.I), 0.9),
    ("nmap", re.compile(r"nmap|NW SCAN|ET SCAN|port scan", re.I), 0.9),
    ("hydra", re.compile(r"hydra", re.I), 0.85),
    ("masscan", re.compile(r"masscan", re.I), 0.9),
    ("curl", re.compile(r"^curl/", re.I), 0.5),
]


def identify(ip: str, rows: list[dict]) -> dict:
    texts = []
    paths, rules = set(), []
    first = last = ""
    for r in rows:
        e = r.get("evidence") or {}
        first = first or r["ts"]
        last = r["ts"]
        for k in ("ua", "signature", "crs_message", "message", "rule_id",
                  "reason_code", "honeypot", "path"):
            v = e.get(k)
            if v:
                texts.append(str(v))
        if e.get("path"):
            paths.add(str(e["path"])[:120])
        if r.get("rule_id"):
            rules.append(str(r["rule_id"]))
    blob = " ".join(texts)
    hits = []
    for name, rx, conf in PATTERNS:
        if rx.search(blob):
            hits.append((name, conf))
    hits.sort(key=lambda x: -x[1])
    tool, confidence = (hits[0] if hits else ("unknown", 0.0))
    return {
        "ip": ip, "tool": tool, "confidence": confidence,
        "events": len(rows), "first_seen": first, "last_seen": last,
        "paths": sorted(paths)[:10],
        "rules": list(dict.fromkeys(rules))[:10],
        "matched": [h[0] for h in hits],
        "note": "基于 UA / 签名 / CRS 规则的启发式判断，不是身份确认",
    }
