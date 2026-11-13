"""滑动窗口检测：应用层 + 网络层 + WAF 告警，输出 Signal（不做裁决）。"""
from __future__ import annotations

from datetime import datetime, timezone

from .rules import map_crs, map_suricata

BUCKET_SEC = 1  # 1 秒桶，避免 10 秒桶把窗口边界外的旧事件算进来


class Detector:
    def __init__(self, cfg: dict):
        b = cfg["detect"]["brute"]
        s = cfg["detect"]["scan"]
        self.win_brute = int(b["window_sec"])
        self.fail_th = int(b["fail_threshold"])
        self.win_scan = int(s["window_sec"])
        self.s404_th = int(s["status_404_threshold"])
        self.sens_th = int(s["distinct_sensitive_paths"])
        self.prefixes = [p.lstrip("/") for p in s.get("sensitive_prefixes", [])]
        self.cooldown = int(cfg["enforce"]["cooldown_sec"])
        self.state: dict[str, dict] = {}
        self.last_emit: dict[tuple[str, str], float] = {}
        self.last_counts: dict[str, dict] = {}
        # ponytail: IP 表上限 20000 条 LRU；高流量时按最后活跃时间淘汰，历史已落库。
        self.max_ips = 20000

    # ---------- 窗口 ----------
    def _st(self, ip: str, now: datetime) -> dict:
        st = self.state.get(ip)
        if st is None:
            if len(self.state) >= self.max_ips:
                oldest = min(self.state, key=lambda k: self.state[k]["last"])
                self.state.pop(oldest, None)
            st = self.state[ip] = {"b": {}, "last": 0.0}
        st["last"] = now.timestamp()
        return st

    def _bucket(self, st: dict, now: datetime) -> dict:
        k = int(now.timestamp()) // BUCKET_SEC
        return st["b"].setdefault(k, {
            "f": 0, "s": 0, "p404": 0, "paths": set(), "users": set(),
            "ids": 0, "waf": 0, "req": 0, "r429": 0, "hp": 0,
            "id_counts": {}, "waf_counts": {},
        })

    def _prune(self, st: dict, now: datetime, win: int):
        cutoff = int(now.timestamp()) // BUCKET_SEC - win // BUCKET_SEC
        for k in [k for k in st["b"] if k < cutoff]:
            del st["b"][k]

    def _sum(self, st: dict, now: datetime, win: int) -> dict:
        cutoff = int(now.timestamp()) // BUCKET_SEC - win // BUCKET_SEC
        f = s = p404 = ids = waf = req = r429 = hp = 0
        paths, users = set(), set()
        id_counts: dict[str, int] = {}
        waf_counts: dict[str, int] = {}
        for k, b in st["b"].items():
            if k < cutoff:
                continue
            f += b["f"]; s += b["s"]; p404 += b["p404"]
            ids += b["ids"]; waf += b["waf"]; req += b["req"]; r429 += b["r429"]
            hp += b.get("hp", 0)
            paths |= b["paths"]; users |= b["users"]
            for r, n in b["id_counts"].items():
                id_counts[r] = id_counts.get(r, 0) + n
            for r, n in b["waf_counts"].items():
                waf_counts[r] = waf_counts.get(r, 0) + n
        return {"fails": f, "successes": s, "s404": p404,
                "paths": sorted(paths), "users": sorted(users),
                "ids": ids, "waf": waf, "req": req, "r429": r429, "hp": hp,
                "id_counts": id_counts, "waf_counts": waf_counts}

    def _emit(self, ip: str, kind: str, now: datetime, cool: int | None = None) -> bool:
        key = (ip, kind)
        if now.timestamp() - self.last_emit.get(key, 0) < (cool or self.cooldown):
            return False
        self.last_emit[key] = now.timestamp()
        return True

    @staticmethod
    def _sensitive(path: str, prefixes: list[str]) -> bool:
        p = path.lstrip("/").lower()
        return any(p.startswith(x.lower()) for x in prefixes)

    # ---------- 输入 ----------
    def feed(self, ev, now: datetime | None = None) -> dict | None:
        now = now or datetime.fromisoformat(ev.ts.replace("Z", "+00:00"))
        st = self._st(ev.ip, now)
        self._prune(st, now, max(self.win_brute, self.win_scan))
        b = self._bucket(st, now)
        extra = ev.extra or {}

        if ev.kind == "login_fail":
            b["f"] += 1
            if ev.user:
                b["users"].add(ev.user)
        elif ev.kind == "login_success":
            b["s"] += 1
            if ev.user:
                b["users"].add(ev.user)
        elif ev.kind == "http_404":
            b["p404"] += 1
            if self._sensitive(ev.path, self.prefixes):
                b["paths"].add(ev.path)
        elif ev.kind == "http_429":
            b["req"] += 1
            b["r429"] += 1
        elif ev.kind == "http_request":
            b["req"] += 1
        elif ev.kind == "honeypot":
            b["hp"] += 1
        elif ev.kind == "net_alert":
            m = map_suricata(str(extra.get("category", "")),
                             str(extra.get("signature", "")), extra.get("severity"))
            b["ids"] += 1
            b["id_counts"][m["rule"]] = b["id_counts"].get(m["rule"], 0) + 1
            ev._mapped = m
        elif ev.kind == "waf_alert":
            m = map_crs(extra.get("rule_id"))
            b["waf"] += 1
            b["waf_counts"][m["rule"]] = b["waf_counts"].get(m["rule"], 0) + 1
            ev._mapped = m

        scan = self._sum(st, now, self.win_scan)
        brute = self._sum(st, now, self.win_brute)
        self.last_counts[ev.ip] = {
            "fail": brute["fails"], "success": brute["successes"],
            "s404": scan["s404"], "sensitive_paths": scan["paths"][:8],
            "ids": scan["ids"], "waf": scan["waf"], "req": scan["req"], "r429": scan["r429"],
        }

        # 应用层
        if ev.kind == "http_404" and (scan["s404"] >= self.s404_th
                                      and len(scan["paths"]) >= self.sens_th
                                      and self._emit(ev.ip, "PATH_SCAN", now)):
            return self._signal(ev, "PATH_SCAN.v1", now, scan, self.win_scan,
                                {"s404": scan["s404"],
                                 "distinct_sensitive_paths": len(scan["paths"]),
                                 "sensitive_paths": scan["paths"][:8], "ttl_sec": 600})

        if ev.kind in ("login_fail", "login_success"):
            if (brute["fails"] >= self.fail_th and brute["successes"] == 0
                    and self._emit(ev.ip, "BRUTE_FORCE", now)):
                return self._signal(ev, "BRUTE_FORCE.v1", now, brute, self.win_brute,
                                    {"fail_count": brute["fails"],
                                     "distinct_users": len(brute["users"]),
                                     "ttl_sec": 600})
            if ev.kind == "login_success" and brute["fails"] > 0 and self._emit(ev.ip, "SUCCESS", now):
                return self._signal(ev, "BRUTE_FORCE.v1", now, brute, self.win_brute,
                                    {"fail_count": brute["fails"],
                                     "observation": "SUCCESS_IN_WINDOW", "ttl_sec": 0})
            if brute["fails"] >= 3 and brute["successes"] == 0 and self._emit(ev.ip, "BELOW", now):
                return self._signal(ev, "BRUTE_FORCE.v1", now, brute, self.win_brute,
                                    {"fail_count": brute["fails"],
                                     "observation": "BELOW_THRESHOLD", "ttl_sec": 0})

        # 蜜罐：命中即高置信，直接封
        if ev.kind == "honeypot" and self._emit(ev.ip, "HONEYPOT", now):
            s = self._sum(st, now, 60)
            return self._signal(ev, "HONEYPOT.v1", now, s, 60, {
                "honeypot": extra.get("honeypot", ""), "ttl_sec": 3600})

        # 网络层 / WAF
        if ev.kind == "net_alert":
            m = getattr(ev, "_mapped", None) or map_suricata(
                str(extra.get("category", "")), str(extra.get("signature", "")),
                extra.get("severity"))
            if m["rule"] == "NET_ALERT.v1":
                return None
            win = int(m["window"])
            s = self._sum(st, now, win)
            if (s["id_counts"].get(m["rule"], 0) >= max(1, int(m["threshold"]))
                    and self._emit(ev.ip, m["rule"], now)):
                return self._signal(ev, m["rule"], now, s, win, {
                    "signature": extra.get("signature", ""),
                    "category": extra.get("category", ""),
                    "severity": extra.get("severity"),
                    "alert_count": s["id_counts"].get(m["rule"], 0),
                    "ttl_sec": m["ttl"], "auto": m["auto"],
                })

        if ev.kind == "waf_alert":
            m = getattr(ev, "_mapped", None) or map_crs(extra.get("rule_id"))
            if m["rule"] == "WAF_ALERT.v1":
                return None
            s = self._sum(st, now, 60)
            if (s["waf_counts"].get(m["rule"], 0) >= 1
                    and self._emit(ev.ip, m["rule"], now)):
                return self._signal(ev, m["rule"], now, s, 60, {
                    "crs_rule": extra.get("rule_id"),
                    "crs_message": extra.get("message", ""),
                    "severity": extra.get("severity"),
                    "uri": extra.get("uri", ""),
                    "alert_count": s["waf_counts"].get(m["rule"], 0),
                    "ttl_sec": m["ttl"], "auto": m["auto"],
                })

        if ev.kind == "http_429":
            s = self._sum(st, now, 60)
            if (s["r429"] >= 60 or s["req"] >= 600) and self._emit(ev.ip, "HTTP_FLOOD", now):
                return self._signal(ev, "HTTP_FLOOD.v1", now, s, 60, {
                    "requests_60s": s["req"], "429_60s": s["r429"], "ttl_sec": 300,
                })
        return None

    def _signal(self, ev, rule: str, now: datetime, counts: dict, win: int,
                extra: dict | None = None) -> dict:
        ev_ts = now.timestamp()
        return {
            "ip": ev.ip, "rule_id": rule,
            "window": {"start": _iso(ev_ts - win), "end": _iso(ev_ts), "sec": win},
            "counts": {
                "fail": counts.get("fails", 0), "success": counts.get("successes", 0),
                "distinct_users": len(counts.get("users", [])),
                "users": counts.get("users", [])[:5],
                "s404": counts.get("s404", 0),
                "sensitive_paths": counts.get("paths", [])[:8],
                "ids": counts.get("ids", 0), "waf": counts.get("waf", 0),
                "requests_60s": counts.get("req", 0), "429_60s": counts.get("r429", 0),
            },
            "thresholds": {"fail": self.fail_th, "s404": self.s404_th,
                           "sensitive_paths": self.sens_th},
            "sample_raw": [ev.raw_line[:500]],
            "ua": ev.ua,
            **(extra or {}),
        }


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
