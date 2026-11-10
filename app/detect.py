"""滑动窗口检测：每 IP 6×10s 分桶，输出 Signal（不做裁决）。"""
from __future__ import annotations

from datetime import datetime, timezone

BUCKET_SEC = 10


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
        # ponytail: IP 表上限 20000 条 LRU；演示与单机内网远达不到，超限淘汰最久未活跃，
        # 历史已落库可复盘；升级路径是 Count-Min Sketch。
        self.max_ips = 20000

    def _st(self, ip: str, now: datetime) -> dict:
        st = self.state.setdefault(ip, {"b": {}, "last": 0.0})
        st["last"] = now.timestamp()
        return st

    def _prune(self, st: dict, now: datetime, win: int):
        cutoff = int(now.timestamp()) // BUCKET_SEC - win // BUCKET_SEC
        for k in [k for k in st["b"] if k < cutoff]:
            del st["b"][k]

    def _bucket(self, st: dict, now: datetime) -> dict:
        k = int(now.timestamp()) // BUCKET_SEC
        return st["b"].setdefault(k, {"f": 0, "s": 0, "p404": 0,
                                      "paths": set(), "users": set()})

    def _sum(self, st: dict, now: datetime, win: int) -> dict:
        cutoff = int(now.timestamp()) // BUCKET_SEC - win // BUCKET_SEC
        f = s = p404 = 0
        paths, users = set(), set()
        for k, b in st["b"].items():
            if k < cutoff:
                continue
            f += b["f"]; s += b["s"]; p404 += b["p404"]
            paths |= b["paths"]; users |= b["users"]
        return {"fails": f, "successes": s, "s404": p404,
                "paths": sorted(paths), "users": sorted(users)}

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

    def feed(self, ev, now: datetime | None = None) -> dict | None:
        now = now or datetime.fromisoformat(ev.ts.replace("Z", "+00:00"))
        st = self._st(ev.ip, now)
        self._prune(st, now, max(self.win_brute, self.win_scan))
        b = self._bucket(st, now)
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

        scan = self._sum(st, now, self.win_scan)
        brute = self._sum(st, now, self.win_brute)
        self.last_counts[ev.ip] = {
            "fail": brute["fails"], "success": brute["successes"],
            "s404": scan["s404"], "sensitive_paths": scan["paths"][:8],
        }
        sig = None

        if (scan["s404"] >= self.s404_th and len(scan["paths"]) >= self.sens_th
                and self._emit(ev.ip, "PATH_SCAN", now)):
            sig = self._signal(ev, "PATH_SCAN.v1", now, scan, self.win_scan,
                               extra={"status_404": scan["s404"],
                                      "distinct_sensitive_paths": len(scan["paths"]),
                                      "sensitive_paths": scan["paths"][:8]})
        elif (brute["fails"] >= self.fail_th and brute["successes"] == 0
              and self._emit(ev.ip, "BRUTE_FORCE", now)):
            sig = self._signal(ev, "BRUTE_FORCE.v1", now, brute, self.win_brute,
                               extra={"fail_count": brute["fails"],
                                      "distinct_users": len(brute["users"])})
        elif ev.kind == "login_success" and brute["fails"] > 0 and self._emit(ev.ip, "SUCCESS", now):
            sig = self._signal(ev, "BRUTE_FORCE.v1", now, brute, self.win_brute,
                               extra={"fail_count": brute["fails"],
                                      "observation": "SUCCESS_IN_WINDOW"})
        elif brute["fails"] >= 3 and brute["successes"] == 0 and self._emit(ev.ip, "BELOW", now):
            sig = self._signal(ev, "BRUTE_FORCE.v1", now, brute, self.win_brute,
                               extra={"fail_count": brute["fails"],
                                      "observation": "BELOW_THRESHOLD"})
        return sig

    def _signal(self, ev, rule: str, now: datetime, counts: dict, win: int,
                extra: dict | None = None) -> dict:
        ev_ts = now.timestamp()
        return {
            "ip": ev.ip, "rule_id": rule,
            "window": {"start": _iso(ev_ts - win), "end": _iso(ev_ts), "sec": win},
            "counts": {"fail": counts["fails"], "success": counts["successes"],
                       "distinct_users": len(counts["users"]), "users": counts["users"][:5],
                       "s404": counts["s404"], "sensitive_paths": counts["paths"][:8]},
            "thresholds": {"fail": self.fail_th, "s404": self.s404_th,
                           "sensitive_paths": self.sens_th},
            "sample_raw": [ev.raw_line[:500]],
            "ua": ev.ua,
            **(extra or {}),
        }


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
