"""处置执行 + 留痕：封禁/观察/到期/回滚都写哈希链事件。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _until(now_iso: str, ttl: int) -> str:
    dt = datetime.fromisoformat(now_iso.replace("Z", "+00:00")) + timedelta(seconds=ttl)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Enforcer:
    def __init__(self, store, cfg: dict, publish=None):
        self.store = store
        self.cfg = cfg
        self.publish = publish or (lambda row: None)
        self._expired_notified: set[tuple[str, str]] = set()

    def handle(self, sig: dict, verdict: dict, ts: str) -> dict:
        action = verdict["action"]
        evidence = dict(verdict["evidence"])
        evidence["action"] = action
        evidence["reason_code"] = verdict["reason_code"]
        if verdict["ttl_sec"]:
            evidence["ttl_sec"] = verdict["ttl_sec"]
        row = self.store.append_event(
            ts=ts, kind="decision", ip=sig["ip"], rule_id=sig["rule_id"],
            evidence=evidence, raw_line=(sig.get("sample_raw") or [""])[0])
        if action == "ban":
            self.store.ban(sig["ip"], _until(ts, verdict["ttl_sec"]),
                           decision_event=row["id"], operator="auto",
                           reason=verdict["reason_code"])
            row["until_ts"] = _until(ts, verdict["ttl_sec"])
        self.publish(row)
        return row

    def sweep(self, now_iso: str) -> list[dict]:
        out = []
        for b in self.store.expired_bans(now_iso):
            key = (b["ip"], b["until_ts"])
            if key in self._expired_notified:
                continue
            self._expired_notified.add(key)
            row = self.store.append_event(
                ts=now_iso, kind="decision", ip=b["ip"],
                rule_id="BAN_EXPIRED",
                evidence={"action": "expire", "reason_code": "TTL_EXPIRED",
                          "ban_until": b["until_ts"],
                          "decision_event": b["decision_event"]})
            self.publish(row)
            out.append(row)
        return out

    def rollback(self, ip: str, operator: str, reason: str, now_iso: str) -> dict | None:
        if not self.store.rollback(ip, operator, reason):
            return None
        row = self.store.append_event(
            ts=now_iso, kind="rollback", ip=ip, rule_id="MANUAL_ROLLBACK",
            evidence={"action": "rollback", "operator": operator, "reason": reason})
        self.publish(row)
        return row

    def list_active(self, now_iso: str) -> list[dict]:
        return self.store.active_bans(now_iso)


def apply_production_ban(ip: str, ttl: int) -> None:
    """本期不实现。生产落地示例：
    sudo ipset create nightwatch_block hash:ip timeout 600
    sudo ipset add nightwatch_block {ip} timeout {ttl}
    sudo iptables -I INPUT -m set --match-set nightwatch_block src -j DROP
    回滚：sudo ipset del nightwatch_block {ip}
    注意：sudoers 只授权这三条命令，不可给全量 root。
    """
    raise NotImplementedError("本期为应用层封禁，见方案 3.3")
