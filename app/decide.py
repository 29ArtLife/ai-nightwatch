"""验真裁决：纯函数，无 I/O、无时钟副作用。顺序本身就是可解释性。"""
from __future__ import annotations


def decide(sig: dict, cfg: dict, now_iso: str, *, whitelisted: bool,
           already_banned: bool, auto_enabled: bool) -> dict:
    ttl = int(cfg["enforce"]["default_ttl_sec"])
    thresholds = sig.get("thresholds", {})
    ev = {
        "rule_id": sig["rule_id"],
        "window": sig["window"],
        "counts": sig["counts"],
        "thresholds": thresholds,
        "ua": sig.get("ua", ""),
        "whitelist": {"checked": True, "hit": whitelisted,
                      "rules": cfg["enforce"].get("whitelist_ips", [])},
        "observation": sig.get("observation"),
        "negatives": [],
    }
    negatives: list[str] = []

    def verdict(action: str, reason: str, note: str, ttl_sec: int = 0) -> dict:
        if note:
            negatives.append(note)
        ev["negatives"] = negatives
        return {"action": action, "reason_code": reason,
                "ttl_sec": ttl_sec, "evidence": ev, "decided_at": now_iso}

    if not auto_enabled:
        return verdict("alert", "AUTO_DISABLED", "自动处置已暂停，仅告警")

    if whitelisted:
        return verdict("no_action", "WHITELIST",
                       f"命中白名单（{', '.join(ev['whitelist']['rules'])}），永不处置")

    if already_banned:
        return verdict("observe", "ALREADY_BANNED", "该 IP 已在封禁期内，不重复处置")

    if sig["rule_id"] == "PATH_SCAN.v1":
        return verdict("ban", "PATH_SCAN",
                       "", ttl)

    if ev["counts"]["success"] > 0:
        return verdict("observe", "SUCCESS_IN_WINDOW",
                       f"窗口内失败 {ev['counts']['fail']} 次但成功登录 "
                       f"{ev['counts']['success']} 次，判定为用户手滑")

    if ev["counts"]["fail"] >= thresholds.get("fail", 5):
        return verdict("ban", "BRUTE_FORCE", "", ttl)

    return verdict("observe", "BELOW_THRESHOLD",
                   f"失败 {ev['counts']['fail']} 次 < 阈值 {thresholds.get('fail', 5)}，仅记录")
