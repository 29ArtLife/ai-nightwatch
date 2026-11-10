"""值班日报：纯模板 + SQL，不调用任何大模型。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def build(store, cfg: dict) -> str:
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    rows = store.events_since(0, 100000)
    today = [r for r in rows if r["ts"] >= start]
    decisions = [r for r in today if r["kind"] == "decision"]
    bans = [r for r in decisions if r["evidence"].get("action") == "ban"]
    observes = [r for r in decisions if r["evidence"].get("action") == "observe"]
    expires = [r for r in decisions if r["evidence"].get("action") == "expire"]
    rollbacks = [r for r in today if r["kind"] == "rollback"]
    obs_by = {}
    for r in observes:
        code = r["evidence"].get("reason_code", "UNKNOWN")
        obs_by[code] = obs_by.get(code, 0) + 1

    lines = [f"# 值班日报 {now.strftime('%Y-%m-%d')}（最近 24 小时）", ""]
    lines.append("## 处置")
    if bans:
        for r in bans:
            e = r["evidence"]
            c = e.get("counts", {})
            lines.append(
                f"- 封禁 `{r['ip']}`（{e.get('reason_code')}）：失败 {c.get('fail', 0)}/"
                f"阈值 {e.get('thresholds', {}).get('fail', 5)}，404 {c.get('s404', 0)}，"
                f"敏感路径 {len(c.get('sensitive_paths', []))}，TTL {e.get('ttl_sec', 600)} 秒")
    else:
        lines.append("- 无封禁")
    lines.append(f"- 到期解除 {len(expires)} 次；人工回滚 {len(rollbacks)} 次")
    for r in rollbacks:
        lines.append(f"  - `{r['ip']}` by {r['evidence'].get('operator')}"
                     f"（{r['evidence'].get('reason')}）")
    lines += ["", "## 未处置（负证据）"]
    if obs_by:
        for code, n in sorted(obs_by.items(), key=lambda x: -x[1]):
            lines.append(f"- {code}：{n} 条")
    else:
        lines.append("- 无观察记录")
    lines += ["", "## 体检"]
    audit = store.latest_audit()
    if audit:
        s = audit["summary"]
        lines.append(f"- 依赖 {s.get('deps')} 个；清单 {s.get('total')} 条；"
                     f"确认 {s.get('confirmed')}；版本不符 {s.get('version_mismatch')}；"
                     f"未引用 {s.get('unreachable')}；仅开发 {s.get('dev_only')}")
        lines.append(f"- 数据源 {audit['source']}；快照 {audit['snapshot_ts'] or '在线'}")
    else:
        lines.append("- 本期未运行体检")
    v = store.verify_chain()
    lines += ["", "## 证据完整性",
              f"- 链上 {v.get('count', 0)} 条，"
              + ("校验通过（哈希链连续）" if v.get("ok") else f"校验失败：{v.get('reason')}"),
              "", "> 本报告由确定性模板生成，未使用大模型参与裁决。"]
    return "\n".join(lines) + "\n"
