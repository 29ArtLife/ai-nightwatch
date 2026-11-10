"""OSV 版本范围判定：ECOSYSTEM range 优先，CPE_RANGE / versions 兜底。

返回 True/False/None，None 表示证据不足（UNDETERMINED），绝不猜。
"""
from __future__ import annotations

from packaging.version import InvalidVersion, Version


def _v(s: str) -> Version | None:
    try:
        return Version(s.strip().lstrip("vV"))
    except (InvalidVersion, AttributeError):
        return None


def _events_to_intervals(events: list[dict]) -> list[tuple[Version | None, Version | None, bool]]:
    """事件序列 → [(lo, hi, hi_inclusive)]；lo=None 表示从最早版本起。"""
    out, lo = [], None
    for e in events:
        for k, raw in e.items():
            v = None if str(raw) == "0" else _v(str(raw))
            if k == "introduced":
                lo = v
            elif k in ("fixed", "limit"):
                out.append((lo, v, False))
                lo = None
            elif k == "last_affected":
                out.append((lo, v, True))
                lo = None
    if lo is not None:
        out.append((lo, None, False))
    return out


def _in_intervals(ver: Version, intervals) -> bool:
    for lo, hi, incl in intervals:
        if lo is not None and ver < lo:
            continue
        if hi is None:
            return True
        if incl and ver <= hi:
            return True
        if not incl and ver < hi:
            return True
    return False


def _entry_intervals(entry: dict):
    intervals, labels = [], []
    for r in entry.get("ranges", []):
        if r.get("type") == "ECOSYSTEM":
            iv = _events_to_intervals(r.get("events", []))
            intervals += iv
            labels += [_fmt(lo, hi, incl) for lo, hi, incl in iv]
        for ee in r.get("database_specific", {}).get("extracted_events", []):
            if ee.get("source") == "CPE_RANGE":
                iv = _events_to_intervals(ee.get("range", []))
                intervals += iv
                labels += [_fmt(lo, hi, incl) + " (CPE)" for lo, hi, incl in iv]
    return intervals, labels


def _fmt(lo, hi, incl) -> str:
    left = ">=0" if lo is None else f">={lo}"
    if hi is None:
        return left
    return f"{left}, {'<=' if incl else '<'}{hi}"


def entry_hits(entry: dict, version: str) -> tuple[bool | None, str]:
    """单条 affected 记录是否命中。返回 (命中?, 范围文字)。"""
    intervals, labels = _entry_intervals(entry)
    ver = _v(version)
    if ver is None:
        return None, "pinned 版本无法解析"
    if intervals:
        return _in_intervals(ver, intervals), "; ".join(labels)
    versions = entry.get("versions") or []
    if versions:
        exact = {_v(x) for x in versions} - {None}
        return ver in exact, f"受影响版本列表（{len(versions)} 个）"
    return None, "无可比对的版本范围（仅 GIT range）"


def resolve(records: list[dict], pkg: str, version: str) -> dict:
    """在一组别名记录里找该包，返回 {hit, ranges, records, eco}。"""
    pkg_l = pkg.lower().replace("_", "-")
    hits: list[bool] = []
    ranges: list[str] = []
    matched: list[str] = []
    eco = ""
    for rec in records:
        for a in rec.get("affected", []):
            name = a.get("package", {}).get("name", "")
            cpe = ""
            for r in a.get("ranges", []):
                for ee in r.get("database_specific", {}).get("extracted_events", []):
                    cpe = ee.get("cpe", "") or cpe
            name_l = name.lower().replace("_", "-")
            cpe_ok = cpe and (pkg_l.replace("-", "") in cpe.lower().replace("-", "")
                              or pkg_l.split("-")[0] in cpe.lower())
            if not (name_l == pkg_l or (not name and cpe_ok)):
                continue
            hit, rng = entry_hits(a, version)
            if hit is None:
                continue
            hits.append(hit)
            ranges.append(rng)
            matched.append(rec.get("id", ""))
            eco = a.get("package", {}).get("ecosystem", "") or eco
    if not hits:
        return {"hit": None, "ranges": [], "records": matched, "eco": eco}
    return {"hit": any(hits), "ranges": sorted(set(ranges)), "records": matched, "eco": eco}
