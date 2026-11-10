"""漏洞验真管线：外部扫描清单 → 按 CVE 反查 OSV → 版本/作用域/可达性三层核验。

输入是扫描器的「按包名粗筛」结果，不依赖 querybatch 的版本过滤；
因此「版本不在受影响范围」这一层才真的能产出。
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from packaging.utils import canonicalize_name  # noqa: E402

from verify import alias as alias_mod  # noqa: E402
from verify import deps as deps_mod  # noqa: E402
from verify import reach as reach_mod  # noqa: E402
from verify import vrange  # noqa: E402
from verify.osv import OsvClient  # noqa: E402

ORDER = ["CONFIRMED", "DEV_ONLY", "UNREACHABLE", "VERSION_MISMATCH", "UNDETERMINED"]
STRENGTH = {v: i for i, v in enumerate(ORDER)}


def _verdict(hit, scope, sites, dynamic):
    if hit is None:
        return "UNDETERMINED", "NO_VERSION_RANGE"
    if hit is False:
        return "VERSION_MISMATCH", "OUT_OF_RANGE"
    if scope == "dev":
        return "DEV_ONLY", "DEV_SCOPE"
    if sites is None:
        return "UNREACHABLE", "NO_MODULE_MAPPING"
    if not sites:
        return "UNREACHABLE", "NOT_IMPORTED"
    return "CONFIRMED", "IN_RANGE_REACHABLE"


def run_audit(project_dir: str, cfg: dict, raw_path: str | None = None,
              include_querybatch: bool | None = None) -> dict:
    project_dir = os.path.abspath(project_dir)
    raw_path = raw_path or os.path.join(project_dir, "raw_findings.json")
    deps = deps_mod.load_project(project_dir)
    dep_by = {d["canonical"]: d for d in deps}
    aliases = reach_mod.load_aliases(cfg["reach"]["aliases_file"])
    scanned = reach_mod.scan(project_dir)
    osv = OsvClient(cfg)

    with open(raw_path, encoding="utf-8") as f:
        raw = json.load(f)

    findings, seen = [], set()
    for item in raw:
        pkg = item["pkg"]
        canon = canonicalize_name(pkg)
        dep = dep_by.get(canon)
        version = (dep or {}).get("version") or item.get("version")
        scope = (dep or {}).get("scope", item.get("scope", "prod"))
        cve = item["cve"]
        records = osv.records_for(cve)
        groups = alias_mod.group(records)
        gkey = alias_mod.canonical(records)
        if (gkey, canon) in seen:
            continue
        seen.add((gkey, canon))
        res = vrange.resolve(records, pkg, version) if version else {
            "hit": None, "ranges": [], "records": [], "eco": ""}
        sites = reach_mod.sites_for(pkg, aliases, scanned)
        verdict, reason = _verdict(res["hit"], scope, sites, scanned["dynamic"])
        findings.append({
            "group_key": gkey, "pkg": pkg, "version": version, "cve": cve,
            "scope": scope, "verdict": verdict, "reason_code": reason,
            "evidence": {
                "pinned": version,
                "affected_range": res["ranges"],
                "matched_records": res["records"],
                "aliases": alias_mod.all_aliases(records),
                "scope": scope,
                "import_site": sites,
                "dynamic_imports_uncovered": scanned["dynamic"],
                "parse_errors": scanned["parse_errors"],
                "source": "raw_findings",
            },
        })

    if include_querybatch if include_querybatch is not None else cfg["osv"].get("include_querybatch"):
        try:
            results = osv.querybatch([d for d in deps if d["version"]])
            for dep, res in zip([d for d in deps if d["version"]], results):
                for v in res.get("vulns", []):
                    recs = osv.records_for(v["id"])
                    gkey = alias_mod.canonical(recs)
                    if (gkey, dep["canonical"]) in seen:
                        continue
                    seen.add((gkey, dep["canonical"]))
                    sites = reach_mod.sites_for(dep["name"], aliases, scanned)
                    verdict, reason = _verdict(True, dep["scope"], sites, scanned["dynamic"])
                    findings.append({
                        "group_key": gkey, "pkg": dep["name"], "version": dep["version"],
                        "cve": v["id"], "scope": dep["scope"], "verdict": verdict,
                        "reason_code": reason,
                        "evidence": {"pinned": dep["version"], "affected_range": ["querybatch in-range"],
                                     "matched_records": [v["id"]],
                                     "aliases": alias_mod.all_aliases(recs), "scope": dep["scope"],
                                     "import_site": sites,
                                     "dynamic_imports_uncovered": scanned["dynamic"],
                                     "source": "querybatch"}})
        except Exception as e:
            findings.append({"group_key": "ENRICH", "pkg": "-", "version": "-", "cve": "-",
                             "scope": "-", "verdict": "UNDETERMINED", "reason_code": "ENRICH_FAILED",
                             "evidence": {"error": str(e)}})

    summary = {"total": len(findings), "deps": len(deps)}
    for v in ORDER:
        summary[v.lower()] = sum(1 for f in findings if f["verdict"] == v)
    summary["snapshot"] = osv.snapshot_meta.get("generated_at", "")
    summary["source_mode"] = osv.mode
    return {"project": project_dir, "summary": summary, "findings": findings,
            "snapshot_ts": osv.snapshot_meta.get("generated_at", ""), "source": osv.mode}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", default="demo/demo_project")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--save-db", action="store_true")
    a = ap.parse_args()
    cfg = __import__("app.config", fromlist=["load"]).load()
    result = run_audit(a.project, cfg)
    if a.save_db:
        from app.store import Store
        store = Store("data/nightwatch.db")
        run_id = store.save_audit(result["project"], result["source"],
                                  result["snapshot_ts"], result["summary"], result["findings"])
        result["run_id"] = run_id
    if a.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        s = result["summary"]
        print(f"依赖 {s['deps']} 个，发现 {s['total']} 条：确认 {s['confirmed']} / "
              f"版本不符 {s['version_mismatch']} / 未引用 {s['unreachable']} / "
              f"仅开发 {s['dev_only']} / 待定 {s['undetermined']}")
        for f in result["findings"]:
            print(f"  [{f['verdict']:16}] {f['pkg']} {f['version']} {f['cve']} "
                  f"({f['reason_code']})")


if __name__ == "__main__":
    main()
