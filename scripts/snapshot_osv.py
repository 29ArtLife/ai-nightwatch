"""联网生成 OSV 离线快照：只存原始响应，一字节不改，可对拍线上。"""
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)
os.environ["NW_OSV_MODE"] = "online"

from app.config import load  # noqa: E402
from verify.osv import OsvClient, OsvUnavailable  # noqa: E402


def main():
    cfg = load("config.toml")
    project = os.path.join(ROOT, "demo/demo_project")
    with open(os.path.join(project, "raw_findings.json"), encoding="utf-8") as f:
        raw = json.load(f)
    out = os.path.join(ROOT, cfg["osv"]["snapshot_dir"], "vulns")
    os.makedirs(out, exist_ok=True)
    client = OsvClient(cfg)
    ids, failed = set(), []
    for item in raw:
        try:
            recs = client.records_for(item["cve"])
        except OsvUnavailable as e:
            failed.append(f"{item['cve']}: {e}")
            continue
        for r in recs:
            ids.add(r["id"])
            with open(os.path.join(out, f"{r['id']}.json"), "w", encoding="utf-8") as f:
                json.dump(r, f, ensure_ascii=False, sort_keys=True, indent=1)
    h = hashlib.sha256()
    for vid in sorted(ids):
        with open(os.path.join(out, f"{vid}.json"), "rb") as f:
            h.update(f.read())
    meta = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": cfg["osv"]["api"],
        "queries": len(raw), "records": len(ids),
        "failed": failed,
        "sha256": h.hexdigest(),
        "note": "vulns/*.json 为 OSV 原始响应，可用 /v1/vulns/{id} 对拍",
    }
    with open(os.path.join(ROOT, cfg["osv"]["snapshot_dir"], "meta.json"), "w",
              encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print(json.dumps(meta, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
