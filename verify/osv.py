"""OSV 数据访问：离线快照优先，在线兜底；不可用时明确失败。"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .alias import group


class OsvUnavailable(RuntimeError):
    pass


class OsvClient:
    def __init__(self, cfg: dict):
        self.cfg = cfg["osv"]
        self.mode = os.getenv("NW_OSV_MODE", self.cfg.get("mode", "offline"))
        self.api = self.cfg.get("api", "https://api.osv.dev").rstrip("/")
        self.dir = self.cfg.get("snapshot_dir", "osv")
        self._mem: dict[str, dict] = {}
        self.snapshot_meta = self._read_meta()

    def _read_meta(self) -> dict:
        try:
            with open(os.path.join(self.dir, "meta.json"), encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _file(self, vid: str) -> str:
        return os.path.join(self.dir, "vulns", f"{vid}.json")

    def get(self, vid: str) -> dict:
        if vid in self._mem:
            return self._mem[vid]
        if self.mode == "offline":
            try:
                with open(self._file(vid), encoding="utf-8") as f:
                    d = json.load(f)
            except FileNotFoundError as e:
                raise OsvUnavailable(
                    f"离线快照缺少 {vid}；请先运行 scripts/snapshot_osv.py") from e
        else:
            try:
                with urllib.request.urlopen(f"{self.api}/v1/vulns/{vid}", timeout=15) as r:
                    d = json.load(r)
            except (urllib.error.URLError, TimeoutError) as e:
                raise OsvUnavailable(f"在线查询 {vid} 失败：{e}") from e
        self._mem[vid] = d
        return d

    def records_for(self, vid: str) -> list[dict]:
        """返回该编号 + 其 aliases 的全部记录（别名对齐的原始证据）。"""
        root = self.get(vid)
        out, seen = [root], {root.get("id", vid)}
        for a in root.get("aliases", []) or []:
            if a in seen:
                continue
            seen.add(a)
            try:
                out.append(self.get(a))
            except OsvUnavailable:
                continue
        return out

    def groups_for(self, vid: str):
        recs = self.records_for(vid)
        return group(recs), recs

    def querybatch(self, pkgs: list[dict]) -> list[dict]:
        if self.mode == "offline":
            raise OsvUnavailable("querybatch 需要在线模式")
        qs = [{"package": {"name": p["name"], "ecosystem": p.get("eco", "PyPI")},
               "version": p["version"]} for p in pkgs if p.get("version")]
        body = json.dumps({"queries": qs}).encode()
        req = urllib.request.Request(f"{self.api}/v1/querybatch", data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                return json.load(r).get("results", [])
        except (urllib.error.URLError, TimeoutError) as e:
            raise OsvUnavailable(f"querybatch 失败：{e}") from e
