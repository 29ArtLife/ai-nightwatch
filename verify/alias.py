"""别名并查集：只合并 id 与 aliases；related/upstream 绝不合并。"""
from __future__ import annotations


class DSU:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def group(records: list[dict]) -> dict[str, list[dict]]:
    """返回 {group_key: [record,...]}。"""
    dsu = DSU()
    for r in records:
        rid = r.get("id")
        if not rid:
            continue
        dsu.find(rid)
        for a in r.get("aliases", []) or []:
            dsu.union(rid, a)
    groups: dict[str, list[dict]] = {}
    for r in records:
        rid = r.get("id")
        if not rid:
            continue
        groups.setdefault(dsu.find(rid), []).append(r)
    return groups


def canonical(records: list[dict]) -> str:
    ids = set()
    for r in records:
        if r.get("id"):
            ids.add(r["id"])
        ids.update(r.get("aliases", []) or [])
    ids = sorted(ids - {""})
    cves = [i for i in ids if i.startswith("CVE-")]
    ghsas = [i for i in ids if i.startswith("GHSA-")]
    return (min(cves) if cves else (min(ghsas) if ghsas else (ids[0] if ids else "UNKNOWN")))


def all_aliases(records: list[dict]) -> list[str]:
    out = set()
    for r in records:
        out.add(r.get("id", ""))
        out.update(r.get("aliases", []) or [])
    out.discard("")
    return sorted(out)
