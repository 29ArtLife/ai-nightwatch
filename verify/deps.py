"""依赖清单解析：requirements.txt / requirements-dev.txt → 锁定版本与作用域。"""
from __future__ import annotations

import os
import re

from packaging.utils import canonicalize_name

_REQ = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(===|==|>=|~=|<=)?\s*([^\s;#]+)?")


def parse_requirements(path: str, scope: str = "prod", seen: set | None = None) -> list[dict]:
    seen = seen or set()
    real = os.path.abspath(path)
    if real in seen or not os.path.exists(real):
        return []
    seen.add(real)
    out = []
    with open(real, encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.split("#", 1)[0].strip()
            if not s:
                continue
            if s.startswith("-r ") or s.startswith("--requirement "):
                inc = s.split(maxsplit=1)[1]
                out += parse_requirements(os.path.join(os.path.dirname(real), inc), scope, seen)
                continue
            if s.startswith("-"):
                continue
            m = _REQ.match(s)
            if not m:
                continue
            name, op, ver = m.group(1), m.group(2), m.group(3)
            pinned = ver if op in ("==", "===") else None
            out.append({"eco": "PyPI", "name": name, "canonical": canonicalize_name(name),
                        "version": pinned, "scope": scope, "source": os.path.basename(real)})
    return out


def load_project(project_dir: str) -> list[dict]:
    deps = []
    for fn, scope in (("requirements.txt", "prod"), ("requirements-dev.txt", "dev")):
        p = os.path.join(project_dir, fn)
        if os.path.exists(p):
            deps += parse_requirements(p, scope)
    # 同名包只留第一条（prod 优先）
    out, seen = [], set()
    for d in deps:
        if d["canonical"] in seen:
            continue
        seen.add(d["canonical"])
        out.append(d)
    return out
