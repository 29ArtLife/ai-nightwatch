"""可达性：ast 扫直接 import + 分发名映射；动态导入如实标 unknown。"""
from __future__ import annotations

import ast
import json
import os


def scan(project_dir: str) -> dict:
    imports: dict[str, list[dict]] = {}
    dynamic = False
    parse_errors = 0
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", ".venv", "venv")]
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    tree = ast.parse(f.read(), filename=path)
            except (SyntaxError, ValueError):
                parse_errors += 1
                continue
            rel = os.path.relpath(path, project_dir)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        imports.setdefault(a.name.split(".")[0], []).append(
                            {"file": rel, "line": node.lineno})
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.setdefault(node.module.split(".")[0], []).append(
                        {"file": rel, "line": node.lineno})
                elif isinstance(node, ast.Call):
                    fn = node.func
                    name = getattr(fn, "id", None) or getattr(fn, "attr", None)
                    if name in ("__import__", "import_module", "exec", "eval"):
                        dynamic = True
    return {"imports": imports, "dynamic": dynamic, "parse_errors": parse_errors}


def load_aliases(path: str) -> dict[str, str]:
    try:
        with open(path, encoding="utf-8") as f:
            return {k.lower(): v for k, v in json.load(f).items()}
    except Exception:
        return {}


def sites_for(pkg: str, aliases: dict[str, str], scanned: dict) -> list[dict] | None:
    module = aliases.get(pkg.lower())
    if not module:
        return None
    return scanned["imports"].get(module.split(".")[0], [])
