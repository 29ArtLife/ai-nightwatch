"""nftables 后端客户端：唯一通过 sudo 调用 root wrapper 的地方。

失败不抛出到采集线程：返回 {"ok": False, "error": ...}，由 Enforcer 记
enforce_error 事件；应用层封禁仍然生效（fail-open 内核层 / fail-safe 应用层）。
"""
from __future__ import annotations

import ipaddress
import json
import subprocess


class FwError(ValueError):
    pass


class NullFw:
    """tests / 未启用时的空后端。"""
    def ban(self, ip: str, ttl: int) -> dict:
        return {"ok": True, "skipped": True}

    def unban(self, ip: str) -> dict:
        return {"ok": True, "skipped": True}

    def status(self) -> dict:
        return {"ok": True, "skipped": True, "count": 0, "entries": []}

    def flush(self) -> dict:
        return {"ok": True, "skipped": True}

    def reconcile(self, pairs) -> dict:
        return {"ok": True, "skipped": True, "count": 0}


class FwBackend:
    def __init__(self, cfg: dict):
        c = cfg.get("fw", {})
        self.enabled = bool(c.get("enabled", False))
        self.wrapper = c.get("wrapper", "/usr/local/sbin/nw-fw")
        self.timeout = float(c.get("timeout_sec", 5))

    @staticmethod
    def validate_ip(ip: str) -> str:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError as e:
            raise FwError(f"非法 IP: {ip}") from e
        if a.version != 4:
            raise FwError("仅支持 IPv4")
        if (a.is_loopback or a.is_unspecified or a.is_multicast or
                a.is_link_local or a.is_reserved):
            raise FwError(f"拒绝保留/环回/组播地址: {ip}")
        return str(a)

    @staticmethod
    def validate_ttl(ttl: int) -> int:
        ttl = int(ttl)
        if not 60 <= ttl <= 86400:
            raise FwError("TTL 必须在 60..86400")
        return ttl

    def _call(self, args: list[str], stdin: str | None = None) -> dict:
        if not self.enabled:
            return {"ok": False, "error": "firewall backend disabled"}
        try:
            p = subprocess.run(
                ["sudo", "-n", self.wrapper, *args],
                input=stdin, capture_output=True, text=True,
                timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        out = ((p.stdout or "") + (p.stderr or "")).strip()
        return {"ok": p.returncode == 0, "rc": p.returncode, "output": out[:2000]}

    def ban(self, ip: str, ttl: int) -> dict:
        # 回环来源由应用层兜底，内核层封回环没有意义且可能误伤本机
        if str(ip).startswith("127."):
            return {"ok": True, "skipped": "loopback"}
        try:
            ip = self.validate_ip(ip)
            ttl = self.validate_ttl(ttl)
        except FwError as e:
            return {"ok": False, "error": str(e)}
        return self._call(["ban", ip, str(ttl)])

    def unban(self, ip: str) -> dict:
        if str(ip).startswith("127."):
            return {"ok": True, "skipped": "loopback"}
        try:
            ip = self.validate_ip(ip)
        except FwError as e:
            return {"ok": False, "error": str(e)}
        return self._call(["unban", ip])

    def status(self) -> dict:
        r = self._call(["status"])
        if not r.get("ok"):
            return {"ok": False, "error": r.get("error") or r.get("output"),
                    "count": 0, "entries": []}
        try:
            data = json.loads(r["output"])
        except json.JSONDecodeError:
            return {"ok": False, "error": "nft 输出不是合法 JSON",
                    "count": 0, "entries": [], "raw": r["output"][:500]}
        entries = []
        for item in data.get("nftables", []):
            s = item.get("set")
            if not s:
                continue
            for el in s.get("elem", []) or []:
                if isinstance(el, dict):
                    e = el.get("elem", el)
                    entries.append({"ip": e.get("val"),
                                    "timeout": e.get("timeout"),
                                    "expires": e.get("expires")})
                else:
                    entries.append({"ip": el})
        return {"ok": True, "count": len(entries), "entries": entries}

    def flush(self) -> dict:
        return self._call(["flush"])

    def panic(self) -> dict:
        return self._call(["panic"])

    def reconcile(self, pairs: list[tuple[str, int]]) -> dict:
        lines = []
        for ip, ttl in pairs:
            try:
                lines.append(f"{self.validate_ip(ip)} {self.validate_ttl(ttl)}")
            except FwError:
                continue
        if not lines:
            return {"ok": True, "count": 0}
        r = self._call(["reconcile"], stdin="\n".join(lines) + "\n")
        r["count"] = len(lines)
        return r
