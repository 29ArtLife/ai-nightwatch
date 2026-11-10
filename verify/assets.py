"""资产验真：内置探测（nmap 可选，本期不依赖）+ banner 证据降级。

硬闸：所有发包入口先规范化为 IP 并与白名单精确比对，拒绝主机名/未列出地址。
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import struct

NAIVE_SSH_CVE = "CVE-2018-15473"   # 影响 <7.7，banner 声称 7.4 时会被“粗筛”关联
NAIVE_FIXED = "7.7"


class UnauthorizedTarget(RuntimeError):
    pass


def _normalize(host: str) -> str:
    """只接受字面 IP；主机名/带前导零的写法一律拒绝。"""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError as e:
        raise UnauthorizedTarget(f"拒绝：目标必须是字面 IP（{host}）") from e


def _connect(host: str, port: int, allowed: set[str], timeout: float):
    ip = _normalize(host)
    if ip not in allowed:
        raise UnauthorizedTarget(f"拒绝：{ip} 不在授权资产白名单")
    return socket.create_connection((ip, port), timeout=timeout)


def _read_ssh_banner(s: socket.socket) -> str:
    buf = b""
    while b"\n" not in buf and len(buf) < 4096:
        chunk = s.recv(1)
        if not chunk:
            break
        buf += chunk
        if buf.count(b"\n") >= 5:
            break
    text = buf.decode("utf-8", "replace")
    for line in text.splitlines():
        if line.startswith("SSH-"):
            return line.strip()
    return ""


def _kexinit_present(s: socket.socket) -> bool:
    s.sendall(b"SSH-2.0-NightwatchProbe_1.0\r\n")
    head = b""
    while len(head) < 4:
        chunk = s.recv(4 - len(head))
        if not chunk:
            return False
        head += chunk
    length = struct.unpack(">I", head)[0]
    if not 0 < length <= 262144:
        return False
    body = b""
    while len(body) < length:
        chunk = s.recv(length - len(body))
        if not chunk:
            return False
        body += chunk
    # body[0]=padding_length, body[1]=msg_type
    return len(body) >= 2 and body[1] == 20


_OPENSSH = re.compile(r"OpenSSH[_-]([0-9][0-9A-Za-z.\-]*)")


def probe_ssh(host: str, port: int, allowed: set[str], timeout: float) -> dict:
    obs = {"target": host, "port": port, "banner": "", "product": "", "version": "",
           "handshake": "missing", "engine": "builtin", "reason": ""}
    try:
        s = _connect(host, port, allowed, timeout)
    except UnauthorizedTarget:
        raise
    except OSError as e:
        obs["reason"] = f"连接失败：{e}"
        return obs
    try:
        s.settimeout(timeout)
        banner = _read_ssh_banner(s)
        obs["banner"] = banner
        m = _OPENSSH.search(banner)
        if m:
            obs["product"] = "OpenSSH"
            obs["version"] = m.group(1)
        try:
            obs["handshake"] = "present" if _kexinit_present(s) else "missing"
        except (socket.timeout, OSError):
            obs["handshake"] = "missing"
    finally:
        s.close()
    return obs


def probe_http(host: str, port: int, allowed: set[str], timeout: float) -> dict:
    obs = {"target": host, "port": port, "banner": "", "product": "HTTP",
           "version": "", "handshake": "n/a", "engine": "builtin", "reason": ""}
    try:
        s = _connect(host, port, allowed, timeout)
    except UnauthorizedTarget:
        raise
    except OSError as e:
        obs["reason"] = f"连接失败：{e}"
        return obs
    try:
        s.settimeout(timeout)
        s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        raw = b""
        while len(raw) < 4096:
            chunk = s.recv(1024)
            if not chunk:
                break
            raw += chunk
        text = raw.decode("latin-1", "replace")
        line = text.splitlines()[0] if text else ""
        server = ""
        for h in text.splitlines():
            if h.lower().startswith("server:"):
                server = h.split(":", 1)[1].strip()
        obs["banner"] = f"{line} | Server: {server}" if server else line
        obs["product"] = server.split("/")[0] if server else "HTTP"
        obs["version"] = server.split("/", 1)[1] if "/" in server else ""
        obs["handshake"] = "present" if line.startswith("HTTP/") else "missing"
    except OSError as e:
        obs["reason"] = f"读取失败：{e}"
    finally:
        s.close()
    return obs


def verdict(obs: dict) -> dict:
    if obs.get("handshake") == "n/a":
        if obs.get("banner"):
            return {"state": "PROTOCOL_CONFIRMED", "cve_linked": 0,
                    "note": "确认是 HTTP 服务；banner 可伪造，版本未做登录核对"}
        return {"state": "UNREACHABLE", "cve_linked": 0,
                "note": "未取得 HTTP 响应，未识别；不代表安全"}
    banner = obs.get("banner", "")
    hs = obs.get("handshake")
    if not banner:
        return {"state": "UNREACHABLE", "cve_linked": 0,
                "note": "未取得 banner，未识别；不代表安全"}
    if hs != "present":
        return {"state": "SUSPECTED", "cve_linked": 0,
                "note": f"仅 banner 证据，无协议握手；已拦下按 banner 关联的 "
                        f"{NAIVE_SSH_CVE}，不据此下结论"}
    ver = obs.get("version", "")
    if obs.get("product") == "OpenSSH" and ver:
        try:
            from packaging.version import Version
            affected = Version(ver.split("p")[0]) < Version(NAIVE_FIXED)
        except Exception:
            affected = None
        if affected is False:
            return {"state": "PROTOCOL_CONFIRMED", "cve_linked": 0,
                    "note": f"确认是 SSH 服务；版本 {ver} 不在 {NAIVE_SSH_CVE}"
                            f"（<{NAIVE_FIXED}）影响范围，判版本不符"}
        if affected:
            return {"state": "PROTOCOL_CONFIRMED", "cve_linked": 1,
                    "note": f"确认是 SSH 服务且版本 {ver} 落在 {NAIVE_SSH_CVE} 影响范围"}
    return {"state": "PROTOCOL_CONFIRMED", "cve_linked": 0,
            "note": "确认是 SSH 服务；版本信息不足，不对 CVE 下结论"}


def probe_all(cfg: dict) -> list[dict]:
    allowed = {str(ipaddress.ip_address(x)) for x in cfg["asset"]["allowed_targets"]}
    timeout = float(cfg["asset"].get("timeout_sec", 2.0))
    out = []
    for asset in cfg["asset"]["assets"]:
        fn = probe_http if asset.get("kind") == "http" else probe_ssh
        obs = fn(asset["target"], int(asset["port"]), allowed, timeout)
        obs["id"] = asset["id"]
        obs["label"] = asset.get("label", asset["id"])
        obs.update(verdict(obs))
        out.append(obs)
    return out
