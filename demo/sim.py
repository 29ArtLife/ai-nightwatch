"""授权攻击模拟器：只允许回环源地址 + 明确目标，绑定真实源 IP，不伪造头。"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from urllib.parse import urlencode

ALLOWED_SRC = {"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.12"}
ALLOWED_TARGETS = {"127.0.0.1", "10.2.102.143"}
ALLOWED_PORTS = {8081}

SENSITIVE = ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/",
             "/admin.php", "/.aws/credentials", "/backup.zip",
             "/actuator/env", "/console", "/config.json"]


def _parse_target(s: str):
    host, _, port = s.partition(":")
    port = int(port or 8081)
    if host not in ALLOWED_TARGETS or port not in ALLOWED_PORTS:
        print(f"拒绝：目标 {host}:{port} 不在授权白名单", file=sys.stderr)
        sys.exit(2)
    return host, port


def _request(src: str, host: str, port: int, method: str, path: str,
             body: str = "") -> int:
    if src not in ALLOWED_SRC:
        print(f"拒绝：源地址 {src} 不在授权白名单", file=sys.stderr)
        sys.exit(2)
    data = body.encode()
    req = (f"{method} {path} HTTP/1.0\r\nHost: {host}:{port}\r\n"
           f"User-Agent: nw-sim/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(data)}\r\n\r\n").encode() + data
    s = socket.create_connection((host, port), timeout=5, source_address=(src, 0))
    try:
        s.sendall(req)
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
    finally:
        s.close()
    try:
        return int(resp.split(b" ")[1])
    except Exception:
        return 0


def _login(src, host, port, password):
    body = urlencode({"user": "demo", "password": password})
    return _request(src, host, port, "POST", "/login", body)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("normal", "whitelist", "brute", "scan"):
        p = sub.add_parser(name)
        p.add_argument("--src", default="127.0.0.3")
        p.add_argument("--target", default="127.0.0.1:8081")
        p.add_argument("--interval", type=float,
                       default=6.7 if name == "brute" else 0.2)
        p.add_argument("--n", type=int, default=5)
    a = ap.parse_args()
    host, port = _parse_target(a.target)

    if a.cmd == "normal":
        for pw in ("wrong1", "wrong2"):
            print("login", pw, "->", _login(a.src, host, port, pw), flush=True)
            time.sleep(a.interval)
        print("login demo ->", _login(a.src, host, port, "demo"), flush=True)
    elif a.cmd == "whitelist":
        for i in range(a.n):
            print("login wrong ->", _login(a.src, host, port, "wrong"), flush=True)
            time.sleep(a.interval)
    elif a.cmd == "brute":
        for i in range(a.n):
            print(f"fail {i + 1}/{a.n} ->", _login(a.src, host, port, "wrong"), flush=True)
            time.sleep(a.interval)
        print("correct password ->", _login(a.src, host, port, "demo"), flush=True)
    else:
        for i, path in enumerate(SENSITIVE[:a.n]):
            print(f"scan {path} ->", _request(a.src, host, port, "GET", path), flush=True)
            time.sleep(a.interval)


if __name__ == "__main__":
    main()
