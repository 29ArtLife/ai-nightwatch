"""演示站：:8081。登录 + 后台 + 报表；被封禁 IP 一律 403，并留痕。

业务进程只写 JSONL，不写 SQLite（避免第二个写者）。
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

LOGIN_HTML = """<!doctype html><meta charset=utf-8><title>星火报表</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;display:grid;
place-items:center;height:100vh;margin:0}form{background:#1e293b;padding:28px 32px;
border-radius:12px;width:280px}input{width:100%;margin:8px 0;padding:9px;border-radius:6px;
border:1px solid #334155;background:#0f172a;color:#e2e8f0;box-sizing:border-box}
button{width:100%;margin-top:12px;padding:10px;border:0;border-radius:6px;
background:#3b82f6;color:#fff;font-size:15px}h1{font-size:18px;margin:0 0 6px}
p{color:#94a3b8;font-size:12px}</style>
<h1>星火报表 · 登录</h1><p>演示账号 demo / demo</p>
<form method=post action=/login><input name=user placeholder=用户名 value=demo>
<input name=password type=password placeholder=密码><button>登录</button></form>"""

REPORT_HTML = """<!doctype html><meta charset=utf-8><title>报表</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;padding:40px}
table{border-collapse:collapse;margin-top:16px}td,th{border:1px solid #334155;
padding:8px 14px;text-align:left}th{background:#1e293b}</style>
<h2>2026 年第三季度经营报表</h2>
<table><tr><th>部门</th><th>营收</th><th>同比</th></tr>
<tr><td>华东</td><td>¥12,480,000</td><td>+18.2%</td></tr>
<tr><td>华南</td><td>¥9,320,000</td><td>+11.6%</td></tr>
<tr><td>华北</td><td>¥7,150,000</td><td>+6.4%</td></tr></table>"""

BANNED_HTML = """<!doctype html><meta charset=utf-8><title>403</title>
<style>body{font-family:system-ui;background:#1a0b0b;color:#fecaca;display:grid;
place-items:center;height:100vh;margin:0;text-align:center}</style>
<div><h1>403 已拦截</h1><p>该来源 IP 已被守夜人临时封禁（10 分钟，可回滚）。</p>
<p>此请求已写入证据链。</p></div>"""


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Site:
    def __init__(self, db: str, logdir: str):
        os.makedirs(logdir, exist_ok=True)
        self.db = db
        self.logdir = logdir
        self.lock = threading.Lock()
        self.access = open(os.path.join(logdir, "app_access.jsonl"), "a",
                           encoding="utf-8", buffering=1)
        self.auth = open(os.path.join(logdir, "app_auth.jsonl"), "a",
                         encoding="utf-8", buffering=1)
        self.conn = None
        self.dblock = threading.Lock()
        self._db_retry(10)

    def _db_retry(self, n):
        for _ in range(n):
            try:
                self.conn = sqlite3.connect(self.db, timeout=2, isolation_level=None,
                                            check_same_thread=False)
                self.conn.execute("SELECT 1 FROM bans LIMIT 1")
                return
            except sqlite3.Error:
                time.sleep(0.5)
        self.conn = None

    def banned(self, ip: str) -> bool:
        if self.conn is None:
            self._db_retry(1)
        if self.conn is None:
            return False
        try:
            with self.dblock:
                row = self.conn.execute(
                    "SELECT 1 FROM bans WHERE ip=? AND revoked_ts IS NULL AND until_ts>?",
                    (ip, ts())).fetchone()
            return row is not None
        except sqlite3.Error:
            return False

    def log(self, fh, obj):
        with self.lock:
            fh.write(json.dumps(obj, ensure_ascii=False) + "\n")


class Handler(BaseHTTPRequestHandler):
    site: Site = None
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code: int, body: str = "", ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _record(self, status: int, path: str):
        ip = self.client_address[0]
        self.site.log(self.site.access, {"ts": ts(), "ip": ip, "method": self.command,
                                         "path": path, "status": status,
                                         "ua": self.headers.get("User-Agent", "")[:120]})

    def do_GET(self):
        ip = self.client_address[0]
        path = self.path.split("?")[0]
        if self.site.banned(ip):
            self._record(403, path)
            return self._send(403, BANNED_HTML)
        if path in ("/", "/login"):
            self._record(200, path)
            return self._send(200, LOGIN_HTML)
        if path == "/reports":
            self._record(200, path)
            return self._send(200, REPORT_HTML)
        self._record(404, path)
        return self._send(404, "<h1>404 Not Found</h1>")

    def do_POST(self):
        ip = self.client_address[0]
        path = self.path.split("?")[0]
        if self.site.banned(ip):
            self._record(403, path)
            return self._send(403, BANNED_HTML)
        if path != "/login":
            self._record(404, path)
            return self._send(404, "not found")
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(min(n, 8192)).decode("utf-8", "replace")
        form = parse_qs(body)
        user = (form.get("user") or [""])[0]
        password = (form.get("password") or [""])[0]
        ok = user == "demo" and password == "demo"
        # 只记录判定结果与用户名，绝不落密码原文
        self.site.log(self.site.auth, {"ts": ts(), "ip": ip, "user": user[:40],
                                       "result": "success" if ok else "fail",
                                       "reason": "ok" if ok else "bad_password"})
        self._record(200 if ok else 401, path)
        if ok:
            return self._send(200, REPORT_HTML)
        return self._send(401, "<h1>401 用户名或密码错误</h1><p><a href=/>返回</a></p>")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--db", default="data/nightwatch.db")
    ap.add_argument("--logdir", default="logs")
    a = ap.parse_args()
    site = Site(a.db, a.logdir)
    Handler.site = site
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.daemon_threads = True
    print(f"demo site on http://{a.host}:{a.port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
