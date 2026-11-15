#!/usr/bin/env python3
"""
Nightwatch x HALOFLUX 轻量 Web 可视化桥接服务（仅使用 Python 3.12 标准库）
- 以只读 URI 模式轮询 data/nightwatch.db，不与 daemon 单写线程冲突
- 通过 SSE (/events) 实时推送新告警、裁决、封禁和 DeepSeek Agent 调用记录
- 暴露受控的 /api/unban（校验 IPv4 后调用 ./nightwatch unban）
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "nightwatch.db"
HTML_PATH = ROOT / "docs" / "haloflux" / "nightwatch-halo.html"
AUDIO_DIR = ROOT / "docs" / "haloflux" / "audio"


def open_ro_db() -> sqlite3.Connection | None:
    if not DB_PATH.exists():
        return None
    uri = f"file:{DB_PATH.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=3.0)
    conn.row_factory = sqlite3.Row
    return conn


def read_flag(name: str, default: str) -> str:
    p = ROOT / "data" / name
    if p.exists():
        return p.read_text(encoding="utf-8").strip().lower()
    return default


def get_snapshot() -> dict:
    conn = open_ro_db()
    if conn is None:
        return {"event_count": 0, "bans": [], "chain_ok": True, "autonomy": "auto", "autopilot": True, "max_id": 0}
    try:
        cur = conn.cursor()
        meta = {r["k"]: r["v"] for r in cur.execute("SELECT k, v FROM meta")}
        now_iso = datetime.now(timezone.utc).isoformat()
        bans = [
            dict(r)
            for r in cur.execute(
                "SELECT ip, until_ts, decision_event, created_ts, operator, reason "
                "FROM bans WHERE revoked_ts IS NULL AND until_ts > ? ORDER BY created_ts DESC",
                (now_iso,),
            )
        ]
        max_row = cur.execute("SELECT COALESCE(MAX(id), 0) AS m FROM events").fetchone()
        max_id = int(max_row["m"]) if max_row else 0
        return {
            "event_count": int(meta.get("event_count", max_id)),
            "bans": bans,
            "chain_ok": True,
            "autonomy": read_flag("autonomy.flag", "auto"),
            "autopilot": read_flag("autopilot.flag", "on") in ("on", "true", "1"),
            "max_id": max_id,
        }
    finally:
        conn.close()


def fetch_events_since(last_id: int, limit: int = 100) -> list[dict]:
    conn = open_ro_db()
    if conn is None:
        return []
    try:
        rows = conn.execute(
            "SELECT id, ts, kind, ip, rule_id, evidence_json, raw_line "
            "FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
            (last_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


class BridgeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        return  # 保持控制台干净

    def _send_json(self, obj: dict, code: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path, mime: str) -> None:
        if not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html", "/nightwatch-halo.html"):
            self._send_file(HTML_PATH, "text/html; charset=utf-8")
        elif path.startswith("/audio/"):
            fname = Path(path).name
            self._send_file(AUDIO_DIR / fname, "audio/mpeg")
        elif path == "/api/snapshot":
            self._send_json(get_snapshot())
        elif path == "/events":
            self._handle_sse()
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(min(length, 8192)) if length > 0 else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send_json({"ok": False, "error": "invalid json"}, 400)
            return

        if path == "/api/unban":
            ip_str = str(payload.get("ip", "")).strip()
            try:
                ipaddress.IPv4Address(ip_str)
            except Exception:
                self._send_json({"ok": False, "error": "invalid ipv4"}, 400)
                return
            proc = subprocess.run(
                [sys.executable, "-m", "app.cli", "unban", ip_str, "--operator", "web-hud", "--reason", "haloflux unban"],
                cwd=str(ROOT), capture_output=True, text=True, timeout=10
            )
            self._send_json({"ok": proc.returncode == 0, "stdout": proc.stdout, "error": proc.stderr})

        elif path == "/api/sim":
            # 联动自带演示模拟器（仅本地 127.0.0.3 安全模拟）
            sc = str(payload.get("scenario", "normal"))
            map_sc = {"brute": "brute", "sqli": "normal", "normal": "normal"}
            if sc in map_sc:
                subprocess.Popen(
                    [sys.executable, "-m", "app.cli", "demo", "sim", map_sc[sc], "--src", "127.0.0.3"],
                    cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            self._send_json({"ok": True})
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def _handle_sse(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        snap = get_snapshot()
        last_id = max(0, snap["max_id"] - 15)  # 初次连上回放最近 15 条，立刻出效果
        last_snap_ts = 0.0

        try:
            while True:
                now = time.monotonic()
                if now - last_snap_ts >= 2.0:
                    snap = get_snapshot()
                    msg = f"event: snapshot\ndata: {json.dumps(snap, ensure_ascii=False)}\n\n"
                    self.wfile.write(msg.encode("utf-8"))
                    self.wfile.flush()
                    last_snap_ts = now

                events = fetch_events_since(last_id)
                for ev in events:
                    last_id = max(last_id, int(ev["id"]))
                    # 过滤掉纯高频正常 http_request 噪声，只推送核心攻防与 AI 事件
                    if ev["kind"] in ("http_request", "parse_error"):
                        continue
                    msg = f"event: nw_event\ndata: {json.dumps(ev, ensure_ascii=False)}\n\n"
                    self.wfile.write(msg.encode("utf-8"))
                if events:
                    self.wfile.flush()

                time.sleep(0.35)
        except (BrokenPipeError, ConnectionResetError):
            return


def main() -> None:
    parser = argparse.ArgumentParser(description="Nightwatch x HALOFLUX Web Bridge")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认仅本机 127.0.0.1）")
    parser.add_argument("--port", type=int, default=8765, help="监听端口（默认 8765）")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), BridgeHandler)
    print(f"[Nightwatch x HALOFLUX] http://{args.host}:{args.port} (DB: {DB_PATH})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping bridge...")
        server.shutdown()


if __name__ == "__main__":
    main()
