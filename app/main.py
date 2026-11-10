"""监控台 + API + SSE。stdlib http.server，无框架。"""
from __future__ import annotations

import json
import os
import queue
import re
import secrets
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.api import Service  # noqa: E402
from app.broker import Broker  # noqa: E402
from app.config import load  # noqa: E402
from app.store import Store, now_iso  # noqa: E402
from app.worker import Worker  # noqa: E402

CT = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
      ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}


class Handler(BaseHTTPRequestHandler):
    sys_version = ""
    server_version = "nightwatch"
    protocol_version = "HTTP/1.1"
    service: Service = None
    token: str = ""
    webdir: str = ""

    def log_message(self, *a):
        pass

    # ---------- 工具 ----------
    def _json(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _text(self, text, status=200, ctype="text/plain; charset=utf-8"):
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _authed(self, query) -> bool:
        if not self.token:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and secrets.compare_digest(auth[7:], self.token):
            return True
        q = (query.get("token") or [""])[0]
        return bool(q) and secrets.compare_digest(q, self.token)

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            host = urlparse(origin).netloc
            return host.split(":")[0] == (self.headers.get("Host", "").split(":")[0])
        except Exception:
            return False

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(min(n, 65536)).decode("utf-8"))
        except Exception:
            return {}

    # ---------- GET ----------
    def do_GET(self):
        u = urlparse(self.path)
        path, query = u.path, parse_qs(u.query)
        try:
            if path == "/api/health":
                return self._json({"ok": True})
            if path == "/api/stream":
                return self._stream(query)
            if path.startswith("/api/"):
                if not self._authed(query):
                    return self._json({"error": "unauthorized"}, 401)
                return self._api_get(path, query)
            return self._static(path)
        except Exception:
            traceback.print_exc()
            return self._json({"error": "internal"}, 500)

    def _api_get(self, path, query):
        svc = self.service
        if path == "/api/status":
            return self._json(svc.status())
        if path == "/api/events":
            since = int((query.get("since") or ["0"])[0])
            limit = int((query.get("limit") or ["200"])[0])
            latest = (query.get("latest") or ["0"])[0] in ("1", "true")
            return self._json(svc.events(since, limit, latest))
        if path == "/api/bans":
            return self._json(svc.bans())
        if path == "/api/audit/latest":
            return self._json(svc.latest_audit() or {})
        if path == "/api/assets":
            return self._json(svc.assets())
        if path == "/api/chain/verify":
            return self._json(svc.chain())
        if path == "/api/fw/status":
            return self._json(svc.fw_status())
        if path == "/api/report":
            return self._text(svc.report())
        if path == "/api/agent/info":
            return self._json(svc.agent_info())
        if path == "/api/agent/actions":
            return self._json(svc.agent_actions())
        return self._json({"error": "not found"}, 404)

    def _static(self, path):
        rel = "index.html" if path in ("/", "") else unquote(path.lstrip("/"))
        full = os.path.abspath(os.path.join(self.webdir, rel))
        if not full.startswith(os.path.abspath(self.webdir)) or not os.path.isfile(full):
            return self._text("not found", 404)
        ext = os.path.splitext(full)[1]
        with open(full, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", CT.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _stream(self, query):
        if not self._authed(query):
            return self._json({"error": "unauthorized"}, 401)
        last = int((query.get("since") or ["0"])[0])
        if self.headers.get("Last-Event-ID"):
            try:
                last = max(last, int(self.headers["Last-Event-ID"]))
            except ValueError:
                pass
        q = self.service.broker.subscribe(last)
        if q is None:
            return self._json({"error": "too many subscribers"}, 503)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        try:
            self._chunk(b"retry: 2000\n\n")
            while True:
                try:
                    row = q.get(timeout=15)
                    payload = json.dumps(row, ensure_ascii=False)
                    self._chunk(f"id: {row['id']}\ndata: {payload}\n\n".encode("utf-8"))
                except queue.Empty:
                    self._chunk(b": ping\n\n")
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.service.broker.unsubscribe(q)

    def _chunk(self, data: bytes):
        self.wfile.write(f"{len(data):X}\r\n".encode() + data + b"\r\n")
        self.wfile.flush()

    # ---------- POST ----------
    def do_POST(self):
        u = urlparse(self.path)
        path, query = u.path, parse_qs(u.query)
        if not self._origin_ok():
            return self._json({"error": "bad origin"}, 403)
        if not self._authed(query):
            return self._json({"error": "unauthorized"}, 401)
        try:
            if path == "/api/control":
                body = self._body()
                return self._json({"auto_response": self.service.set_auto(bool(body.get("auto_response", True)))})
            if path == "/api/audit/run":
                return self._json(self.service.audit())
            if path == "/api/fw/flush":
                body = self._body()
                return self._json(self.service.fw_flush(str(body.get("operator", "operator"))))
            if path == "/api/fw/reconcile":
                return self._json(self.service.fw_reconcile())
            if path == "/api/agent/chat":
                body = self._body()
                msg = str(body.get("message", "")).strip()
                if not msg:
                    return self._json({"ok": False, "error": "message 为空"}, 400)
                hist = body.get("history") if isinstance(body.get("history"), list) else []
                return self._json(self.service.agent_chat(msg, hist))
            m = re.fullmatch(r"/api/agent/actions/([^/]+)/(approve|reject)", path)
            if m:
                body = self._body()
                op = str(body.get("operator", "operator"))
                if m.group(2) == "approve":
                    row = self.service.agent_approve(m.group(1), op)
                    if not row:
                        return self._json({"error": "建议不存在或已处理"}, 404)
                    return self._json({"ok": True, "event": row})
                ok = self.service.agent_reject(m.group(1), op)
                return self._json({"ok": ok})
            m = re.fullmatch(r"/api/bans/([^/]+)/rollback", path)
            if m:
                body = self._body()
                row = self.service.rollback(unquote(m.group(1)),
                                            str(body.get("operator", "operator")),
                                            str(body.get("reason", "manual")))
                if not row:
                    return self._json({"error": "no active ban"}, 404)
                return self._json({"ok": True, "event": row})
            return self._json({"error": "not found"}, 404)
        except Exception as e:
            traceback.print_exc()
            return self._json({"error": str(e)}, 500)


def main():
    os.chdir(ROOT)
    os.makedirs("data", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    cfg = load("config.toml")
    token = cfg["server"].get("token") or os.environ.get("NW_TOKEN", "")
    if not token:
        try:
            with open("data/token.txt", encoding="utf-8") as f:
                token = f.read().strip()
        except FileNotFoundError:
            token = ""
    if not token:
        token = secrets.token_hex(16)
        with open("data/token.txt", "w", encoding="utf-8") as f:
            f.write(token)
        os.chmod("data/token.txt", 0o600)
    store = Store("data/nightwatch.db")
    broker = Broker()
    worker = Worker(cfg, store, publish=broker.publish)
    worker.start()
    try:
        rr = worker.enforcer.reconcile(now_iso())
        print(f"fw reconcile: {len(rr)} entries {[x.get('ip') for x in rr]}", flush=True)
    except Exception:
        traceback.print_exc()
    Handler.service = Service(cfg, store, broker, worker)
    Handler.token = token
    Handler.webdir = os.path.join(ROOT, "web")
    host, port = cfg["server"]["host"], int(cfg["server"]["port"])
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    print(f"nightwatch on http://{host}:{port}  token={token}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
