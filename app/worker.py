"""单写线程：采集线程只解析投递，写线程串行落库 → 事件顺序天然等于 id 顺序。"""
from __future__ import annotations

import json
import queue
import threading
import time

from .config import ip_allowed, whitelist_nets
from .decide import decide
from .detect import Detector
from .enforce import Enforcer
from .ingest import TailSource
from .parsers import PARSERS, ParseError, now_ts
from .store import now_iso


class Worker:
    def __init__(self, cfg: dict, store, publish=None):
        self.cfg = cfg
        self.store = store
        self.publish = publish or (lambda row: None)
        self.q: queue.Queue = queue.Queue(maxsize=20000)
        self.stop_event = threading.Event()
        self.detector = Detector(cfg)
        self.enforcer = Enforcer(store, cfg, publish=self.publish)
        self.whitelist, self.bad_whitelist = whitelist_nets(cfg)
        self.auto_enabled = bool(cfg["mode"]["auto_response"])
        self.parse_errors = 0
        self._err_events: dict[str, float] = {}
        self.sources: list[TailSource] = []
        self._threads: list[threading.Thread] = []

    def start(self):
        for src in self.cfg.get("ingest", {}).get("sources", []):
            t = TailSource(src["name"], src["path"], src["parser"],
                           self.q, self.stop_event)
            t.start()
            self.sources.append(t)
        for target in (self._writer_loop, self._sweeper_loop):
            th = threading.Thread(target=target, daemon=True)
            th.start()
            self._threads.append(th)

    def stop(self):
        self.stop_event.set()

    def _writer_loop(self):
        while not self.stop_event.is_set():
            try:
                item = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            self.process_line(*item)

    def _sweeper_loop(self):
        while not self.stop_event.is_set():
            try:
                self.enforcer.sweep(now_iso())
            except Exception:
                pass
            time.sleep(1)

    def enqueue_event(self, kind: str, ip: str, evidence: dict):
        """Agent 等外部写入统一走单写线程，保证 id 顺序与 SSE 顺序一致。"""
        self.q.put(("__event__", kind, json.dumps(evidence, ensure_ascii=False), ip, 0))

    def process_line(self, source_name: str, parser_name: str, line: str,
                     source_file: str = "", offset: int = 0):
        if source_name == "__event__":
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                ev = {"raw": line[:500]}
            row = self.store.append_event(now_ts(), parser_name, source_file, ev)
            self.publish(row)
            return
        parser = PARSERS.get(parser_name)
        try:
            if parser is None:
                raise ParseError(f"unknown parser {parser_name}")
            ev = parser(line)
        except ParseError as e:
            self.parse_errors += 1
            key = f"{source_name}:{str(e)[:40]}"
            last = self._err_events.get(key, 0)
            if time.time() - last > 60:
                self._err_events[key] = time.time()
                row = self.store.append_event(
                    now_ts(), "parse_error", "0.0.0.0",
                    {"source": source_name, "error": str(e)[:300]},
                    source_file=source_file, source_offset=offset)
                self.publish(row)
            return
        ev.source_file = source_file
        ev.source_offset = offset
        sig = self.detector.feed(ev)
        counts = self.detector.last_counts.get(ev.ip, {})
        row = self.store.append_event(
            ev.ts, ev.kind, ev.ip,
            {"user": ev.user, "path": ev.path, "status": ev.status, "ua": ev.ua,
             "window_counts": counts},
            raw_line=ev.raw_line, source_file=source_file, source_offset=offset)
        self.publish(row)
        if not sig:
            return
        verdict = decide(
            sig, self.cfg, now_iso(),
            whitelisted=ip_allowed(sig["ip"], self.whitelist),
            already_banned=self.store.is_banned(sig["ip"]),
            auto_enabled=self.auto_enabled)
        self.enforcer.handle(sig, verdict, ev.ts)
