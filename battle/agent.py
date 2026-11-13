"""Battle Agent：轮询新事件，遇告警调模型，工具调用实时打印。"""
from __future__ import annotations

import hashlib
import json
import os
import time

from agent.runner import run_agent
from agent.tools import Ctx

ALERT_KINDS = {"net_alert", "waf_alert", "honeypot"}


class BattleAgent:
    def __init__(self, cfg, store, worker, service, printer,
                 interval: float = 0.5, model: bool = True):
        self.cfg = cfg
        self.store = store
        self.worker = worker
        self.service = service
        self.printer = printer
        self.interval = interval
        self.model = model
        self.last_id = store.max_event_id()
        self.last_hash = ""
        self.last_call = 0.0
        self.stop = False

    def _prompt(self, batch: list[dict]) -> str:
        lines = []
        for r in batch:
            e = r["evidence"]
            desc = (e.get("signature") or e.get("reason_code")
                    or e.get("crs_message") or e.get("message")
                    or e.get("observation") or "")
            lines.append(f"- #{r['id']} {r['ip']} {r['kind']} "
                         f"{r.get('rule_id') or '-'} {desc}")
        return ("你是蓝队指挥官，正在直播防守。你只能防守，不能攻击或扫描。\n"
                "新事件：\n" + "\n".join(lines) + "\n"
                "规则：\n"
                "1. 先用 attack_chain / query_events 核对证据。\n"
                "2. 高置信攻击（WAF SQLi/XSS/RCE、NET_SCAN/NET_DOS、蜜罐）直接 "
                "execute_ban，TTL 600–1800；已被规则封禁的只确认并解释。\n"
                "3. 实验模式：授权资产上的 net_alert/waf_alert 即视为足够证据，"
                "直接 execute_ban 600 秒；不要以“单包/低 severity/历史回滚”为由拒绝。\n"
                "4. 证据确实不足（如 http_request 噪声）才只解释。\n"
                "4. 不封白名单/管理网段；不解封、不清空。\n"
                "5. 回答最多 4 行，每行一句，必须带事件号。")

    def _call(self, batch: list[dict]):
        if not self.model or not os.environ.get("DEEPSEEK_API_KEY"):
            return
        h = hashlib.sha256(
            json.dumps([r["id"] for r in batch]).encode()).hexdigest()
        if h == self.last_hash:
            return
        if time.time() - self.last_call < 2.0:
            return
        self.last_call = time.time()
        self.last_hash = h
        ctx = Ctx(cfg=self.cfg, store=self.store, worker=self.worker,
                  service=self.service, pending=self.service.pending)
        res = run_agent(self._prompt(batch), self.cfg, ctx,
                        source="battle", on_trace=self.printer.trace)
        self.printer.final(res)

    def run(self):
        self.printer.header(
            f"watching since #{self.last_id} | model={'on' if self.model else 'off'} "
            f"| Ctrl-C to stop")
        while not self.stop:
            rows = self.store.events_since(self.last_id, 200)
            batch = []
            for r in rows:
                self.last_id = max(self.last_id, r["id"])
                e = r.get("evidence") or {}
                if r["kind"] in ALERT_KINDS:
                    self.printer.event(r)
                    batch.append(r)
                elif (r["kind"] == "decision"
                      and e.get("action") in ("ban", "alert", "observe")
                      and e.get("reason_code") not in ("TTL_EXPIRED", "ALREADY_BANNED")):
                    self.printer.event(r)
                    batch.append(r)
            if batch:
                self._call(batch)
            time.sleep(self.interval)
