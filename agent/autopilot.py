"""7×24 值守：只在新告警出现时唤醒模型，避免空转与重复调用。"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time

from .runner import run_agent
from .tools import Ctx

# 这些 decision 属于“规则没有自动封”的高风险观察项，交给 AI 复核
REVIEW_REASONS = {"SUCCESS_AFTER_THRESHOLD", "WAF_PROTOCOL", "BELOW_THRESHOLD"}


class Autopilot(threading.Thread):
    def __init__(self, cfg: dict, store, worker, service):
        super().__init__(daemon=True, name="agent-autopilot")
        a = cfg["agent"]
        self.cfg = cfg
        self.store = store
        self.worker = worker
        self.service = service
        self.stop_event = threading.Event()
        self.enabled = self._flag_enabled()
        self.interval = max(30, int(a.get("autopilot_interval_sec", 120)))
        self.max_calls = int(a.get("autopilot_max_calls_per_hour", 20))
        self.max_alerts = int(a.get("autopilot_max_alerts", 8))
        self.last_id = store.max_event_id()
        self.last_hash = ""
        self.calls: list[float] = []
        self.backoff_until = 0.0
        self.last_run = 0.0
        self.last_error = ""
        self.last_result = ""

    def _flag_enabled(self) -> bool:
        try:
            with open(os.path.join("data", "autopilot.flag"), encoding="utf-8") as f:
                return f.read().strip().lower() != "off"
        except OSError:
            return bool(self.cfg["agent"].get("autopilot", False))

    def status(self) -> dict:
        now = time.time()
        return {"enabled": self.enabled,
                "interval_sec": self.interval,
                "calls_last_hour": len([t for t in self.calls if now - t < 3600]),
                "max_calls_per_hour": self.max_calls,
                "last_run": self.last_run,
                "last_error": self.last_error,
                "last_result": self.last_result[:300]}

    def select(self) -> list[dict]:
        """只取新告警；已被封禁的 IP 跳过；按 IP+签名去重。"""
        rows = self.store.events_since(self.last_id, 500)
        if rows:
            self.last_id = max(r["id"] for r in rows)
        out, seen = [], set()
        for r in rows:
            e = r["evidence"]
            if r["kind"] in ("net_alert", "waf_alert"):
                key = (r["ip"], e.get("signature") or e.get("rule_id") or r["kind"])
                if key in seen or self.store.is_banned(r["ip"]):
                    continue
                seen.add(key)
                out.append(r)
            elif (r["kind"] == "decision"
                  and e.get("action") in ("alert", "observe")
                  and e.get("reason_code") in REVIEW_REASONS):
                key = (r["ip"], e.get("reason_code"))
                if key in seen or self.store.is_banned(r["ip"]):
                    continue
                seen.add(key)
                out.append(r)
        return out[: self.max_alerts]

    def _prompt(self, alerts: list[dict]) -> str:
        lines = []
        for r in alerts:
            e = r["evidence"]
            desc = (e.get("signature") or e.get("reason_code")
                    or e.get("message") or r["kind"])
            lines.append(f"- #{r['id']} {r['ip']} {r['kind']} {desc} "
                         f"counts={json.dumps(e.get('window_counts', {}), ensure_ascii=False)}")
        return ("值守巡检：以下是刚出现的新告警。\n" + "\n".join(lines) + "\n\n"
                "实验值守策略（优先于一般判断）：授权资产包含 lab-host(10.200.0.1)。"
                "只要来源 IP 不在白名单/管理网段，且命中 net_alert 或 waf_alert，"
                "即视为足够证据，直接调用 execute_ban 封禁 600 秒。"
                "不要以“单包”“低 severity”“历史人工回滚”为由拒绝；历史回滚是实验操作，不代表豁免。"
                "每个来源只封一次，最多封 3 个；不要主动扫描。"
                "回答控制在 6 行以内，必须引用事件号。")

    def tick(self) -> bool:
        if not self.enabled:
            return False
        if self.service.agent_autonomy != "auto" or not self.worker.auto_enabled:
            return False
        if not os.environ.get("DEEPSEEK_API_KEY"):
            self.last_error = "DEEPSEEK_API_KEY 未配置"
            return False
        if time.time() < self.backoff_until:
            return False
        alerts = self.select()
        if not alerts:
            return False
        h = hashlib.sha256(
            json.dumps([a["id"] for a in alerts]).encode()).hexdigest()
        if h == self.last_hash:
            return False
        now = time.time()
        self.calls = [t for t in self.calls if now - t < 3600]
        if len(self.calls) >= self.max_calls:
            self.last_error = "每小时调用上限已达"
            return False

        ctx = Ctx(cfg=self.cfg, store=self.store, worker=self.worker,
                  service=self.service, pending=self.service.pending)
        res = run_agent(self._prompt(alerts), self.cfg, ctx, source="autopilot")
        self.calls.append(now)
        self.last_run = now
        if res.get("ok"):
            self.last_hash = h
            self.last_error = ""
            self.last_result = res.get("answer", "")
        else:
            self.last_error = res.get("error", "unknown")
            self.backoff_until = now + 300
        return True

    def run(self):
        while not self.stop_event.is_set():
            self.enabled = self._flag_enabled()
            try:
                self.tick()
            except Exception as e:
                self.last_error = f"{type(e).__name__}: {e}"
                self.backoff_until = time.time() + 300
            self.stop_event.wait(self.interval)
