"""Battle 的纯文本输出（TUI 的降级形态）。"""
from __future__ import annotations

import json

RED = "\033[31;1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
GRAY = "\033[90m"
RESET = "\033[0m"


class PlainPrinter:
    def __init__(self, color: bool = True):
        self.color = color

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def header(self, text: str):
        print(self._c(MAGENTA, f"[BATTLE] {text}"), flush=True)

    def event(self, r: dict):
        e = r.get("evidence") or {}
        desc = (e.get("signature") or e.get("reason_code")
                or e.get("crs_message") or e.get("message") or "")
        if r["kind"] == "decision":
            action = e.get("action") or ""
            line = (f"[{r['ts'][11:19]}] {self._c(RED if action == 'ban' else GREEN, action.upper() or 'DECISION')}"
                    f"  #{r['id']}  {r['ip']:<15} {r.get('rule_id') or '-':<18} {str(desc)[:60]}")
        else:
            color = CYAN if r["kind"] == "net_alert" else MAGENTA
            line = (f"[{r['ts'][11:19]}] {self._c(color, r['kind'].upper()):<12} "
                    f"#{r['id']}  {r['ip']:<15} {str(desc)[:70]}")
        print(line, flush=True)

    def trace(self, ev: dict):
        t = ev.get("type")
        if t == "tool_start":
            args = json.dumps(ev.get("args") or {}, ensure_ascii=False)[:100]
            print(self._c(MAGENTA, f"  [TOOL] {ev.get('tool')}({args})"), flush=True)
        elif t == "tool_end":
            ok = "OK" if ev.get("ok") else "ERR"
            print(self._c(GREEN if ev.get("ok") else RED,
                          f"  [{ok}] {ev.get('tool')} {ev.get('duration_ms')}ms "
                          f"{str(ev.get('preview',''))[:120]}"), flush=True)

    def final(self, res: dict):
        ans = (res.get("answer") or res.get("error") or "").strip()
        if not ans:
            return
        print(self._c(MAGENTA, "  [AGENT] " + ans.splitlines()[0][:160]), flush=True)
        for line in ans.splitlines()[1:6]:
            if line.strip():
                print("          " + line.strip()[:160], flush=True)
