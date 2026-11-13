"""终端作战室：Textual 全屏 TUI。"""
from __future__ import annotations

import json
import queue
import threading
import time

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Footer, Header, RichLog, Static

from .agent import BattleAgent


class QueuePrinter:
    def __init__(self, q: queue.Queue):
        self.q = q

    def header(self, text: str):
        self.q.put(("header", text))

    def event(self, r: dict):
        self.q.put(("event", r))

    def trace(self, ev: dict):
        self.q.put(("trace", ev))

    def final(self, res: dict):
        self.q.put(("final", res))


class BattleTUI(App):
    CSS = """
    Screen { background: #0b1220; color: #dbe5f4; }
    Header { background: #111c2e; color: #dbe5f4; }
    #top { height: 3; content-align: center middle; background: #111c2e;
           border-bottom: solid #1e2d45; }
    #body { height: 1fr; }
    #attack { width: 1fr; border: round #1e2d45; background: #0d1728;
              padding: 0 1; }
    #agent { width: 1fr; border: round #1e2d45; background: #0d1728;
             padding: 0 1; }
    #score { height: 3; content-align: center middle; background: #111c2e;
             border-top: solid #1e2d45; }
    Footer { background: #0e1929; color: #8aa0bd; }
    """
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("p", "toggle_pause", "Pause/Resume"),
        ("u", "unban", "Unban first"),
    ]

    def __init__(self, cfg, store, worker, core, interval: float = 0.5,
                 model: bool = True):
        super().__init__()
        self.cfg = cfg
        self.store = store
        self.worker = worker
        self.core = core
        self.q: queue.Queue = queue.Queue()
        self.printer = QueuePrinter(self.q)
        self.agent = BattleAgent(cfg, store, worker, core, self.printer,
                                 interval=interval, model=model)
        self.attacks = 0
        self.bans = 0
        self.paused = not worker.auto_enabled
        self.last_event = 0.0
        self.last_ip = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("AI NIGHTWATCH · BATTLE", id="top")
        with Horizontal(id="body"):
            yield RichLog(id="attack", markup=False, wrap=True, max_lines=500)
            yield RichLog(id="agent", markup=False, wrap=True, max_lines=500)
        yield Static("", id="score")
        yield Footer()

    def on_mount(self):
        self.title = "AI Nightwatch · Battle"
        self.query_one("#attack", RichLog).write(
            Text("攻击流（你从 Kali 打的流量会出现在这里）", style="bold cyan"))
        self.query_one("#agent", RichLog).write(
            Text("AI 防守控制台（工具调用会逐条出现）", style="bold magenta"))
        self.agent.stop = False
        threading.Thread(target=self.agent.run, daemon=True).start()
        self.set_interval(0.35, self._drain)
        self.set_interval(1.0, self._status)

    def on_unmount(self):
        self.agent.stop = True

    def _write_attack(self, text: Text):
        self.query_one("#attack", RichLog).write(text)

    def _write_agent(self, text: Text):
        self.query_one("#agent", RichLog).write(text)

    def _drain(self):
        drained = False
        while True:
            try:
                kind, payload = self.q.get_nowait()
            except queue.Empty:
                break
            drained = True
            if kind == "event":
                self._event(payload)
            elif kind == "trace":
                self._trace(payload)
            elif kind == "final":
                self._final(payload)
            elif kind == "header":
                self._write_agent(Text(str(payload), style="dim"))
        if drained:
            self._status()

    def _event(self, r: dict):
        e = r.get("evidence") or {}
        desc = (e.get("signature") or e.get("reason_code")
                or e.get("crs_message") or e.get("message") or "")
        ts = r["ts"][11:19]
        if r["kind"] == "decision":
            action = (e.get("action") or "decision").upper()
            style = "bold red" if action == "BAN" else "green"
            line = (f"{ts}  {action:<8} #{r['id']:<6} {r['ip']:<15} "
                    f"{r.get('rule_id') or '-':<20} {str(desc)[:60]}")
            self._write_attack(Text(line, style=style))
            if action == "BAN":
                self.bans += 1
                self.last_ip = r["ip"]
        else:
            style = "cyan" if r["kind"] == "net_alert" else "magenta"
            line = (f"{ts}  {r['kind'].upper():<10} #{r['id']:<6} "
                    f"{r['ip']:<15} {str(desc)[:70]}")
            self._write_attack(Text(line, style=style))
            self.attacks += 1
        self.last_event = time.time()

    def _trace(self, ev: dict):
        if ev.get("type") == "tool_start":
            args = json.dumps(ev.get("args") or {}, ensure_ascii=False)[:80]
            self._write_agent(Text(f"  [TOOL] {ev.get('tool')}({args})",
                                   style="magenta"))
        elif ev.get("type") == "tool_end":
            ok = ev.get("ok")
            self._write_agent(Text(
                f"  [{'OK' if ok else 'ERR'}] {ev.get('tool')} "
                f"{ev.get('duration_ms')}ms {str(ev.get('preview',''))[:100]}",
                style="green" if ok else "red"))

    def _final(self, res: dict):
        ans = (res.get("answer") or res.get("error") or "").strip()
        if not ans:
            return
        for i, line in enumerate(ans.splitlines()[:6]):
            self._write_agent(Text(("  [AGENT] " if i == 0 else "          ")
                                   + line.strip()[:150], style="bold magenta"))

    def _status(self):
        try:
            st = self.core.status()
        except Exception:
            return
        active = len(self.core.bans())
        now = time.time()
        defcon = 4
        if active:
            defcon = 2
        elif now - self.last_event < 15:
            defcon = 3
        top = (f"DEFCON {defcon}   │   events {st['events']}   │   "
               f"active bans {active}   │   chain {'OK' if st['chain_ok'] else 'BROKEN'}   │   "
               f"AI {st['agent_autonomy']}   │   {'PAUSED' if self.paused else 'GUARDING'}")
        self.query_one("#top", Static).update(top)
        score = (f"attacks {self.attacks}   │   bans {self.bans}   │   "
                 f"last event {time.strftime('%H:%M:%S', time.localtime(self.last_event)) if self.last_event else '-'}   │   "
                 f"q quit   p pause   u unban")
        self.query_one("#score", Static).update(score)

    def action_toggle_pause(self):
        self.paused = not self.paused
        self.core.set_auto_response(not self.paused, "tui")
        self._status()

    def action_unban(self):
        bans = self.core.bans()
        if bans:
            ip = bans[0]["ip"]
            self.core.unban(ip, "tui", "manual from TUI")
            self._write_agent(Text(f"  [UNBAN] {ip}", style="blue"))
            self._status()
