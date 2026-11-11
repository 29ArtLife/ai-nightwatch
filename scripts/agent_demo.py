"""命令行运行 AI 调查员：DEEPSEEK_API_KEY=... python scripts/agent_demo.py "问题" """
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from agent.runner import run_agent  # noqa: E402
from agent.tools import Ctx  # noqa: E402
from app.config import load  # noqa: E402
from app.core import Core  # noqa: E402
from app.store import Store, now_iso  # noqa: E402
from app.worker import Worker  # noqa: E402

question = " ".join(sys.argv[1:]) or "巡检本机：查看守卫状态和最近事件，给出结论。"
cfg = load("config.toml")
store = Store("data/nightwatch.db")
worker = Worker(cfg, store)
worker.enqueue_event = lambda kind, ip, ev: store.append_event(now_iso(), kind, ip, ev)
core = Core(cfg, store, worker)
ctx = Ctx(cfg=cfg, store=store, worker=worker, service=core, pending=core.pending)
r = run_agent(question, cfg, ctx)
print("=" * 60)
print("问题：", question)
print("模型：", r.get("model") or cfg["agent"]["model"],
      "| 步骤：", r.get("steps"), "| 工具：", [t["tool"] for t in r.get("trace", [])])
for t in r.get("trace", []):
    print(f"  [{t['step']}] {t['tool']}({json.dumps(t['args'], ensure_ascii=False)}) "
          f"{'OK' if t['ok'] else 'ERROR'} {t['duration_ms']}ms")
print("=" * 60)
print(r.get("answer") or ("错误：" + str(r.get("error"))))
