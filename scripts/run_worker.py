"""调试用：只跑采集/检测/处置，不启 HTTP（M1 闭环验证）。"""
import sys
import time
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config import load  # noqa: E402
from app.store import Store  # noqa: E402
from app.worker import Worker  # noqa: E402

cfg = load(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.toml"))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
store = Store("data/nightwatch.db")
w = Worker(cfg, store)
w.start()
print("worker started", flush=True)
try:
    while True:
        time.sleep(2)
except KeyboardInterrupt:
    w.stop()
