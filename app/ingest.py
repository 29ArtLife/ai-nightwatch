"""日志尾随：tail -F 子进程，逐行投递；坏行交给上层计数。"""
from __future__ import annotations

import os
import subprocess
import threading
import time


def ensure_file(path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    open(path, "a", encoding="utf-8").close()


class TailSource(threading.Thread):
    def __init__(self, name: str, path: str, parser: str, out_queue, stop_event):
        super().__init__(daemon=True, name=f"tail-{name}")
        self.source_name = name
        self.path = path
        self.parser = parser
        self.q = out_queue
        self.stop_event = stop_event
        self.online = False

    def run(self):
        offset = 0
        while not self.stop_event.is_set():
            try:
                ensure_file(self.path)
                proc = subprocess.Popen(
                    ["tail", "-F", "-n", "0", self.path],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=True, encoding="utf-8", errors="replace", bufsize=1)
                self.online = True
                for line in proc.stdout:
                    offset += len(line.encode("utf-8", "replace"))
                    self.q.put((self.source_name, self.parser, line.rstrip("\n"),
                                self.path, offset))
                    if self.stop_event.is_set():
                        break
            except Exception:
                self.online = False
            finally:
                self.online = False
                try:
                    proc.terminate()
                except Exception:
                    pass
            if not self.stop_event.is_set():
                time.sleep(3)
