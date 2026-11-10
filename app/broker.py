"""SSE 广播：单写线程 publish，订阅者按 id 顺序收；环形缓冲支持 Last-Event-ID 补发。"""
from __future__ import annotations

import queue
import threading
from collections import deque


class Broker:
    def __init__(self, maxlen: int = 200, max_subs: int = 16):
        self.buf = deque(maxlen=maxlen)
        self.subs: set[queue.Queue] = set()
        self.lock = threading.Lock()
        self.max_subs = max_subs

    def publish(self, row: dict) -> None:
        with self.lock:
            self.buf.append(row)
            dead = []
            for q in self.subs:
                try:
                    q.put_nowait(row)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self.subs.discard(q)

    def subscribe(self, last_id: int = 0) -> queue.Queue | None:
        with self.lock:
            if len(self.subs) >= self.max_subs:
                return None
            q: queue.Queue = queue.Queue(maxsize=500)
            for row in self.buf:
                if row["id"] > last_id:
                    q.put_nowait(row)
            self.subs.add(q)
            return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self.lock:
            self.subs.discard(q)
