import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.store import Store, now_iso  # noqa: E402


def tmp_store():
    d = tempfile.mkdtemp()
    return Store(os.path.join(d, "t.db"))


def test_append_and_verify():
    s = tmp_store()
    for i in range(5):
        s.append_event(now_iso(), "http_404", "127.0.0.2", {"i": i})
    v = s.verify_chain()
    assert v["ok"] and v["count"] == 5
    s.close()


def test_concurrent_no_duplicate_ids():
    s = tmp_store()
    def worker(n):
        for i in range(50):
            s.append_event(now_iso(), "http_404", f"127.0.0.{n}", {"i": i})
    ts = [threading.Thread(target=worker, args=(n,)) for n in range(3)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    rows = s.events_since(0, 1000)
    assert len(rows) == 150
    assert [r["id"] for r in rows] == list(range(1, 151))
    assert s.verify_chain()["ok"]
    s.close()


def test_middle_tamper_detected():
    s = tmp_store()
    for i in range(5):
        s.append_event(now_iso(), "http_404", "127.0.0.2", {"i": i})
    s._w.execute("UPDATE events SET ip='9.9.9.9' WHERE id=3")
    v = s.verify_chain()
    assert not v["ok"]
    assert v["broken_at"] == 3
    s.close()


def test_tail_delete_detected():
    s = tmp_store()
    for i in range(5):
        s.append_event(now_iso(), "http_404", "127.0.0.2", {"i": i})
    s._w.execute("DELETE FROM events WHERE id=5")
    v = s.verify_chain()
    assert not v["ok"] and "行数" in v["reason"]
    s.close()


if __name__ == "__main__":
    test_append_and_verify()
    test_concurrent_no_duplicate_ids()
    test_middle_tamper_detected()
    test_tail_delete_detected()
    print("chain selftest OK")
