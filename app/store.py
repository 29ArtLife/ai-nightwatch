"""SQLite 账本：单写连接 + 哈希链 + 尾部锚点。

事务约定：连接 isolation_level=None，所有写操作显式 BEGIN IMMEDIATE。
序号唯一来源是 events.id，由 meta.event_count 推导，不另设 seq。
哈希对象是写入时的 canonical 字符串（落库保存），校验时直接重算，不重新序列化。
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  kind TEXT NOT NULL,
  ip TEXT NOT NULL,
  rule_id TEXT,
  evidence_json TEXT NOT NULL,
  raw_line TEXT,
  source_file TEXT,
  source_offset INTEGER,
  canonical TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events(ip, ts);
CREATE TABLE IF NOT EXISTS bans(
  ip TEXT PRIMARY KEY,
  until_ts TEXT NOT NULL,
  decision_event INTEGER NOT NULL,
  created_ts TEXT NOT NULL,
  revoked_ts TEXT,
  operator TEXT,
  reason TEXT
);
CREATE TABLE IF NOT EXISTS audit_runs(
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  project TEXT NOT NULL,
  snapshot_ts TEXT,
  source TEXT NOT NULL,
  summary_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL,
  group_key TEXT NOT NULL,
  pkg TEXT NOT NULL,
  version TEXT NOT NULL,
  cve TEXT NOT NULL,
  scope TEXT NOT NULL,
  verdict TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  evidence_json TEXT NOT NULL
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _connect(path: str) -> sqlite3.Connection:
    c = sqlite3.connect(path, isolation_level=None, timeout=5, check_same_thread=False)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=3000")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


class Store:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._w = _connect(path)
        self._w.executescript(SCHEMA)
        with self._lock:
            self._w.execute("BEGIN IMMEDIATE")
            cur = self._w.execute("SELECT count(*) FROM meta")
            if cur.fetchone()[0] == 0:
                self._w.executemany(
                    "INSERT INTO meta(k,v) VALUES(?,?)",
                    [("event_count", "0"), ("last_hash", GENESIS), ("genesis", GENESIS)],
                )
            self._w.execute("COMMIT")
        self._read = _connect(path)

    # ---------- 事件 ----------
    def append_event(self, ts: str, kind: str, ip: str, evidence: dict,
                     rule_id: str | None = None, raw_line: str = "",
                     source_file: str = "", source_offset: int = 0) -> dict:
        raw_line = raw_line[:4096]
        canonical_obj = {
            "id": None, "ts": ts, "kind": kind, "ip": ip, "rule_id": rule_id,
            "evidence": evidence, "raw_line": raw_line,
            "source_file": source_file, "source_offset": source_offset,
        }
        with self._lock:
            c = self._w
            c.execute("BEGIN IMMEDIATE")
            try:
                count = int(c.execute("SELECT v FROM meta WHERE k='event_count'").fetchone()[0])
                prev = c.execute("SELECT v FROM meta WHERE k='last_hash'").fetchone()[0]
                eid = count + 1
                canonical_obj["id"] = eid
                canonical = json.dumps(canonical_obj, sort_keys=True,
                                       separators=(",", ":"), ensure_ascii=False)
                h = hashlib.sha256((prev + "\n" + canonical).encode("utf-8")).hexdigest()
                c.execute(
                    "INSERT INTO events(id,ts,kind,ip,rule_id,evidence_json,raw_line,"
                    "source_file,source_offset,canonical,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (eid, ts, kind, ip, rule_id, json.dumps(evidence, ensure_ascii=False),
                     raw_line[:4096], source_file, source_offset, canonical, prev, h),
                )
                c.execute("UPDATE meta SET v=? WHERE k='event_count'", (str(eid),))
                c.execute("UPDATE meta SET v=? WHERE k='last_hash'", (h,))
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
        return {"id": eid, "ts": ts, "kind": kind, "ip": ip, "rule_id": rule_id,
                "evidence": evidence, "raw_line": raw_line,
                "source_file": source_file, "source_offset": source_offset,
                "prev_hash": prev, "hash": h}

    def _rows(self, sql: str, args=()) -> list[dict]:
        cur = self._read.execute(sql, args)
        cols = [d[0] for d in cur.description]
        out = []
        for r in cur.fetchall():
            d = dict(zip(cols, r))
            if "evidence_json" in d:
                try:
                    d["evidence"] = json.loads(d["evidence_json"])
                except Exception:
                    d["evidence"] = {}
            out.append(d)
        return out

    def events_since(self, since: int = 0, limit: int = 500) -> list[dict]:
        return self._rows("SELECT * FROM events WHERE id>? ORDER BY id LIMIT ?", (since, limit))

    def query_events(self, ip: str = "", kind: str = "", rule_prefix: str = "",
                     limit: int = 50) -> list[dict]:
        """SQL 过滤，供 AI 调查员使用（避免把整库拉进内存）。"""
        sql = "SELECT * FROM events WHERE 1=1"
        args: list = []
        if ip:
            sql += " AND ip=?"
            args.append(ip)
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        if rule_prefix:
            sql += " AND COALESCE(rule_id,'') LIKE ?"
            args.append(rule_prefix + "%")
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 200)))
        return list(reversed(self._rows(sql, args)))

    def recent_events(self, limit: int = 50) -> list[dict]:
        rows = self._rows("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return list(reversed(rows))

    def event(self, eid: int) -> dict | None:
        rows = self._rows("SELECT * FROM events WHERE id=?", (eid,))
        return rows[0] if rows else None

    # ---------- 哈希链 ----------
    def verify_chain(self) -> dict:
        count = int(self._read.execute("SELECT v FROM meta WHERE k='event_count'").fetchone()[0])
        last = self._read.execute("SELECT v FROM meta WHERE k='last_hash'").fetchone()[0]
        rows = self._read.execute(
            "SELECT id,ts,kind,ip,rule_id,evidence_json,raw_line,source_file,source_offset,"
            "prev_hash,hash,canonical FROM events ORDER BY id").fetchall()
        if len(rows) != count:
            return {"ok": False, "count": count, "actual_rows": len(rows),
                    "reason": "event_count 与实际行数不一致（尾部被删/被追加）"}
        prev = GENESIS
        for i, (eid, ts, kind, ip, rule_id, evidence_json, raw_line, source_file,
                source_offset, prev_hash, h, canonical) in enumerate(rows, start=1):
            if eid != i:
                return {"ok": False, "count": count, "broken_at": eid,
                        "reason": "序号不连续"}
            if prev_hash != prev:
                return {"ok": False, "count": count, "broken_at": eid,
                        "reason": "prev_hash 断链"}
            calc = hashlib.sha256((prev + "\n" + canonical).encode("utf-8")).hexdigest()
            if calc != h:
                return {"ok": False, "count": count, "broken_at": eid,
                        "reason": "内容哈希不符（事件被篡改）"}
            try:
                obj = json.loads(canonical)
                if obj.get("id") != eid:
                    return {"ok": False, "count": count, "broken_at": eid,
                            "reason": "canonical 内 id 与行 id 不符"}
                # 列内容必须与 canonical 一致，防止只改列不改链
                try:
                    ev = json.loads(evidence_json)
                except Exception:
                    ev = None
                if not (obj.get("ts") == ts and obj.get("kind") == kind and obj.get("ip") == ip
                        and obj.get("rule_id") == rule_id and obj.get("raw_line") == raw_line
                        and obj.get("source_file") == source_file
                        and obj.get("source_offset") == source_offset
                        and obj.get("evidence") == ev):
                    return {"ok": False, "count": count, "broken_at": eid,
                            "reason": "列内容与 canonical 不一致（事件被篡改）"}
            except ValueError:
                return {"ok": False, "count": count, "broken_at": eid,
                        "reason": "canonical 不是合法 JSON"}
            prev = h
        if prev != last:
            return {"ok": False, "count": count, "reason": "链尾哈希与 meta 锚点不符（尾部被重写）"}
        return {"ok": True, "count": count, "head": last}

    # ---------- 封禁 ----------
    def ban(self, ip: str, until_ts: str, decision_event: int, operator: str = "auto",
            reason: str = "") -> None:
        with self._lock:
            self._w.execute("BEGIN IMMEDIATE")
            try:
                self._w.execute(
                    "INSERT INTO bans(ip,until_ts,decision_event,created_ts,operator,reason) "
                    "VALUES(?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET "
                    "until_ts=excluded.until_ts, decision_event=excluded.decision_event, "
                    "created_ts=excluded.created_ts, revoked_ts=NULL, "
                    "operator=excluded.operator, reason=excluded.reason",
                    (ip, until_ts, decision_event, now_iso(), operator, reason))
                self._w.execute("COMMIT")
            except Exception:
                self._w.execute("ROLLBACK")
                raise

    def rollback(self, ip: str, operator: str, reason: str) -> bool:
        with self._lock:
            self._w.execute("BEGIN IMMEDIATE")
            try:
                cur = self._w.execute(
                    "UPDATE bans SET revoked_ts=?, operator=?, reason=? "
                    "WHERE ip=? AND revoked_ts IS NULL", (now_iso(), operator, reason, ip))
                self._w.execute("COMMIT")
                return cur.rowcount > 0
            except Exception:
                self._w.execute("ROLLBACK")
                raise

    def is_banned(self, ip: str, at_ts: str | None = None) -> bool:
        at = at_ts or now_iso()
        row = self._read.execute(
            "SELECT 1 FROM bans WHERE ip=? AND revoked_ts IS NULL AND until_ts>?",
            (ip, at)).fetchone()
        return row is not None

    def active_bans(self, at_ts: str | None = None) -> list[dict]:
        at = at_ts or now_iso()
        rows = self._rows(
            "SELECT * FROM bans WHERE revoked_ts IS NULL AND until_ts>? ORDER BY until_ts", (at,))
        return rows

    def expired_bans(self, at_ts: str | None = None) -> list[dict]:
        at = at_ts or now_iso()
        return self._rows(
            "SELECT * FROM bans WHERE revoked_ts IS NULL AND until_ts<=?", (at,))

    # ---------- 体检 ----------
    def save_audit(self, project: str, source: str, snapshot_ts: str,
                   summary: dict, findings: list[dict]) -> int:
        with self._lock:
            c = self._w
            c.execute("BEGIN IMMEDIATE")
            try:
                cur = c.execute(
                    "INSERT INTO audit_runs(ts,project,snapshot_ts,source,summary_json) "
                    "VALUES(?,?,?,?,?)",
                    (now_iso(), project, snapshot_ts, source,
                     json.dumps(summary, ensure_ascii=False)))
                run_id = cur.lastrowid
                c.executemany(
                    "INSERT INTO findings(run_id,group_key,pkg,version,cve,scope,verdict,"
                    "reason_code,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)",
                    [(run_id, f["group_key"], f["pkg"], f["version"], f["cve"],
                      f["scope"], f["verdict"], f["reason_code"],
                      json.dumps(f["evidence"], ensure_ascii=False)) for f in findings])
                c.execute("COMMIT")
                return run_id
            except Exception:
                c.execute("ROLLBACK")
                raise

    def latest_audit(self) -> dict | None:
        rows = self._rows("SELECT * FROM audit_runs ORDER BY id DESC LIMIT 1")
        if not rows:
            return None
        run = rows[0]
        run["summary"] = json.loads(run.pop("summary_json"))
        run["findings"] = self._rows(
            "SELECT * FROM findings WHERE run_id=? ORDER BY id", (run["id"],))
        for f in run["findings"]:
            f["evidence"] = json.loads(f.pop("evidence_json"))
        return run

    def close(self):
        self._read.close()
        self._w.close()
