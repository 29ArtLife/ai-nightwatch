"""日志解析：统一成 ParsedEvent。坏行抛 ParseError，绝不静默跳过。"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone


class ParseError(ValueError):
    pass


@dataclass
class ParsedEvent:
    ts: str
    ip: str
    kind: str          # login_fail | login_success | http_404 | http_request
    user: str = ""
    path: str = ""
    status: int = 0
    ua: str = ""
    raw_line: str = ""
    source_file: str = ""
    source_offset: int = 0
    extra: dict = field(default_factory=dict)

    def as_dict(self):
        return asdict(self)


def norm_ts(raw: str) -> str:
    """统一成 UTC ISO8601（毫秒 + Z）。"""
    if not raw:
        raise ParseError("missing ts")
    s = raw.strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as e:
        raise ParseError(f"bad ts: {raw!r}") from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _json(line: str) -> dict:
    try:
        d = json.loads(line)
    except json.JSONDecodeError as e:
        raise ParseError(f"bad json: {e}") from e
    if not isinstance(d, dict):
        raise ParseError("json is not object")
    return d


def parse_jsonl_http(line: str) -> ParsedEvent:
    d = _json(line)
    for k in ("ts", "ip", "path"):
        if k not in d:
            raise ParseError(f"missing {k}")
    status = int(d.get("status", 200))
    hp = d.get("honeypot")
    kind = "honeypot" if hp else ("http_404" if status == 404 else "http_request")
    return ParsedEvent(
        ts=norm_ts(str(d["ts"])), ip=str(d["ip"]),
        kind=kind,
        user=str(d.get("user", "")), path=str(d["path"]), status=status,
        ua=str(d.get("ua", ""))[:200], raw_line=line,
        extra={"honeypot": str(hp)} if hp else {})


def parse_jsonl_auth(line: str) -> ParsedEvent:
    d = _json(line)
    for k in ("ts", "ip", "result"):
        if k not in d:
            raise ParseError(f"missing {k}")
    result = str(d["result"]).lower()
    if result not in ("fail", "success"):
        raise ParseError(f"bad result: {result}")
    return ParsedEvent(
        ts=norm_ts(str(d["ts"])), ip=str(d["ip"]),
        kind="login_fail" if result == "fail" else "login_success",
        user=str(d.get("user", "")), raw_line=line)


# 只统计密码失败；Failed none/publickey 不计入（Debian #481760 的误封根因）
_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<u>\S+) from (?P<ip>[\d.]+) port \d+ ssh2")
_OK = re.compile(r"Accepted password for (?P<u>\S+) from (?P<ip>[\d.]+) port \d+ ssh2")


def parse_authlog(line: str) -> ParsedEvent:
    m = _FAIL.search(line)
    if m:
        return ParsedEvent(ts=now_ts(), ip=m.group("ip"), kind="login_fail",
                           user=m.group("u"), raw_line=line)
    m = _OK.search(line)
    if m:
        return ParsedEvent(ts=now_ts(), ip=m.group("ip"), kind="login_success",
                           user=m.group("u"), raw_line=line)
    raise ParseError("not a counted auth event")


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_suricata_eve(line: str) -> ParsedEvent:
    d = _json(line)
    if d.get("event_type") != "alert":
        raise ParseError("not an alert event")
    a = d.get("alert") or {}
    return ParsedEvent(
        ts=now_ts(), ip=str(d.get("src_ip", "")), kind="net_alert",
        raw_line=line,
        extra={"signature": str(a.get("signature", ""))[:200],
               "category": str(a.get("category", ""))[:120],
               "severity": a.get("severity"),
               "signature_id": a.get("signature_id"),
               "dest_ip": d.get("dest_ip", ""),
               "dest_port": d.get("dest_port"),
               "proto": d.get("proto", ""),
               "orig_ts": d.get("timestamp", "")})


def parse_modsec_json(line: str) -> ParsedEvent:
    d = _json(line)
    t = d.get("transaction")
    if not isinstance(t, dict):
        raise ParseError("not a modsec transaction")
    msgs = [m for m in t.get("messages", [])
            if isinstance(m, dict) and (m.get("details") or {}).get("ruleId")]
    if not msgs:
        raise ParseError("no rule messages")
    ids = [str(m["details"]["ruleId"]) for m in msgs]
    # 优先具体规则，949 只是“总分超阈值”的汇总
    specific = [i for i in ids if not i.startswith("949")] or ids
    first = next((m for m in msgs
                  if str(m["details"]["ruleId"]) == specific[0]), msgs[0])
    req = t.get("request") or {}
    uri = str(req.get("uri", ""))
    return ParsedEvent(
        ts=now_ts(), ip=str(t.get("client_ip", "")), kind="waf_alert",
        path=uri.split("?")[0][:300], status=int((t.get("response") or {}).get("http_code", 0) or 0),
        ua=str((req.get("headers") or {}).get("User-Agent", ""))[:200],
        raw_line=line,
        extra={"rule_ids": ids, "rule_id": specific[0],
               "message": str(first.get("message", ""))[:200],
               "severity": (first.get("details") or {}).get("severity"),
               "uri": uri[:300],
               "engine": (t.get("producer") or {}).get("secrules_engine", "")})


def parse_nginx_json(line: str) -> ParsedEvent:
    d = _json(line)
    status = int(d.get("status", 0) or 0)
    # 只接限流事件；普通请求由演示站 JSONL 记录，避免重复计数
    if status != 429:
        raise ParseError("only rate-limit records")
    kind = "http_429"
    return ParsedEvent(
        ts=norm_ts(str(d.get("ts", ""))), ip=str(d.get("ip", "")), kind=kind,
        path=str(d.get("path", "")).split("?")[0][:300], status=status,
        ua=str(d.get("ua", ""))[:200], raw_line=line,
        extra={"method": d.get("method", ""), "rt": d.get("rt")})


PARSERS = {
    "jsonl_http": parse_jsonl_http,
    "jsonl_auth": parse_jsonl_auth,
    "authlog": parse_authlog,
    "suricata_eve": parse_suricata_eve,
    "modsec_json": parse_modsec_json,
    "nginx_json": parse_nginx_json,
}
