"""日志解析：统一成 ParsedEvent。坏行抛 ParseError，绝不静默跳过。"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
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
    return ParsedEvent(
        ts=norm_ts(str(d["ts"])), ip=str(d["ip"]),
        kind="http_404" if status == 404 else "http_request",
        user=str(d.get("user", "")), path=str(d["path"]), status=status,
        ua=str(d.get("ua", ""))[:200], raw_line=line)


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


PARSERS = {
    "jsonl_http": parse_jsonl_http,
    "jsonl_auth": parse_jsonl_auth,
    "authlog": parse_authlog,
}
