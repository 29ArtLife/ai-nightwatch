import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.parsers import ParseError, parse_jsonl_auth, parse_jsonl_http  # noqa: E402

import pytest


def test_http_404():
    e = parse_jsonl_http('{"ts":"2026-11-10T05:00:00.000Z","ip":"127.0.0.2",'
                         '"path":"/.env","status":404,"ua":"x"}')
    assert e.kind == "http_404" and e.ip == "127.0.0.2"


def test_auth_fail_success():
    assert parse_jsonl_auth('{"ts":"2026-11-10T05:00:00Z","ip":"1.2.3.4",'
                            '"result":"fail","user":"admin"}').kind == "login_fail"
    assert parse_jsonl_auth('{"ts":"2026-11-10T05:00:00Z","ip":"1.2.3.4",'
                            '"result":"success"}').kind == "login_success"


def test_bad_line_raises():
    with pytest.raises(ParseError):
        parse_jsonl_http("not json")
    with pytest.raises(ParseError):
        parse_jsonl_auth('{"ts":"2026-11-10T05:00:00Z","ip":"1.2.3.4","result":"weird"}')
