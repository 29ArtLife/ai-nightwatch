import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.config import load  # noqa: E402
from app.decide import decide  # noqa: E402
from app.detect import Detector  # noqa: E402
from app.parsers import (ParseError, ParsedEvent, parse_modsec_json,  # noqa: E402
                         parse_nginx_json, parse_suricata_eve)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = load(os.path.join(ROOT, "config.toml"))
T0 = datetime(2026, 11, 10, 5, 0, 0, tzinfo=timezone.utc)

EVE = json.dumps({
    "timestamp": "2026-11-10T14:40:00.123456+0800", "event_type": "alert",
    "src_ip": "10.200.0.2", "src_port": 40000, "dest_ip": "10.200.0.1",
    "dest_port": 8081, "proto": "TCP",
    "alert": {"signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
              "category": "Attempted Information Leak", "severity": 2,
              "signature_id": 2024360}})

MODSEC = json.dumps({"transaction": {
    "client_ip": "10.200.0.2", "request": {"uri": "/lab/item?id=1 OR 1=1",
                                           "headers": {"User-Agent": "sqlmap"}},
    "response": {"http_code": 403},
    "producer": {"secrules_engine": "On"},
    "messages": [
        {"message": "SQL Injection", "details": {"ruleId": "942100", "severity": "2"}},
        {"message": "Inbound Anomaly Score Exceeded", "details": {"ruleId": "949110"}}]}})

NGINX = json.dumps({"ts": "2026-11-10T14:40:00+08:00", "ip": "10.200.0.2",
                    "method": "GET", "path": "/", "status": 429,
                    "ua": "ab", "rt": 0.1})


def test_suricata_alert():
    e = parse_suricata_eve(EVE)
    assert e.kind == "net_alert" and e.ip == "10.200.0.2"
    assert "SCAN" in e.extra["signature"]


def test_suricata_rejects_non_alert():
    with pytest.raises(ParseError):
        parse_suricata_eve('{"event_type":"flow","src_ip":"1.2.3.4"}')


def test_modsec_picks_specific_rule():
    e = parse_modsec_json(MODSEC)
    assert e.kind == "waf_alert" and e.extra["rule_id"] == "942100"
    assert e.status == 403


def test_nginx_429():
    e = parse_nginx_json(NGINX)
    assert e.kind == "http_429" and e.status == 429


def ev(kind, ip="10.200.0.2", sec=0, **extra):
    ts = (T0 + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return ParsedEvent(ts=ts, ip=ip, kind=kind, extra=extra)


def test_net_scan_three_alerts():
    d = Detector(CFG)
    sig = None
    for i in range(3):
        sig = d.feed(ev("net_alert", sec=i, category="Attempted Information Leak",
                        signature="ET SCAN Nmap", severity=2), T0 + timedelta(seconds=i)) or sig
    assert sig and sig["rule_id"] == "NET_SCAN.v1"
    v = decide(sig, CFG, "x", whitelisted=False, already_banned=False, auto_enabled=True)
    assert v["action"] == "ban" and v["reason_code"] == "NET_SCAN"
    assert v["ttl_sec"] == 1800


def test_waf_sqli_ban():
    d = Detector(CFG)
    sig = d.feed(ev("waf_alert", rule_id="942100", message="SQLi", uri="/lab/item"),
                 T0)
    assert sig and sig["rule_id"] == "WAF_SQLI.v1"
    v = decide(sig, CFG, "x", whitelisted=False, already_banned=False, auto_enabled=True)
    assert v["action"] == "ban" and v["reason_code"] == "WAF_SQLI"


def test_dos_single_alert_bans():
    d = Detector(CFG)
    sig = d.feed(ev("net_alert", category="Attempted Denial of Service",
                    signature="NW SYN FLOOD 8081 >=200/10s", severity=2), T0)
    assert sig and sig["rule_id"] == "NET_DOS.v1"
    v = decide(sig, CFG, "x", whitelisted=False, already_banned=False, auto_enabled=True)
    assert v["action"] == "ban" and v["reason_code"] == "NET_DOS"


def test_waf_protocol_only_alert():
    d = Detector(CFG)
    sig = d.feed(ev("waf_alert", rule_id="920350", message="protocol"), T0)
    v = decide(sig, CFG, "x", whitelisted=False, already_banned=False, auto_enabled=True)
    assert v["action"] == "alert" and v["reason_code"] == "WAF_PROTOCOL"


def test_http_flood():
    d = Detector(CFG)
    sig = None
    for i in range(60):
        sig = d.feed(ev("http_429", sec=i), T0 + timedelta(seconds=i)) or sig
    assert sig and sig["rule_id"] == "HTTP_FLOOD.v1"
    v = decide(sig, CFG, "x", whitelisted=False, already_banned=False, auto_enabled=True)
    assert v["action"] == "ban" and v["ttl_sec"] == 300
