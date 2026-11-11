"""nightwatch 命令行入口。"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import signal
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)


def _load_env():
    """CLI 也从 data/agent.env 读密钥，避免必须手动 export。"""
    try:
        with open(os.path.join("data", "agent.env"), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("DEEPSEEK_API_KEY=") and \
                        not os.environ.get("DEEPSEEK_API_KEY"):
                    os.environ["DEEPSEEK_API_KEY"] = line.split("=", 1)[1]
    except OSError:
        pass


_load_env()

from app.config import ip_allowed, load, whitelist_nets  # noqa: E402
from app.core import Core  # noqa: E402
from app.store import Store, now_iso  # noqa: E402
from app.worker import Worker  # noqa: E402


def _ctx():
    cfg = load("config.toml")
    store = Store("data/nightwatch.db")
    worker = Worker(cfg, store)
    return cfg, store, worker, Core(cfg, store, worker)


def _json(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def _fmt_event(r: dict) -> str:
    e = r.get("evidence") or {}
    desc = (e.get("reason_code") or e.get("signature")
            or e.get("crs_message") or e.get("observation") or "")
    return (f"#{r['id']:<6} {r['ts']}  {r['ip']:<16} {r['kind']:<13} "
            f"{(r.get('rule_id') or '-'):<18} {str(desc)[:50]}")


_COLORS = {
    "ban": "\033[31;1m", "alert": "\033[33m", "observe": "\033[32m",
    "no_action": "\033[32m", "rollback": "\033[34m", "expire": "\033[90m",
    "net_alert": "\033[36m", "waf_alert": "\033[35m",
    "agent_run": "\033[1;35m", "agent_tool": "\033[35m",
    "firewall": "\033[33m", "enforce_error": "\033[31m",
}
_RESET = "\033[0m"


def _watch_line(r: dict, color: bool, jsonl: bool) -> str:
    if jsonl:
        return json.dumps(r, ensure_ascii=False)
    e = r.get("evidence") or {}
    action = e.get("action") or ""
    desc = (e.get("reason_code") or e.get("signature") or e.get("crs_message")
            or e.get("observation") or e.get("message") or "")
    if r["kind"] == "agent_tool":
        desc = e.get("tool", "agent_tool")
    if r["kind"] == "agent_run":
        desc = f"source={e.get('source','chat')} steps={e.get('steps')}"
    if r["kind"] == "decision" and action:
        desc = f"{action}  {desc}"
    line = (f"{r['ts'][11:19]}  #{r['id']:<6} {r['ip']:<15} "
            f"{r['kind']:<12} {(r.get('rule_id') or '-'):<20} {str(desc)[:80]}")
    if not color:
        return line
    c = _COLORS.get(action) or _COLORS.get(r["kind"]) or ""
    return f"{c}{line}{_RESET}" if c else line


def cmd_watch(args):
    cfg, store, worker, core = _ctx()
    last = args.since or (0 if args.from_start else store.max_event_id())
    color = (not args.no_color) and sys.stdout.isatty()
    st = core.status()
    print(f"watching events since #{last} | daemon={'up' if st['daemon'] else 'down'} "
          f"| bans={st['bans']} | chain={'ok' if st['chain_ok'] else 'BROKEN'} "
          f"| Ctrl-C to stop", flush=True)
    try:
        while True:
            rows = store.events_since(last, 200)
            for r in rows:
                last = max(last, r["id"])
                if args.ip and r["ip"] != args.ip:
                    continue
                if args.kind and r["kind"] != args.kind:
                    continue
                if args.rule and not (r.get("rule_id") or "").startswith(args.rule):
                    continue
                if not args.all and r["kind"] in ("http_request", "parse_error"):
                    continue
                print(_watch_line(r, color, args.jsonl), flush=True)
            time.sleep(max(0.2, args.interval))
    except KeyboardInterrupt:
        print("stopped", flush=True)


def _check_ip(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError as e:
        raise SystemExit(f"非法 IP: {ip}") from e
    if a.version != 4:
        raise SystemExit("仅支持 IPv4")
    return str(a)


def cmd_daemon(args):
    from agent.autopilot import Autopilot
    cfg, store, worker, core = _ctx()
    worker.start()
    try:
        rr = worker.enforcer.reconcile(now_iso())
        print(f"fw reconcile: {len(rr)} entries", flush=True)
    except Exception as e:
        print(f"fw reconcile failed: {e}", flush=True)
    ap = None
    if not args.no_autopilot and cfg.get("agent", {}).get("enabled"):
        ap = Autopilot(cfg, store, worker, core)
        core.autopilot = ap
        ap.start()
        print(f"autopilot enabled={ap.enabled} interval={ap.interval}s", flush=True)
    os.makedirs("data", exist_ok=True)
    pidfile = os.path.join("data", "daemon.pid")
    with open(pidfile, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))
    stop = {"v": False}

    def _stop(signum, frame):
        stop["v"] = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    print(f"nightwatch daemon pid={os.getpid()}", flush=True)
    try:
        while not stop["v"]:
            time.sleep(1)
    finally:
        if ap:
            ap.stop_event.set()
        worker.stop()
        try:
            os.remove(pidfile)
        except OSError:
            pass
        print("nightwatch stopped", flush=True)


def cmd_status(args):
    _, _, _, core = _ctx()
    d = core.status()
    if args.json:
        return _json(d)
    print(f"daemon:        {'running' if d['daemon'] else 'stopped'}")
    print(f"guard:         {'on' if d['auto_response'] else 'paused'}")
    print(f"events:        {d['events']}")
    print(f"active bans:   {d['bans']}")
    print(f"chain:         {'ok' if d['chain_ok'] else 'BROKEN'}")
    print(f"osv:           {d['osv_mode']}")
    print(f"AI autonomy:   {d['agent_autonomy']}")
    print(f"AI autopilot:  {'on' if d['autopilot'] else 'off'}")
    print(f"model key:     {'present' if d['key_present'] else 'missing'}")
    for s in d["sources"]:
        print(f"source {s['name']:<12} {'online' if s['online'] else 'offline'}  {s['path']}")


def cmd_events(args):
    _, _, _, core = _ctx()
    rows = core.events(since=args.since, limit=args.limit,
                       latest=(args.since == 0),
                       ip=args.ip, kind=args.kind, rule_prefix=args.rule)
    if args.json:
        return _json(rows)
    for r in rows:
        print(_fmt_event(r))


def cmd_event(args):
    _, _, _, core = _ctx()
    r = core.event(args.id)
    if not r:
        raise SystemExit(f"事件 #{args.id} 不存在")
    if args.json:
        return _json(r)
    print(_fmt_event(r))
    print(json.dumps(r.get("evidence"), ensure_ascii=False, indent=2))
    print(f"raw: {r.get('raw_line','')[:500]}")
    print(f"hash: {r.get('hash')}")


def cmd_bans(args):
    _, _, _, core = _ctx()
    rows = core.bans()
    if args.json:
        return _json(rows)
    if not rows:
        print("no active bans")
    for b in rows:
        print(f"{b['ip']:<16} until {b['until_ts']}  {b['reason']}")


def cmd_ban(args):
    cfg, store, worker, core = _ctx()
    ip = _check_ip(args.ip)
    nets, _ = whitelist_nets(cfg)
    if ip_allowed(ip, nets):
        raise SystemExit(f"拒绝：{ip} 在白名单/管理网段")
    row = core.ban_manual(ip, args.ttl, args.reason, args.operator)
    print(f"banned {ip} ttl={args.ttl}s decision_event=#{row['id']}")


def cmd_unban(args):
    _, _, _, core = _ctx()
    row = core.unban(_check_ip(args.ip), args.operator, args.reason)
    if not row:
        raise SystemExit(f"{args.ip} 没有生效中的封禁")
    print(f"unbanned {args.ip} event=#{row['id']}")


def cmd_flush(args):
    _, _, _, core = _ctx()
    r = core.fw_flush(args.operator)
    print(json.dumps(r, ensure_ascii=False))


def cmd_chain(args):
    _, _, _, core = _ctx()
    r = core.chain()
    if args.json:
        return _json(r)
    print(json.dumps(r, ensure_ascii=False))


def cmd_report(args):
    _, _, _, core = _ctx()
    print(core.report())


def cmd_audit(args):
    _, _, _, core = _ctx()
    r = core.audit()
    if args.json:
        return _json(r)
    s = r["summary"]
    print(f"依赖 {s.get('deps')} 个，清单 {s.get('total')} 条：确认 {s.get('confirmed')} / "
          f"版本不符 {s.get('version_mismatch')} / 未引用 {s.get('unreachable')} / "
          f"仅开发 {s.get('dev_only')} / 待定 {s.get('undetermined')}")
    for f in r["findings"]:
        print(f"  {f['verdict']:<16} {f['pkg']} {f['version']} {f['cve']} {f['reason_code']}")


def cmd_probe(args):
    cfg, _, _, core = _ctx()
    rows = core.assets()
    if args.asset:
        rows = [r for r in rows if r["id"] == args.asset]
        if not rows:
            raise SystemExit(f"未知资产: {args.asset}")
    if args.json:
        return _json(rows)
    for r in rows:
        print(f"{r['id']:<12} {r['state']:<20} {r.get('banner','')[:60]}")
        print(f"  {r.get('note','')}")


def cmd_ai(args):
    _, _, _, core = _ctx()
    info = core.agent_info()
    if not info["enabled"]:
        raise SystemExit("AI 调查已在配置中关闭")
    if not info["key_present"]:
        raise SystemExit("DEEPSEEK_API_KEY 未配置")
    r = core.agent_chat(" ".join(args.message))
    if args.json:
        return _json(r)
    print(f"model={r.get('model')} steps={r.get('steps')} "
          f"tools={[t['tool'] for t in r.get('trace', [])]}")
    print("=" * 60)
    print(r.get("answer") or ("错误：" + str(r.get("error"))))


def cmd_autonomy(args):
    _, _, _, core = _ctx()
    print("autonomy:", core.set_autonomy(args.mode))


def cmd_autopilot(args):
    _, _, _, core = _ctx()
    if args.action == "status":
        print(json.dumps({"enabled": core.autopilot_enabled()}, ensure_ascii=False))
    else:
        print("autopilot:", core.set_autopilot(args.action == "on"))


def cmd_auto_response(args):
    _, _, _, core = _ctx()
    print("auto_response:", core.set_auto_response(args.action == "on"))


def cmd_info(args):
    _, _, _, core = _ctx()
    _json(core.agent_info())


def cmd_fw_status(args):
    _, _, _, core = _ctx()
    _json(core.fw_status())


def cmd_reconcile(args):
    _, _, _, core = _ctx()
    _json(core.fw_reconcile())


def cmd_demo(args):
    extra = args.extra or []
    if args.kind == "site":
        cmd = [sys.executable, "demo/site.py"] + extra
    elif args.kind == "fake-ssh":
        cmd = [sys.executable, "demo/fake_ssh.py"] + extra
    elif args.kind == "sim":
        cmd = [sys.executable, "demo/sim.py"] + extra
    elif args.kind == "netns":
        if not extra:
            raise SystemExit("用法: nightwatch demo netns {up|down|status}")
        cmd = ["sudo", "bash", "scripts/lab_netns.sh"] + extra
    else:
        raise SystemExit("未知 demo 类型")
    raise SystemExit(subprocess.call(cmd, cwd=ROOT))


def main():
    ap = argparse.ArgumentParser(prog="nightwatch",
                                 description="AI 守夜人 · 命令行")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("daemon", help="常驻采集/检测/AI 值守")
    p.add_argument("--no-autopilot", action="store_true")
    p.set_defaults(fn=cmd_daemon)

    p = sub.add_parser("status", help="运行状态")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("watch", help="实时输出新事件（攻击→检测→封禁）")
    p.add_argument("--ip", default="")
    p.add_argument("--kind", default="")
    p.add_argument("--rule", default="")
    p.add_argument("--since", type=int, default=0)
    p.add_argument("--from-start", action="store_true")
    p.add_argument("--interval", type=float, default=0.5)
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--jsonl", action="store_true")
    p.add_argument("--all", action="store_true", help="包含 http_request/parse_error")
    p.set_defaults(fn=cmd_watch)

    p = sub.add_parser("events", help="查询事件")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--since", type=int, default=0)
    p.add_argument("--latest", action="store_true", default=True)
    p.add_argument("--ip", default="")
    p.add_argument("--kind", default="")
    p.add_argument("--rule", default="")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_events)

    p = sub.add_parser("event", help="单条事件证据")
    p.add_argument("id", type=int)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_event)

    p = sub.add_parser("bans", help="生效封禁")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_bans)

    p = sub.add_parser("ban", help="手动封禁")
    p.add_argument("ip")
    p.add_argument("--ttl", type=int, default=600)
    p.add_argument("--reason", default="manual")
    p.add_argument("--operator", default="cli")
    p.set_defaults(fn=cmd_ban)

    p = sub.add_parser("unban", help="解封")
    p.add_argument("ip")
    p.add_argument("--operator", default="cli")
    p.add_argument("--reason", default="manual")
    p.set_defaults(fn=cmd_unban)

    p = sub.add_parser("flush", help="清空 nftables 封禁集")
    p.add_argument("--operator", default="cli")
    p.set_defaults(fn=cmd_flush)

    p = sub.add_parser("chain", help="校验哈希链")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_chain)

    p = sub.add_parser("report", help="值班日报")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("audit", help="依赖漏洞验真")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_audit)

    p = sub.add_parser("probe", help="资产探测")
    p.add_argument("asset", nargs="?")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_probe)

    p = sub.add_parser("ai", help="AI 调查")
    p.add_argument("message", nargs="+")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_ai)

    p = sub.add_parser("autonomy", help="AI 自主封禁模式")
    p.add_argument("mode", choices=["auto", "approve"])
    p.set_defaults(fn=cmd_autonomy)

    p = sub.add_parser("autopilot", help="7×24 值守")
    p.add_argument("action", choices=["on", "off", "status"])
    p.set_defaults(fn=cmd_autopilot)

    p = sub.add_parser("auto-response", help="确定性自动处置开关")
    p.add_argument("action", choices=["on", "off"])
    p.set_defaults(fn=cmd_auto_response)

    p = sub.add_parser("info", help="AI 工具与配置")
    p.set_defaults(fn=cmd_info)

    p = sub.add_parser("fw-status", help="nftables 封禁集")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_fw_status)

    p = sub.add_parser("reconcile", help="按账本对账 nft")
    p.set_defaults(fn=cmd_reconcile)

    p = sub.add_parser("demo", help="演示站/模拟器/实验网")
    p.add_argument("kind", choices=["site", "fake-ssh", "sim", "netns"])
    p.add_argument("extra", nargs=argparse.REMAINDER)
    p.set_defaults(fn=cmd_demo)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
