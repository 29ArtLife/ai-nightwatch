"""LLM 工具调用循环：模型选工具 → 执行 → 回填结果 → 直到给出结论。"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

from .prompt import system_prompt
from .tools import Ctx, build_specs, execute

CITE = re.compile(r"#(\d+)")


def _chat(cfg: dict, messages: list[dict], tools: list[dict]) -> dict:
    key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not key:
        raise RuntimeError("DEEPSEEK_API_KEY 未配置，AI 调查不可用")
    a = cfg["agent"]
    body = {
        "model": a.get("model", "deepseek-chat"),
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
        "temperature": 0.2,
        "max_tokens": 2000,
        "stream": False,
    }
    req = urllib.request.Request(
        a.get("api", "https://api.deepseek.com/v1").rstrip("/") + "/chat/completions",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
    try:
        with urllib.request.urlopen(req, timeout=int(a.get("api_timeout_sec", 60))) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"模型接口 HTTP {e.code}: {detail}") from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise RuntimeError(f"模型接口不可达：{e}") from e


def _assistant_msg(msg: dict) -> dict:
    out = {"role": "assistant", "content": msg.get("content") or ""}
    if msg.get("tool_calls"):
        out["tool_calls"] = msg["tool_calls"]
    return out


def _validate_citations(store, answer: str) -> list[int]:
    bad = []
    for x in set(CITE.findall(answer or "")):
        if not store.event(int(x)):
            bad.append(int(x))
    return sorted(bad)


def run_agent(message: str, cfg: dict, ctx: Ctx, history: list[dict] | None = None) -> dict:
    if not cfg.get("agent", {}).get("enabled", False):
        return {"ok": False, "error": "AI 调查已在配置中关闭"}
    specs = build_specs(cfg)
    messages = [{"role": "system", "content": system_prompt(
        cfg, getattr(ctx.service, "agent_autonomy", "approve"))}]
    for h in history or []:
        if h.get("role") in ("user", "assistant") and h.get("content"):
            messages.append({"role": h["role"], "content": h["content"][:4000]})
    messages.append({"role": "user", "content": message[:4000]})

    trace, steps, final, deadline = [], 0, "", time.time() + int(
        cfg["agent"].get("deadline_sec", 180))
    try:
        for step in range(int(cfg["agent"].get("max_steps", 8))):
            if time.time() > deadline:
                final = "达到本次调查时间上限，以下是已收集到的信息。"
                break
            steps += 1
            resp = _chat(cfg, messages, specs)
            msg = resp["choices"][0]["message"]
            messages.append(_assistant_msg(msg))
            calls = msg.get("tool_calls") or []
            if not calls:
                final = msg.get("content") or ""
                break
            for call in calls:
                fn = call.get("function", {})
                name = fn.get("name", "")
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                t0 = time.time()
                result = execute(ctx, name, args)
                ms = int((time.time() - t0) * 1000)
                ctx.worker.enqueue_event("agent_tool", "0.0.0.0", {
                    "tool": name, "args": args, "ok": "error" not in result,
                    "duration_ms": ms,
                    "result_preview": json.dumps(result, ensure_ascii=False)[:600],
                })
                trace.append({"step": steps, "tool": name, "args": args,
                              "ok": "error" not in result, "duration_ms": ms,
                              "result_preview": json.dumps(result, ensure_ascii=False)[:800]})
                cap = int(cfg["agent"].get("max_output_bytes", 12000))
                payload = json.dumps(result, ensure_ascii=False)
                if len(payload.encode("utf-8")) > cap:
                    payload = payload.encode("utf-8")[:cap].decode("utf-8", "ignore")
                messages.append({"role": "tool", "tool_call_id": call.get("id", ""),
                                 "content": payload})
        else:
            final = "达到最大工具调用步数，未能形成最终结论。"
    except Exception as e:
        err = str(e)
        ctx.worker.enqueue_event("agent_run", "0.0.0.0", {
            "message": message[:500], "error": err, "model": cfg["agent"].get("model")})
        return {"ok": False, "error": err, "trace": trace, "steps": steps}

    bad = _validate_citations(ctx.store, final)
    warning = ""
    if bad:
        warning = ("以下引用的事件编号不存在，结论可信度存疑："
                   + ", ".join(f"#{i}" for i in bad))
        final += f"\n\n> ⚠️ 引用校验：{warning}"
    ctx.worker.enqueue_event("agent_run", "0.0.0.0", {
        "message": message[:500], "answer": final[:3000],
        "model": cfg["agent"].get("model"), "steps": steps,
        "tools": [t["tool"] for t in trace],
        "citations_invalid": bad})
    return {"ok": True, "answer": final, "trace": trace, "steps": steps,
            "citations_invalid": bad, "warning": warning,
            "model": cfg["agent"].get("model")}
