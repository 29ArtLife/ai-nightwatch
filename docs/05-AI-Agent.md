# 05 · AI Agent

## 1. 定位

AI **不参与确定性裁决**。它负责：

- 调查：查账本、还原攻击链、识别工具；
- 解释：引用事件号，说明为什么封/为什么没封；
- 补处置：在 `autonomy=auto` 时直接封禁/升级/写 WAF 规则；
- 值守：7×24 有新告警才醒来。

封禁结论仍由 `app/decide.py` 的规则给出，保证可复现、可审计。

## 2. 模型

- 默认 `deepseek-chat`，OpenAI 兼容 `/v1/chat/completions`
- 函数调用（tools）循环，最多 8 步
- 密钥：`data/agent.env` 或环境变量 `DEEPSEEK_API_KEY`
- 断网/失败：确定性引擎继续工作，AI 退避

## 3. 工具清单

| 工具 | 作用 | 权限 |
|---|---|---|
| `guard_status` | 事件数、封禁、采集源、链 | 只读 |
| `query_events(ip,kind,rule_prefix,limit)` | SQL 过滤查账本 | 只读 |
| `get_event(id)` | 单条完整证据 | 只读 |
| `verify_chain` | 哈希链校验 | 只读 |
| `audit_dependencies` | OSV 依赖验真 | 只读 |
| `probe_asset(asset_id)` | SSH/HTTP 资产探测 | 白名单资产 |
| `nmap_scan(asset_id)` | 端口/服务识别 | 白名单资产 |
| `nikto_scan(asset_id)` | Web 配置检查 | 白名单 HTTP 资产 |
| `whatweb_scan(asset_id)` | 指纹识别 | 白名单 HTTP 资产 |
| `host_audit` | 本机端口/负载/内存/磁盘 | 只读 |
| `attack_chain(ip)` | 串应用/网络/WAF 事件 | 只读 |
| `profile_attacker(ip)` | 识别 nmap/nikto/sqlmap/hydra | 只读 |
| `firewall_status` | nft 活跃封禁 + 账本封禁 | 只读 |
| `propose_ban(ip,reason,evidence_ids)` | 生成待人工确认建议 | 不执行 |
| `list_pending` | 待确认建议 | 只读 |
| `execute_ban(ip,reason,ttl,evidence_ids)` | 直接封禁 | 需 autonomy=auto |
| `escalate_ban(ip,reason,ttl,evidence_ids)` | 延长已有封禁 | 需 autonomy=auto |
| `deploy_waf_rule(match,value,note)` | 写 UA/路径 WAF 规则 | 需 autonomy=auto |

## 4. 自主模式

```toml
[agent]
autonomy = "auto"      # auto | approve
auto_ban_ttl = 600
max_auto_bans_per_min = 3
```

- `auto`：模型可在证据充分时直接调用 `execute_ban` / `escalate_ban` / `deploy_waf_rule`。
- `approve`：只能 `propose_ban`，人工批准后执行。

运行时切换（不需要重启）：

```bash
./nightwatch autonomy auto
./nightwatch autonomy approve
```

写入 `data/autonomy.flag`，daemon 立即读取。

## 5. 7×24 值守

```toml
[agent]
autopilot = true
autopilot_interval_sec = 30
autopilot_max_calls_per_hour = 20
autopilot_max_alerts = 8
```

行为：

- 每 30 秒检查一次新事件；
- 只有新的 `net_alert` / `waf_alert` / `honeypot` / 高风险 observe 才调模型；
- 没有新告警 → 不调用模型；
- 已封禁 IP 跳过；同一批告警按事件 id 哈希去重；
- 每小时最多 20 次模型调用；
- API 失败退避 5 分钟；
- 状态可在 `./nightwatch status` / `info` / TUI 查看。

运行时开关：

```bash
./nightwatch autopilot on|off|status
```

## 6. 护栏（工具层强制，不靠模型自觉）

1. 只有 `autonomy=auto` 且 `auto_response` 未暂停时才能执行封禁；
2. 白名单/管理网段永不可封：`127.0.0.1`、`10.2.102.143`、`10.200.0.1`、`172.20.10.0/28`；
3. 必须引用**同一 IP** 的 `net_alert` / `waf_alert` / `decision` 强证据；
4. TTL：execute 60–3600 秒；escalate 3600–86400 秒；
5. 自动封禁最多 3 次/分钟；
6. AI 不能解封、清空、改 nft 规则；
7. 动态 WAF 规则只能 UA/路径模板，最多 3 条，`nginx -t` 失败回滚；
8. 所有动作写哈希链，记录 `actor=ai-agent` 与证据事件号；
9. 不能对非授权地址扫描，不能运行攻击工具（红队只能人工/实验 netns）。

## 7. Battle 模式

### 7.1 Plain

```bash
./nightwatch battle --plain
```

逐行输出：攻击事件 + `[TOOL]` + `[OK]` + `[AGENT]`。

### 7.2 TUI

```bash
./nightwatch battle --tui
```

Textual 全屏：

- 顶部：DEFCON / events / bans / chain / AI 模式 / PAUSED
- 左栏：攻击流（NET/WAF/HONEYPOT/BAN）
- 右栏：AI 控制台（工具调用与结论）
- 底部：attacks / bans / last event
- 按键：`q` 退出、`p` 暂停、`u` 解封第一个

### 7.3 流式 trace

`run_agent(..., on_trace=callback)` 在每次工具开始/结束、最终答案时回调；
TUI 通过队列实时渲染。所有工具调用同时写 `agent_tool` 事件。

## 8. 提示词

- `agent/prompt.py`：通用调查员，强调证据、引用、授权资产、不得攻击。
- `battle/agent.py`：蓝队指挥官，实验模式：授权资产上的 `net_alert`/`waf_alert`
  即视为足够证据，直接 `execute_ban`；重复攻击可 `escalate_ban`；可 `profile_attacker`；
  新扫描器 UA/路径可 `deploy_waf_rule`。

## 9. 失败与降级

- 密钥缺失：AI 命令报错；daemon 的 autopilot 不调用；确定性防线正常。
- API 失败：autopilot 退避 5 分钟；battle 只显示确定性事件。
- TUI 不可用：`--plain`。
- 模型乱说：结论引用会回查，引用不存在的事件会被标注“可信度存疑”。
