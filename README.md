# AI 守夜人 · Nightwatch（CLI 版）

24 小时驻守中小网站与服务器的防御侧安全 Agent：**先验真、再处置、全程留痕**；
网络层 Suricata + Web 层 ModSecurity + 主机层 nftables，AI 负责调查、解释与处置建议。

- 部署：Ubuntu 24.04 / Python 3.12
- 入口：`./nightwatch`（或 `.venv/bin/python -m app.cli`）
- 数据：SQLite WAL + 哈希链
- 运行时依赖只有 `packaging`

## 快速开始

```bash
cd ~/nightwatch
./nightwatch status              # 运行状态
./nightwatch watch               # 实时事件流（另开终端攻击）
./nightwatch events --limit 20   # 最近事件
./nightwatch bans                # 生效封禁
./nightwatch chain               # 校验哈希链
./nightwatch ai "巡检当前状态，有明确攻击就封 600 秒"
```

常驻服务由 systemd 管理：

```bash
sudo systemctl status nightwatch
sudo systemctl restart nightwatch
sudo journalctl -u nightwatch -f
```

## 命令

| 命令 | 作用 |
|---|---|
| `daemon` | 常驻采集/检测/裁决/封禁 + AI 值守（systemd 使用） |
| `status [--json]` | 守护状态、事件数、封禁数、采集源、链完整性、AI 状态 |
| `watch [--ip] [--kind] [--rule] [--jsonl]` | **实时输出**新事件（攻击→检测→封禁） |
| `events [--ip] [--kind] [--rule] [--since] [--limit] [--json]` | 查事件账本 |
| `event <id> [--json]` | 单条事件的完整证据与哈希 |
| `bans [--json]` | 生效封禁 |
| `ban <ip> [--ttl 600] [--reason]` | 手动封禁（写链 + nft） |
| `unban <ip>` | 解封（写链 + 删除 nft 元素） |
| `flush` | 清空 nftables 封禁集（kill switch） |
| `chain [--json]` | 哈希链校验 |
| `report` | 值班日报（模板，不含大模型裁决） |
| `audit [--json]` | 依赖漏洞验真（OSV 版本/作用域/可达性） |
| `probe [asset] [--json]` | 资产探测（SSH banner+握手 / HTTP） |
| `ai "<问题>" [--json]` | AI 调查；auto 模式下可直接封禁 |
| `autonomy auto\|approve` | AI 能否直接封禁 |
| `autopilot on\|off\|status` | 7×24 值守开关/状态 |
| `auto-response on\|off` | 确定性引擎自动处置开关 |
| `fw-status [--json]` | nftables 活跃封禁集 |
| `reconcile` | 按账本回放 nft 封禁 |
| `info` | AI 工具、资产、密钥状态 |
| `demo site\|fake-ssh\|sim\|netns` | 演示站/假 SSH/模拟器/实验网 |

## 架构

```
Suricata 旁路 ─┐
nginx + ModSecurity (8081→8082) ─┤
应用 JSONL ────┴─> TailSource ─> 单写线程 ─> 检测 ─> 纯函数裁决
                                                │
                                    ┌───────────┴───────────┐
                                    ▼                       ▼
                            Store（哈希链账本）        Enforcer
                                    │                       ├─ 应用层 403
                                    ▼                       └─ nftables 丢包
                              CLI 查询/回放
AI：只读工具 + 建议/执行封禁（autonomy=auto 且有护栏）；不在裁决链路上。
```

进程：

| 服务 | 端口 | 作用 |
|---|---|---|
| `nightwatch` | — | daemon：采集/检测/裁决/封禁/AI 值守 |
| `nginx` | 8081 | WAF 反代 → 8082 |
| `nightwatch-demo` | 8082 | 演示站（仅回环） |
| `nightwatch-fakessh` | 2222 | 假 banner 资产 |
| `suricata` | — | 旁路 IDS，eve.json |

## 网络防线

- Suricata：ET SCAN/DOS + 本地 SYN 规则 → `NET_SCAN/NET_DOS/NET_EXPLOIT/NET_C2`
- ModSecurity CRS：913/930/932/941/942 等 → `WAF_SCANNER/LFI/RCE/XSS/SQLI`
- nginx limit_req 429 → `HTTP_FLOOD`
- nftables `inet nightwatch`：`nw_block` 带 timeout；22 端口在 drop 之前放行；
  白名单在 `/etc/nightwatch/fw-allow`，li 只能通过 root wrapper `nw-fw` 操作。
- 封禁/解封/到期/清空全部写哈希链；启动时按账本对账回放。

## AI 调查与自主处置

```toml
[agent]
enabled = true
model = "deepseek-chat"
autonomy = "auto"          # auto=可直接封；approve=只建议
auto_ban_ttl = 600
max_auto_bans_per_min = 3
autopilot = true
autopilot_interval_sec = 30
autopilot_max_calls_per_hour = 20
```

- `./nightwatch ai "..."`：AI 可查事件、还原攻击链、看防火墙状态、执行 `execute_ban`。
- `autonomy=auto` 时，`execute_ban` 的护栏：白名单/管理网段不可封、必须引用同 IP 的
  `net_alert/waf_alert/decision`、TTL 60–3600、最多 3 次/分钟、全局自动处置关闭时禁止；
  AI 无解封/清空权限。所有 AI 封禁记录 `actor=ai-agent` 与证据事件号。
- `autopilot=on`：后台线程每 30 秒检查新告警，没有新告警不调用模型；已封禁 IP 跳过、
  同批去重、每小时最多 20 次调用、API 失败退避 5 分钟。
- 密钥放 `data/agent.env`（600）：

```bash
umask 077
printf 'DEEPSEEK_API_KEY=%s\n' '<你的 Key>' > data/agent.env
sudo systemctl restart nightwatch
```

## 测试

```bash
.venv/bin/python -m pytest -q        # 47 个单测
.venv/bin/python scripts/selftest.py # 16 条端到端（CLI）
bash scripts/redteam.sh              # 9 个红队用例 → 矩阵
```

红队只打实验 netns（10.200.0.2，无默认路由）里的授权资产。

## 部署

```bash
sudo apt-get install -y suricata nginx libnginx-mod-http-modsecurity modsecurity-crs \
  nftables logrotate nmap nikto hydra sqlmap hping3 tcpdump
sudo python3 scripts/patch_suricata.py
sudo install -m 644 deploy/suricata/local.rules /var/lib/suricata/rules/local.rules
sudo systemctl enable --now suricata
bash scripts/deploy.sh
```

换网络后同步四处：`config.toml` 的 `enforce.whitelist_ips`、`/etc/nightwatch/fw-allow`、
nft `nw_allow`、`scripts/patch_suricata.py` 的 `HOME_NET`。

## 边界

- 只守护自有/授权资产；只封禁/告警/观察，不做反击。
- 不做 inline IPS、不做 DDoS 流量清洗、不解密 TLS、不防 0-day。
- AI 可能出错；它不参与确定性裁决，封禁有证据、TTL、可回滚。
- 生产防火墙封禁（ipset/nftables）通过 wrapper 已落地；其他主机/云 WAF 需自行接入。
