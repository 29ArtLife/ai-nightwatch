# AI 守夜人 · Nightwatch

24 小时驻守中小网站与服务器的防御侧 AI Agent：**先验真、再处置、全程留痕**；
配套上线前的漏洞验真体检（剔除扫描器误报）。

- 监控台：`http://10.2.102.143:8080/?token=<见服务器 data/token.txt>`
- 演示站：`http://10.2.102.143:8081`（账号 `demo / demo`）
- 部署：Ubuntu 24.04 / Python 3.12 / 运行时依赖只有 `packaging`
- 数据：SQLite WAL + JSONL；裁决不使用任何大模型

## 架构

```
日志 JSONL ──tail -F──> 单写线程 ──> 事件账本(SQLite, 哈希链)
                          │              │
                          ├─ 滑窗检测(6×10s) ──> 验真裁决(纯函数) ──> 封禁/观察/告警
                          │                                        └─> SSE 推送监控台
                          └─ 解析失败也入账（parse_error）
体检管线：扫描器清单 → OSV 按 CVE 反查 → 别名并查集 → 版本范围 → 作用域 → import 可达性
资产验真：内置 SSH 探测（banner + KEXINIT）→ banner 单独证据一律“存疑”
AI 调查员：用户提问 → 模型选工具 → 工具层白名单执行 → 结果回填 → 带引用结论
             （只读 + 建议；裁决与处置仍由确定性引擎/人工完成）
```

进程（systemd，均以 `li` 运行，端口 >1024）：

| 服务 | 端口 | 作用 |
|---|---|---|
| `nightwatch` | 8080 | 采集/检测/裁决/API/SSE/监控台 |
| `nightwatch-demo` | 8081 | 被守护的演示站（被封 IP 返回 403） |
| `nightwatch-fakessh` | 2222 | 假 banner 资产（自称 OpenSSH 7.4，无握手） |

## 3 分钟演示

```bash
cd ~/nightwatch
# 1) 对照组：正常用户 2 次输错后成功，不会被封
.venv/bin/python demo/sim.py normal --src 127.0.0.3
# 2) 爆破：第 5 次失败触发封禁；随后用正确密码仍 403
.venv/bin/python demo/sim.py brute  --src 127.0.0.2 --n 5
# 3) 扫描：404 与敏感路径双阈值触发第二个封禁
.venv/bin/python demo/sim.py scan   --src 127.0.0.12
# 4) 白名单：6 次失败也只观察（负证据 WHITELIST）
.venv/bin/python demo/sim.py whitelist --src 127.0.0.1 --n 6
```

监控台：实时事件流（每条的原始日志行与哈希可展开）→ 封禁名单倒计时/一键解封 →
「未处置」区解释**为什么没封** → 体检页运行漏洞验真 → 资产页探测 → 日报页校验哈希链。

## AI 调查员（大模型驱动）

监控台「AI 调查」页签是一个工具调用型 Agent：模型（默认 `deepseek-chat`）自己决定调用哪个工具、
看哪条证据，最后输出带 `#事件号` 引用的结论。

| 工具 | 作用 |
|---|---|
| `guard_status` / `query_events` / `get_event` / `verify_chain` | 只读查看守夜人状态与证据链 |
| `audit_dependencies` | 运行漏洞验真管线 |
| `probe_asset(id)` | 内置探测（SSH banner+握手 / HTTP） |
| `nmap_scan(id)` / `nikto_scan(id)` / `whatweb_scan(id)` | 对**配置中的授权资产**做主动检查 |
| `host_audit` | 本机只读巡检（监听端口/负载/内存/磁盘） |
| `propose_ban(ip, reason, evidence_ids)` | 只生成待人工确认的封禁建议 |

安全边界（工具层强制，不依赖模型自觉）：
- 扫描工具只接受 `asset_id`，host/port 从 `config.toml` 解析并二次校验 IP 白名单；
- 模型不能调用封禁/解封；`propose_ban` 只是建议，必须在监控台点「批准封禁」才会执行；
- 所有工具调用与 Agent 结论写入哈希链（`agent_tool` / `agent_run`）；
- 结论里的 `#id` 会被回查，引用不存在的事件会标注「可信度存疑」；
- 主动扫描同一资产有 60 秒冷却；命令全部用参数列表执行，无 shell 拼接。

启用需要模型密钥（只写入服务器本地，权限 600）：

```bash
ssh li@10.2.102.143
umask 077
printf 'DEEPSEEK_API_KEY=%s\n' '<你的 DeepSeek Key>' > ~/nightwatch/data/agent.env
sudo systemctl restart nightwatch
```

依赖工具（已安装）：`nmap`、`nikto`、`whatweb`。未配置密钥或断网时，AI 页签提示不可用，
确定性守卫与全部演示照常运行。LYNIS 因单次 >90 秒，未接入交互链路。

## 测试

```bash
.venv/bin/python -m pytest -q          # 25 个单测：链/并发/篡改/尾删/滑窗/裁决/范围/别名/Agent
.venv/bin/python scripts/selftest.py   # 10 条端到端（需服务已启动）
```

`selftest` 覆盖：正常用户不误封、第 5 次封禁、封后正确密码 403、扫描封禁、回滚恢复、
体检 12→5/5/1/1、假 banner 存疑、链校验、未授权目标 0 发包、日报生成。

## 漏洞验真口径

- 输入是**外部扫描器的按包名粗筛清单**（`demo/demo_project/raw_findings.json`），
  每条按 CVE 反查 OSV 并解析其 aliases，再用锁定版本比对 `introduced/fixed/last_affected`。
  因此「版本不符」是真算出来的，不是 querybatch 猜出来的。
- 判定：`CONFIRMED`（在范围 + 生产 + 被 import）/ `VERSION_MISMATCH`（不在范围）/
  `UNREACHABLE`（在范围但未 import）/ `DEV_ONLY`（仅开发依赖）/ `UNDETERMINED`（无可比对范围）。
- 可达性只覆盖**直接 import**（`ast` 扫 `Import` 与 `ImportFrom`）；动态导入会在证据里
  标 `dynamic_imports_uncovered=true`，不冒充已覆盖传递依赖。
- 数据不可用时**明确失败**（`UNDETERMINED` / 报错），绝不输出“0 漏洞”的空报告。

## OSV 离线快照

```bash
.venv/bin/python scripts/snapshot_osv.py    # 联网时执行，写入 osv/vulns/*.json 与 meta.json
NW_OSV_MODE=offline .venv/bin/python -m verify.findings --project demo/demo_project
```

快照保存 OSV **原始响应**，可用 `https://api.osv.dev/v1/vulns/{id}` 对拍；
`meta.json` 记录生成时间与 sha256。默认 `offline`，现场断网不影响演示。

## 配置要点（config.toml）

- `server.token`：留空则首次启动生成并写入 `data/token.txt`（所有 `/api/*` 需要 Bearer 或 `?token=`）
- `enforce.whitelist_ips`：永不处置；封禁默认 600 秒，可一键回滚
- `asset.allowed_targets`：唯一发包白名单，写入 `verify/assets.py` 的唯一连接入口，API 不接受任意 host
- `osv.mode`：`offline | online`；`NW_OSV_MODE` 环境变量优先
- `mode.auto_response=false` 时所有裁决降级为告警

## 运维

```bash
sudo systemctl status nightwatch nightwatch-demo nightwatch-fakessh
sudo systemctl restart nightwatch nightwatch-demo nightwatch-fakessh
sudo journalctl -u nightwatch --since today
sudo journalctl -u nightwatch-demo --since today
```

- 日志：`logs/app_access.jsonl`、`logs/app_auth.jsonl`（演示站写入）；stdout 交 journald
- 数据：`data/nightwatch.db`（WAL）；`data/reports/` 预留
- 备份：`tar czf ~/nightwatch-$(date +%F).tgz -C ~ --exclude='nightwatch/.venv' \
  --exclude='nightwatch/data' nightwatch`

## 安全边界（主动声明）

- 只守护**自有或授权资产**；资产探测唯一发包入口有 IP 白名单硬闸，拒绝主机名与未列出地址。
- 只做封禁/告警/观察，**不做任何形式的反击**；生产防火墙封禁仅预留接口（`apply_production_ban`）。
- 演示封禁在应用层（演示站中间件），最坏代价是该 IP 10 分钟无法访问演示站，监控台不受影响。
- 日志字段白名单：只记 `ts/ip/user/path/status/ua`，不记录密码/token/cookie。
- 哈希链是 **tamper-evident**，不是 tamper-proof：有数据库写权限者可整库重写，
  需配合外部锚点/备份；但删尾、改中间行、改列内容都会被 `count + last_hash + canonical` 发现。

## 已知局限

- 检测器为规则/统计型，覆盖爆破与路径扫描两类；未知攻击不在能力内。
- 漏洞验真仅 Python 生态（requirements），不支持 npm；可达性为直接 import 级。
- 内置 SSH 探测不依赖 nmap；`nmap` 引擎未启用（方案中“骗过 nmap”的表述需按实际实现调整）。
- `auth.log` 解析器保留但默认不接（logrotate 会丢 ACL，演示不依赖它）。
- 不支持多租户/账号体系；内网单机部署，靠 token 保护监控台。
- AI 调查员的结论仍可能出错；它没有处置权，且引用会被回查，但不应把它的建议当裁决。
