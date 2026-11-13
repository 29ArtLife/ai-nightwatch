# 03 · CLI 参考

入口：`./nightwatch`（等价于 `.venv/bin/python -m app.cli`）。

所有命令在仓库根目录执行；`--json` 输出机器可读。

## 1. 守护与状态

### `daemon`

```bash
./nightwatch daemon              # 常驻：采集/检测/裁决/封禁/AI 值守
./nightwatch daemon --no-autopilot
```

systemd 使用：

```ini
ExecStart=/home/li/nightwatch/.venv/bin/python -m app.cli daemon
```

### `status`

```bash
./nightwatch status
./nightwatch status --json
```

输出：daemon 是否运行、事件数、封禁数、采集源在线、链状态、OSV 模式、AI autonomy/autopilot、模型密钥。

### `info`

```bash
./nightwatch info
```

AI 工具数量、资产、autonomy/autopilot、密钥状态。

## 2. 事件

### `events`

```bash
./nightwatch events --limit 20
./nightwatch events --ip 10.2.31.236 --limit 20
./nightwatch events --kind waf_alert --limit 10
./nightwatch events --rule NET_ --limit 10
./nightwatch events --since 1000 --limit 200
./nightwatch events --json
```

默认取最近 N 条；`--since <id>` 从指定 id 之后按升序取。

### `event <id>`

```bash
./nightwatch event 1678
./nightwatch event 1678 --json
```

显示完整 evidence、原始日志行、prev_hash/hash。

### `watch`

实时轮询账本并输出新事件：

```bash
./nightwatch watch
./nightwatch watch --ip 10.2.31.236
./nightwatch watch --kind decision
./nightwatch watch --rule WAF_
./nightwatch watch --all          # 包含 http_request/parse_error
./nightwatch watch --jsonl | jq .
./nightwatch watch --from-start   # 从头回放
```

默认隐藏 `http_request` / `parse_error` 噪声；封禁红色、观察绿色、网络告警青色、WAF 紫色。

## 3. 封禁

### `bans`

```bash
./nightwatch bans
./nightwatch bans --json
```

### `ban`

```bash
./nightwatch ban 1.2.3.4 --ttl 600 --reason "manual test"
```

校验：IPv4、非白名单/管理网段；写 decision + bans + nft。

### `unban`

```bash
./nightwatch unban 1.2.3.4 --operator demo --reason "false positive"
```

写 rollback 事件并删除 nft 元素。

### `flush`

```bash
./nightwatch flush
```

清空 `nw_block`（kill switch），不影响 nft 表和其他规则；写 firewall 事件。

### `fw-status` / `reconcile`

```bash
./nightwatch fw-status --json
./nightwatch reconcile
```

`reconcile` 按账本生效封禁重放 nft 集合，幂等。

## 4. 证据

### `chain`

```bash
./nightwatch chain
./nightwatch chain --json
```

返回 `{ok, count, head}`；失败时带 `broken_at` / `reason`。

## 5. 体检与资产

### `audit`

```bash
./nightwatch audit
./nightwatch audit --json
```

依赖 → OSV 按 CVE 反查 → 别名并查集 → 版本范围 → 作用域 → import 可达性。

### `probe`

```bash
./nightwatch probe                # 全部资产
./nightwatch probe sshd
./nightwatch probe fake-ssh --json
```

SSH：banner + KEXINIT；HTTP：响应头。仅白名单资产。

### `profile`

```bash
./nightwatch profile 10.2.31.236
./nightwatch profile 10.2.31.236 --json
```

启发式识别 nmap / nikto / sqlmap / hydra / masscan / curl。

## 6. AI

### `ai`

```bash
./nightwatch ai "巡检当前状态，有明确攻击就封 600 秒"
./nightwatch ai "调查 10.2.31.236，证据明确就直接封禁" --json
```

需要 `DEEPSEEK_API_KEY`（`data/agent.env` 或环境变量）。

### `autonomy`

```bash
./nightwatch autonomy auto       # AI 可直接封禁
./nightwatch autonomy approve    # AI 只能建议
```

写入 `data/autonomy.flag`；daemon 立即读取，无需重启。

### `autopilot`

```bash
./nightwatch autopilot on
./nightwatch autopilot off
./nightwatch autopilot status
```

写入 `data/autopilot.flag`；daemon 每 30 秒读取。

### `auto-response`

```bash
./nightwatch auto-response off   # 确定性引擎只告警
./nightwatch auto-response on
```

影响 `decide` 的 `AUTO_DISABLED` 分支，也影响 AI `execute_ban`（暂停时禁止）。

## 7. 实战

### `battle`

```bash
./nightwatch battle --tui        # 全屏作战室（需要 textual）
./nightwatch battle --plain      # 彩色行输出
./nightwatch battle --no-model   # 只显示确定性防线
./nightwatch battle --interval 0.5
```

TUI 按键：`q` 退出、`p` 暂停/恢复自动处置、`u` 解封第一个。

### `demo`

```bash
./nightwatch demo site --host 127.0.0.1 --port 8082
./nightwatch demo fake-ssh --port 2222
./nightwatch demo sim normal --src 127.0.0.3
./nightwatch demo netns up|down|status
```

`demo netns` 需要 sudo。

## 8. 返回码与错误

- 参数/校验错误：非 0，stderr 说明
- `bans` 为空：正常输出 `no active bans`
- `unban` 无生效封禁：非 0
- `chain`：JSON 内 `ok` 字段，不以退出码区分
- AI 未配置密钥：`ai` 命令报错并退出
