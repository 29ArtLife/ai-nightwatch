# 09 · 安全边界与 FAQ

## 1. 授权边界

- 只守护**自有或明确授权**的资产；
- 只对授权地址发包：资产探测和红队脚本都有硬编码白名单；
- 实验 netns `nw-attacker`（10.200.0.2）**没有默认路由**，物理上打不到外网；
- Kali 只打 `10.2.102.143` / 实验宿主，不扫描第三方；
- 不做任何形式的反击、不拖库、不横向移动、不做漏洞利用。

## 2. 能力边界

**能做：**

- 登录爆破、路径扫描、端口扫描、SYN Flood、HTTP Flood；
- OWASP CRS 覆盖的 SQLi / XSS / RCE / LFI / 扫描器；
- 已知依赖漏洞验真（OSV，剔除版本不符/未引用/仅开发）；
- 资产 banner+握手验真、攻击者工具画像；
- 短时封禁、TTL、回滚、哈希链审计；
- AI 调查、解释、建议、自主封禁、7×24 值守、动态 WAF 规则。

**不能做：**

- 0-day、未知攻击；
- 大规模 DDoS 流量清洗；
- HTTPS 内容解密（生产可在 nginx 终止 TLS 后再过 WAF）；
- 主机恶意进程/Rootkit/横向移动；
- 正确口令的低频慢速撞库（单 IP 低于阈值）；
- 覆盖非 HTTP 端口的应用层攻击（除非日志接入）。

## 3. 安全设计

- nft 链没有 policy drop，未命中流量放行；
- 22 端口在 drop 之前 accept，永远不封 SSH；
- 白名单真相在 root 文件 `/etc/nightwatch/fw-allow`，不读应用配置；
- li 只能通过 root wrapper `nw-fw` / `nw-waf` 操作，参数在 wrapper 内校验；
- AI 不能解封/清空/改 nft 规则；
- 动态 WAF 规则模板化、最多 3 条、`nginx -t` 失败回滚；
- 所有动作写哈希链，记录 actor 与证据事件号；
- 哈希链 tamper-evident 而非 tamper-proof，需外部锚点/备份配合。

## 4. 数据与隐私

- 演示站日志只记 `ts/ip/method/path/status/ua`，不记密码/token/cookie；
- 登录日志只记用户名与结果；
- 蜜罐返回的是假数据，明确标注 FAKE，不含真实密钥；
- 模型只收到结构化事件摘要/证据，不接收原始密钥；
- 所有数据本地 SQLite，不上传第三方（模型 API 除外，且只发调查所需内容）。

## 5. FAQ

**Q：为什么没有 Web 监控台？**
A：已改纯 CLI。`battle --tui` 是终端作战室，`watch` 是实时流，避免额外 Web 攻击面。

**Q：AI 为什么不直接裁决？**
A：裁决必须可复现、可审计。确定性规则负责封禁；AI 只做调查/解释/补处置，且在护栏内。

**Q：为什么 127.0.0.2 被封却看不到 nft 元素？**
A：回环来源由应用层 403 兜底，`FwBackend` 对 loopback 返回 skipped；内核封回环没有意义。

**Q：WAF 403 为什么没进账本？**
A：审计日志路径必须是 `/var/log/nginx/modsec_audit.json`，不能是 `.log`；nginx 包的 `*.log` 轮转会改名，ModSecurity 不会重开文件。

**Q：为什么改 WAF 规则后 `reload` 不生效？**
A：ModSecurity 规则在 `restart nginx` 时才重新加载；`nw-waf` 已改用 restart。

**Q：Kali 桥接能上网却打不到服务器？**
A：校园网对 VM MAC 做准入，桥接/静态 IP 都可能被拦；改用 NAT。服务器看到宿主出口 IP，22 端口仍放行。

**Q：nmap 扫描没触发 NET_SCAN？**
A：校园网会过滤大规模端口扫描；用 `hping3` 或服务器 netns 做网络层演示。

**Q：怎么关闭 AI/自动处置？**

```bash
./nightwatch autopilot off
./nightwatch autonomy approve
./nightwatch auto-response off
```

**Q：怎么换模型？**
改 `config.toml` 的 `[agent] model` 和 `api`，重启 nightwatch；密钥放 `data/agent.env`。

**Q：怎么接入真实站点？**
让站点按 `docs/01` 的 JSONL 格式写访问/登录日志；在 `config.toml` 增加 `[[ingest.sources]]`；生产封禁对接 `apply_production_ban()`（ipset/nftables），本期只预留。

**Q：AI API 挂了怎么办？**
autopilot 退避 5 分钟；确定性检测/封禁继续；TUI 左侧仍有事件。

**Q：能商用吗？**
Suricata 是 GPLv2，CRS 是 Apache-2.0，ET Open 规则有使用条款；对外商业分发需复核许可。本仓库是实验性 Demo。

## 6. 免责声明

本项目用于授权安全测试、教学与竞赛演示。使用者必须确保对目标拥有明确授权，
并遵守当地法律法规。作者不对未授权使用造成的后果负责。
