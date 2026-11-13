"""生成《AI 守夜人 · 实战对抗演示方案》Word 文档。"""
from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

OUT = "D:/AI/ku/docs/网安agent/AI守夜人-实战对抗演示方案.docx"
FONT = "微软雅黑"
MONO = "Consolas"
DARK = RGBColor(0x1F, 0x3A, 0x5F)
ACCENT = RGBColor(0x2E, 0x74, 0xB5)

doc = Document()
sec = doc.sections[0]
sec.top_margin = Cm(2.2)
sec.bottom_margin = Cm(2.2)
sec.left_margin = Cm(2.4)
sec.right_margin = Cm(2.4)


def set_font(run, size=10.5, bold=False, color=None, mono=False):
    run.font.name = MONO if mono else FONT
    run._element.get_or_add_rPr().rFonts.set(qn("w:eastAsia"), FONT)
    run.font.size = Pt(size)
    run.bold = bold
    if color is not None:
        run.font.color.rgb = color


def style_setup():
    for name, size, color in (("Normal", 10.5, RGBColor(0x22, 0x22, 0x22)),
                              ("Heading 1", 16, DARK),
                              ("Heading 2", 13, ACCENT),
                              ("Heading 3", 11.5, ACCENT)):
        st = doc.styles[name]
        st.font.name = FONT
        st._element.get_or_add_rPr().rFonts.set(qn("w:eastAsia"), FONT)
        st.font.size = Pt(size)
        st.font.bold = name.startswith("Heading")
        if name != "Normal":
            st.font.color.rgb = color
    doc.styles["Normal"].paragraph_format.line_spacing = 1.35
    doc.styles["Normal"].paragraph_format.space_after = Pt(4)


def h(text, level=1):
    p = doc.add_heading(level=level)
    r = p.add_run(text)
    set_font(r, 16 if level == 1 else 13 if level == 2 else 11.5, True,
             DARK if level == 1 else ACCENT)
    p.paragraph_format.space_before = Pt(14 if level == 1 else 10)
    p.paragraph_format.space_after = Pt(5)
    return p


def para(text, bold=False, size=10.5, color=None, align=None, after=4):
    p = doc.add_paragraph()
    r = p.add_run(text)
    set_font(r, size, bold, color)
    if align:
        p.alignment = align
    p.paragraph_format.space_after = Pt(after)
    return p


def bullets(items, style="List Bullet"):
    for it in items:
        p = doc.add_paragraph(style=style)
        r = p.add_run(it)
        set_font(r, 10.5)
        p.paragraph_format.space_after = Pt(2)


def shade(cell, hexcolor):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hexcolor)
    tcPr.append(shd)


def table(headers, rows, widths=None, font_size=9.5, header_bg="1F4E79"):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = True
    hdr = t.rows[0].cells
    for i, text in enumerate(headers):
        hdr[i].text = ""
        p = hdr[i].paragraphs[0]
        r = p.add_run(str(text))
        set_font(r, font_size, True, RGBColor(0xFF, 0xFF, 0xFF))
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        shade(hdr[i], header_bg)
    for row in rows:
        cells = t.add_row().cells
        for i, text in enumerate(row):
            cells[i].text = ""
            p = cells[i].paragraphs[0]
            r = p.add_run(str(text))
            set_font(r, font_size)
            p.paragraph_format.space_after = Pt(1)
    if widths:
        for i, w in enumerate(widths):
            for row in t.rows:
                row.cells[i].width = Cm(w)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return t


def code_block(text, bg="F2F5F9"):
    t = doc.add_table(rows=1, cols=1)
    t.style = "Table Grid"
    cell = t.rows[0].cells[0]
    shade(cell, bg)
    cell.text = ""
    for i, line in enumerate(text.splitlines()):
        p = cell.paragraphs[0] if i == 0 else cell.add_paragraph()
        r = p.add_run(line if line else " ")
        set_font(r, 8.8, mono=True, color=RGBColor(0x1A, 0x1A, 0x1A))
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.05
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def page_break():
    doc.add_page_break()


def footer_page_numbers():
    p = sec.footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("AI 守夜人 · 实战对抗演示方案   |   第 ")
    set_font(r, 8.5, color=RGBColor(0x77, 0x77, 0x77))
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), "PAGE")
    rr = OxmlElement("w:r")
    tt = OxmlElement("w:t")
    tt.text = "1"
    rr.append(tt)
    fld.append(rr)
    p._p.append(fld)


style_setup()

# ---------------- 封面 ----------------
for _ in range(4):
    doc.add_paragraph()
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("AI 守夜人 · 实战对抗演示方案")
set_font(r, 25, True, DARK)
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("Battle Mode：你攻击，AI 防守，终端实时作战室")
set_font(r, 13, False, ACCENT)
doc.add_paragraph()
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("版本 v1.0   ·   2026-11-11   ·   实验性 Demo")
set_font(r, 10.5, False, RGBColor(0x66, 0x66, 0x66))
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("目标：在不推翻现有防线的前提下，把产品包装成一场可观看的 AI 攻防对抗")
set_font(r, 10.5, False, RGBColor(0x66, 0x66, 0x66))
page_break()

# ---------------- 目录 ----------------
h("目录", 1)
toc = [
    "1. 方案一句话",
    "2. 判断：能不能搞，已经做好的有没有用",
    "3. 目标形态：Battle Mode",
    "4. 总体架构与网络拓扑",
    "5. AI 防守 Agent 设计",
    "6. 激进防御工具",
    "7. 实时展示：终端作战室",
    "8. 攻击方剧本（Kali）",
    "9. 3 分钟演示脚本",
    "10. 工期与里程碑",
    "11. 验收标准",
    "12. 风险与降级",
    "13. 不做什么与安全边界",
    "14. 复用清单：已经做好的部分",
    "15. 结论与下一步",
]
for item in toc:
    p = doc.add_paragraph()
    r = p.add_run(item)
    set_font(r, 11, False, RGBColor(0x33, 0x33, 0x33))
    p.paragraph_format.space_after = Pt(5)
page_break()

# ---------------- 1 ----------------
h("1. 方案一句话", 1)
para("你从 Kali 或本机充当攻击者，运行 nmap、nikto、hydra、sqlmap；服务器上的 AI Agent "
     "实时读取攻击告警，自己查证据、调用防御工具、封禁来源 IP、生成案卷；终端左右分屏，"
     "把“你打了什么 → 它怎么判断 → 它做了什么”实时显示出来。")
para("这不是生产产品，是一场实验性 Demo。核心防线是真实的，表现层可以激进："
     "目标不是“真能上路”，而是“看上去像未来”。", bold=True, color=ACCENT)

# ---------------- 2 ----------------
h("2. 判断：能不能搞，已经做好的有没有用", 1)
para("结论：可以搞，4–5 天，现有代码约 80% 直接复用，不需要推翻重来。", bold=True)

h("2.1 现有能力盘点", 2)
table(
    ["已有模块", "现状", "在 Battle Mode 里的用途", "复用度"],
    [
        ["日志采集 / 解析 / 单写线程", "已完成", "接 Suricata、WAF、应用日志", "100%"],
        ["滑窗检测 / 纯函数裁决", "已完成", "爆破、扫描、HTTP Flood、NET/WAF 规则", "100%"],
        ["封禁执行 / TTL / 回滚", "已完成", "应用层 403 + nftables 丢包", "100%"],
        ["哈希链账本", "已完成", "每一步动作留证据、可校验", "100%"],
        ["Suricata + WAF + nftables", "已部署", "网络层、Web 层、主机层防线", "100%"],
        ["AI 工具 / 自主封禁 / 值守", "已完成", "Agent 的“手”和“脑”", "90%"],
        ["CLI（status/events/bans/watch/ai）", "已完成", "Battle 的基础命令与实时流", "100%"],
        ["测试 / 红队脚本", "已完成", "回归与演示兜底", "90%"],
        ["演示站 / 假 SSH / 实验 netns", "已完成", "攻击靶标与安全实验网", "90%"],
        ["Web 监控台", "已删除", "由终端 TUI 替代", "0%（不需要）"],
    ],
    widths=[4.2, 2.2, 6.2, 2.2],
)

h("2.2 真正缺的东西", 2)
bullets([
    "把“你作为攻击者”接到服务器：Kali VM 桥接，或服务器内 attack netns 兜底。",
    "把 Agent 的工具调用实时推给终端：现在 run_agent 跑完才返回，TUI 看不到“正在调工具”。",
    "终端作战室：攻击流、Agent 控制台、封禁倒计时、记分牌。",
    "两三个更激进的防御工具：蜜罐秒封、重复攻击升级、动态 WAF 规则。",
])

h("2.3 判断结论", 2)
table(
    ["维度", "判断"],
    [
        ["技术可行性", "高。防线、账本、AI 工具、CLI 都已存在，增量集中在展示层与编排层。"],
        ["工期", "4–5 天（含彩排与兜底）。"],
        ["演示效果", "高。左右分屏 + 实时工具调用 + 记分牌，观感接近“AI 作战室”。"],
        ["风险", "中。主要风险是 Kali 网络、模型延迟、TUI 兼容性；均有降级方案。"],
        ["复用度", "约 80%。核心不用改，Web 不需要恢复。"],
    ],
    widths=[3.2, 12.8],
)

# ---------------- 3 ----------------
h("3. 目标形态：Battle Mode", 1)
h("3.1 三个角色", 2)
table(
    ["角色", "是谁", "职责"],
    [
        ["攻击者", "你（Kali VM 或服务器 attack netns）", "运行 nmap / nikto / hydra / sqlmap / curl，制造真实攻击流量"],
        ["防守 Agent", "服务器上的 AI Commander", "读告警、查证据、选工具、封禁/升级、写案卷"],
        ["裁判", "确定性规则引擎", "按固定规则判定；AI 不在裁决链路上，保证可复现"],
    ],
    widths=[3, 5.5, 7.5],
)

h("3.2 终端布局（示意）", 2)
code_block("""
┌─ NIGHTWATCH BATTLE ── DEFCON 2 ── 03:12:44 ─────────────────────────┐
│ 攻击方（你）                          │ 防守方（AI Commander）        │
│                                      │                               │
│ 10.2.31.50  nmap SYN scan 1024 端口  │ [观察] NET_SCAN，证据 #1201   │
│ 10.2.31.50  sqlmap SQLi /lab/item    │ [取证] 攻击链 04:23–04:24     │
│ 10.2.31.50  蜜罐 /admin 触发         │ [工具] execute_ban(…, 1800)   │
│                                      │ [结果] 已封 30 分钟，案卷 #1203│
│                                      │                               │
│ 攻击 5 次   拦截 5 次   误封 0       │ 平均检测 0.9s   链 OK         │
└──────────────────────────────────────────────────────────────────────┘
 q 退出   b 手动封禁   u 解封   p 暂停   ? 帮助
""")

h("3.3 一次交手的完整流程", 2)
bullets([
    "你在 Kali 执行 nmap -sS -p 1-1024 10.2.102.143。",
    "Suricata 在 wlp1s0 抓到 SYN 突发，写入 eve.json。",
    "nightwatch 采集→检测→NET_SCAN 信号；确定性引擎先封 30 分钟。",
    "Battle Agent 同时看到新事件，调用 attack_chain/执行封禁确认，在 TUI 右侧输出一行结论。",
    "你换 sqlmap 打 /lab/item，WAF 942100 命中，Agent 展示 CRS 规则号并封 1 小时。",
    "你访问 /admin 蜜罐，Agent 立即以 HONEYPOT 规则封 1 小时，零误报。",
    "记分牌更新；案卷写入 data/reports/。",
])

# ---------------- 4 ----------------
h("4. 总体架构与网络拓扑", 1)
h("4.1 网络拓扑", 2)
code_block("""
Kali VM (10.2.102.x)  ──LAN/Wi-Fi──►  10.2.102.143
                                       ├─ Suricata（pcap 旁路）
                                       ├─ nginx :8081 + ModSecurity/CRS ─► demo :8082
                                       ├─ nightwatch-fakessh :2222
                                       └─ nftables（按 IP 丢包）

服务器内部：
  nightwatch daemon ─► SQLite 哈希链账本 ─► Battle Agent ─► TUI / CLI
""")
para("推荐 Kali VM 使用 Bridged Adapter 桥接到同一 Wi-Fi，拿到 10.2.102.x 地址。"
     "如果桥接不通，备用方案是在服务器上使用 nw-attacker netns（10.200.0.2 → 10.200.0.1），"
     "物理上无默认路由，打不到外网。")

h("4.2 数据流", 2)
table(
    ["层", "数据", "去向"],
    [
        ["攻击流量", "Kali → 10.2.102.143", "Suricata / nginx / demo"],
        ["网络告警", "eve.json（仅 alert）", "TailSource → detecor"],
        ["Web 告警", "modsec_audit.json（4xx/5xx）", "TailSource → detector"],
        ["应用日志", "app_access/app_auth.jsonl", "TailSource → detector"],
        ["裁决与动作", "decision / rollback / agent_tool", "SQLite 哈希链 → TUI/CLI"],
        ["AI 结论", "agent_run（source=battle）", "TUI 右侧 + 案卷"],
    ],
    widths=[3.2, 6.3, 6.5],
)

h("4.3 组件改动清单", 2)
table(
    ["类型", "组件", "说明"],
    [
        ["复用", "app/store, detect, decide, enforce, fw, worker", "核心防线不改"],
        ["复用", "Suricata, nginx+CRS, nftables, nw-fw", "防线不改"],
        ["复用", "agent/tools, runner, autopilot", "AI 能力复用"],
        ["改造", "agent/runner.py", "增加 on_trace 回调，工具调用实时推送"],
        ["改造", "app/cli.py", "新增 battle / tui / profile 子命令"],
        ["改造", "demo/site.py", "新增 /admin、/.env、/wp-login.php 蜜罐"],
        ["改造", "app/detect.py / rules.py", "新增 HONEYPOT.v1 秒封规则"],
        ["新增", "battle/agent.py", "Battle Agent 循环与提示词"],
        ["新增", "battle/tui.py", "textual 作战室"],
        ["新增", "battle/scoreboard.py", "记分牌与案卷"],
        ["新增", "app/profile.py", "攻击者画像（工具识别）"],
    ],
    widths=[2, 6.2, 7.8],
)

# ---------------- 5 ----------------
h("5. AI 防守 Agent 设计", 1)
h("5.1 循环", 2)
code_block("""
每 1 秒：
  读取 since=last_id 的新事件
  如果只有 http_request / parse_error：继续睡
  如果有 net_alert / waf_alert / honeypot / 高风险 decision：
      打包事件摘要 → 调模型（带工具）
      模型自行决定：
        - 只解释（证据不足）
        - execute_ban(ip, ttl)
        - escalate_ban(ip)（重复攻击）
        - honeypot_ban(ip)（蜜罐）
        - deploy_waf_rule(...)（新 UA/路径）
      工具调用通过 on_trace 实时推给 TUI
      结论写 agent_run（source=battle），动作写哈希链
""")
para("模型调用频率：有新告警才调用；同一批告警去重；最多 1 次/2 秒、30 次/分钟。"
     "模型失败/断网时，确定性引擎继续封禁，TUI 左侧仍然实时。")

h("5.2 工具清单", 2)
table(
    ["工具", "作用", "权限/护栏"],
    [
        ["query_events / attack_chain", "查账本、还原攻击链", "只读"],
        ["profile_attacker", "识别 nmap/nikto/sqlmap/hydra", "只读，基于 UA/签名/节奏"],
        ["firewall_status", "看 nft 封禁集", "只读"],
        ["execute_ban", "直接封 IP", "已有；同 IP 证据、TTL 60–3600、3 次/分钟"],
        ["escalate_ban", "重复攻击延长封禁", "新增；TTL 最多 24h，仅 lab 模式"],
        ["honeypot_ban", "蜜罐触发立即封", "新增；仅授权靶标，零误报"],
        ["deploy_waf_rule", "现场写 WAF 规则", "新增；模板化、nginx -t、最多 3 条、失败回滚"],
        ["rate_limit", "对 Flood 限速", "可选；nft/nginx 限速，不直接封"],
    ],
    widths=[4.5, 6.5, 5],
)

h("5.3 提示词（Battle Commander）", 2)
code_block("""
你是蓝队指挥官。你只能防守，不能攻击、不能扫描攻击者。
新告警如下：<事件摘要>
规则：
1. 先查证据（attack_chain / query_events），再决定。
2. 高置信（WAF SQLi/XSS/RCE、NET_SCAN、NET_DOS、蜜罐）→ execute_ban，
   TTL 600–1800；重复攻击 → escalate_ban。
3. 证据不足 → 只解释，不封。
4. 每步只输出一行：观察 / 工具 / 结果，必须带事件号。
5. 不封白名单/管理机；不解封、不清空。
""")

h("5.4 流式 trace", 2)
para("改造 agent/runner.py：run_agent(..., on_trace=fn)。每次工具执行前后、每次模型回复，"
     "把 {step, tool, args, ok, duration_ms, preview} 回调给 Battle TUI；同时写入 "
     "agent_tool 事件，保证即使 TUI 崩了，watch/CLI 也能看到完整过程。")

# ---------------- 6 ----------------
h("6. 激进防御工具", 1)
h("6.1 蜜罐秒封（首选）", 2)
para("演示站新增 /admin、/.env、/wp-login.php：返回假页面/假配置（明确标注 fake），"
     "正常用户不会访问；任何来源访问即写 honeypot 事件，规则 HONEYPOT.v1 立即封 1 小时。"
     "零误报，最适合现场演示。")

h("6.2 重复攻击升级", 2)
para("同一 IP 在 10 分钟内被封 ≥2 次，Agent 可调用 escalate_ban，把 TTL 从 30 分钟延长到 "
     "1 小时/24 小时。演示效果：“你越打，它封得越久”。")

h("6.3 动态 WAF 规则（最炸）", 2)
para("Agent 发现新的扫描器 UA 或攻击路径，生成一条模板化 ModSecurity 规则，例如：")
code_block("""
SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" \\
  "id:91001,phase:1,deny,status:403,msg:'AI generated: sqlmap UA'"
""")
bullets([
    "只能套模板：UA 包含、路径前缀、方法；不能写 shell/命令。",
    "写入独立文件 /etc/nginx/modsec/ai-rules.conf；先 nginx -t，失败自动回滚。",
    "每场最多 3 条，全部入哈希链，人工可删除。",
])

h("6.4 护栏（不可放松）", 2)
table(
    ["护栏", "规则"],
    [
        ["目标", "只能封攻击来源 IP；不能封白名单/管理网段/本机"],
        ["证据", "必须引用同 IP 的告警事件；无证据不封"],
        ["TTL", "60–3600 秒；升级最多 24 小时"],
        ["频率", "AI 自动封禁 ≤3 次/分钟；模型调用 ≤30 次/分钟"],
        ["权限", "AI 不能解封、清空、改 nft 规则、扫描攻击者"],
        ["规则", "动态 WAF 规则模板化、语法校验、最多 3 条、可回滚"],
        ["审计", "每次动作写哈希链，记录 actor=ai-agent、证据号"],
    ],
    widths=[3, 13],
)

# ---------------- 7 ----------------
h("7. 实时展示：终端作战室", 1)
h("7.1 布局", 2)
bullets([
    "顶部：DEFCON、时间、事件/秒、链状态、封禁数。",
    "左侧：攻击流/雷达，按来源 IP 聚合，显示工具、目标、频率。",
    "右侧：AI 控制台，逐行显示 [观察]/[取证]/[工具]/[结果]，带事件号。",
    "底部：记分牌（攻击/拦截/误封/平均检测/链校验）。",
    "按键：q 退出，b 手动封，u 解封，p 暂停自动处置，? 帮助。",
])
h("7.2 降级", 2)
para("textual 装不上或终端不兼容时，nightwatch battle --plain 退化为彩色行输出，"
     "功能不变，只是没有全屏布局。")
h("7.3 延迟预期", 2)
para("确定性事件流 0.2–1 秒；AI 工具调用 1–3 秒。左侧即时，右侧稍慢，"
     "但“已封禁”由确定性引擎先落地，不会等模型。")

# ---------------- 8 ----------------
h("8. 攻击方剧本（Kali）", 1)
h("8.1 网络准备", 2)
bullets([
    "VirtualBox：Kali 网卡设为 Bridged Adapter，桥接当前 Wi-Fi。",
    "验证：ping 10.2.102.143；不通则改 NAT 或使用服务器 netns 兜底。",
    "确认目标端口：8081（WAF）、2222（假 SSH）；不要打真实 SSH 22。",
])
h("8.2 攻击命令", 2)
code_block("""
# 1) 端口扫描
nmap -sS -Pn -p 1-1024 10.2.102.143

# 2) Web 扫描
nikto -h http://10.2.102.143:8081 -Tuning 123b -maxtime 12s

# 3) SQL 注入
sqlmap -u "http://10.2.102.143:8081/lab/item?id=1" --batch --level 1 --risk 1

# 4) HTTP 爆破（演示账号，错误口令）
hydra -l demo -P /tmp/wrong10.txt -s 8081 10.2.102.143 \\
  http-post-form "/login:user=^USER^&password=^PASS^:F=401"

# 5) 蜜罐
curl -s http://10.2.102.143:8081/admin
""")
h("8.3 预期防守反应", 2)
table(
    ["你的动作", "防守规则", "Agent 动作"],
    [
        ["nmap 端口扫描", "NET_SCAN", "execute_ban 30m"],
        ["nikto", "WAF_SCANNER", "execute_ban 1h"],
        ["sqlmap", "WAF_SQLI（942100）", "execute_ban 1h，展示规则号"],
        ["hydra 5 次失败", "BRUTE_FORCE", "execute_ban 1h"],
        ["/admin 蜜罐", "HONEYPOT", "honeypot_ban 1h，零误报"],
    ],
    widths=[4, 5, 7],
)

# ---------------- 9 ----------------
h("9. 3 分钟演示脚本", 1)
table(
    ["时间", "你（Kali）", "屏幕（TUI）"],
    [
        ["0:00", "启动 nightwatch battle --tui", "DEFCON 3，雷达扫描"],
        ["0:20", "nmap -sS -p 1-1024", "红点出现；AI：NET_SCAN，工具 execute_ban，封 30m"],
        ["0:50", "nikto", "WAF_SCANNER；AI：扫描器，封 1h"],
        ["1:20", "sqlmap", "WAF_SQLI 942100；AI 展示规则号，封 1h"],
        ["1:50", "hydra 5 次失败", "BRUTE_FORCE；AI：重复攻击，escalate_ban"],
        ["2:10", "curl /admin", "蜜罐触发；AI：零误报，honeypot_ban"],
        ["2:30", "停手", "记分牌：5 进攻 / 5 拦截 / 误封 0 / 平均 0.9s / 链 OK"],
        ["2:50", "按 u 解封", "恢复，案卷归档，演示结束"],
    ],
    widths=[1.8, 6.2, 8],
)

# ---------------- 10 ----------------
h("10. 工期与里程碑", 1)
table(
    ["日期/阶段", "任务", "硬检查点"],
    [
        ["D1", "流式 trace + battle --plain；Kali 网络验证", "你打 nmap，终端出现 AI 工具调用与封禁"],
        ["D2", "TUI 骨架：攻击流/Agent 控制台/记分牌", "battle --tui 可运行，实时刷新"],
        ["D3", "激进工具：蜜罐秒封、升级封禁、动态 WAF 规则", "蜜罐 1 秒内封；规则校验/回滚通过"],
        ["D4", "攻击剧本、彩排、兜底", "3 分钟零卡顿；--plain 可用"],
        ["D5", "备份/冻结", "不改代码，录屏/离线包"],
    ],
    widths=[2.2, 8.3, 5.5],
)

# ---------------- 11 ----------------
h("11. 验收标准", 1)
bullets([
    "Kali 执行 nmap，2 秒内 TUI 出现 NET_SCAN 与封禁动作；",
    "sqlmap/nikto/hydra 分别触发 WAF_SCANNER、WAF_SQLI、BRUTE_FORCE；",
    "访问 /admin 蜜罐 1 秒内封禁，误封 0；",
    "TUI 右侧逐条显示工具调用，不是最后一次性输出；",
    "记分牌 5/5，平均检测 <2 秒，哈希链 ok；",
    "模型断网时，确定性防线仍工作，TUI 左侧继续刷新；",
    "pytest 全绿、selftest 16 条通过。",
])

# ---------------- 12 ----------------
h("12. 风险与降级", 1)
table(
    ["风险", "概率/影响", "应对"],
    [
        ["Kali 桥接不通", "中/高", "切服务器 nw-attacker netns；或 NAT 模式"],
        ["模型延迟/额度", "中/中", "左侧确定性实时；AI 解说可暂停；--plain"],
        ["TUI 依赖装不上", "低/中", "退回 --plain 或 watch"],
        ["动态 WAF 规则写坏", "中/高", "模板 + nginx -t + 自动回滚 + 最多 3 条"],
        ["攻击把演示站打挂", "中/中", "固定剧本 + 限速 + systemd Restart"],
        ["误封你的 Kali", "高/低", "本来就是攻击者；演示结束 u 解封"],
        ["现场终端尺寸", "低/低", "TUI 自适应 + 双分辨率彩排"],
    ],
    widths=[4.8, 3.2, 8],
)

# ---------------- 13 ----------------
h("13. 不做什么与安全边界", 1)
bullets([
    "不做对外反击、不扫描攻击者、不向第三方发包。",
    "不做真实漏洞利用、不拖库、不横向移动。",
    "只守护自有/授权资产；攻击只打 10.2.102.143 或实验 netns。",
    "AI 不参与确定性裁决；封禁仍由规则引擎给出结论。",
    "AI 不能解封/清空/改 nft 规则；动态 WAF 规则必须模板化并校验。",
    "所有动作写哈希链，人工随时可回滚。",
])

# ---------------- 14 ----------------
h("14. 复用清单：已经做好的部分", 1)
para("直接回答“现在已经做好的那些有没有用了”：有用，而且是大头。", bold=True)
table(
    ["已做好的部分", "是否还用", "怎么用 / 改动"],
    [
        ["三层防线（Suricata/WAF/nftables）", "完全保留", "Battle Mode 的防守底座"],
        ["检测/裁决/封禁/哈希链", "完全保留", "裁判与执行器"],
        ["CLI status/events/bans/watch/ai", "完全保留", "Battle 的命令基础"],
        ["AI 工具/自主封禁/7×24 值守", "保留并增强", "增加流式 trace 与 3 个激进工具"],
        ["演示站/假 SSH/实验 netns", "保留", "新增蜜罐入口；攻击靶标"],
        ["测试/红队脚本/矩阵", "保留", "回归与演示兜底"],
        ["Web 监控台", "不再需要", "已删除；TUI 替代，不恢复"],
        ["旧 API/SSE/token", "不再需要", "已删除；CLI 直连 SQLite"],
    ],
    widths=[5.5, 3.2, 7.3],
)
para("估算：核心 80% 复用；新增主要是 battle/、tui/、profile、蜜罐与动态 WAF 规则，"
     "约 4–5 天工作量。")

# ---------------- 15 ----------------
h("15. 结论与下一步", 1)
para("可搞，且不需要推翻现有系统。最短闭环是：")
bullets([
    "D1：你从 Kali/ netns 打 nmap → AI 调 execute_ban → 终端实时显示；",
    "D2：TUI 左右分屏 + 记分牌；",
    "D3：蜜罐秒封 + 升级封禁 + 动态 WAF 规则；",
    "D4：完整剧本彩排与降级。",
])
para("一句话：把“装甲车”加上“作战室、指挥官、记分牌”，它还是那辆能防的车，"
     "但看起来像飞行汽车。", bold=True, color=ACCENT)

footer_page_numbers()
doc.save(OUT)
print("saved", OUT)
