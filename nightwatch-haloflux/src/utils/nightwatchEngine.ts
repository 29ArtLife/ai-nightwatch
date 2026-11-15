export interface NightwatchEvent {
  id?: number;
  ts?: string;
  kind:
    | 'net_alert'
    | 'waf_alert'
    | 'honeypot'
    | 'login_fail'
    | 'http_404'
    | 'http_429'
    | 'decision'
    | 'rollback'
    | 'expire'
    | 'agent_tool'
    | 'agent_run'
    | 'info';
  ip?: string;
  target_ip?: string;
  rule_id?: string;
  evidence_json?: string | Record<string, any>;
  raw_line?: string;
}

export interface ActiveBan {
  ip: string;
  angle: number;
  rule: string;
  reason: string;
  actor: string;
  ttl: number;
  expiresAtMs: number;
}

export interface RedNodeInfo {
  ip: string;
  label: string;
  angleOnRedRing: number;
  strikes: number;
  lastTool: string;
  lastSeenMs: number;
  locked: boolean;
}

export interface RedBlueHostConfig {
  blueHostName: string;
  blueHostIp: string;
  redHostName: string;
  redPrimaryIp: string;
}

export interface CombatOperationLog {
  id: number;
  ts: string;
  actorCamp: 'red' | 'blue' | 'ai';
  directionLabel: string;
  actionTitle: string;
  commandLine: string;
  detailDesc: string;
  hpEffectText: string;
  blueDeltaHp: number;
  redDeltaHp: number;
  blocked: boolean;
  srcIp: string;
  dstIp: string;
}

export interface FeedRecord {
  id: number;
  tag: string;
  cls: 'waf' | 'net' | 'ban' | 'hp' | 'ai' | 'ok';
  msg: string;
}

export interface AiTraceLine {
  ln: number;
  text: string;
  cls: 'fn' | 'ok' | 'op';
}

export const MAX_CAMP_HP = 10000;

export const RULE_ROWS = [
  'NET_SCAN',
  'NET_DOS',
  'WAF_SQLI',
  'WAF_XSS',
  'WAF_SCAN',
  'HONEYPOT',
  'BRUTE_5X',
  'PATH_404',
  'HTTP_429',
  'AI_BAN',
  'CHAIN_OK',
] as const;

export const LAYERS = [
  { name: 'SURICATA', cols: ['PCAP', 'ALERT', 'NET_BAN'] },
  { name: 'MODSEC WAF', cols: ['CRS', 'SCORE', 'WAF_BAN'] },
  { name: 'HONEYPOT', cols: ['TRAP', 'ZERO_FP', 'BAN_1H'] },
  { name: 'APP AUTH', cols: ['LOG', 'WIN_5', '403_BAN'] },
  { name: 'NFTABLES', cols: ['ALLOW', 'NW_FW', 'DROP'] },
] as const;

/**
 * Deterministic FNV-1a hash mapping an IPv4 string into the visible right-hand
 * sector [-thS * 0.72, +thS * 0.72] of the Left (Blue Team) HALOFLUX ring.
 */
export function ipToAngle(ip: string, thS = 0.75): number {
  const s = String(ip || '0.0.0.0');
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const span = (thS || 0.75) * 0.72;
  return (((h >>> 0) % 2000) / 1000 - 1) * span;
}

/**
 * Deterministic mapping of an attacker IPv4 onto the left-facing visible arc
 * [Math.PI - thRed * 0.72, Math.PI + thRed * 0.72] of the Right (Red Team) ring.
 */
export function ipToRedAngle(ip: string, thRed = 0.68): number {
  const s = String(ip || '0.0.0.0');
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const offset = (((h >>> 0) % 2000) / 1000 - 1) * (thRed * 0.72);
  return Math.PI + offset;
}

/**
 * Evaluate a cubic Bezier point for cross-screen trajectories between Red and Blue camps.
 */
export function evalCubicBezier(
  p0: { x: number; y: number },
  p1: { x: number; y: number },
  p2: { x: number; y: number },
  p3: { x: number; y: number },
  t: number
): { x: number; y: number } {
  const u = 1 - t;
  const tt = t * t;
  const uu = u * u;
  const uuu = uu * u;
  const ttt = tt * t;
  return {
    x: uuu * p0.x + 3 * uu * t * p1.x + 3 * u * tt * p2.x + ttt * p3.x,
    y: uuu * p0.y + 3 * uu * t * p1.y + 3 * u * tt * p2.y + ttt * p3.y,
  };
}

/**
 * Calculate Blue vs Red momentum ratio (0..100 for Blue dominance) based on
 * active blocks, intercepted strikes, and unmitigated threat energy.
 */
export function computeBattleMomentum(
  blueBlocksCount: number,
  activeBansCount: number,
  redStrikesCount: number,
  threatEnergy: number
): { bluePct: number; redPct: number } {
  const blueScore = 50 + blueBlocksCount * 4 + activeBansCount * 12;
  const redScore = 50 + redStrikesCount * 2.5 + threatEnergy * 35;
  const total = Math.max(1, blueScore + redScore);
  const bluePct = Math.min(88, Math.max(12, Math.round((blueScore / total) * 100)));
  return { bluePct, redPct: 100 - bluePct };
}

/**
 * Apply HP deltas for Blue and Red camps and clamp within [0, maxHp].
 */
export function applyCombatHp(
  blueHp: number,
  redHp: number,
  blueDelta: number,
  redDelta: number,
  maxHp = MAX_CAMP_HP
): { blueHp: number; redHp: number } {
  const nextBlue = Math.max(0, Math.min(maxHp, Math.round(blueHp + blueDelta)));
  const nextRed = Math.max(0, Math.min(maxHp, Math.round(redHp + redDelta)));
  return { blueHp: nextBlue, redHp: nextRed };
}

/**
 * Derive a concrete, human-readable CombatOperationLog from a NightwatchEvent
 * so the HUD clearly explains what specific attack/defense command is executing.
 */
export function deriveCombatOperation(
  ev: NightwatchEvent,
  isBlocked: boolean,
  blueHostIp: string,
  seqId: number
): CombatOperationLog {
  const evd = parseEvidence(ev.evidence_json);
  const srcIp = ev.ip || ev.target_ip || evd.ip || '10.2.31.236';
  const dstIp = blueHostIp || '10.2.102.143';
  const rule = ev.rule_id || evd.rule_id || 'NW_RULE';
  const nowStr = new Date().toTimeString().slice(0, 8);

  if (ev.kind === 'waf_alert') {
    const uri = evd.uri || "/lab/item?id=1' OR 1=1--";
    const blockedDmg = isBlocked ? 0 : -280;
    const redRecoil = isBlocked ? -140 : 0;
    return {
      id: seqId,
      ts: nowStr,
      actorCamp: 'red',
      directionLabel: isBlocked ? 'RED ➔ 🛡️ BLOCKED' : 'RED ➔ BLUE [HIT]',
      actionTitle: isBlocked
        ? `SQL 注入攻击被护盾拦截 (${rule})`
        : `发起 SQL 注入渗透攻击 (${rule})`,
      commandLine: `curl -G "http://${dstIp}:8081${uri}" -H "User-Agent: sqlmap/1.8"`,
      detailDesc: isBlocked
        ? `红方 ${srcIp} 尝试注入脱库，数据包在蓝方 nftables 外环护盾处被直接丢弃（DROP）`
        : `红方 ${srcIp} 向蓝方 Web 接口发送恶意 UNION/布尔盲注载荷，试图绕过认证读取数据库`,
      hpEffectText: isBlocked
        ? `🛡️ 护盾格挡 (蓝方 0 伤 · 反震红方 -140 HP)`
        : `💥 命中蓝方防线 (蓝方 -280 HP)`,
      blueDeltaHp: blockedDmg,
      redDeltaHp: redRecoil,
      blocked: isBlocked,
      srcIp,
      dstIp,
    };
  }

  if (ev.kind === 'net_alert') {
    const sig = evd.signature || 'NW SYN FLOOD 8081 >=200/10s';
    const blockedDmg = isBlocked ? 0 : -190;
    const redRecoil = isBlocked ? -90 : 0;
    return {
      id: seqId,
      ts: nowStr,
      actorCamp: 'red',
      directionLabel: isBlocked ? 'RED ➔ 🛡️ BLOCKED' : 'RED ➔ BLUE [HIT]',
      actionTitle: isBlocked
        ? `SYN 洪泛攻击被内核丢弃 (${rule})`
        : `发起高频 SYN Flood 洪泛冲击 (${rule})`,
      commandLine: `hping3 -S --flood -V -p 8081 ${dstIp} # ${sig}`,
      detailDesc: isBlocked
        ? `红方 ${srcIp} 的高频半连接洪泛包被蓝方 nftables 黑洞集合直接过滤`
        : `红方 ${srcIp} 持续发送伪造 TCP SYN 握手包冲击蓝方 8081 端口连接队列`,
      hpEffectText: isBlocked
        ? `🛡️ 护盾格挡 (蓝方 0 伤 · 反震红方 -90 HP)`
        : `💥 冲击蓝方核心 (蓝方 -190 HP)`,
      blueDeltaHp: blockedDmg,
      redDeltaHp: redRecoil,
      blocked: isBlocked,
      srcIp,
      dstIp,
    };
  }

  if (ev.kind === 'honeypot') {
    const path = evd.path || '/admin';
    const blockedDmg = isBlocked ? 0 : -150;
    return {
      id: seqId,
      ts: nowStr,
      actorCamp: 'red',
      directionLabel: 'RED ➔ 🍯 HONEYPOT',
      actionTitle: `红方踩中蓝方高交互蜜罐陷阱 (${path})`,
      commandLine: `gobuster dir -u http://${dstIp}:8081 -w common.txt -> GET ${path}`,
      detailDesc: `红方 ${srcIp} 扫描敏感后台路径 ${path}，触发蓝方零误报蜜罐告警并立即锁定指纹`,
      hpEffectText: isBlocked
        ? `🛡️ 蜜罐已锁死该节点 (红方 -160 HP)`
        : `🍯 诱捕成功 (蓝方 -150 HP · 触发即时反制)`,
      blueDeltaHp: blockedDmg,
      redDeltaHp: -160,
      blocked: isBlocked,
      srcIp,
      dstIp,
    };
  }

  if (ev.kind === 'login_fail' || ev.kind === 'http_404' || ev.kind === 'http_429') {
    const user = evd.username || 'root';
    const blockedDmg = isBlocked ? 0 : -110;
    const redRecoil = isBlocked ? -70 : 0;
    return {
      id: seqId,
      ts: nowStr,
      actorCamp: 'red',
      directionLabel: isBlocked ? 'RED ➔ 🛡️ BLOCKED' : 'RED ➔ BLUE [BRUTE]',
      actionTitle: isBlocked
        ? `暴力破解请求被护盾阻断`
        : `发起字典暴力口令枚举 (账号: ${user})`,
      commandLine: `hydra -l ${user} -P rockyou.txt ${dstIp} http-post-form "/login:user=^USER^&pass=^PASS^"`,
      detailDesc: isBlocked
        ? `红方 ${srcIp} 的自动化口令爆破流量被蓝方外环防火墙直接拦截`
        : `红方 ${srcIp} 正在高频并发尝试破解蓝方管理员账户 ${user} 的登录凭证`,
      hpEffectText: isBlocked
        ? `🛡️ 护盾格挡 (蓝方 0 伤 · 反震红方 -70 HP)`
        : `💥 口令爆破冲击 (蓝方 -110 HP)`,
      blueDeltaHp: blockedDmg,
      redDeltaHp: redRecoil,
      blocked: isBlocked,
      srcIp,
      dstIp,
    };
  }

  if (ev.kind === 'decision') {
    const ttl = Number(evd.ttl) || 3600;
    return {
      id: seqId,
      ts: nowStr,
      actorCamp: 'blue',
      directionLabel: 'BLUE ➔ RED [COUNTER]',
      actionTitle: `蓝方发射电磁反制光束 · 封锁红方节点 (${rule})`,
      commandLine: `nft add element inet nightwatch blackhole { ${srcIp} timeout ${ttl}s }`,
      detailDesc: `蓝方 Nightwatch 引擎下发内核级 nftables 封禁指令，将红方节点 ${srcIp} 彻底锁死 ${ttl} 秒并回充护盾`,
      hpEffectText: `⚡ 蓝方反制重创 (红方 -680 HP · 蓝方护盾修复 +220 HP)`,
      blueDeltaHp: 220,
      redDeltaHp: -680,
      blocked: true,
      srcIp: dstIp,
      dstIp: srcIp,
    };
  }

  if (ev.kind === 'agent_tool' || ev.kind === 'agent_run') {
    const tool = evd.tool || (ev.kind === 'agent_run' ? 'deepseek_verdict' : 'attack_chain');
    const summary =
      evd.result_summary || evd.summary || `关联分析红方 ${srcIp} 攻击链并热更新 WAF 防御策略`;
    return {
      id: seqId,
      ts: nowStr,
      actorCamp: 'ai',
      directionLabel: '🧠 DEEPSEEK AI 研判',
      actionTitle: `DeepSeek AI 执行自主防御工具: ${tool}()`,
      commandLine: `nightwatch-agent --tool ${tool} --target ${srcIp} --autonomy auto`,
      detailDesc: String(summary),
      hpEffectText: `✨ AI 神经加固 (蓝方修复 +160 HP · 压制红方 -240 HP)`,
      blueDeltaHp: 160,
      redDeltaHp: -240,
      blocked: false,
      srcIp: dstIp,
      dstIp: srcIp,
    };
  }

  if (ev.kind === 'rollback' || ev.kind === 'expire') {
    return {
      id: seqId,
      ts: nowStr,
      actorCamp: 'blue',
      directionLabel: 'BLUE ↺ UNBAN',
      actionTitle: `解除对红方节点 ${srcIp} 的封禁锁死`,
      commandLine: `./nightwatch unban ${srcIp} --reason "operator_rollback"`,
      detailDesc: `蓝方从 nftables 黑洞集合移除 ${srcIp}，该红方节点恢复发射能力`,
      hpEffectText: `↺ 节点解封 (双方血量维持不变)`,
      blueDeltaHp: 0,
      redDeltaHp: 0,
      blocked: false,
      srcIp: dstIp,
      dstIp: srcIp,
    };
  }

  return {
    id: seqId,
    ts: nowStr,
    actorCamp: 'blue',
    directionLabel: 'SYSTEM SYNC',
    actionTitle: '双球交火监控引擎就绪',
    commandLine: './nightwatch daemon --wal-mode & python3 scripts/web_bridge.py',
    detailDesc: ev.raw_line || '左右双核心粒子场已同步，等待红蓝双方交火指令',
    hpEffectText: '状态正常',
    blueDeltaHp: 0,
    redDeltaHp: 0,
    blocked: false,
    srcIp: dstIp,
    dstIp: srcIp,
  };
}

/**
 * Strict IPv4 validation matching Python's ipaddress.IPv4Address check in web_bridge.py.
 */
export function validateIpv4(ip: string): boolean {
  const trimmed = String(ip || '').trim();
  const parts = trimmed.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
    const n = Number(part);
    if (n < 0 || n > 255) return false;
  }
  return true;
}

/**
 * Compute DEFCON level from active nftables bans count and threat energy.
 */
export function computeDefcon(
  activeBansCount: number,
  threatEnergy: number
): 'DEFCON 1' | 'DEFCON 2' | 'DEFCON 3' {
  if (activeBansCount >= 3 || threatEnergy > 0.7) return 'DEFCON 1';
  if (activeBansCount >= 1 || threatEnergy > 0.35) return 'DEFCON 2';
  return 'DEFCON 3';
}

/**
 * Calculate events per second over a sliding time window (default 5000ms).
 */
export function calculateEps(
  timestamps: number[],
  nowMs: number,
  windowMs = 5000
): { eps: number; filtered: number[] } {
  const filtered = timestamps.filter((t) => nowMs - t < windowMs);
  const eps = Number((filtered.length / (windowMs / 1000)).toFixed(1));
  return { eps, filtered };
}

/**
 * Match a Nightwatch rule_id to one of the 11 detector signature rows (0..10).
 */
export function matchRuleRowIndex(ruleId: string): number {
  const upper = String(ruleId || '').toUpperCase();
  const idx = RULE_ROWS.findIndex((r) =>
    upper.includes(r.replace('_5X', '').replace('_404', '').replace('_429', ''))
  );
  return idx >= 0 ? idx : 10;
}

/**
 * Safely parse evidence_json whether string or object.
 */
export function parseEvidence(
  evidence: string | Record<string, any> | undefined
): Record<string, any> {
  if (!evidence) return {};
  if (typeof evidence === 'object') return evidence;
  try {
    return JSON.parse(evidence);
  } catch {
    return {};
  }
}
