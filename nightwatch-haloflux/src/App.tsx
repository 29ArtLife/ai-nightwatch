import React, { useEffect, useRef, useState, useCallback } from 'react';
import {
  ActiveBan,
  AiTraceLine,
  CombatOperationLog,
  FeedRecord,
  LAYERS,
  MAX_CAMP_HP,
  NightwatchEvent,
  RULE_ROWS,
  RedBlueHostConfig,
  RedNodeInfo,
  applyCombatHp,
  calculateEps,
  computeDefcon,
  deriveCombatOperation,
  evalCubicBezier,
  ipToAngle,
  ipToRedAngle,
  matchRuleRowIndex,
  parseEvidence,
} from './utils/nightwatchEngine';
import { BAKED_MINE, HaloParamDef, SFX } from './utils/haloParams';
import { ConsoleDrawer } from './components/ConsoleDrawer';
import { BridgeModal } from './components/BridgeModal';
import { HostLinkModal } from './components/HostLinkModal';

const TAU = Math.PI * 2;
const rnd = Math.random;
const rr = (a: number, b: number) => a + rnd() * (b - a);
const pick = <T,>(a: readonly T[] | T[]): T => a[(rnd() * a.length) | 0];
const gauss = () => (rnd() + rnd() + rnd() - 1.5) / 1.5;
const easeIO = (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
const easeO = (t: number) => 1 - Math.pow(1 - t, 3);
const easeOX = (t: number) => (t >= 1 ? 1 : 1 - Math.pow(2, -10 * t));
const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v));
const normA = (a: number) => (((a + Math.PI) % TAU) + TAU) % TAU - Math.PI;
const hash = (x: number) => {
  const s = Math.sin(x * 12.9898) * 43758.5453;
  return s - Math.floor(s);
};

const FONT = '"JetBrains Mono",Consolas,monospace';
const PATTERN = [0.5, 0.25, 0.25, 0.5, 0.5, 0.75, 0.25, 0.25, 0.25, 1.0];
const EDGE_A = [0.28, 0.62, 1];
const FLY_A = [0.16, 0.36, 0.7];
const TINTS = [
  [232, 234, 240],
  [232, 234, 240],
  [232, 234, 240],
  [192, 132, 252],
  [152, 224, 207],
  [240, 166, 198],
  [56, 189, 248],
];
const RED_TINTS = [
  [248, 228, 232],
  [248, 228, 232],
  [255, 59, 92],
  [255, 170, 43],
  [255, 120, 145],
  [240, 166, 198],
  [255, 90, 115],
];
const HEAD = [
  'SURICATA',
  'MODSEC CRS',
  'NFTABLES',
  'BRUTE_FORCE',
  'WAF_SQLI',
  'HONEYPOT',
  'HASH CHAIN',
  'DEEPSEEK',
  'NET_DOS',
  'PATH_SCAN',
  'EVE.JSON',
  'AUTOPILOT',
];
const RED_HEAD = [
  'KALI_C2',
  'SQLMAP_1.8',
  'HPING3_SYN',
  'HYDRA_SSH',
  'MSF6_EXP',
  'GOBUSTER',
  'BURP_PRO',
  'NMAP_SYN',
  'XSS_PROBE',
  'LFI_SCAN',
  'CVE_2026',
  'RED_MATRIX',
];
const KEYS = ['ttl', 'eps', 'fails', 'crs', 'sid', 'drop', 'chain', 'risk', 'port', 'hits'];
const CODE_T = [
  'decide()',
  'nw-fw ban',
  'DROP',
  'WAF_SQLI',
  'NET_DOS',
  'sha256',
  'verify()',
  'PASS',
  'allow',
  'chain_ok',
  'tail -F',
  'eve.json',
  'crs-942',
  'hp/admin',
  '403',
];
const RED_CODE_T = [
  'UNION ALL',
  'OR 1=1--',
  'SYN_SENT',
  'hydra -l',
  'sqlmap -u',
  '/admin',
  'rockyou',
  'msfvenom',
  'reverse_tcp',
  '0xdeadbeef',
  'flood()',
  'bypass_waf',
  'shell.sh',
  'root:x:0',
];
const rgba = (t: number[], a: number) => `rgba(${t[0]},${t[1]},${t[2]},${a})`;


function OrbOpsPanel({ side, ops, live }: { side: 'blue' | 'red'; ops: CombatOperationLog[]; live: boolean }) {
  const label = side === 'blue' ? 'BLUE BASTION' : 'RED STRIKE';
  const accent = side === 'blue' ? 'blue' : 'red';
  return (
    <div className={`orb-ops ${accent}`} aria-label={`${label} 执行操作`}>
      <div className="orb-ops-head">
        <span>{label} // 执行操作</span>
        <i>{ops.length ? (live ? 'LIVE' : 'DEMO') : live ? 'IDLE' : 'DEMO'}</i>
      </div>
      {ops.length === 0 ? (
        <div className="orb-op-empty">等待{side === 'blue' ? '蓝方' : '红方'}真实事件</div>
      ) : (
        ops.map((op, idx) => (
          <div key={`${op.id}-${op.ts}-${idx}`} className={`orb-op ${op.actorCamp}`}>
            <div className="orb-op-top">
              <span>#{op.id}</span>
              <span>{op.ts}</span>
            </div>
            <div className="orb-op-title">{op.actionTitle}</div>
            <div className="orb-op-dir">{op.directionLabel}</div>
            <div className="orb-op-cmd" title={op.commandLine}>{op.commandLine}</div>
            <div className="orb-op-hp">{op.hpEffectText}</div>
          </div>
        ))
      )}
    </div>
  );
}



function OrbLiveLog({ ops, live }: { ops: CombatOperationLog[]; live: boolean }) {
  const rows = ops.length ? [...ops, ...ops] : [];
  return (
    <div className="orb-log" aria-label="左侧蓝盘实时操作记录">
      <div className="orb-log-head">
        <span>BLUE BASTION // 实时操作记录</span>
        <i>{live ? 'LIVE' : 'DEMO'}</i>
      </div>
      <div className="orb-log-scroll">
        {rows.length === 0 ? (
          <div className="orb-log-empty">等待真实攻防事件...</div>
        ) : (
          <div className="orb-log-track">
            {rows.map((op, idx) => (
              <div key={`${op.id}-${op.ts}-${idx}`} className={`orb-log-row ${op.actorCamp}`}>
                <span className="orb-log-time">{op.ts}</span>
                <span className="orb-log-tag">
                  {op.actorCamp === 'red' ? 'RED' : op.actorCamp === 'ai' ? 'AI' : 'BLUE'}
                </span>
                <span className="orb-log-title">{op.actionTitle}</span>
                <span className="orb-log-cmd" title={op.commandLine}>{op.commandLine}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function App() {
  // React UI state for DOM overlays & panels
  const [viewVersion, setViewVersion] = useState<'v2' | 'v1'>('v2');
  const [mode, setModeState] = useState<'live' | 'demo'>('demo');
  const [sfxOn, setSfxOn] = useState(false);
  const [bgmOn, setBgmOn] = useState(false);
  const [bgmVol, setBgmVol] = useState(60);
  const [consoleOpen, setConsoleOpen] = useState(false);
  const [bridgeModalOpen, setBridgeModalOpen] = useState(false);
  const [hostModalOpen, setHostModalOpen] = useState(false);
  const [hostConfig, setHostConfig] = useState<RedBlueHostConfig>({
    blueHostName: 'BLUE BASTION // UBUNTU',
    blueHostIp: '10.2.102.143',
    redHostName: 'RED STRIKE // KALI',
    redPrimaryIp: '10.2.31.236',
  });
  const [paramValues, setParamValues] = useState<Record<string, number>>(() => ({
    ...BAKED_MINE,
  }));

  const [blueHp, setBlueHp] = useState<number>(MAX_CAMP_HP);
  const [redHp, setRedHp] = useState<number>(MAX_CAMP_HP);
  const [combatOps, setCombatOps] = useState<CombatOperationLog[]>([]);

  const [eventCount, setEventCount] = useState(1);
  const [chainOk, setChainOk] = useState(true);
  const [autonomy, setAutonomy] = useState('auto');
  const [autopilot, setAutopilot] = useState(true);
  const [eps, setEps] = useState(0);
  const [defcon, setDefcon] = useState<'DEFCON 1' | 'DEFCON 2' | 'DEFCON 3'>('DEFCON 3');
  const [activeBansList, setActiveBansList] = useState<ActiveBan[]>([]);
  const [redNodesList, setRedNodesList] = useState<RedNodeInfo[]>([]);
  const [blueBlocksCount, setBlueBlocksCount] = useState(0);
  const [redStrikesCount, setRedStrikesCount] = useState(0);
  const [feedList, setFeedList] = useState<FeedRecord[]>([
    {
      id: 1,
      tag: 'OK',
      cls: 'ok',
      msg: 'Nightwatch perimeter armed · Red vs Blue Symmetrical Dual-Sphere Ready',
    },
  ]);
  const [aiLines, setAiLines] = useState<AiTraceLine[]>([
    {
      ln: 1,
      text: '[BOOT] DeepSeek Agent Ready · autonomy=auto · autopilot=on',
      cls: 'ok',
    },
  ]);
  const [layerState, setLayerState] = useState<number[]>([0, 0, 0, 0, 0]);
  const [advBtnIdx, setAdvBtnIdx] = useState(0);

  // Canvas & DOM refs
  const stageWrapRef = useRef<HTMLDivElement | null>(null);
  const stageRef = useRef<HTMLCanvasElement | null>(null);
  const chkRef = useRef<HTMLDivElement | null>(null);
  const chkKRef = useRef<HTMLElement | null>(null);
  const chkVRef = useRef<HTMLSpanElement | null>(null);
  const cAdvRef = useRef<HTMLCanvasElement | null>(null);
  const cDiffRef = useRef<HTMLCanvasElement | null>(null);
  const cValRef = useRef<HTMLCanvasElement | null>(null);
  const cIdxRef = useRef<HTMLCanvasElement | null>(null);

  // Mutable engine ref so 30Hz loop never triggers React re-renders
  const engineRef = useRef<{
    C: Record<string, number>;
    viewVersion: 'v2' | 'v1';
    mode: 'live' | 'demo';
    hostConfig: RedBlueHostConfig;
    blueHp: number;
    redHp: number;
    opSeq: number;
    eventCount: number;
    chainOk: boolean;
    autonomy: string;
    autopilot: boolean;
    epsWindow: number[];
    aiLineCounter: number;
    ruleHits: number[][];
    anomSpike: number;
    threatWave: number;
    dropWave: number;
    threatEnergy: number;
    aiEnergy: number;
    banEnergy: number;
    redEnergy: number;
    blueBlocks: number;
    redStrikes: number;
    projectiles: any[];
    sparks: any[];
    shockwaves: any[];
    arcs: any[];
    activeBans: Map<string, ActiveBan>;
    redNodes: Map<string, RedNodeInfo>;
    focusTarget: { angle: number; kind: string; text: string; cls: string };
    ipHistory: Map<string, number>;
    rebuildQueue: Set<string>;
    flashSlotAt: (ang: number) => void;
    flashRedSlotAt: (ang: number) => void;
    spawnComet: () => void;
    spawnRedComet: () => void;
    thS: number;
  }>({
    C: { ...BAKED_MINE },
    viewVersion: 'v2',
    mode: 'demo',
    hostConfig: {
      blueHostName: 'BLUE BASTION // UBUNTU',
      blueHostIp: '10.2.102.143',
      redHostName: 'RED STRIKE // KALI',
      redPrimaryIp: '10.2.31.236',
    },
    blueHp: MAX_CAMP_HP,
    redHp: MAX_CAMP_HP,
    opSeq: 1,
    eventCount: 1,
    chainOk: true,
    autonomy: 'auto',
    autopilot: true,
    epsWindow: [],
    aiLineCounter: 2,
    ruleHits: Array.from({ length: 11 }, () => Array.from({ length: 24 }, () => 0.08)),
    anomSpike: 0,
    threatWave: 0.1,
    dropWave: 0.05,
    threatEnergy: 0,
    aiEnergy: 0,
    banEnergy: 0,
    redEnergy: 0.25,
    blueBlocks: 0,
    redStrikes: 0,
    projectiles: [],
    sparks: [],
    shockwaves: [],
    arcs: [],
    activeBans: new Map(),
    redNodes: new Map([
      [
        '10.2.31.236',
        {
          ip: '10.2.31.236',
          label: 'KALI-PRIMARY',
          angleOnRedRing: ipToRedAngle('10.2.31.236'),
          strikes: 0,
          lastTool: 'READY',
          lastSeenMs: Date.now(),
          locked: false,
        },
      ],
    ]),
    focusTarget: {
      angle: -0.22,
      kind: 'PERIMETER WATCH',
      text: 'NFTABLES · READY',
      cls: '',
    },
    ipHistory: new Map(),
    rebuildQueue: new Set(),
    flashSlotAt: () => {},
    flashRedSlotAt: () => {},
    spawnComet: () => {},
    spawnRedComet: () => {},
    thS: 0.75,
  });

  const syncUiFromEngine = useCallback(() => {
    const eng = engineRef.current;
    const now = Date.now();
    const { eps: curEps, filtered } = calculateEps(eng.epsWindow, now, 5000);
    eng.epsWindow = filtered;
    const bansArr = Array.from(eng.activeBans.values());
    const curDefcon = computeDefcon(bansArr.length, eng.threatEnergy);

    for (const [ip, rn] of eng.redNodes.entries()) {
      rn.locked = eng.activeBans.has(ip);
    }

    setEventCount(eng.eventCount);
    setEps(curEps);
    setDefcon(curDefcon);
    setChainOk(eng.chainOk);
    setAutonomy(eng.autonomy);
    setAutopilot(eng.autopilot);
    setActiveBansList(bansArr);
    setRedNodesList(Array.from(eng.redNodes.values()));
    setBlueBlocksCount(eng.blueBlocks);
    setRedStrikesCount(eng.redStrikes);
    setBlueHp(eng.blueHp);
    setRedHp(eng.redHp);
  }, []);

  const enterLive = useCallback(() => {
    const eng = engineRef.current;
    eng.mode = 'live';
    eng.eventCount = 0;
    eng.blueBlocks = 0;
    eng.redStrikes = 0;
    eng.blueHp = MAX_CAMP_HP;
    eng.redHp = MAX_CAMP_HP;
    eng.activeBans.clear();
    eng.redNodes.clear();
    setCombatOps([]);
    setModeState('live');
    syncUiFromEngine();
  }, [syncUiFromEngine]);

  const pushFeed = useCallback(
    (id: number, tag: string, cls: FeedRecord['cls'], msg: string) => {
      setFeedList((prev) => {
        const next = [...prev, { id, tag, cls, msg }];
        return next.length > 14 ? next.slice(next.length - 14) : next;
      });
    },
    []
  );

  const pushAI = useCallback((text: string, isTool = false, isOk = false) => {
    const ln = engineRef.current.aiLineCounter++;
    const cls: AiTraceLine['cls'] = isOk ? 'ok' : isTool ? 'fn' : 'op';
    setAiLines((prev) => {
      const next = [...prev, { ln, text, cls }];
      return next.length > 10 ? next.slice(next.length - 10) : next;
    });
  }, []);

  const bumpRule = useCallback((ruleId: string, tNow: number) => {
    const row = matchRuleRowIndex(ruleId);
    const col = Math.floor(tNow * 5) % 24;
    const grid = engineRef.current.ruleHits;
    if (grid[row]) {
      grid[row][col] = Math.min(1, (grid[row][col] || 0) + 0.85);
    }
  }, []);

  const handleNightwatchEvent = useCallback(
    (ev: NightwatchEvent) => {
      const eng = engineRef.current;
      eng.eventCount = Math.max(eng.eventCount + 1, ev.id || 0);
      eng.epsWindow.push(Date.now());
      const ip = ev.ip || eng.hostConfig.redPrimaryIp || '10.2.31.236';
      const kind = ev.kind || 'info';
      const rule = ev.rule_id || kind.toUpperCase();
      const eid = ev.id || eng.eventCount;
      const extra = parseEvidence(ev.evidence_json);
      const tNow = performance.now() / 1000;
      const baseAngle = ipToAngle(ip, eng.thS);
      const redAngle = ipToRedAngle(ip, eng.thS);
      const isAlreadyBlocked = eng.activeBans.has(ip);

      // Derive concrete CombatOperationLog and update Dual-Camp HP
      if (kind !== 'info') {
        const opLog = deriveCombatOperation(
          ev,
          isAlreadyBlocked,
          eng.hostConfig.blueHostIp,
          eng.opSeq++
        );
        const nextHp = applyCombatHp(
          eng.blueHp,
          eng.redHp,
          opLog.blueDeltaHp,
          opLog.redDeltaHp,
          MAX_CAMP_HP
        );
        // Auto-refill if either side reaches 0 so continuous demo stays lively
        eng.blueHp = nextHp.blueHp <= 200 ? MAX_CAMP_HP : nextHp.blueHp;
        eng.redHp = nextHp.redHp <= 200 ? MAX_CAMP_HP : nextHp.redHp;
        setCombatOps((prev) => {
          const next = [...prev, opLog];
          return next.length > 40 ? next.slice(next.length - 40) : next;
        });
      }

      // Register or update Red Node on the Right Offensive Sphere
      const ensureRedNode = (toolLabel: string) => {
        const existing = eng.redNodes.get(ip);
        if (existing) {
          existing.strikes += 1;
          existing.lastTool = toolLabel;
          existing.lastSeenMs = Date.now();
          existing.locked = eng.activeBans.has(ip);
        } else {
          if (eng.redNodes.size >= 6) {
            const oldestKey = eng.redNodes.keys().next().value;
            if (oldestKey && oldestKey !== eng.hostConfig.redPrimaryIp) {
              eng.redNodes.delete(oldestKey);
            }
          }
          eng.redNodes.set(ip, {
            ip,
            label: ip === eng.hostConfig.redPrimaryIp ? 'RED-PRIMARY' : 'RED-NODE',
            angleOnRedRing: redAngle,
            strikes: 1,
            lastTool: toolLabel,
            lastSeenMs: Date.now(),
            locked: eng.activeBans.has(ip),
          });
        }
      };

      // Launch cross-screen ballistic arcs from Right Sphere (Red Camp) to Left Sphere (Blue Camp)
      const triggerCrossScreenStrike = (
        color: string,
        tagLabel: string,
        count = 1,
        speed = 0.82
      ) => {
        ensureRedNode(tagLabel);
        eng.redStrikes += count;
        eng.redEnergy = Math.min(1, eng.redEnergy + 0.42);
        const blocked = eng.activeBans.has(ip);
        // Flash the launching sector and spawn an internal comet inside the Right Red Sphere!
        eng.flashRedSlotAt(Math.PI - redAngle);
        eng.spawnRedComet();
        for (let i = 0; i < count; i++) {
          const jitterBlue = baseAngle + (rnd() - 0.5) * 0.07;
          const jitterRed = redAngle + (rnd() - 0.5) * 0.05;
          const arcLift = (rnd() - 0.48) * 250;
          eng.projectiles.push({
            mode: 'cross_strike',
            ip,
            redAngle: jitterRed,
            blueAngle: jitterBlue,
            arcLift,
            progress: -i * 0.08,
            speed: speed * rr(0.92, 1.14),
            color,
            blocked,
            label: i === 0 ? `${tagLabel} · ${ip}` : '',
          });
        }
        eng.ipHistory.set(ip, baseAngle);
      };

      if (kind === 'net_alert') {
        eng.threatEnergy = Math.min(1, eng.threatEnergy + 0.35);
        triggerCrossScreenStrike('#ffaa2b', 'SYN_FLOOD', 3, 0.95);
        eng.focusTarget = {
          angle: baseAngle,
          kind: `RED->BLUE // ${rule}`,
          text: `${ip} ➔ ${eng.hostConfig.blueHostIp} · ${extra.signature || 'SYN_FLOOD'}`,
          cls: 'alert',
        };
        setLayerState((ls) => [2, ls[1], ls[2], ls[3], ls[4]]);
        eng.anomSpike = 1;
        eng.threatWave = 0.9;
        pushFeed(eid, 'NET', 'net', `${ip} ➔ ${rule} ${extra.signature || ''}`);
        bumpRule(rule, tNow);
        SFX.attack();
      } else if (kind === 'waf_alert') {
        eng.threatEnergy = Math.min(1, eng.threatEnergy + 0.42);
        triggerCrossScreenStrike('#ff3b5c', 'WAF_SQLI', 3, 0.88);
        eng.focusTarget = {
          angle: baseAngle,
          kind: `MODSEC WAF // ${rule}`,
          text: `${ip} ➔ ${extra.uri || 'CRS SQLi BLOCK'}`,
          cls: 'alert',
        };
        setLayerState((ls) => [ls[0], 2, ls[2], ls[3], ls[4]]);
        eng.anomSpike = 1;
        eng.threatWave = 0.95;
        pushFeed(eid, 'WAF', 'waf', `${ip} ➔ ${rule} ${extra.uri || ''}`);
        bumpRule(rule, tNow);
        SFX.attack();
      } else if (kind === 'honeypot') {
        eng.threatEnergy = 0.9;
        triggerCrossScreenStrike('#ff3b5c', 'TRAP_/ADMIN', 4, 1.05);
        eng.focusTarget = {
          angle: baseAngle,
          kind: 'HONEYPOT TRAP',
          text: `${ip} touched ${extra.path || '/admin'}`,
          cls: 'alert',
        };
        setLayerState((ls) => [ls[0], ls[1], 3, ls[3], ls[4]]);
        eng.anomSpike = 1;
        eng.threatWave = 1.0;
        pushFeed(eid, 'TRAP', 'hp', `${ip} ➔ hit honeypot ${extra.path || '/admin'}`);
        bumpRule('HONEYPOT', tNow);
        SFX.attack();
      } else if (kind === 'login_fail' || kind === 'http_404' || kind === 'http_429') {
        eng.threatEnergy = Math.min(1, eng.threatEnergy + 0.16);
        triggerCrossScreenStrike('#f0a6c6', 'SSH_BRUTE', 2, 0.92);
        setLayerState((ls) => [ls[0], ls[1], ls[2], Math.max(ls[3], 1), ls[4]]);
        eng.anomSpike = Math.max(eng.anomSpike, 0.65);
        eng.threatWave = Math.max(eng.threatWave, 0.55);
        pushFeed(
          eid,
          kind === 'http_429' ? 'FLOOD' : 'AUTH',
          'waf',
          `${ip} ➔ ${kind} ${extra.path || extra.user || ''}`
        );
        bumpRule(
          kind === 'login_fail' ? 'BRUTE' : kind === 'http_429' ? 'HTTP_429' : 'PATH_404',
          tNow
        );
        SFX.attack();
      } else if (kind === 'decision') {
        const act = extra.action || (String(rule).includes('BAN') ? 'ban' : 'observe');
        if (act === 'ban') {
          const ttl = Number(extra.ttl_seconds || 600);
          eng.banEnergy = 1.0;
          eng.blueBlocks += 1;
          eng.threatEnergy = Math.max(eng.threatEnergy, 0.7);
          eng.activeBans.set(ip, {
            ip,
            angle: baseAngle,
            rule: rule || 'RULE_BAN',
            reason: extra.reason || rule || 'blocked',
            actor: extra.actor || 'rule-engine',
            ttl,
            expiresAtMs: Date.now() + ttl * 1000,
          });
          const rn = eng.redNodes.get(ip);
          if (rn) rn.locked = true;

          // Fire Blue -> Red Counter-Strike Beam across the entire battlefield!
          eng.projectiles.push({
            mode: 'counter_beam',
            ip,
            blueAngle: baseAngle,
            redAngle,
            life: 1.0,
            color: extra.actor === 'ai-agent' ? '#c084fc' : '#38bdf8',
            label: `COUNTER-BAN // ${rule}`,
          });
          eng.shockwaves.push({ camp: 'blue', rRatio: 0.28, life: 1.0, color: '#38bdf8' });
          eng.shockwaves.push({
            camp: 'redNode',
            redAngle,
            rRatio: 0.05,
            life: 1.0,
            color: '#38bdf8',
          });
          eng.focusTarget = {
            angle: baseAngle,
            kind: `BLUE COUNTER-BAN // ${rule || 'NFTABLES'}`,
            text: `LOCKED ${ip} · DROP ${ttl}s`,
            cls: 'ban',
          };
          eng.flashSlotAt(baseAngle);
          eng.flashRedSlotAt(Math.PI - redAngle);
          eng.spawnComet();
          eng.spawnRedComet();
          SFX.ban();
          setLayerState((ls) => [ls[0], ls[1], ls[2], ls[3], 3]);
          eng.dropWave = 1.0;
          pushFeed(eid, 'BAN', 'ban', `BLUE ➔ RED ${ip} LOCKED (${rule} · ${ttl}s)`);
          bumpRule(rule, tNow);
        } else {
          pushFeed(eid, 'OBS', 'ok', `${ip} -> observe (${rule})`);
        }
      } else if (kind === 'rollback' || kind === 'expire') {
        const b = eng.activeBans.get(ip);
        const angle = b ? b.angle : baseAngle;
        for (let i = 0; i < 20; i++) {
          const sp = angle + (rnd() - 0.5) * 1.6;
          const spd = rr(0.08, 0.32);
          eng.sparks.push({
            angle,
            rRatio: 1.06,
            ox: 0,
            oy: 0,
            vx: Math.cos(sp) * spd,
            vy: Math.sin(sp) * spd,
            life: 1.0,
            color: '#98e0cf',
          });
        }
        eng.shockwaves.push({ camp: 'blue', rRatio: 1.04, life: 0.8, color: '#98e0cf' });
        eng.activeBans.delete(ip);
        const rn = eng.redNodes.get(ip);
        if (rn) rn.locked = false;
        eng.focusTarget = {
          angle,
          kind: 'ROLLBACK // UNBAN',
          text: `${ip} · ${kind}`,
          cls: '',
        };
        SFX.unban();
        pushFeed(eid, 'UNBAN', 'ok', `${ip} · ${kind} (${extra.operator || 'sweeper'})`);
      } else if (kind === 'agent_tool' || kind === 'agent_run') {
        const tool = extra.tool || rule || 'agent_run';
        const summary = extra.summary || extra.conclusion || ev.raw_line || `${tool}(${ip})`;
        const others = Array.from(eng.ipHistory.values());
        const a2 = others.length ? pick(others) : -baseAngle * 0.6;
        eng.aiEnergy = 1.0;
        eng.arcs.push({ a1: baseAngle, a2, life: 1.0 });
        for (let i = 0; i < 2; i++) eng.spawnComet();
        eng.focusTarget = {
          angle: baseAngle,
          kind: 'DEEPSEEK AGENT',
          text: summary,
          cls: 'ai',
        };
        SFX.ai();
        pushAI(
          kind === 'agent_tool' ? `[TOOL] ${tool}(${ip}) -> ${summary}` : `[AGENT] ${summary}`,
          kind === 'agent_tool',
          false
        );
        if (String(tool).includes('execute_ban')) bumpRule('AI_BAN', tNow);
        pushFeed(eid, 'AI', 'ai', `${tool} · ${ip}`);
      } else {
        bumpRule('CHAIN_OK', tNow);
      }

      syncUiFromEngine();
    },
    [bumpRule, pushAI, pushFeed, syncUiFromEngine]
  );

  // Request unban (works in both LIVE SSE mode and DEMO mode)
  const requestUnban = useCallback(
    async (ip: string) => {
      if (engineRef.current.mode === 'live') {
        try {
          const r = await fetch('/api/unban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
          });
          const d = await r.json();
          if (!d.ok) {
            pushAI(`[WARN] unban ${ip}: ${d.error || 'failed'}`);
          }
        } catch (err: any) {
          pushAI(`[ERR] unban ${ip}: ${err?.message || 'network error'}`);
        }
      } else {
        handleNightwatchEvent({
          kind: 'rollback',
          ip,
          evidence_json: { operator: 'web-hud' },
        });
      }
    },
    [handleNightwatchEvent, pushAI]
  );

  // Run scenario (SQLi, SYN Flood, Honeypot, Brute Force, DeepSeek AI, Unban All)
  const runScenario = useCallback(
    (kind: string, customIp?: string) => {
      const primaryRedIp = engineRef.current.hostConfig.redPrimaryIp;
      const ip =
        customIp ||
        (rnd() < 0.55
          ? primaryRedIp
          : pick([primaryRedIp, '185.220.101.4', '45.155.205.91', '10.200.0.2']));

      if (engineRef.current.mode === 'live') {
        if (kind === 'unban_all') {
          for (const bannedIp of Array.from(engineRef.current.activeBans.keys())) {
            requestUnban(bannedIp);
          }
          return;
        }
        fetch('/api/sim', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario: kind, ip }),
        }).catch(() => {});
        return;
      }

      if (kind === 'sqli') {
        handleNightwatchEvent({
          kind: 'waf_alert',
          ip,
          rule_id: 'WAF_SQLI.v1',
          evidence_json: {
            uri: "/lab/item?id=1' OR 1=1--",
            msg: 'SQL Injection Attack Detected via libinjection',
          },
        });
        setTimeout(
          () =>
            handleNightwatchEvent({
              kind: 'decision',
              ip,
              rule_id: 'WAF_SQLI.v1',
              evidence_json: {
                action: 'ban',
                ttl_seconds: 3600,
                actor: 'rule-engine',
                reason: 'WAF_SQLI',
              },
            }),
          680
        );
        setTimeout(() => {
          handleNightwatchEvent({
            kind: 'agent_tool',
            ip,
            evidence_json: {
              tool: 'attack_chain',
              summary: 'found WAF_SQLI #event -> verified',
            },
          });
          setTimeout(
            () =>
              handleNightwatchEvent({
                kind: 'agent_run',
                ip,
                evidence_json: {
                  conclusion: `${ip} 已被蓝方 WAF_SQLI.v1 反制封锁 3600s，哈希链已入账。`,
                },
              }),
            500
          );
        }, 1050);
      } else if (kind === 'syn') {
        for (let i = 0; i < 4; i++) {
          setTimeout(
            () =>
              handleNightwatchEvent({
                kind: 'net_alert',
                ip,
                rule_id: 'NET_DOS.v1',
                evidence_json: { signature: 'NW SYN FLOOD 8081 >=200/10s' },
              }),
            i * 120
          );
        }
        setTimeout(
          () =>
            handleNightwatchEvent({
              kind: 'decision',
              ip,
              rule_id: 'NET_DOS.v1',
              evidence_json: {
                action: 'ban',
                ttl_seconds: 600,
                actor: 'rule-engine',
                reason: 'SYN_FLOOD',
              },
            }),
          620
        );
      } else if (kind === 'honeypot') {
        handleNightwatchEvent({
          kind: 'honeypot',
          ip,
          rule_id: 'HONEYPOT.v1',
          evidence_json: { path: '/admin', ua: 'gobuster/3.6' },
        });
        setTimeout(
          () =>
            handleNightwatchEvent({
              kind: 'decision',
              ip,
              rule_id: 'HONEYPOT.v1',
              evidence_json: {
                action: 'ban',
                ttl_seconds: 3600,
                actor: 'rule-engine',
                reason: 'HONEYPOT_TRAP',
              },
            }),
          360
        );
      } else if (kind === 'brute') {
        for (let i = 0; i < 5; i++) {
          setTimeout(
            () =>
              handleNightwatchEvent({
                kind: 'login_fail',
                ip,
                rule_id: 'BRUTE_FORCE.v1',
                evidence_json: { user: 'root', attempt: i + 1 },
              }),
            i * 110
          );
        }
        setTimeout(
          () =>
            handleNightwatchEvent({
              kind: 'decision',
              ip,
              rule_id: 'BRUTE_FORCE.v1',
              evidence_json: {
                action: 'ban',
                ttl_seconds: 600,
                actor: 'rule-engine',
                reason: '5_LOGIN_FAILS_60S',
              },
            }),
          680
        );
      } else if (kind === 'ai') {
        const steps = [
          {
            tool: 'profile_attacker',
            summary: 'tool=sqlmap (95% conf)',
            d: 0,
          },
          {
            tool: 'correlate_ip',
            summary: '3 rules matched in 42s -> lateral scan',
            d: 350,
          },
          {
            tool: 'deploy_waf_rule',
            summary: 'SecRule UA @contains sqlmap -> hot-reload nginx',
            d: 700,
          },
          {
            tool: 'execute_ban',
            summary: `ban ${ip} ttl=3600s via AI verdict`,
            d: 1050,
          },
        ];
        steps.forEach((s) =>
          setTimeout(
            () =>
              handleNightwatchEvent({
                kind: 'agent_tool',
                ip,
                evidence_json: s,
              }),
            s.d
          )
        );
        setTimeout(
          () =>
            handleNightwatchEvent({
              kind: 'decision',
              ip,
              rule_id: 'AI_AGENT.ban',
              evidence_json: {
                action: 'ban',
                ttl_seconds: 3600,
                actor: 'ai-agent',
                reason: 'DeepSeek multi-vector correlation',
              },
            }),
          1150
        );
        setTimeout(
          () =>
            handleNightwatchEvent({
              kind: 'agent_run',
              ip,
              evidence_json: {
                conclusion: `DeepSeek 完成全链溯源：已对红方 ${ip} 下发 WAF 补丁与封锁令。`,
              },
            }),
          1500
        );
      } else if (kind === 'unban_all') {
        const ips = Array.from(engineRef.current.activeBans.keys());
        if (!ips.length) {
          pushAI('[INFO] 当前无生效封禁，外环防线畅通。', false, true);
        }
        ips.forEach((bIp, idx) =>
          setTimeout(
            () =>
              handleNightwatchEvent({
                kind: 'rollback',
                ip: bIp,
                evidence_json: { operator: 'web-hud' },
              }),
            idx * 150
          )
        );
      }
    },
    [handleNightwatchEvent, pushAI, requestUnban]
  );

  // Update host configuration
  const handleSaveHostConfig = useCallback(
    (nextCfg: RedBlueHostConfig) => {
      engineRef.current.hostConfig = nextCfg;
      setHostConfig(nextCfg);
      const redAngle = ipToRedAngle(nextCfg.redPrimaryIp, engineRef.current.thS);
      engineRef.current.redNodes.set(nextCfg.redPrimaryIp, {
        ip: nextCfg.redPrimaryIp,
        label: 'RED-PRIMARY',
        angleOnRedRing: redAngle,
        strikes: engineRef.current.redNodes.get(nextCfg.redPrimaryIp)?.strikes || 0,
        lastTool: 'LINKED',
        lastSeenMs: Date.now(),
        locked: engineRef.current.activeBans.has(nextCfg.redPrimaryIp),
      });
      syncUiFromEngine();
      pushFeed(
        engineRef.current.eventCount,
        'OK',
        'ok',
        `LINKED: BLUE(${nextCfg.blueHostIp}) ⇄ RED(${nextCfg.redPrimaryIp})`
      );
    },
    [pushFeed, syncUiFromEngine]
  );

  // SSE Connection + Demo Replay Timer + 1Hz UI Sync
  useEffect(() => {
    let es: EventSource | null = null;

    const connectSSE = () => {
      try {
        es = new EventSource('/events');
        es.onopen = () => {
          if (engineRef.current.mode !== 'live') enterLive();
        };
        es.addEventListener('nw_event', (msg: MessageEvent) => {
          if (engineRef.current.mode !== 'live') return;
          try {
            const ev = JSON.parse(msg.data);
            handleNightwatchEvent(ev);
          } catch {
            // ignore
          }
        });
        es.onmessage = (msg) => {
          try {
            const payload = JSON.parse(msg.data);
            if (payload.type === 'hello' || payload.type === 'status') {
              if (typeof payload.chain_ok === 'boolean') {
                engineRef.current.chainOk = payload.chain_ok;
              }
              if (payload.autonomy) engineRef.current.autonomy = payload.autonomy;
              if (typeof payload.autopilot === 'boolean') {
                engineRef.current.autopilot = payload.autopilot;
              }
              syncUiFromEngine();
            } else if (payload.type === 'event' && payload.event && engineRef.current.mode === 'live') {
              handleNightwatchEvent(payload.event);
            }
          } catch {
            // ignore malformed frame
          }
        };
        es.onerror = () => {
          if (es) {
            es.close();
            es = null;
          }
        };
      } catch {
        engineRef.current.mode = 'demo';
        setModeState('demo');
      }
    };

    connectSSE();

    // Launch initial Red vs Blue cross-screen demonstration salvo on boot
    const bootTimer = window.setTimeout(() => {
      if (engineRef.current.mode === 'demo') {
        runScenario('sqli', engineRef.current.hostConfig.redPrimaryIp);
      }
    }, 650);

    // Built-in continuous Red vs Blue cyber duel when in DEMO mode
    const demoInterval = window.setInterval(() => {
      if (engineRef.current.mode !== 'demo') return;
      const primaryIp = engineRef.current.hostConfig.redPrimaryIp;
      const ips = [primaryIp, '185.220.101.4', '45.155.205.91', '10.200.0.2'];
      const ip = rnd() < 0.5 ? primaryIp : pick(ips);
      const r = rnd();
      if (r < 0.28) {
        handleNightwatchEvent({
          kind: 'net_alert',
          ip,
          rule_id: 'NET_DOS.v1',
          evidence_json: { signature: 'NW SYN FLOOD 8081 >=200/10s' },
        });
      } else if (r < 0.54) {
        handleNightwatchEvent({
          kind: 'waf_alert',
          ip,
          rule_id: 'WAF_SQLI.v1',
          evidence_json: { uri: "/lab/item?id=1' UNION SELECT 1,2--" },
        });
      } else if (r < 0.7) {
        handleNightwatchEvent({
          kind: 'login_fail',
          ip,
          rule_id: 'BRUTE_FORCE.v1',
          evidence_json: { user: 'admin' },
        });
      } else if (r < 0.84) {
        handleNightwatchEvent({
          kind: 'honeypot',
          ip,
          rule_id: 'HONEYPOT.v1',
          evidence_json: { path: pick(['/admin', '/.env', '/wp-login.php']) },
        });
      } else {
        const t = pick([
          {
            tool: 'profile_attacker',
            summary: 'tool=sqlmap (95% conf)',
          },
          {
            tool: 'correlate_ip',
            summary: 'multi-vector hit: WAF + NET_SCAN',
          },
          {
            tool: 'deploy_waf_rule',
            summary: 'UA @contains sqlmap -> restart nginx',
          },
        ]);
        handleNightwatchEvent({
          kind: 'agent_tool',
          ip,
          evidence_json: t,
        });
      }

      if (rnd() < 0.42 && !engineRef.current.activeBans.has(ip)) {
        setTimeout(() => {
          handleNightwatchEvent({
            kind: 'decision',
            ip,
            rule_id: pick(['WAF_SQLI.v1', 'NET_DOS.v1', 'HONEYPOT.v1', 'BRUTE_FORCE.v1']),
            evidence_json: {
              action: 'ban',
              ttl_seconds: pick([300, 600, 3600]),
              actor: rnd() < 0.35 ? 'ai-agent' : 'rule-engine',
            },
          });
        }, 480);
      } else if (engineRef.current.activeBans.size > 3 && rnd() < 0.48) {
        const firstIp = engineRef.current.activeBans.keys().next().value;
        if (firstIp) {
          handleNightwatchEvent({
            kind: 'expire',
            ip: firstIp,
            evidence_json: { operator: 'ttl-sweeper' },
          });
        }
      }
    }, 2400);

    // 1Hz UI & Pipeline Ticker
    const uiTicker = window.setInterval(() => {
      syncUiFromEngine();
      setAdvBtnIdx((prev) => (prev + 1) % 3);
    }, 1000);

    return () => {
      if (es) es.close();
      clearTimeout(bootTimer);
      clearInterval(demoInterval);
      clearInterval(uiTicker);
    };
  }, [handleNightwatchEvent, runScenario, syncUiFromEngine, enterLive]);

  // Keyboard shortcuts: C (Console), M (BGM), S (SFX), F (Fullscreen), H (Cinema)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.target && ['INPUT', 'TEXTAREA', 'SELECT'].includes((e.target as HTMLElement).tagName)) {
        return;
      }
      if (e.key === 'c' || e.key === 'C') {
        setConsoleOpen((v) => !v);
      } else if (e.key === 'm' || e.key === 'M') {
        const next = SFX.toggleBgm();
        setBgmOn(next);
      } else if (e.key === 's' || e.key === 'S') {
        const next = SFX.toggle();
        setSfxOn(next);
      } else if (e.key === 'h' || e.key === 'H') {
        document.body.classList.toggle('cinema');
        setTimeout(() => engineRef.current.rebuildQueue.add('resize'), 60);
      } else if (e.key === 'f' || e.key === 'F') {
        if (!document.fullscreenElement) {
          document.documentElement.requestFullscreen?.().catch(() => {});
        } else {
          document.exitFullscreen?.().catch(() => {});
        }
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  // Main Symmetrical Dual-Sphere HALOFLUX Canvas Engine
  useEffect(() => {
    const stageWrap = stageWrapRef.current;
    const stage = stageRef.current;
    const cAdv = cAdvRef.current;
    const cDiff = cDiffRef.current;
    const cVal = cValRef.current;
    const cIdx = cIdxRef.current;
    if (!stageWrap || !stage) return;

    const S_MAIN = stage.getContext('2d')!;
    let S: CanvasRenderingContext2D = S_MAIN;
    let DPR = 1;
    const RING_SC = 2;
    const FS = 0.55;
    const GS = 4;
    const HAS_FILTER = 'filter' in S_MAIN;

    let W = 0,
      H = 0,
      cx = 0,
      cy = 0,
      R = 0,
      RO = 0,
      RMAX = 0,
      thV = 0,
      thS = 0;

    // Right Camp (Red Team Symmetrical Sphere) geometry
    let redCx = 0,
      redCy = 0,
      redR = 0,
      redRO = 0,
      thRed = 0,
      redRingRot = 0;

    let T = 0,
      ringRot = 0,
      webRot = 0,
      env = 0,
      beatT = 0,
      beatI = 0,
      beatN = 0,
      sinceBeat = 99;
    let layerEnv = [0, 0, 0];
    const cam = { x: 0, y: 0, z: 1, tx: 0, ty: 0, tz: 1 };
    const rot = { from: 0, to: 0, t: 1, dur: 1, ease: easeIO, hold: 0 };

    // Left (Blue) & Right (Red) Symmetrical Sphere Offscreen Canvases & Particle Arrays
    let webBase: any,
      webLayers: any[] = [],
      redWebBase: any,
      redWebLayers: any[] = [],
      trailC: any,
      redTrailC: any,
      laneC: any,
      farC: any,
      glowC: any;
    let curves: any[] = [],
      runners: any[] = [],
      redRunners: any[] = [],
      comets: any[] = [],
      redComets: any[] = [],
      slots: any[] = [],
      redSlots: any[] = [],
      strandLayers: any[] = [],
      wedges: any[] = [],
      pulses: any[] = [];
    let hazes: any[] = [],
      flares: any[] = [],
      flyers: any[] = [],
      flyBands: any[] = [],
      GR: Record<string, CanvasGradient> = {};

    const C = engineRef.current.C;
    C.runnerCount = 0;
    C.cometPerBeat = 0;
    C.cometTrickle = 0;
    C.cometBurst = 0;
    C.dataFlicker = 0;
    C.webSpin = 0;

    function mkd(w: number, h: number, d = DPR) {
      const c = document.createElement('canvas') as HTMLCanvasElement & {
        x: CanvasRenderingContext2D;
      };
      c.width = Math.max(1, Math.round(w * d));
      c.height = Math.max(1, Math.round(h * d));
      const x = c.getContext('2d')!;
      x.scale(d, d);
      c.x = x;
      return c;
    }

    const qpt = (cv: any, t: number) => {
      const u = 1 - t;
      return {
        x: u * u * cv.p0.x + 2 * u * t * cv.c.x + t * t * cv.p1.x,
        y: u * u * cv.p0.y + 2 * u * t * cv.c.y + t * t * cv.p1.y,
      };
    };

    function newRunner(init: boolean) {
      const cv = pick(curves),
        t = init ? rnd() : 0,
        p = qpt(cv, t),
        m = rnd();
      const mode = m < 0.45 ? 0 : m < 0.78 ? 1 : 2;
      return {
        cv,
        t,
        sp: mode === 0 ? rr(0.14, 0.36) : mode === 1 ? rr(0.22, 0.52) : rr(0.18, 0.38),
        mode,
        b: rnd() < 0.28,
        px: p.x,
        py: p.y,
      };
    }

    function createCometObject() {
      const a2 = rr(-thV, thV) * 0.92,
        a1 = a2 + (rnd() < 0.5 ? 1 : -1) * rr(0.55, 2.3),
        n = 5 + ((rnd() * 8) | 0);
      const lines: any[] = [];
      if (rnd() < 0.5) {
        const r0 = rr(0.08, 0.38) * R,
          span = normA(a2 - a1) * rr(0.4, 0.9);
        for (let k = 0; k < n; k++)
          lines.push({
            arc: true,
            r: r0 + gauss() * 16,
            a0: a1 + gauss() * 0.07,
            span: span + gauss() * 0.06,
          });
      } else {
        const r0 = rr(0.2, 0.92) * R,
          bend = rr(-0.4, 0.4),
          sp1 = rr(0.04, 0.14),
          sp2 = rr(0.015, 0.06);
        for (let k = 0; k < n; k++) {
          const u = n > 1 ? k / (n - 1) - 0.5 : 0;
          const b1 = a1 + u * sp1 + gauss() * 0.008,
            b2 = a2 + u * sp2 + gauss() * 0.005,
            rk = clamp(r0 + gauss() * 14, 20, R - 4);
          const p0 = { x: Math.cos(b1) * rk, y: Math.sin(b1) * rk },
            p1 = { x: Math.cos(b2) * (R - 2), y: Math.sin(b2) * (R - 2) };
          const mx = (p0.x + p1.x) * 0.5,
            my = (p0.y + p1.y) * 0.5,
            dx = p1.x - p0.x,
            dy = p1.y - p0.y;
          lines.push({
            p0,
            c: { x: mx - dy * bend + gauss() * 8, y: my + dx * bend + gauss() * 8 },
            p1,
          });
        }
      }
      return {
        lines,
        life: 0,
        hit: false,
        rot0: ringRot,
        dur: rr(0.4, 0.85) / C.cometSpeed,
        win: rr(0.22, 0.4),
        glow: rnd() < 0.45,
        tint: rnd() < 0.35,
      };
    }

    function spawnComet() {}

    function spawnRedComet() {}

    function flashSlotAt(_ang: number) {}

    function flashRedSlotAt(_ang: number) {}

    engineRef.current.flashSlotAt = flashSlotAt;
    engineRef.current.flashRedSlotAt = flashRedSlotAt;
    engineRef.current.spawnComet = spawnComet;
    engineRef.current.spawnRedComet = spawnRedComet;

    function buildWeb() {
      const size = 2 * R + 4,
        d = 0.85;
      webBase = mkd(size, size, d);
      const b = webBase.x;
      b.save();
      b.translate(R + 2, R + 2);
      b.beginPath();
      b.arc(0, 0, R, 0, TAU);
      const g = b.createRadialGradient(0, 0, R * 0.2, 0, 0, R);
      g.addColorStop(0, '#0d131c');
      g.addColorStop(1, '#090c12');
      b.fillStyle = g;
      b.fill();
      b.restore();

      redWebBase = mkd(size, size, d);
      const rb = redWebBase.x;
      rb.save();
      rb.translate(R + 2, R + 2);
      rb.beginPath();
      rb.arc(0, 0, R, 0, TAU);
      const rg = rb.createRadialGradient(0, 0, R * 0.2, 0, 0, R);
      rg.addColorStop(0, '#1e0b10');
      rg.addColorStop(1, '#0d0608');
      rb.fillStyle = rg;
      rb.fill();
      rb.restore();
    }

    function makeProfile(n: number) {
      const prof: number[] = [];
      let v = rr(0.45, 1),
        run = 0;
      for (let k = 0; k < n; k++) {
        if (run-- <= 0) {
          v = clamp(v + gauss() * 0.4, 0.22, 1);
          run = 2 + ((rnd() * 5) | 0);
        }
        prof.push(clamp(v + gauss() * 0.07, 0.18, 1));
      }
      return prof;
    }

    function makeStrandLayer(
      stepDeg: number,
      rotK: number,
      lumK: number,
      lw: number,
      lenK: number,
      solidK: number,
      cover: number,
      nMin: number,
      nMax: number,
      brightP: number,
      dyn = 'soft'
    ) {
      const step = (stepDeg * Math.PI) / 180,
        nb = Math.floor(TAU / step),
        ws: any[] = [];
      const count = Math.round((nb * cover) / ((nMin + nMax) / 2));
      for (let j = 0; j < count; j++) {
        const n = nMin + ((rnd() * (nMax - nMin)) | 0),
          bright = rnd() < brightP;
        ws.push({
          i0: (rnd() * nb) | 0,
          n,
          base: rr(0.35, 1),
          len: rr(0.1, 0.5),
          kick: 0,
          ph: rnd() * TAU,
          ph2: rnd() * TAU,
          f1: rr(0.22, 0.6),
          f2: rr(0.8, 1.7),
          lum: bright ? rr(0.75, 1) : rr(0.16, 0.55),
          tint: rnd() < 0.5 ? 1 : 0,
          lwK: rnd() < 0.2 ? rr(1.35, 2.1) : rr(0.6, 1.15),
          lenS: rr(0.6, 1.25),
          prof: makeProfile(n),
          pf: Array.from({ length: n }, () => rr(1, 4)),
          pp: Array.from({ length: n }, () => rnd() * TAU),
          ds: Array.from({ length: n }, () => rnd()),
          dsp: rr(0.7, 1.8),
          flow: 0,
        });
      }
      return { step, rotK, lumK, lw, lenK, solidK, wedges: ws, off: rnd() * TAU, dyn };
    }

    function spawnHaze(init: boolean) {
      const k = rnd();
      hazes.push({
        a: rr(-thS, thS) - ringRot,
        w: rnd() < 0.7 ? rr(0.015, 0.07) : rr(0.08, 0.18),
        len: rr(0.25, 0.65),
        cur: init ? rr(0.2, 0.5) : 0,
        age: init ? rr(0, 0.5) : 0,
        life: rr(0.35, 1.6),
        alpha: rr(0.12, 0.36),
        tint: k < 0.55 ? 0 : k < 0.85 ? 1 : 2,
      });
    }

    function spawnFlare(a?: number | null) {
      flares.push({
        a: a == null ? rr(-thS, thS) * 0.95 - ringRot : a,
        w: rr(0.006, 0.04),
        len: rr(18, 95),
        age: 0,
        life: rr(0.2, 0.55),
        alpha: rr(0.6, 1),
      });
    }

    function newFlyBand() {
      return { a: rr(-thS, thS), w: rr(0.01, 0.05), life: rr(2, 6) };
    }

    function newFlyer(init: boolean) {
      let a: number;
      if (rnd() < 0.5) {
        const b = pick(flyBands);
        a = b.a + gauss() * b.w;
      } else a = rr(-thS, thS);
      return {
        a: a - ringRot,
        len: 20 + Math.pow(rnd(), 2) * 220,
        r: init ? rr(RO, RMAX * 0.7) : RO + rr(0, 25),
        sp: rr(260, 750),
        lw: rnd() < 0.08 ? rr(1.2, 1.7) : rr(0.5, 1),
        lv: rnd() < 0.12 ? 1 : 0,
        tint: rnd() < 0.22 ? 1 : 0,
        burst: false,
      };
    }

    function spawnFlyBurst() {
      const a = rr(-thS, thS) * 0.95,
        n = Math.max(1, Math.round((10 + ((rnd() * 18) | 0)) * C.burstSize)),
        spread = rr(0.01, 0.045);
      const sp = rr(450, 950),
        len = rr(60, 240),
        r0 = RO + rr(0, 8),
        tint = rnd() < 0.3 ? 1 : 0,
        lv = rnd() < 0.45 ? 2 : 1;
      for (let i = 0; i < n; i++) {
        flyers.push({
          a: a + (i / n - 0.5) * spread + gauss() * 0.0015 - ringRot,
          len: len * rr(0.7, 1.15),
          r: r0 - rr(0, len * 0.35),
          sp: sp * rr(0.92, 1.08),
          lw: rnd() < 0.2 ? 1.3 : rr(0.6, 1),
          lv,
          tint,
          burst: true,
        });
      }
    }

    function initFlyers() {
      flyBands = Array.from({ length: 7 }, newFlyBand);
      flyers = Array.from(
        { length: Math.round(Math.min(180, 100 + W * 0.06) * C.flyerCount) },
        () => newFlyer(true)
      );
    }

    function buildOuter() {
      strandLayers = [
        makeStrandLayer(0.52, 0.45, 0.3, 0.55, 0.72, 0.9, 0.8, 10, 32, 0.2),
        makeStrandLayer(0.38, 0.75, 0.58, 0.8, 0.68, 0.7, 0.7, 8, 26, 0.28),
        makeStrandLayer(0.3, 1.0, 1.0, 1.0, 0.65, 0.5, 0.62, 8, 24, 0.32),
        makeStrandLayer(0.68, 1.0, 0.5, 1.8, 0.58, 0.6, 0.35, 4, 12, 0.3),
        makeStrandLayer(0.3, 1.0, 0.85, 1.0, 0.65, 0.5, 0.48, 8, 26, 0.32, 'bounce'),
      ];
      wedges = strandLayers[2].wedges.concat(strandLayers[4].wedges);
      hazes = [];
      flares = [];
      GR = {};
      const mkG = (stops: [number, string][], r1: number) => {
        const g = S.createRadialGradient(cx, cy, RO, cx, cy, r1);
        stops.forEach((s) => g.addColorStop(s[0], s[1]));
        return g;
      };
      GR.s0 = mkG(
        [
          [0, 'rgba(220,242,255,1)'],
          [0.35, 'rgba(135,206,250,.78)'],
          [1, 'rgba(56,189,248,.18)'],
        ],
        RMAX * 0.75
      );
      GR.s2 = mkG(
        [
          [0, 'rgba(225,245,242,1)'],
          [0.3, 'rgba(152,224,207,.8)'],
          [1, 'rgba(56,189,248,.2)'],
        ],
        RMAX * 0.75
      );
      GR.s1 = mkG(
        [
          [0, 'rgba(240,236,255,1)'],
          [0.3, 'rgba(196,182,244,.82)'],
          [1, 'rgba(160,140,228,.22)'],
        ],
        RMAX * 0.75
      );
      for (let i = 0; i < 12; i++) spawnHaze(true);
      initFlyers();
    }

    function buildLanes() {
      laneC = mkd(W, H, DPR);
      const x = laneC.x;
      for (let i = 0; i < 420; i++) {
        const a = rr(-thS, thS);
        x.strokeStyle = `rgba(56,189,248,${rr(0.01, 0.032)})`;
        x.lineWidth = rr(0.5, 1);
        const r0 = RO + 4,
          r1 = rr(RO + 50, RMAX * 0.58);
        x.beginPath();
        x.moveTo(cx + Math.cos(a) * r0, cy + Math.sin(a) * r0);
        x.lineTo(cx + Math.cos(a) * r1, cy + Math.sin(a) * r1);
        x.stroke();
      }
    }

    function buildCards() {
      slots = [];
      redSlots = [];
    }

    function rimW() {
      return Math.max(3, (RO - R) * 0.065 * C.rimWidth);
    }

    function headerSlot(
      c: CanvasRenderingContext2D,
      x0: number,
      x1: number,
      y: number,
      t: number[],
      isRed = false
    ) {
      c.font = `700 4.3px ${FONT}`;
      c.fillStyle = rgba(t, 0.95);
      c.fillText(pick(isRed ? RED_HEAD : HEAD), x0, y);
      c.fillStyle = rgba(t, 0.55);
      c.fillText(String((rnd() * 99) | 0).padStart(2, '0'), x1 - 6, y);
      c.fillStyle = rgba(t, 0.3);
      c.fillRect(x0, y + 5.6, x1 - x0, 0.45);
      return y + 7.5;
    }

    const BLOCKS: Record<string, Function> = {
      code(
        c: CanvasRenderingContext2D,
        x0: number,
        x1: number,
        y0: number,
        y1: number,
        t: number[],
        isRed = false
      ) {
        let y = headerSlot(c, x0, x1, y0, t, isRed);
        c.font = `500 3.5px ${FONT}`;
        let n = 1 + ((rnd() * 40) | 0);
        const words = isRed ? RED_CODE_T : CODE_T;
        while (y < y1 - 3.5) {
          c.fillStyle = rgba(t, 0.3);
          c.fillText(String(n++).padStart(3, '0'), x0, y);
          let xx = x0 + 9;
          for (let i = 0; i < 3 && xx < x1 - 4; i++) {
            const w = pick(words);
            c.fillStyle = rgba(t, rnd() < 0.3 ? 1 : rr(0.5, 0.8));
            c.fillText(w, xx, y);
            xx += w.length * 2.15 + 2;
          }
          y += 4.6;
        }
      },
      kv(
        c: CanvasRenderingContext2D,
        x0: number,
        x1: number,
        y0: number,
        y1: number,
        t: number[],
        isRed = false
      ) {
        let y = y1 - y0 > 18 ? headerSlot(c, x0, x1, y0, t, isRed) : y0 + 1;
        c.font = `500 3.6px ${FONT}`;
        while (y < y1 - 4) {
          c.fillStyle = rgba(t, 0.55);
          c.fillText(pick(KEYS), x0, y);
          const v = String((rnd() * 999) | 0);
          c.fillStyle = rgba(t, 0.95);
          c.textAlign = 'right';
          c.fillText(v, x1, y);
          c.textAlign = 'left';
          const bx = x0 + 14,
            bw = Math.max(0, x1 - x0 - 24);
          c.fillStyle = rgba(t, 0.15);
          c.fillRect(bx, y + 1.2, bw, 1.2);
          c.fillStyle = rgba(t, 0.75);
          c.fillRect(bx, y + 1.2, bw * rnd(), 1.2);
          y += 5.2;
        }
      },
      spark(
        c: CanvasRenderingContext2D,
        x0: number,
        x1: number,
        y0: number,
        y1: number,
        t: number[],
        isRed = false
      ) {
        const y = headerSlot(c, x0, x1, y0, t, isRed),
          top = y + 1,
          bot = y1 - 2,
          n = 36;
        c.strokeStyle = rgba(t, 0.95);
        c.lineWidth = 0.55;
        c.beginPath();
        let v = rnd(),
          lx = 0,
          ly = 0;
        for (let i = 0; i <= n; i++) {
          v = clamp(v + gauss() * 0.25, 0, 1);
          lx = x0 + ((x1 - x0) * i) / n;
          ly = bot - v * (bot - top);
          i ? c.lineTo(lx, ly) : c.moveTo(lx, ly);
        }
        c.stroke();
        c.fillStyle = '#fff';
        c.fillRect(lx - 0.9, ly - 0.9, 1.8, 1.8);
      },
      grid(
        c: CanvasRenderingContext2D,
        x0: number,
        x1: number,
        y0: number,
        y1: number,
        t: number[],
        isRed = false
      ) {
        const y = y1 - y0 > 20 ? headerSlot(c, x0, x1, y0, t, isRed) : y0 + 1,
          p = rr(2.4, 3.2);
        for (let yy = y; yy < y1 - p + 0.5; yy += p)
          for (let xx = x0; xx < x1 - p + 0.5; xx += p) {
            const v = rnd();
            c.fillStyle =
              v > 0.92
                ? isRed
                  ? 'rgba(255,170,43,.95)'
                  : 'rgba(255,59,92,.95)'
                : rgba(t, 0.08 + v * v * 0.8);
            c.fillRect(xx, yy, p - 0.6, p - 0.6);
          }
      },
    };

    function renderSlot(s: any, isRed = false) {
      const band = RO - R,
        h = s.hpx;
      const c = document.createElement('canvas');
      c.width = Math.ceil(band * RING_SC);
      c.height = Math.ceil((h + 2) * RING_SC);
      const x = c.getContext('2d')!;
      x.scale(RING_SC, RING_SC);
      if (isRed) {
        // Pre-flip horizontally in local slot space so when drawRedRing mirrors X (-1, 1),
        // the outer zone stays at the outer rim while text & numbers read right-side-up!
        x.translate(band, 0);
        x.scale(-1, 1);
      }
      x.textBaseline = 'top';
      const RB = rimW(),
        dz0 = isRed ? RB + 5 : RB + 6,
        dz1 = isRed ? band - RB - 6 : band * 0.72,
        oz0 = band * 0.78,
        oz1 = band - RB - 5;
      const tint = pick(isRed ? RED_TINTS : TINTS),
        y0 = 1,
        y1 = h;
      x.save();
      x.beginPath();
      if (isRed) {
        const rDz0 = band * 0.28;
        const rDz1 = band - RB - 6;
        x.rect(rDz0, y0, rDz1 - rDz0, y1 - y0);
        x.clip();
        BLOCKS[h > 22 ? pick(['code', 'spark', 'grid', 'kv']) : 'kv'](
          x,
          rDz0,
          rDz1,
          y0,
          y1,
          tint,
          true
        );
      } else {
        x.rect(dz0, y0, dz1 - dz0, y1 - y0);
        x.clip();
        BLOCKS[h > 22 ? pick(['code', 'spark', 'grid', 'kv']) : 'kv'](
          x,
          dz0,
          dz1,
          y0,
          y1,
          tint,
          false
        );
      }
      x.restore();
      const pitch = rr(8, 12);
      x.font = `600 3.1px ${FONT}`;
      const barStart = isRed ? RB + 5 : oz0;
      const barEnd = isRed ? band * 0.22 : oz1;
      for (let yy = rr(1, pitch); yy < h - 2; yy += pitch) {
        let xx = barStart + rr(0, 3);
        if (rnd() < 0.5) {
          x.fillStyle = isRed
            ? `rgba(255,215,222,${rr(0.55, 0.95)})`
            : `rgba(225,228,236,${rr(0.55, 0.95)})`;
          x.fillText(String((rnd() * 999) | 0).padStart(3, '0'), xx, yy - 1);
          xx += 9;
        }
        for (let i = 0; i < 3 && xx < barEnd; i++) {
          x.fillStyle = isRed
            ? `rgba(255,140,160,${rr(0.5, 0.95)})`
            : `rgba(225,228,236,${rr(0.5, 0.95)})`;
          x.fillRect(xx, yy, rr(1.2, 2.4), 1.2);
          xx += rr(2.4, 3.6);
        }
      }
      s.c = c;
    }

    function resizeStage() {
      const r = stage!.getBoundingClientRect();
      W = Math.max(100, r.width);
      H = Math.max(100, r.height);
      stage!.width = Math.round(W * DPR);
      stage!.height = Math.round(H * DPR);

      // Symmetrical Left (Blue) and Right (Red) Spheres with a wide central battle corridor!
      cx = W * 0.015;
      cy = H * 0.51;
      R = Math.max(H * 0.54, W * 0.185);
      RO = R + Math.max(66, Math.min(138, H * 0.19, W * 0.078)) * C.ringWidth;
      RMAX = Math.hypot(W - cx, H / 2) + 60;
      thV = Math.asin(Math.min(1, (H / 2 + 60) / R));
      thS = Math.asin(Math.min(1, (H / 2 + 40) / RO));
      engineRef.current.thS = thS;

      // Exact Mirrored Right Sphere (Red Camp)
      redCx = W - cx;
      redCy = cy;
      redR = R;
      redRO = RO;
      thRed = thS;

      // Re-sync Red Node angles to match thRed
      for (const [ip, rn] of engineRef.current.redNodes.entries()) {
        rn.angleOnRedRing = ipToRedAngle(ip, thRed);
      }

      cam.x = W / 2;
      cam.y = H / 2;
      cam.z = 1;

      buildWeb();
      buildLanes();
      buildCards();
      buildOuter();
      trailC = mkd(2 * R + 4, 2 * R + 4, 0.85);
      redTrailC = mkd(2 * R + 4, 2 * R + 4, 0.85);
      farC = document.createElement('canvas') as any;
      farC.width = Math.max(1, Math.ceil(W * FS));
      farC.height = Math.max(1, Math.ceil(H * FS));
      farC.x = farC.getContext('2d')!;
      glowC = document.createElement('canvas') as any;
      glowC.width = Math.max(1, Math.ceil(W / GS));
      glowC.height = Math.max(1, Math.ceil(H / GS));
      glowC.x = glowC.getContext('2d')!;
      runners = [];
      redRunners = [];
      comets = [];
      redComets = [];
      pulses = [];
    }

    function fitPanel(c: HTMLCanvasElement | null) {
      if (!c) return;
      const r = c.getBoundingClientRect();
      if (r.width < 10 || r.height < 10) return;
      c.width = Math.round(r.width * DPR);
      c.height = Math.round(r.height * DPR);
      const x = c.getContext('2d')!;
      x.setTransform(DPR, 0, 0, DPR, 0, 0);
      pSizes.set(c, { x, w: r.width, h: r.height });
    }

    const pSizes = new Map<
      HTMLCanvasElement,
      { x: CanvasRenderingContext2D; w: number; h: number }
    >();
    let advP: { x: number; y: number; l: number }[] = [];
    let valBuf: number[][] = [[], [], []];

    function resizePanels() {
      if (engineRef.current.viewVersion !== 'v1') return;
      [cAdv, cDiff, cVal, cIdx].forEach(fitPanel);
      const advInfo = cAdv ? pSizes.get(cAdv) : null;
      if (advInfo) {
        advP = Array.from({ length: 280 }, () => ({
          x: rnd() * advInfo.w,
          y: rnd() * advInfo.h,
          l: rnd() * 3,
        }));
      }
      const valInfo = cVal ? pSizes.get(cVal) : null;
      if (valInfo) {
        const nInit = Math.max(20, Math.floor((valInfo.w - 52) / 2));
        valBuf = [
          Array.from({ length: nInit }, (_, i) => Math.sin(i * 0.25) * 0.18),
          Array.from({ length: nInit }, (_, i) => Math.sin(i * 0.4) * 0.12 - 0.15),
          Array.from({ length: nInit }, (_, i) => Math.cos(i * 0.3) * 0.1 - 0.1),
        ];
      }
    }

    function ringMove() {}

    function onBeatOuter() {
      if (engineRef.current.viewVersion !== 'v1') return;
      const n = Math.round(
        (beatN % 4 === 0 ? 3 + ((rnd() * 2) | 0) : 1 + ((rnd() * 2) | 0)) * C.burstRate
      );
      for (let i = 0; i < n; i++) setTimeout(spawnFlyBurst, i * rr(20, 120));
      for (let i = 0; i < 2 + ((rnd() * 5) | 0); i++) {
        const w = pick(wedges);
        if (w) {
          w.kick = rr(0.4, 1);
          if (rnd() < 0.5) w.prof = makeProfile(w.n);
        }
      }
      const nh = beatN % 4 === 0 ? 5 + ((rnd() * 4) | 0) : 1 + ((rnd() * 3) | 0);
      for (let i = 0; i < Math.round((nh * C.hazeCount) / 8); i++) spawnHaze(false);
      const nf = Math.round((1 + ((rnd() * 4) | 0)) * C.flareRate);
      for (let i = 0; i < nf; i++)
        spawnFlare(hazes.length && rnd() < 0.6 ? pick(hazes).a : null);
    }

    function onBeat() {
      if (rot.t >= rot.dur && rot.hold <= 0) ringMove();
      const n = Math.round((beatN % 4 === 0 ? C.cometBurst : C.cometPerBeat) * rr(0.6, 1.4));
      for (let i = 0; i < n; i++) {
        setTimeout(spawnComet, i * rr(30, 90));
        setTimeout(spawnRedComet, i * rr(35, 95));
      }
      layerEnv[(rnd() * 3) | 0] = 1;
      if (beatN % 4 === 0) layerEnv = layerEnv.map(() => rr(0.6, 1));
      const dir = rnd() < 0.5 ? 1 : -1,
        big = beatN % 8 === 0;
      pulses.push({
        c: dir > 0 ? -thS - 0.15 : thS + 0.15,
        v: dir * rr(0.7, 1.6) * (big ? 0.7 : 1),
        w: big ? rr(0.25, 0.4) : rr(0.05, 0.16),
        amp: big ? 1 : rr(0.45, 0.9),
        life: rr(1.2, 2.0),
        L: 0,
      });
      pulses.forEach((p) => p.L || (p.L = p.life));
      onBeatOuter();
      if (slots.length) {
        for (let i = 0; i < Math.round(5 * C.dataFlicker); i++) pick(slots).c = null;
        for (let i = 0; i < Math.round(2 * C.dataFlicker); i++) pick(slots).flash = rr(0.35, 0.7);
      }
      if (redSlots.length) {
        for (let i = 0; i < Math.round(5 * C.dataFlicker); i++) pick(redSlots).c = null;
        for (let i = 0; i < Math.round(2 * C.dataFlicker); i++)
          pick(redSlots).flash = rr(0.35, 0.7);
      }
    }

    function updateBeat(dt: number) {
      const eng = engineRef.current;
      const tempoBoost = 1 + eng.threatEnergy * 0.55;
      beatT -= dt * tempoBoost;
      sinceBeat += dt;
      if (beatT <= 0) {
        beatT += (PATTERN[beatI++ % PATTERN.length] * 0.92) / C.tempo;
        sinceBeat = 0;
        beatN++;
        onBeat();
      }
      env = Math.min(
        1,
        Math.exp(-sinceBeat * 4.5) + eng.threatEnergy * 0.5 + eng.banEnergy * 0.6
      );
    }

    function updateCam() {
      cam.x = W / 2;
      cam.y = H / 2 + (C.camera ? Math.sin(T * 0.65) * 2.5 : 0);
      cam.z = C.camera ? 1 + 0.012 * Math.sin(T * 0.45) * C.camZoom : 1;
    }

    function camT(ctx: CanvasRenderingContext2D, d: number) {
      ctx.setTransform(
        d * cam.z,
        0,
        0,
        d * cam.z,
        d * (W / 2 - cam.x * cam.z),
        d * (H / 2 - cam.y * cam.z)
      );
    }

    function camTk(ctx: CanvasRenderingContext2D, d: number, k: number) {
      const z = 1 + (cam.z - 1) * k,
        x = W / 2 + (cam.x - W / 2) * k,
        y = H / 2 + (cam.y - H / 2) * k;
      ctx.setTransform(d * z, 0, 0, d * z, d * (W / 2 - x * z), d * (H / 2 - y * z));
    }

    const toScreen = (x: number, y: number) => ({
      x: (x - cam.x) * cam.z + W / 2,
      y: (y - cam.y) * cam.z + H / 2,
    });

    function updateOuter(dt: number) {
      for (let i = pulses.length - 1; i >= 0; i--) {
        const p = pulses[i];
        p.c += p.v * dt;
        p.life -= dt;
        if (p.life <= 0) pulses.splice(i, 1);
      }
      for (const Lr of strandLayers) {
        const rRot = ringRot * Lr.rotK + Lr.off;
        for (const w of Lr.wedges) {
          const am = normA((w.i0 + w.n / 2) * Lr.step + rRot);
          w.vis = Math.abs(am) < thS + 0.2;
          w.flow += dt * w.dsp * (0.45 + 2.2 * env);
          if (!w.vis) {
            w.len *= 0.98;
            continue;
          }
          let p = 0;
          for (const pl of pulses) {
            const f =
              Math.min(1, pl.life / 0.5) * Math.min(1, (pl.L - pl.life) / 0.15 + 0.3);
            p += pl.amp * f * Math.exp(-(((am - pl.c) / pl.w) ** 2));
          }
          if (Lr.dyn === 'bounce') {
            const idle = w.base * (0.36 + 0.14 * Math.sin(T * 0.9 + w.ph));
            const tgt = Math.min(1, idle + p * 0.75 + w.kick * 0.6);
            w.kick *= Math.exp(-dt * 2.4);
            w.len += (tgt - w.len) * Math.min(1, (tgt > w.len ? 15 : 2.2) * dt);
          } else {
            const n1 = 0.5 + 0.5 * Math.sin(T * w.f1 + w.ph),
              n2 = 0.5 + 0.5 * Math.sin(T * w.f2 + w.ph2);
            const idle = w.base * (0.4 + 0.34 * n1 + 0.14 * n2);
            const tgt = Math.min(1.05, (idle + p * 0.7 + w.kick * 0.55) * w.lenS);
            w.kick *= Math.exp(-dt * 1.8);
            w.len += (tgt - w.len) * Math.min(1, (tgt > w.len ? 5 : 1.3) * dt);
          }
        }
      }
      for (let i = hazes.length - 1; i >= 0; i--) {
        const h = hazes[i];
        h.age += dt;
        h.cur += (h.len - h.cur) * Math.min(1, 9 * dt);
        if (h.age > h.life + 0.6) hazes.splice(i, 1);
      }
      if (hazes.length < C.hazeCount && rnd() < 0.25) spawnHaze(false);
      for (let i = flares.length - 1; i >= 0; i--) {
        flares[i].age += dt;
        if (flares[i].age > flares[i].life) flares.splice(i, 1);
      }
      if (rnd() < 0.06 * C.flareRate) spawnFlare();
      for (const b of flyBands) {
        b.life -= dt;
        if (b.life <= 0) Object.assign(b, newFlyBand());
      }
      const k = (0.7 + 0.9 * env) * C.flyerSpeed;
      for (let i = flyers.length - 1; i >= 0; i--) {
        const f = flyers[i];
        f.r += f.sp * dt * k;
        if (f.r - f.len > RMAX * 0.68) {
          if (f.burst) flyers.splice(i, 1);
          else flyers[i] = newFlyer(false);
        }
      }
    }

    function updateBattleFX(dt: number) {
      const eng = engineRef.current;
      eng.threatEnergy = Math.max(0, eng.threatEnergy - dt * 0.42);
      eng.aiEnergy = Math.max(0, eng.aiEnergy - dt * 0.52);
      eng.banEnergy = Math.max(0, eng.banEnergy - dt * 0.65);
      eng.redEnergy = Math.max(0.22, eng.redEnergy - dt * 0.35);

      const nowMs = Date.now();
      for (const [ip, info] of eng.activeBans.entries()) {
        if (nowMs >= info.expiresAtMs) {
          eng.activeBans.delete(ip);
        }
      }

      for (let i = eng.projectiles.length - 1; i >= 0; i--) {
        const p = eng.projectiles[i];
        if (p.mode === 'cross_strike') {
          p.progress += p.speed * dt;
          if (p.progress >= 1.0) {
            const hitR = p.blocked ? 1.05 : 0.98;
            const count = p.blocked ? 18 : 12;
            const col = p.blocked ? '#38bdf8' : p.color;
            if (p.blocked) eng.blueBlocks += 1;
            for (let k = 0; k < count; k++) {
              const sp = p.blueAngle + (rnd() - 0.5) * 1.8;
              const spd = rr(0.09, 0.36);
              eng.sparks.push({
                angle: p.blueAngle,
                rRatio: hitR,
                ox: 0,
                oy: 0,
                vx: Math.cos(sp) * spd,
                vy: Math.sin(sp) * spd,
                life: 1.0,
                color: col,
              });
            }
            flashSlotAt(p.blueAngle);
            spawnComet();
            eng.projectiles.splice(i, 1);
          }
        } else {
          p.life -= dt * 1.25;
          if (p.life <= 0) eng.projectiles.splice(i, 1);
        }
      }
      for (let i = eng.sparks.length - 1; i >= 0; i--) {
        const s = eng.sparks[i];
        s.ox += s.vx * dt;
        s.oy += s.vy * dt;
        s.life -= dt * 2.1;
        if (s.life <= 0) eng.sparks.splice(i, 1);
      }
      for (let i = eng.shockwaves.length - 1; i >= 0; i--) {
        const w = eng.shockwaves[i];
        w.rRatio += dt * 1.7;
        w.life -= dt * 1.35;
        if (w.life <= 0) eng.shockwaves.splice(i, 1);
      }
      for (let i = eng.arcs.length - 1; i >= 0; i--) {
        eng.arcs[i].life -= dt * 0.85;
        if (eng.arcs[i].life <= 0) eng.arcs.splice(i, 1);
      }
    }

    // Symmetrical 48-Sector High-Precision Ring for the Right (Red) Sphere!
    function drawRedRing(dt: number) {
      const band = redRO - redR;
      S.save();
      // Mirror horizontally around (redCx, redCy) so the Right Sphere ring faces Left!
      S.translate(redCx, redCy);
      S.scale(-1, 1);

      S.beginPath();
      S.arc(0, 0, redRO, -thV - 0.1, thV + 0.1);
      S.arc(0, 0, redR, thV + 0.1, -thV - 0.1, true);
      S.fillStyle = '#0e0709';
      S.fill();

      let regen = 4;
      for (const s of redSlots) {
        s.flash *= Math.exp(-dt * 4);
        const A = normA(s.a + redRingRot);
        if (Math.abs(A) > thV + s.da) continue;
        if (!s.c && regen > 0) {
          renderSlot(s, true);
          regen--;
        }
        if (!s.c) continue;
        S.save();
        S.rotate(A);
        const hh = s.hpx + 2;
        S.drawImage(s.c, redR, -hh / 2, band, hh);
        if (s.flash > 0.02) {
          S.globalCompositeOperation = 'lighter';
          S.globalAlpha = s.flash;
          S.drawImage(s.c, redR, -hh / 2, band, hh);
          S.globalAlpha = 1;
          S.globalCompositeOperation = 'source-over';
        }
        S.restore();
      }

      const tick = (step: number, fn: (ca: number, sa: number, n: number) => void) => {
        const n0 = Math.floor((-thV - 0.05 - redRingRot) / step),
          n1 = Math.ceil((thV + 0.05 - redRingRot) / step);
        for (let n = n0; n <= n1; n++) {
          const a = n * step + redRingRot;
          fn(Math.cos(a), Math.sin(a), n);
        }
      };
      const RB = rimW();
      S.beginPath();
      tick(((0.14 / C.rimDensity) * Math.PI) / 180, (ca, sa, n) => {
        const m = ((n % 6) + 6) % 6,
          li = m === 0 ? RB : RB * (0.5 + 0.35 * hash(n)),
          lo = m === 0 ? RB : RB * (0.5 + 0.35 * hash(n + 77));
        S.moveTo(ca * (redR + 1.5), sa * (redR + 1.5));
        S.lineTo(ca * (redR + 1.5 + li), sa * (redR + 1.5 + li));
        S.moveTo(ca * (redRO - 1.5), sa * (redRO - 1.5));
        S.lineTo(ca * (redRO - 1.5 - lo), sa * (redRO - 1.5 - lo));
      });
      S.globalCompositeOperation = 'lighter';
      S.strokeStyle = `rgba(255,59,92,${Math.min(1, 0.06 * C.rimBright * C.rimBright)})`;
      S.lineWidth = 1.2 + 2.4 * C.rimBright;
      S.stroke();
      S.globalCompositeOperation = 'source-over';
      S.strokeStyle = `rgba(255,215,222,${Math.min(1, 0.88 * C.rimBright)})`;
      S.lineWidth = 0.55;
      S.stroke();

      const arc = (r: number, lw: number, a: number) => {
        S.strokeStyle = `rgba(255,165,180,${a})`;
        S.lineWidth = lw;
        S.beginPath();
        S.arc(0, 0, r, -thV, thV);
        S.stroke();
      };
      arc(redR, 1.5, 1);
      arc(redR + RB + 3, 0.6, 0.6);
      arc(redRO - RB - 3, 0.6, 0.55);
      arc(redRO, 1.3, 0.95);
      S.restore();

      // Draw Red Attacker Nodes anchored along the outer rim of the Right Sphere
      const eng = engineRef.current;
      S.save();
      for (const rn of eng.redNodes.values()) {
        const a = rn.angleOnRedRing;
        const nx = redCx + Math.cos(a) * (redRO + 10);
        const ny = redCy + Math.sin(a) * (redRO + 10);
        const isLocked = eng.activeBans.has(rn.ip);

        S.beginPath();
        S.arc(nx, ny, isLocked ? 9 : 7 + Math.sin(T * 6) * 1.5, 0, TAU);
        S.strokeStyle = isLocked ? '#38bdf8' : '#ff3b5c';
        S.lineWidth = 2;
        S.stroke();

        S.fillStyle = isLocked ? '#38bdf8' : '#ffaa2b';
        S.fillRect(nx - 2.5, ny - 2.5, 5, 5);

        S.font = `700 8px ${FONT}`;
        S.textAlign = 'right';
        S.fillStyle = isLocked ? 'rgba(56, 189, 248, 0.95)' : 'rgba(255, 110, 130, 0.95)';
        S.fillText(
          isLocked ? `[LOCKED] ${rn.ip}` : `⚔ ${rn.ip} (${rn.lastTool})`,
          nx - 14,
          ny + 3
        );
      }
      S.textAlign = 'left';
      S.restore();
    }

    function drawBattleFX(ctx: CanvasRenderingContext2D) {
      const eng = engineRef.current;
      ctx.save();
      ctx.globalCompositeOperation = 'lighter';
      const midR = (R + RO) * 0.5;

      // 1. Blue Team nftables Shield Arcs on Left Sphere Outer Rim
      for (const b of eng.activeBans.values()) {
        ctx.beginPath();
        ctx.arc(cx, cy, RO * 1.04, b.angle - 0.11, b.angle + 0.11);
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.9)';
        ctx.lineWidth = 4.5;
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(cx, cy, RO * 1.08, b.angle - 0.08, b.angle + 0.08);
        ctx.strokeStyle = 'rgba(255, 59, 92, 0.75)';
        ctx.lineWidth = 1.6;
        ctx.stroke();

        const lx = cx + Math.cos(b.angle) * (RO + 16),
          ly = cy + Math.sin(b.angle) * (RO + 16);
        ctx.font = `700 8px ${FONT}`;
        ctx.fillStyle = 'rgba(56,189,248,.95)';
        ctx.fillText(`SHIELD BLOCK ${b.ip}`, lx + 6, ly + 3);
      }

      // 2. DeepSeek AI Neural Reasoning Arcs inside Blue Sphere
      for (const arc of eng.arcs) {
        const x1 = cx + Math.cos(arc.a1) * midR,
          y1 = cy + Math.sin(arc.a1) * midR;
        const x2 = cx + Math.cos(arc.a2) * midR,
          y2 = cy + Math.sin(arc.a2) * midR;
        ctx.beginPath();
        ctx.moveTo(x1, y1);
        ctx.quadraticCurveTo(cx + R * 0.35, cy, x2, y2);
        ctx.strokeStyle = `rgba(192, 132, 252, ${arc.life * 0.9})`;
        ctx.lineWidth = 2.2;
        ctx.stroke();
      }

      // 3. Cross-Screen Ballistic Trajectories (Red Sphere -> Blue Sphere) & Counter-Beams (Blue -> Red)
      for (const p of eng.projectiles) {
        if (p.mode === 'cross_strike') {
          if (p.progress < 0) continue;
          const startPt = {
            x: redCx + Math.cos(p.redAngle) * (redRO + 6),
            y: redCy + Math.sin(p.redAngle) * (redRO + 6),
          };
          const hitRadius = p.blocked ? RO * 1.05 : RO * 0.99;
          const endPt = {
            x: cx + Math.cos(p.blueAngle) * hitRadius,
            y: cy + Math.sin(p.blueAngle) * hitRadius,
          };
          const c1 = {
            x: startPt.x - (startPt.x - endPt.x) * 0.32,
            y: startPt.y + p.arcLift,
          };
          const c2 = {
            x: startPt.x - (startPt.x - endPt.x) * 0.68,
            y: endPt.y + p.arcLift * 0.65,
          };

          // Faint ballistic guide curve connecting the two spheres
          ctx.beginPath();
          ctx.moveTo(startPt.x, startPt.y);
          ctx.bezierCurveTo(c1.x, c1.y, c2.x, c2.y, endPt.x, endPt.y);
          ctx.strokeStyle = 'rgba(255, 59, 92, 0.16)';
          ctx.lineWidth = 1;
          ctx.stroke();

          // Glowing flying warhead trail segment
          const headT = Math.min(1, p.progress);
          const tailT = Math.max(0, p.progress - 0.28);
          const steps = 16;

          ctx.beginPath();
          for (let s = 0; s <= steps; s++) {
            const u = tailT + (headT - tailT) * (s / steps);
            const pt = evalCubicBezier(startPt, c1, c2, endPt, u);
            s === 0 ? ctx.moveTo(pt.x, pt.y) : ctx.lineTo(pt.x, pt.y);
          }
          ctx.strokeStyle = p.color;
          ctx.globalAlpha = 0.42;
          ctx.lineWidth = 7.5;
          ctx.stroke();

          ctx.globalAlpha = 0.98;
          ctx.lineWidth = 2.6;
          ctx.stroke();

          // Bright White Core at Warhead Tip + Telemetry Tag
          const headPt = evalCubicBezier(startPt, c1, c2, endPt, headT);
          ctx.fillStyle = '#ffffff';
          ctx.beginPath();
          ctx.arc(headPt.x, headPt.y, 3.6, 0, TAU);
          ctx.fill();

          if (p.label && headT > 0.12 && headT < 0.92) {
            ctx.font = `700 8px ${FONT}`;
            ctx.fillStyle = p.color;
            ctx.fillText(p.label, headPt.x - 24, headPt.y - 10);
          }
          ctx.globalAlpha = 1;
        } else if (p.mode === 'counter_beam') {
          const startPt = {
            x: cx + Math.cos(p.blueAngle) * (RO + 4),
            y: cy + Math.sin(p.blueAngle) * (RO + 4),
          };
          const endPt = {
            x: redCx + Math.cos(p.redAngle) * (redRO + 6),
            y: redCy + Math.sin(p.redAngle) * (redRO + 6),
          };
          const midX = (startPt.x + endPt.x) * 0.5;
          const midY = (startPt.y + endPt.y) * 0.5 - 38;

          ctx.beginPath();
          ctx.moveTo(startPt.x, startPt.y);
          ctx.quadraticCurveTo(midX, midY, endPt.x, endPt.y);
          ctx.strokeStyle = p.color;
          ctx.globalAlpha = p.life * 0.45;
          ctx.lineWidth = 14 * p.life;
          ctx.stroke();

          ctx.beginPath();
          ctx.moveTo(startPt.x, startPt.y);
          ctx.quadraticCurveTo(midX, midY, endPt.x, endPt.y);
          ctx.strokeStyle = '#ffffff';
          ctx.globalAlpha = p.life * 0.95;
          ctx.lineWidth = 3.2 * p.life;
          ctx.stroke();

          if (p.label) {
            ctx.font = `800 8.5px ${FONT}`;
            ctx.fillStyle = '#38bdf8';
            ctx.fillText(p.label, midX - 45, midY - 8);
          }
          ctx.globalAlpha = 1;
        }
      }

      // 4. Deflection / Impact Sparks & Shockwaves
      for (const s of eng.sparks) {
        const bx = cx + (Math.cos(s.angle) * s.rRatio + s.ox) * RO;
        const by = cy + (Math.sin(s.angle) * s.rRatio + s.oy) * RO;
        ctx.fillStyle = s.color;
        ctx.globalAlpha = s.life;
        ctx.fillRect(bx - 1.8, by - 1.8, 3.6, 3.6);
      }
      ctx.globalAlpha = 1;

      for (const w of eng.shockwaves) {
        if (w.camp === 'redNode') {
          const rx = redCx + Math.cos(w.redAngle) * (redRO + 10);
          const ry = redCy + Math.sin(w.redAngle) * (redRO + 10);
          ctx.beginPath();
          ctx.arc(rx, ry, w.rRatio * 55, 0, TAU);
          ctx.strokeStyle = w.color;
          ctx.globalAlpha = w.life * 0.85;
          ctx.lineWidth = 2.5;
          ctx.stroke();
        } else {
          ctx.beginPath();
          ctx.arc(cx, cy, RO * w.rRatio, -thS - 0.1, thS + 0.1);
          ctx.strokeStyle = w.color;
          ctx.globalAlpha = w.life * 0.7;
          ctx.lineWidth = 3;
          ctx.stroke();
        }
      }
      ctx.restore();
    }

    const cpt = (l: any, t: number) => {
      if (!l.arc) return qpt(l, t);
      const r = l.r + (R - 2 - l.r) * t * t,
        a = l.a0 + l.span * t;
      return { x: Math.cos(a) * r, y: Math.sin(a) * r };
    };

    function strokeComet(
      ctx: CanvasRenderingContext2D,
      c: any,
      t0: number,
      t1: number,
      steps: number
    ) {
      ctx.beginPath();
      for (const l of c.lines)
        for (let s = 0; s <= steps; s++) {
          const p = cpt(l, t0 + (t1 - t0) * (s / steps));
          s ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y);
        }
      ctx.stroke();
    }

    function drawStrands(Lr: any, collect: { dash: number[]; tip: number[] } | null) {
      const span = (W * 0.56 - RO) * 0.9,
        r0 = RO + 3,
        rRot = ringRot * Lr.rotK + Lr.off;
      S.lineCap = 'butt';
      for (const w of Lr.wedges) {
        if (!w.vis) continue;
        const L = w.len * span * Lr.lenK * C.beamLen;
        if (L < 3) continue;
        const a0 = normA(w.i0 * Lr.step + rRot),
          a1 = a0 + w.n * Lr.step;
        if (a1 < -thS - 0.03 || a0 > thS + 0.03) continue;
        const alpha = Math.min(
          1,
          w.lum *
            Lr.lumK *
            (0.3 + 0.7 * Math.min(1, w.len * 1.8)) *
            C.beamBright *
            (Lr.dyn === 'bounce' ? C.beamBounce : 1)
        );
        if (alpha < 0.005) continue;
        const lwW = Lr.lw * w.lwK * C.beamWidth;
        const paths = [new Path2D(), new Path2D(), new Path2D()];
        for (let k = 0; k < w.n; k++) {
          const a = a0 + (k + 0.5) * Lr.step,
            ca = Math.cos(a),
            sa = Math.sin(a);
          const edge = Math.sin((Math.PI * (k + 0.5)) / w.n),
            b = edge < 0.38 ? 0 : edge < 0.72 ? 1 : 2;
          const pr = w.prof[k];
          const l =
            L *
            pr *
            (0.5 + 0.5 * Math.sqrt(edge)) *
            (0.92 + 0.08 * Math.sin(T * w.pf[k] + w.pp[k]));
          const solid = l * (Lr.solidK + 0.3 * pr * (1 - Lr.solidK));
          paths[b].moveTo(cx + ca * r0, cy + sa * r0);
          paths[b].lineTo(cx + ca * (r0 + solid), cy + sa * (r0 + solid));
          if (!collect) continue;
          const tail = l - solid,
            da = alpha * EDGE_A[b];
          if (tail > 6)
            for (let d = 0; d < 2; d++) {
              const ph = (w.flow + w.ds[k] + d * 0.5) % 1;
              const s0 = solid + tail * ph,
                s1 = Math.min(l, s0 + 3 + tail * 0.22 * (1 - ph * 0.5));
              if (s1 > s0) collect.dash.push(ca, sa, s0, s1, da);
            }
          if ((k + ((T * 12) | 0)) % 4 === 0) collect.tip.push(ca, sa, l, da);
        }
        S.strokeStyle = GR['s' + w.tint];
        S.lineWidth = lwW;
        for (let b = 0; b < 3; b++) {
          S.globalAlpha = alpha * EDGE_A[b];
          S.stroke(paths[b]);
        }
        if (w.lum > 0.85 && C.beamGlow > 0) {
          S.globalAlpha = Math.min(1, alpha * 0.06 * C.beamGlow);
          S.lineWidth = lwW * 2.5;
          S.stroke(paths[2]);
        }
      }
      S.globalAlpha = 1;
    }

    function drawOuterFar() {
      const span = (W * 0.56 - RO) * 0.9,
        r0 = RO + 3;
      S.save();
      S.globalCompositeOperation = 'lighter';
      for (const h of hazes) {
        const a0 = normA(h.a + ringRot) - h.w / 2,
          a1 = a0 + h.w;
        if (a1 < -thS || a0 > thS) continue;
        const fade =
          Math.min(1, h.age / 0.22) *
          (h.age > h.life ? Math.max(0, 1 - (h.age - h.life) / 0.55) : 1);
        const al = h.alpha * fade * (0.55 + 0.55 * env) * C.hazeBright;
        if (al < 0.004) continue;
        const r1 = RO + Math.max(24, h.cur * span * C.beamLen),
          g = S.createRadialGradient(cx, cy, RO, cx, cy, r1);
        const col =
          h.tint === 1 ? '185,172,240' : h.tint === 2 ? '152,224,207' : '135,206,250';
        g.addColorStop(0, `rgba(${col},${Math.min(1, al)})`);
        g.addColorStop(0.55, `rgba(${col},${Math.min(1, al * 0.4)})`);
        g.addColorStop(1, `rgba(${col},0)`);
        S.fillStyle = g;
        S.beginPath();
        S.arc(cx, cy, r1, a0, a1);
        S.arc(cx, cy, RO + 2, a1, a0, true);
        S.closePath();
        S.fill();
      }
      drawStrands(strandLayers[0], null);
      drawStrands(strandLayers[1], null);
      for (let t = 0; t < 2; t++) {
        S.strokeStyle = t ? GR.s1 : GR.s0;
        for (let lv = 0; lv < 3; lv++) {
          const al = Math.min(1, FLY_A[lv] * C.flyerBright);
          if (al < 0.004) continue;
          S.globalAlpha = al;
          S.lineWidth = (lv === 2 ? 1.25 : 0.85) * C.beamWidth;
          S.beginPath();
          for (const f of flyers) {
            if (f.tint !== t || f.lv !== lv) continue;
            const a = normA(f.a + ringRot);
            if (Math.abs(a) > thS) continue;
            const ca = Math.cos(a),
              sa = Math.sin(a),
              ra = Math.max(r0, f.r - f.len),
              rb = Math.max(r0, f.r);
            if (rb > ra) {
              S.moveTo(cx + ca * ra, cy + sa * ra);
              S.lineTo(cx + ca * rb, cy + sa * rb);
            }
          }
          S.stroke();
        }
      }
      S.restore();
    }

    function drawOuterNear() {
      const r0 = RO + 3,
        G = glowC.x;
      S.save();
      S.globalCompositeOperation = 'lighter';
      const extra = { dash: [] as number[], tip: [] as number[] };
      drawStrands(strandLayers[2], extra);
      drawStrands(strandLayers[3], null);
      drawStrands(strandLayers[4], extra);

      const D = extra.dash;
      S.strokeStyle = 'rgba(220,242,255,1)';
      S.lineWidth = 0.85 * C.beamWidth;
      for (let b = 0; b < 3; b++) {
        const lo = b * 0.3,
          hi = b === 2 ? 9 : (b + 1) * 0.3;
        S.globalAlpha = (b + 1) * 0.24;
        S.beginPath();
        for (let i = 0; i < D.length; i += 5) {
          const a = D[i + 4];
          if (a < lo || a >= hi) continue;
          const ca = D[i],
            sa = D[i + 1];
          S.moveTo(cx + ca * (r0 + D[i + 2]), cy + sa * (r0 + D[i + 2]));
          S.lineTo(cx + ca * (r0 + D[i + 3]), cy + sa * (r0 + D[i + 3]));
        }
        S.stroke();
      }
      const P = extra.tip;
      S.fillStyle = '#e8f4ff';
      S.globalAlpha = 0.7;
      S.beginPath();
      for (let i = 0; i < P.length; i += 4) {
        if (P[i + 3] < 0.2) continue;
        const r = r0 + P[i + 2];
        S.rect(cx + P[i] * r - 0.8, cy + P[i + 1] * r - 0.8, 1.6, 1.6);
      }
      S.fill();

      for (const f of flares) {
        const a0 = normA(f.a + ringRot) - f.w / 2,
          a1 = a0 + f.w;
        if (a1 < -thS || a0 > thS) continue;
        const p = f.age / f.life,
          al = Math.sin(p * Math.PI) * f.alpha * C.flareBright;
        if (al < 0.01) continue;
        const r1 = RO + 3 + f.len * easeO(p);
        S.fillStyle = `rgba(225,245,255,${Math.min(1, al * 0.65)})`;
        S.beginPath();
        S.arc(cx, cy, r1, a0, a1);
        S.arc(cx, cy, RO + 1.5, a1, a0, true);
        S.closePath();
        S.fill();
        G.fillStyle = `rgba(135,206,250,${Math.min(1, al * 0.6)})`;
        G.beginPath();
        G.arc(cx, cy, r1 + 12, a0 - 0.008, a1 + 0.008);
        G.arc(cx, cy, RO, a1 + 0.008, a0 - 0.008, true);
        G.closePath();
        G.fill();
      }
      S.restore();
    }

    function drawRing(dt: number) {
      const band = RO - R;
      S.save();
      S.translate(cx, cy);
      S.beginPath();
      S.arc(0, 0, RO, -thV - 0.1, thV + 0.1);
      S.arc(0, 0, R, thV + 0.1, -thV - 0.1, true);
      S.fillStyle = '#07080a';
      S.fill();
      let regen = 4;
      for (const s of slots) {
        s.flash *= Math.exp(-dt * 4);
        const A = normA(s.a + ringRot);
        if (Math.abs(A) > thV + s.da) continue;
        if (!s.c && regen > 0) {
          renderSlot(s, false);
          regen--;
        }
        if (!s.c) continue;
        S.save();
        S.rotate(A);
        const hh = s.hpx + 2;
        S.drawImage(s.c, R, -hh / 2, band, hh);
        if (s.flash > 0.02) {
          S.globalCompositeOperation = 'lighter';
          S.globalAlpha = s.flash;
          S.drawImage(s.c, R, -hh / 2, band, hh);
          S.globalAlpha = 1;
          S.globalCompositeOperation = 'source-over';
        }
        S.restore();
      }
      const tick = (step: number, fn: (ca: number, sa: number, n: number) => void) => {
        const n0 = Math.floor((-thV - 0.05 - ringRot) / step),
          n1 = Math.ceil((thV + 0.05 - ringRot) / step);
        for (let n = n0; n <= n1; n++) {
          const a = n * step + ringRot;
          fn(Math.cos(a), Math.sin(a), n);
        }
      };
      const RB = rimW();
      S.beginPath();
      tick(((0.14 / C.rimDensity) * Math.PI) / 180, (ca, sa, n) => {
        const m = ((n % 6) + 6) % 6,
          li = m === 0 ? RB : RB * (0.5 + 0.35 * hash(n)),
          lo = m === 0 ? RB : RB * (0.5 + 0.35 * hash(n + 77));
        S.moveTo(ca * (R + 1.5), sa * (R + 1.5));
        S.lineTo(ca * (R + 1.5 + li), sa * (R + 1.5 + li));
        S.moveTo(ca * (RO - 1.5), sa * (RO - 1.5));
        S.lineTo(ca * (RO - 1.5 - lo), sa * (RO - 1.5 - lo));
      });
      S.globalCompositeOperation = 'lighter';
      S.strokeStyle = `rgba(56,189,248,${Math.min(1, 0.05 * C.rimBright * C.rimBright)})`;
      S.lineWidth = 1.2 + 2.4 * C.rimBright;
      S.stroke();
      S.globalCompositeOperation = 'source-over';
      S.strokeStyle = `rgba(210,235,252,${Math.min(1, 0.88 * C.rimBright)})`;
      S.lineWidth = 0.55;
      S.stroke();
      const arc = (r: number, lw: number, a: number) => {
        S.strokeStyle = `rgba(180,225,250,${a})`;
        S.lineWidth = lw;
        S.beginPath();
        S.arc(0, 0, r, -thV, thV);
        S.stroke();
      };
      arc(R, 1.5, 1);
      arc(R + RB + 3, 0.6, 0.6);
      arc(RO - RB - 3, 0.6, 0.55);
      arc(RO, 1.3, 0.95);
      S.restore();
    }

    let lastCalloutKey = '';
    function drawCallout() {
      const ft = engineRef.current.focusTarget;
      const a = ft.angle;
      const anchor = toScreen(cx + Math.cos(a) * (RO + 18), cy + Math.sin(a) * (RO + 18));
      const rawBx = cx + Math.cos(a) * (RO + 16) + 28;
      const rawBy = cy + Math.sin(a) * (RO + 16) - 36;
      const bx = Math.round(Math.min(W * 0.45, Math.max(16, rawBx)));
      const minTopY = 72;
      const by = Math.round(Math.min(H - 68, Math.max(minTopY, rawBy)));
      const nextKey = `${bx},${by},${ft.cls},${ft.kind},${ft.text}`;
      if (nextKey !== lastCalloutKey && chkRef.current && chkKRef.current && chkVRef.current) {
        lastCalloutKey = nextKey;
        chkRef.current.style.transform = `translate(${bx}px,${by}px)`;
        chkRef.current.className = `ov chk ${ft.cls || ''}`;
        chkKRef.current.textContent = ft.kind;
        chkVRef.current.textContent = ft.text;
      }

      S.save();
      S.setTransform(DPR, 0, 0, DPR, 0, 0);
      S.strokeStyle =
        ft.cls === 'ban'
          ? 'rgba(56,189,248,.75)'
          : ft.cls === 'ai'
            ? 'rgba(192,132,252,.75)'
            : ft.cls === 'alert'
              ? 'rgba(255,59,92,.75)'
              : 'rgba(230,233,238,.55)';
      S.lineWidth = 1;
      S.beginPath();
      S.moveTo(anchor.x, anchor.y);
      S.lineTo(bx, by + 14);
      S.stroke();
      S.fillStyle = '#fff';
      S.fillRect(anchor.x - 2, anchor.y - 2, 4, 4);
      S.restore();
    }

    function drawStage(dt: number) {
      const eng = engineRef.current;
      const isV1 = eng.viewVersion === 'v1';
      if (isV1) updateBeat(dt);
      updateCam();
      if (isV1) updateOuter(dt);
      updateBattleFX(dt);
      if (rnd() < dt * C.cometTrickle) {
        spawnComet();
        spawnRedComet();
      }
      // Static dual-orb: no ring/web rotation.
      webRot = 0;
      ringRot = 0;
      redRingRot = 0;

      S.setTransform(DPR, 0, 0, DPR, 0, 0);
      S.globalCompositeOperation = 'source-over';
      S.globalAlpha = 1;
      S.fillStyle = '#08090b';
      S.fillRect(0, 0, W, H);

      const G = glowC.x;
      G.setTransform(1, 0, 0, 1, 0, 0);
      G.clearRect(0, 0, glowC.width, glowC.height);
      camT(G, 1 / GS);
      G.globalCompositeOperation = 'lighter';

      const ws = 2 * R + 4;
      const surge = 0.5 + 2.5 * env;
      const isDanger = eng.threatEnergy > 0.35,
        isAi = eng.aiEnergy > 0.25;

      // ====================================================================
      // 1. STATIC BLUE / RED SPHERE BASES (no synthetic particles)
      // ====================================================================
      camTk(S, DPR, 1 - 0.1 * C.parallax);
      S.save();
      S.translate(cx, cy);
      S.drawImage(webBase, -R - 2, -R - 2, ws, ws);
      S.restore();
      S.save();
      S.translate(redCx, redCy);
      S.scale(-1, 1);
      S.drawImage(redWebBase, -R - 2, -R - 2, ws, ws);
      S.restore();

      // ====================================================================
      // 2. INNER RING SHADOWS & MULTI-FILAMENT COMETS (BOTH SPHERES!)
      // ====================================================================
      camT(S, DPR);
      if (C.ringShadow > 0) {
        // Left Blue Sphere Inner Shadow
        const sg = S.createRadialGradient(cx, cy, R - 110, cx, cy, R);
        sg.addColorStop(0, 'rgba(4,5,6,0)');
        sg.addColorStop(1, `rgba(4,5,6,${Math.min(1, 0.8 * C.ringShadow)})`);
        S.globalCompositeOperation = 'source-over';
        S.globalAlpha = 1;
        S.fillStyle = sg;
        S.beginPath();
        S.arc(cx, cy, R, 0, TAU);
        S.arc(cx, cy, R - 110, 0, TAU, true);
        S.fill('evenodd');

        // Right Red Sphere Inner Shadow
        const rsg = S.createRadialGradient(redCx, redCy, redR - 110, redCx, redCy, redR);
        rsg.addColorStop(0, 'rgba(6,4,5,0)');
        rsg.addColorStop(1, `rgba(6,4,5,${Math.min(1, 0.8 * C.ringShadow)})`);
        S.fillStyle = rsg;
        S.beginPath();
        S.arc(redCx, redCy, redR, 0, TAU);
        S.arc(redCx, redCy, redR - 110, 0, TAU, true);
        S.fill('evenodd');
      }

      // Left Sphere Comets (Blue/Cyan/White)
      S.save();
      S.translate(cx, cy);
      S.globalCompositeOperation = 'lighter';
      S.lineCap = 'round';
      G.save();
      G.translate(cx, cy);
      for (let i = comets.length - 1; i >= 0; i--) {
        const c = comets[i];
        c.life += dt;
        const p = easeIO(Math.min(1, c.life / c.dur));
        const head = Math.min(1, p * (1 + c.win)),
          tail = Math.max(0, p * (1 + c.win) - c.win);
        const fade = c.life > c.dur ? Math.max(0, 1 - (c.life - c.dur) / 0.25) : 1;
        if (fade <= 0) {
          comets.splice(i, 1);
          continue;
        }
        const cr = C.cometFollow ? ringRot - c.rot0 : 0;
        if (head >= 1 && !c.hit) {
          c.hit = true;
          const pe = cpt(c.lines[c.lines.length >> 1], 1);
          flashSlotAt(Math.atan2(pe.y, pe.x) + cr);
        }
        S.save();
        S.rotate(cr);
        G.save();
        G.rotate(cr);
        const col =
          eng.aiEnergy > 0.3 ? '192,132,252' : c.tint ? '56,189,248' : '255,255,255';
        S.strokeStyle = `rgba(${col},${Math.min(1, 0.5 * fade * C.cometBright)})`;
        S.lineWidth = 1;
        strokeComet(S, c, tail, head, 8);
        const hs = head - (head - tail) * 0.35;
        S.strokeStyle = `rgba(${col},${Math.min(1, fade * C.cometBright)})`;
        S.lineWidth = 1.7;
        strokeComet(S, c, hs, head, 5);
        if (c.glow && C.cometGlow > 0) {
          G.strokeStyle = `rgba(${col},${Math.min(1, 0.5 * fade * C.cometGlow)})`;
          G.lineWidth = 2.8;
          strokeComet(G, c, hs, head, 4);
        }
        G.restore();
        S.restore();
      }
      G.restore();
      S.restore();

      // Right Sphere Comets (Crimson/Amber/Rose-White — Mirrored Symmetrically!)
      S.save();
      S.translate(redCx, redCy);
      S.scale(-1, 1);
      S.globalCompositeOperation = 'lighter';
      S.lineCap = 'round';
      G.save();
      G.translate(redCx, redCy);
      G.scale(-1, 1);
      for (let i = redComets.length - 1; i >= 0; i--) {
        const c = redComets[i];
        c.life += dt;
        const p = easeIO(Math.min(1, c.life / c.dur));
        const head = Math.min(1, p * (1 + c.win)),
          tail = Math.max(0, p * (1 + c.win) - c.win);
        const fade = c.life > c.dur ? Math.max(0, 1 - (c.life - c.dur) / 0.25) : 1;
        if (fade <= 0) {
          redComets.splice(i, 1);
          continue;
        }
        const cr = C.cometFollow ? redRingRot - c.rot0 : 0;
        if (head >= 1 && !c.hit) {
          c.hit = true;
          const pe = cpt(c.lines[c.lines.length >> 1], 1);
          flashRedSlotAt(Math.atan2(pe.y, pe.x) + cr);
        }
        S.save();
        S.rotate(cr);
        G.save();
        G.rotate(cr);
        const col = c.tint ? '255,59,92' : '255,215,222';
        S.strokeStyle = `rgba(${col},${Math.min(1, 0.55 * fade * C.cometBright)})`;
        S.lineWidth = 1;
        strokeComet(S, c, tail, head, 8);
        const hs = head - (head - tail) * 0.35;
        S.strokeStyle = `rgba(255,240,245,${Math.min(1, fade * C.cometBright)})`;
        S.lineWidth = 1.7;
        strokeComet(S, c, hs, head, 5);
        if (c.glow && C.cometGlow > 0) {
          G.strokeStyle = `rgba(255,59,92,${Math.min(1, 0.55 * fade * C.cometGlow)})`;
          G.lineWidth = 2.8;
          strokeComet(G, c, hs, head, 4);
        }
        G.restore();
        S.restore();
      }
      G.restore();
      S.restore();

      // ====================================================================
      // 3. OUTER RADIATING BEAMS (Only in Legacy V1; Removed in V2 per Image 2)
      // ====================================================================
      if (isV1) {
        S.globalCompositeOperation = 'lighter';
        S.drawImage(laneC, 0, 0, W, H);
        const F = farC.x;
        F.setTransform(1, 0, 0, 1, 0, 0);
        F.globalAlpha = 1;
        F.globalCompositeOperation = 'source-over';
        F.clearRect(0, 0, farC.width, farC.height);
        camT(F, FS);
        F.globalCompositeOperation = 'lighter';
        S = F;
        drawOuterFar();
        S = S_MAIN;
        S.save();
        S.setTransform(DPR, 0, 0, DPR, 0, 0);
        S.globalCompositeOperation = 'lighter';
        if (HAS_FILTER && C.depthBlur > 0) S.filter = `blur(${C.depthBlur}px)`;
        S.globalAlpha = Math.min(1, C.depthDim);
        S.drawImage(farC, 0, 0, W, H);
        S.restore();
        drawOuterNear();
      }

      // ====================================================================
      // 4. SYMMETRICAL LEFT (BLUE) & RIGHT (RED) 48-SECTOR RINGS + CROSS-STAGE FX
      // ====================================================================
      camT(S, DPR);
      drawRing(dt);
      drawRedRing(dt);
      drawBattleFX(S);

      S.setTransform(DPR, 0, 0, DPR, 0, 0);
      S.globalCompositeOperation = 'lighter';
      S.globalAlpha = Math.min(1, 0.9 * C.glow);
      S.drawImage(glowC, 0, 0, glowC.width * GS, glowC.height * GS);
      S.globalAlpha = 1;
      S.globalCompositeOperation = 'source-over';

      if (C.vignette > 0) {
        const vg = S.createRadialGradient(
          W * 0.5,
          H * 0.5,
          Math.min(W, H) * 0.35,
          W * 0.5,
          H * 0.5,
          Math.hypot(W, H) * 0.62
        );
        vg.addColorStop(0, 'rgba(0,0,0,0)');
        vg.addColorStop(1, `rgba(0,0,0,${Math.min(1, 0.75 * C.vignette)})`);
        S.fillStyle = vg;
        S.fillRect(0, 0, W, H);
      }
      drawCallout();
    }

    function drawAdv(dt: number) {
      if (!cAdv) return;
      const info = pSizes.get(cAdv);
      if (!info) return;
      const { x, w, h } = info;
      const eng = engineRef.current;
      x.fillStyle = 'rgba(14,15,18,0.24)';
      x.fillRect(0, 0, w, h);
      x.strokeStyle =
        eng.banEnergy > 0.2
          ? 'rgba(56,189,248,.85)'
          : eng.threatEnergy > 0.35
            ? 'rgba(255,59,92,.85)'
            : 'rgba(235,238,244,.7)';
      x.lineWidth = 0.85;
      x.beginPath();
      const spd = 22 * (1 + eng.threatEnergy * 1.4);
      const flow = (px: number, py: number) =>
        Math.sin(px * 0.035 + T * (0.6 + eng.threatEnergy * 1.6)) *
          Math.cos(py * 0.05 - T * 0.4) *
          Math.PI +
        Math.sin((px + py) * 0.01 + T * 0.2);

      for (const p of advP) {
        const a = flow(p.x, p.y),
          nx = p.x + Math.cos(a) * spd * dt,
          ny = p.y + Math.sin(a) * spd * dt;
        x.moveTo(p.x, p.y);
        x.lineTo(nx + Math.cos(a) * 2, ny + Math.sin(a) * 2);
        p.x = nx;
        p.y = ny;
        p.l -= dt;
        if (p.l < 0 || p.x < 0 || p.x > w || p.y < 0 || p.y > h) {
          p.x = rnd() * w;
          p.y = rnd() * h;
          p.l = rr(1, 4);
        }
      }
      x.stroke();
    }

    function drawDiff() {
      if (!cDiff) return;
      const info = pSizes.get(cDiff);
      if (!info) return;
      const { x, w, h } = info;
      const eng = engineRef.current;
      x.clearRect(0, 0, w, h);
      x.font = `600 7px ${FONT}`;
      x.textBaseline = 'top';
      eng.anomSpike *= 0.94;
      const gap = 8,
        mw = (w - gap) / 2,
        mh = h * 0.68,
        cols = 22,
        rows = 12,
        cw = mw / cols,
        ch = (mh - 10) / rows;
      const hist = new Array(28).fill(0);
      for (let m = 0; m < 2; m++) {
        const ox = m * (mw + gap);
        x.fillStyle = '#6b6f78';
        x.fillText(m ? 'RED TRAFFIC' : 'BLUE BASELINE', ox, 0);
        for (let j = 0; j < rows; j++)
          for (let i = 0; i < cols; i++) {
            let v =
              0.35 +
              0.2 * Math.sin(i * 0.45 + T * 0.8) * Math.cos(j * 0.5 - T * 0.5);
            let err = 0;
            if (m) {
              const dx = i - 14 - Math.sin(T * 1.1) * 4,
                dy = j - 5;
              err =
                Math.exp(-(dx * dx + dy * dy) / 7) *
                (0.2 + eng.anomSpike * 0.9 + eng.threatEnergy * 0.6);
              v += err * 0.4;
              hist[Math.min(27, (err * 27) | 0)]++;
            }
            const g = Math.max(0, Math.min(255, v * 190 + 20)) | 0;
            x.fillStyle =
              err > 0.35
                ? `rgba(255,59,92,${0.45 + err * 0.55})`
                : `rgb(${g},${g},${g + 4})`;
            x.fillRect(ox + i * cw, 10 + j * ch, cw - 0.6, ch - 0.6);
          }
      }
      const by = mh + 4,
        bh = h - by,
        bw = w / hist.length,
        mx = Math.max(...hist.slice(1), 1);
      hist.forEach((v, i) => {
        const hh = i === 0 ? bh * 0.85 : (v / mx) * bh * 0.8 + 1;
        x.fillStyle = i > 9 ? '#ff3b5c' : '#8a8e97';
        x.fillRect(i * bw, by + bh - hh, bw - 1, hh);
      });
    }

    function drawVal() {
      if (!cVal) return;
      const info = pSizes.get(cVal);
      if (!info) return;
      const { x, w, h } = info;
      const eng = engineRef.current;
      x.clearRect(0, 0, w, h);
      const lx = 48,
        gw = w - lx - 4,
        rh = h / 3;
      const N = Math.max(20, Math.floor(gw / 2));
      eng.threatWave = Math.max(0.05, eng.threatWave * 0.96);
      eng.dropWave = Math.max(0.02, eng.dropWave * 0.96);
      const epsNorm = Math.min(0.45, eng.epsWindow.length / 25);
      const samples = [
        Math.sin(T * 2.2) * 0.12 + epsNorm + (rnd() - 0.5) * 0.05,
        (eng.threatWave - 0.3) * 0.8 + Math.sin(T * 3.5) * 0.06,
        (eng.dropWave - 0.25) * 0.85 + Math.cos(T * 1.8) * 0.04,
      ];
      const names = ['EPS', 'THREAT', 'DROP'];
      const colors = ['#d8dbe2', '#ff3b5c', '#38bdf8'];
      x.font = `600 7px ${FONT}`;
      x.textBaseline = 'middle';
      for (let k = 0; k < 3; k++) {
        const b = valBuf[k];
        if (!b) continue;
        b.push(Math.max(-0.45, Math.min(0.45, samples[k])));
        while (b.length > N) b.shift();
        const cy_ = rh * (k + 0.5);
        x.fillStyle = '#6b6f78';
        x.fillText(names[k], 0, cy_);
        x.strokeStyle = '#1f2228';
        x.lineWidth = 1;
        x.beginPath();
        x.moveTo(lx, cy_);
        x.lineTo(w, cy_);
        x.stroke();
        x.beginPath();
        b.forEach((v, i) => {
          const px = lx + (i / (N - 1)) * gw,
            py = cy_ - v * rh * 0.85;
          i ? x.lineTo(px, py) : x.moveTo(px, py);
        });
        x.strokeStyle = colors[k];
        x.lineWidth = 1.25;
        x.stroke();
      }
    }

    function drawIdx() {
      if (!cIdx) return;
      const info = pSizes.get(cIdx);
      if (!info) return;
      const { x, w, h } = info;
      const eng = engineRef.current;
      x.clearRect(0, 0, w, h);
      const lx = 50,
        rx = 28,
        mw = w - lx - rx,
        rows = RULE_ROWS.length,
        cols = 24;
      const ch = h / rows,
        cw = mw / cols,
        scan = Math.floor(T * 5) % cols;
      x.font = `600 6.5px ${FONT}`;
      x.textBaseline = 'middle';
      for (let j = 0; j < rows; j++) {
        x.fillStyle = '#8b909a';
        x.fillText(RULE_ROWS[j], 0, j * ch + ch / 2);
        let hits = 0;
        for (let i = 0; i < cols; i++) {
          eng.ruleHits[j][i] = Math.max(0.08, eng.ruleHits[j][i] - 0.002);
          const v = eng.ruleHits[j][i];
          if (v > 0.45) hits++;
          x.fillStyle =
            v > 0.7
              ? '#ff3b5c'
              : v > 0.4
                ? '#38bdf8'
                : v > 0.2
                  ? '#4a4e56'
                  : '#1c1e23';
          if (i === scan) x.fillStyle = v > 0.3 ? '#ffffff' : '#32363e';
          x.fillRect(lx + i * cw, j * ch + 1, cw - 1, ch - 2);
        }
        x.fillStyle = hits > 0 ? '#ff3b5c' : '#6b6f78';
        x.fillText(hits > 0 ? 'HIT' : 'IDLE', w - rx + 4, j * ch + ch / 2);
      }
    }

    function resizeAll() {
      const r = stage!.getBoundingClientRect();
      if (r.width < 20 || r.height < 20) return;
      DPR = 1;
      resizeStage();
      resizePanels();
    }

    resizeAll();

    let rzTimer: number | null = null;
    const ro = new ResizeObserver(() => {
      if (rzTimer) clearTimeout(rzTimer);
      rzTimer = window.setTimeout(resizeAll, 120);
    });
    ro.observe(stageWrap);

    let loopTimer = 0;
    let disposed = false;
    let last = performance.now();
    function frame(now: number) {
      if (disposed) return;
      const q = engineRef.current.rebuildQueue;
      if (q.size > 0) {
        if (q.has('resize')) {
          resizeAll();
        } else {
          if (q.has('web')) buildWeb();
          if (q.has('slots')) {
            slots.forEach((s) => (s.c = null));
            redSlots.forEach((s) => (s.c = null));
          }
          if (q.has('flyers')) initFlyers();
        }
        q.clear();
      }

      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      T += dt;
      if (W > 20 && H > 20) {
        drawStage(dt);
        if (engineRef.current.viewVersion === 'v1') {
          drawAdv(dt);
          drawDiff();
          drawVal();
          drawIdx();
        }
      }
      loopTimer = window.setTimeout(() => {
        if (!disposed) frame(performance.now());
      }, 32);
    }
    loopTimer = window.setTimeout(() => frame(performance.now()), 16);

    return () => {
      disposed = true;
      clearTimeout(loopTimer);
      ro.disconnect();
      if (rzTimer) clearTimeout(rzTimer);
    };
  }, []);

  const handleParamChange = (
    key: string,
    val: number,
    rebuild?: HaloParamDef['rebuild']
  ) => {
    engineRef.current.C[key] = val;
    if (key === 'scan') {
      document.body.classList.toggle('noscan', !val);
    }
    if (rebuild) {
      engineRef.current.rebuildQueue.add(rebuild);
    }
    setParamValues((prev) => ({ ...prev, [key]: val }));
  };

  const handleResetParams = () => {
    Object.assign(engineRef.current.C, BAKED_MINE);
    document.body.classList.remove('noscan');
    engineRef.current.rebuildQueue.add('resize');
    setParamValues({ ...BAKED_MINE });
  };

  const toggleMode = () => {
    if (mode === 'live') {
      engineRef.current.mode = 'demo';
      setModeState('demo');
    } else {
      enterLive();
    }
  };

  const toggleViewVersion = () => {
    const next = viewVersion === 'v2' ? 'v1' : 'v2';
    engineRef.current.viewVersion = next;
    setViewVersion(next);
    window.setTimeout(() => {
      engineRef.current.rebuildQueue.add('resize');
    }, 30);
  };

  const nowMs = Date.now();
  const redOps = combatOps.filter((o) => o.actorCamp === 'red').slice(-3).reverse();

  return (
    <div className="app">
      <header className="nw-header">
        <div className="brand">
          <h1>
            NIGHTWATCH <span>//</span> RED vs BLUE
          </h1>
          <p>BLUE BASTION (SURICATA · MODSEC · NFT) ⇄ RED STRIKE (KALI MATRIX)</p>
        </div>

        <div className="kpi">
          <div className="k">BLUE BASTION HP</div>
          <div className="v cyan" id="kEvents">
            {blueHp.toLocaleString()} HP
          </div>
          <div className="seg">
            <i
              id="sEvents"
              style={{
                width: `${Math.round((blueHp / MAX_CAMP_HP) * 100)}%`,
                background: 'var(--cyan)',
              }}
            />
          </div>
        </div>

        <div className="kpi">
          <div className="k">RED STRIKE HP</div>
          <div className="v red" id="kBans">
            {redHp.toLocaleString()} HP
          </div>
          <div className="seg">
            <i
              id="sBans"
              style={{
                width: `${Math.round((redHp / MAX_CAMP_HP) * 100)}%`,
                background: 'var(--red)',
              }}
            />
          </div>
        </div>

        <div className="kpi">
          <div className="k">DEFCON LEVEL</div>
          <div
            className={`v ${
              defcon === 'DEFCON 1' ? 'red' : defcon === 'DEFCON 2' ? 'pink' : 'teal'
            }`}
            id="kDefcon"
          >
            {defcon}
          </div>
          <div className="seg">
            <i
              id="sDefcon"
              style={{
                width: `${
                  defcon === 'DEFCON 1' ? 100 : defcon === 'DEFCON 2' ? 66 : 33
                }%`,
              }}
            />
          </div>
        </div>

        <div className="kpi">
          <div className="k">ACTIVE BANS (NFT)</div>
          <div className="v teal" id="kChain">
            {activeBansList.length} LOCKED
          </div>
          <div className="seg">
            <i
              id="sChain"
              style={{ width: `${Math.min(100, activeBansList.length * 25 + 15)}%` }}
            />
          </div>
        </div>

        <div className="kpi">
          <div className="k">AI AUTONOMY</div>
          <div className="v pink" id="kAi">
            {autonomy.toUpperCase()} · {autopilot ? 'ON' : 'OFF'}
          </div>
          <div className="seg">
            <i id="sAi" style={{ width: autopilot ? '90%' : '25%' }} />
          </div>
        </div>
      </header>

      <main className="stage" id="stageWrap" ref={stageWrapRef}>
        <canvas id="stage" ref={stageRef} data-testid="haloflux-stage" />

        {/* Left Camp HUD: Blue Team Bastion */}
        <div
          className="camp-hud blue"
          onClick={() => setHostModalOpen(true)}
          role="button"
          tabIndex={0}
          title="点击配置蓝方防守电脑 IP"
        >
          <div className="camp-tag">🛡️ {hostConfig.blueHostName}</div>
          <div className="camp-ip">{hostConfig.blueHostIp}</div>
          <div className="camp-sub">
            HP: {blueHp.toLocaleString()} · BLOCKS: {blueBlocksCount}
          </div>
        </div>

        {/* Top-Right Tactical Controls */}
        <div className="ov topbar">
          <button
            type="button"
            className="pill on"
            id="versionSwitchBtn"
            onClick={toggleViewVersion}
            title="在「V2 对称双球血量版」与保留的「V1 经典八栏版」之间切换"
          >
            {viewVersion === 'v2' ? '◧ 视图: 双球对决 V2' : '◧ 视图: 经典八栏 V1'}
          </button>

          <button
            type="button"
            className={`pill ${mode === 'live' ? 'live' : 'demo'}`}
            id="modeBadge"
            title="点击切换 LIVE SSE / 离线演示"
            onClick={toggleMode}
          >
            {mode === 'live' ? '● LIVE SQLITE' : '● DEMO REPLAY'}
          </button>

          <button
            type="button"
            className="pill on"
            id="hostLinkBtn"
            onClick={() => setHostModalOpen(true)}
            title="配置红蓝双方电脑 IP 与发射打击"
          >
            ⇄ 双方电脑接入
          </button>

          <button
            type="button"
            className={`pill ${sfxOn ? 'on' : ''}`}
            id="sfxBtn"
            title="开关战术合成音效 (S 键)"
            onClick={() => setSfxOn(SFX.toggle())}
          >
            {sfxOn ? 'SFX ON' : 'SFX OFF'}
          </button>

          <div className={`music ${bgmOn ? 'on' : ''}`} id="bgm">
            <button
              type="button"
              className="mbtn"
              id="bgmBtn"
              title="开/关背景音乐（M 键）"
              onClick={() => setBgmOn(SFX.toggleBgm())}
            >
              <i className="eq">
                <b />
                <b />
                <b />
              </i>
              <em id="bgmTxt">{bgmOn ? 'BGM ON' : 'BGM OFF'}</em>
            </button>
            <input
              type="range"
              id="bgmVol"
              min={0}
              max={100}
              step={1}
              value={bgmVol}
              aria-label="背景音乐音量"
              title="音量"
              onChange={(e) => {
                const v = Number(e.target.value);
                setBgmVol(v);
                SFX.setBgmVolume(v);
              }}
            />
            <span className="mval" id="bgmVal">
              {bgmVol}
            </span>
          </div>

          <button
            type="button"
            className={`pill console ${consoleOpen ? 'on' : ''}`}
            onClick={() => setConsoleOpen((v) => !v)}
          >
            ◱ CONSOLE
          </button>

          <button
            type="button"
            className="pill"
            onClick={() => setBridgeModalOpen(true)}
            title="查看/导出 scripts/web_bridge.py 与 nightwatch-halo.html"
          >
            ⤓ BRIDGE / EXPORT
          </button>

          <button
            type="button"
            className="pill on"
            id="downloadProjectZipBtn"
            onClick={async () => {
              try {
                const res = await fetch('/api/download-project.zip');
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'nightwatch-haloflux-v2.zip';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
              } catch {
                const a = document.createElement('a');
                a.href = '/api/download-project.zip';
                a.download = 'nightwatch-haloflux-v2.zip';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
              }
            }}
            title="一键打包下载完整项目工程 (nightwatch-haloflux-v2.zip)"
          >
            ⬇ 一键下载项目ZIP
          </button>
        </div>

        <div className="ov simbar" id="simBar">
          <button
            type="button"
            className="atk"
            data-sim="sqli"
            onClick={() => runScenario('sqli')}
          >
            SQLi 注入
          </button>
          <button
            type="button"
            className="atk"
            data-sim="syn"
            onClick={() => runScenario('syn')}
          >
            SYN Flood
          </button>
          <button
            type="button"
            className="atk"
            data-sim="honeypot"
            onClick={() => runScenario('honeypot')}
          >
            /admin 蜜罐
          </button>
          <button
            type="button"
            className="atk"
            data-sim="brute"
            onClick={() => runScenario('brute')}
          >
            暴力登录 ×5
          </button>
          <button
            type="button"
            className="ai"
            data-sim="ai"
            onClick={() => runScenario('ai')}
          >
            DeepSeek 关联研判
          </button>
          <button
            type="button"
            className="def"
            data-sim="unban_all"
            onClick={() => runScenario('unban_all')}
          >
            全部解封
          </button>
        </div>

        {/* Right Camp HUD: Red Team Offensive Matrix */}
        <div
          className="camp-hud red"
          onClick={() => setHostModalOpen(true)}
          role="button"
          tabIndex={0}
          title="点击配置红方攻击电脑 IP"
        >
          <div className="camp-tag">⚔️ {hostConfig.redHostName}</div>
          <div className="camp-ip">{hostConfig.redPrimaryIp}</div>
          <div className="camp-sub">
            HP: {redHp.toLocaleString()} · STRIKES: {redStrikesCount}
          </div>
        </div>

        {viewVersion === 'v2' && (
          <>
            <OrbLiveLog ops={combatOps} live={mode === 'live'} />
            <OrbOpsPanel side="red" ops={redOps} live={mode === 'live'} />
          </>
        )}

        <div className="ov chk" id="chk" ref={chkRef}>
          <b id="chkK" ref={chkKRef}>
            PERIMETER WATCH
          </b>
          <span id="chkV" ref={chkVRef}>
            NFTABLES · READY
          </span>
        </div>

      </main>

      {viewVersion === 'v1' && (
        <section className="panels" aria-label="Tactical Telemetry Panels">
          <div className="p">
            <h3>
              THREAT &amp; AUDIT FEED <i id="feedRate">{eps.toFixed(1)} eps</i>
            </h3>
            <div className="feed" id="feed">
              {feedList.map((f, idx) => (
                <div key={`${f.id}-${idx}`}>
                  <span className="n">#{String(f.id).padStart(4, '0')}</span>
                  <span className={`vb ${f.cls}`}>{f.tag}</span>
                  {f.msg}
                </div>
              ))}
            </div>
          </div>

          <div className="p">
            <h3>
              DEFENSE VECTOR FIELD <i>PIPELINE</i>
            </h3>
            <canvas id="cAdv" ref={cAdvRef} />
            <div className="btns" id="advBtns">
              <span className={advBtnIdx === 0 ? 'on' : ''}>INGEST</span>
              <span className={advBtnIdx === 1 ? 'on' : ''}>DECIDE</span>
              <span className={advBtnIdx === 2 ? 'on' : ''}>NFTABLES</span>
            </div>
          </div>

          <div className="p">
            <h3>
              DEEPSEEK AI INVESTIGATOR <i>TOOLS &amp; TRACE</i>
            </h3>
            <div className="code" id="code">
              {aiLines.map((line) => (
                <div key={line.ln}>
                  <span className="ln">{String(line.ln).padStart(3, '0')}</span>
                  <span className={line.cls}>{line.text}</span>
                </div>
              ))}
              <div>
                <span className="ln">
                  {String((aiLines[aiLines.length - 1]?.ln || 1) + 1).padStart(3, '0')}
                </span>
                <span className="caret" />
              </div>
            </div>
          </div>

          <div className="p">
            <h3>
              SURICATA / WAF DELTA FIELD <i>ANOMALY</i>
            </h3>
            <canvas id="cDiff" ref={cDiffRef} />
            <div className="cap">
              blue baseline vs red strike delta · spikes highlight anomaly
            </div>
          </div>

          <div className="p">
            <h3>
              5-LAYER DEFENSE MATRIX <i>RULES</i>
            </h3>
            <div className="routes" id="routes">
              <span className="h">LAYER</span>
              <span className="h">SENSOR</span>
              <span className="h">DECIDE</span>
              <span className="h">ENFORCE</span>
              {LAYERS.map((L, idx) => {
                const st = layerState[idx] || 0;
                return (
                  <React.Fragment key={L.name}>
                    <span className="nm">{L.name}</span>
                    {L.cols.map((colName, j) => {
                      const cls =
                        st > j ? 'done' : st === j && st > 0 ? (idx < 3 ? 'pk' : 'on') : '';
                      return (
                        <span key={colName}>
                          <span className={`chip ${cls}`}>{colName}</span>
                        </span>
                      );
                    })}
                  </React.Fragment>
                );
              })}
            </div>
            <div className="cap">suricata → modsec → honeypot → app → nftables</div>
          </div>

          <div className="p">
            <h3>
              SECURITY OSCILLOSCOPE <i>EPS / THREAT / DROP</i>
            </h3>
            <canvas id="cVal" ref={cValRef} />
            <div className="cap">real-time telemetry waveform · pink = surge</div>
          </div>

          <div className="p">
            <h3>
              ACTIVE BANS LEDGER <i>NFT_BLOCK</i>
            </h3>
            <div className="bans" id="bansList">
              {activeBansList.length === 0 ? (
                <div className="bans-empty">
                  PERIMETER CLEAR · 暂无生效封禁（可用上方按钮触发红方跨屏打击）
                </div>
              ) : (
                activeBansList.map((b) => {
                  const rem = Math.max(0, Math.round((b.expiresAtMs - nowMs) / 1000));
                  return (
                    <div className="ban-row" key={b.ip}>
                      <span className="ip">{b.ip}</span>
                      <span className="rl" title={b.reason}>
                        {b.rule}
                      </span>
                      <span className="ttl">{rem}s</span>
                      <button
                        type="button"
                        onClick={() => requestUnban(b.ip)}
                        aria-label={`Unban ${b.ip}`}
                      >
                        UNBAN
                      </button>
                    </div>
                  );
                })
              )}
            </div>
            <div className="cap">
              click [UNBAN] to emit rollback &amp; unlock red node
            </div>
          </div>

          <div className="p">
            <h3>
              RULE SIGNATURE MATRIX <i>11 DETECTORS</i>
            </h3>
            <canvas id="cIdx" ref={cIdxRef} />
            <div className="cap">
              scanline = live rule evaluation across tracked Red IPs
            </div>
          </div>
        </section>
      )}

      <ConsoleDrawer
        open={consoleOpen}
        values={paramValues}
        onChangeParam={handleParamChange}
        onReset={handleResetParams}
        onClose={() => setConsoleOpen(false)}
      />

      <BridgeModal
        open={bridgeModalOpen}
        onClose={() => setBridgeModalOpen(false)}
      />

      <HostLinkModal
        open={hostModalOpen}
        config={hostConfig}
        redNodes={redNodesList}
        onSaveConfig={handleSaveHostConfig}
        onTriggerCustomStrike={(ip, vec) => {
          runScenario(vec, ip);
          setHostModalOpen(false);
        }}
        onClose={() => setHostModalOpen(false)}
      />
    </div>
  );
}
