import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import { validateIpv4 } from './src/utils/nightwatchEngine.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

interface DbEventRow {
  id: number;
  ts: string;
  kind: string;
  ip: string;
  rule_id: string;
  evidence_json: string;
  raw_line: string;
}

interface DbBanRow {
  ip: string;
  until_ts: string;
  decision_event: number;
  created_ts: string;
  operator: string;
  reason: string;
  revoked_ts: string | null;
}

// In-memory WAL-like ledger for the live preview environment (mirrors data/nightwatch.db)
let nextEventId = 1;
const eventsTable: DbEventRow[] = [];
const bansTable = new Map<string, DbBanRow>();
let autonomyMode = 'auto';
let autopilotEnabled = true;

function pushEvent(
  kind: string,
  ip: string,
  rule_id: string,
  evidence: Record<string, any>,
  raw_line = ''
): DbEventRow {
  const row: DbEventRow = {
    id: nextEventId++,
    ts: new Date().toISOString(),
    kind,
    ip,
    rule_id,
    evidence_json: JSON.stringify(evidence),
    raw_line: raw_line || `${kind} ${ip} ${rule_id}`,
  };
  eventsTable.push(row);
  if (eventsTable.length > 500) {
    eventsTable.shift();
  }

  if (kind === 'decision' && evidence.action === 'ban') {
    const ttl = Number(evidence.ttl_seconds || 600);
    const until = new Date(Date.now() + ttl * 1000).toISOString();
    bansTable.set(ip, {
      ip,
      until_ts: until,
      decision_event: row.id,
      created_ts: row.ts,
      operator: evidence.actor || 'rule-engine',
      reason: rule_id || evidence.reason || 'RULE_BAN',
      revoked_ts: null,
    });
  } else if (kind === 'rollback' || kind === 'expire') {
    const existing = bansTable.get(ip);
    if (existing) {
      existing.revoked_ts = row.ts;
      bansTable.delete(ip);
    }
  }
  return row;
}

// Seed initial Nightwatch perimeter events
pushEvent('agent_run', '127.0.0.1', 'BOOT', {
  conclusion: 'Nightwatch daemon online · SQLite WAL mode verified · DeepSeek Agent ready',
});
pushEvent('net_alert', '185.220.101.4', 'NET_SCAN.v1', {
  signature: 'ET SCAN Nmap Scripting Engine User-Agent Detected',
});
pushEvent('waf_alert', '10.2.31.236', 'WAF_SQLI.v1', {
  uri: "/lab/item?id=1' UNION SELECT username,password FROM users--",
  msg: 'SQL Injection Attack Detected via libinjection (CRS 942100)',
});
pushEvent('decision', '10.2.31.236', 'WAF_SQLI.v1', {
  action: 'ban',
  ttl_seconds: 3600,
  actor: 'rule-engine',
  reason: 'WAF_SQLI.v1 CRS-942100',
});
pushEvent('agent_tool', '10.2.31.236', 'attack_chain', {
  tool: 'attack_chain',
  summary: 'correlating Suricata EVE + ModSecurity CRS 942100 -> confirmed SQLMap',
});

function getSnapshot() {
  const nowIso = new Date().toISOString();
  const activeBans: DbBanRow[] = [];
  for (const [ip, ban] of bansTable.entries()) {
    if (!ban.revoked_ts && ban.until_ts > nowIso) {
      activeBans.push(ban);
    } else {
      bansTable.delete(ip);
    }
  }
  const maxId = eventsTable.length ? eventsTable[eventsTable.length - 1].id : 0;
  return {
    event_count: maxId,
    bans: activeBans,
    chain_ok: true,
    autonomy: autonomyMode,
    autopilot: autopilotEnabled,
    max_id: maxId,
  };
}

function triggerServerScenario(scenario: string, customIp?: string) {
  const ips = ['10.2.31.236', '185.220.101.4', '45.155.205.91', '10.200.0.2', '91.240.118.172'];
  const ip = customIp || ips[Math.floor(Math.random() * ips.length)];

  if (scenario === 'sqli') {
    pushEvent('waf_alert', ip, 'WAF_SQLI.v1', {
      uri: "/lab/item?id=1' OR 1=1--",
      msg: 'SQL Injection Attack Detected via libinjection',
    });
    setTimeout(() => {
      pushEvent('decision', ip, 'WAF_SQLI.v1', {
        action: 'ban',
        ttl_seconds: 3600,
        actor: 'rule-engine',
        reason: 'WAF_SQLI',
      });
    }, 500);
    setTimeout(() => {
      pushEvent('agent_tool', ip, 'attack_chain', {
        tool: 'attack_chain',
        summary: 'found WAF_SQLI #event -> verified hash chain',
      });
      setTimeout(() => {
        pushEvent('agent_run', ip, 'DEEPSEEK_VERDICT', {
          conclusion: `${ip} 已被 WAF_SQLI.v1 封禁 3600s，SHA-256 哈希链已入账。`,
        });
      }, 450);
    }, 850);
  } else if (scenario === 'syn') {
    for (let i = 0; i < 4; i++) {
      setTimeout(() => {
        pushEvent('net_alert', ip, 'NET_DOS.v1', {
          signature: 'NW SYN FLOOD 8081 >=200/10s',
        });
      }, i * 150);
    }
    setTimeout(() => {
      pushEvent('decision', ip, 'NET_DOS.v1', {
        action: 'ban',
        ttl_seconds: 600,
        actor: 'rule-engine',
        reason: 'NET_DOS',
      });
    }, 700);
  } else if (scenario === 'honeypot') {
    pushEvent('honeypot', ip, 'HONEYPOT.v1', {
      path: '/admin',
    });
    setTimeout(() => {
      pushEvent('decision', ip, 'HONEYPOT.v1', {
        action: 'ban',
        ttl_seconds: 3600,
        actor: 'rule-engine',
        reason: 'HONEYPOT zero-FP trap',
      });
    }, 400);
  } else if (scenario === 'brute') {
    for (let i = 0; i < 5; i++) {
      setTimeout(() => {
        pushEvent('login_fail', ip, 'BRUTE_FORCE.v1', {
          user: 'root',
        });
      }, i * 160);
    }
    setTimeout(() => {
      pushEvent('decision', ip, 'BRUTE_FORCE.v1', {
        action: 'ban',
        ttl_seconds: 600,
        actor: 'rule-engine',
        reason: '5 failed logins in 60s',
      });
    }, 950);
  } else if (scenario === 'ai') {
    pushEvent('agent_tool', ip, 'profile_attacker', {
      tool: 'profile_attacker',
      summary: 'tool=sqlmap (95% conf) · multi-vector probe',
    });
    setTimeout(() => {
      pushEvent('agent_tool', ip, 'deploy_waf_rule', {
        tool: 'deploy_waf_rule',
        summary: 'UA @contains sqlmap -> hot-reload modsec',
      });
    }, 400);
    setTimeout(() => {
      pushEvent('agent_run', ip, 'DEEPSEEK_VERDICT', {
        conclusion: `DeepSeek 完成研判：${ip} 为自动化注入探测，已补强 WAF 规则。`,
      });
    }, 850);
  } else if (scenario === 'unban_all') {
    for (const bannedIp of Array.from(bansTable.keys())) {
      pushEvent('rollback', bannedIp, 'MANUAL_UNBAN', {
        operator: 'web-hud',
        reason: 'batch unban_all',
      });
    }
  }
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '16kb' }));

  app.get('/api/snapshot', (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.json(getSnapshot());
  });

  app.post('/api/unban', (req, res) => {
    const ipStr = String(req.body?.ip || '').trim();
    if (!validateIpv4(ipStr)) {
      res.status(400).json({ ok: false, error: 'invalid ipv4' });
      return;
    }
    pushEvent('rollback', ipStr, 'MANUAL_UNBAN', {
      operator: 'web-hud',
      reason: 'haloflux unban',
    });
    res.json({ ok: true, stdout: `Unbanned ${ipStr} via nftables nw_block`, error: '' });
  });

  app.post('/api/sim', (req, res) => {
    const sc = String(req.body?.scenario || 'sqli');
    const customIp = req.body?.ip ? String(req.body.ip).trim() : undefined;
    triggerServerScenario(sc, customIp);
    res.json({ ok: true, scenario: sc });
  });

  app.get('/api/bridge-files', (_req, res) => {
    const pyPath = path.join(__dirname, 'scripts', 'web_bridge.py');
    const htmlPath = path.join(__dirname, 'docs', 'haloflux', 'nightwatch-halo.html');
    const pyCode = fs.existsSync(pyPath) ? fs.readFileSync(pyPath, 'utf-8') : '';
    const htmlCode = fs.existsSync(htmlPath) ? fs.readFileSync(htmlPath, 'utf-8') : '';
    res.json({
      web_bridge_py: pyCode,
      nightwatch_halo_html: htmlCode,
    });
  });

  // Zero-dependency standard ZIP generator for one-click full project download
  const CRC_TABLE = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    CRC_TABLE[n] = c >>> 0;
  }
  function crc32Buf(buf: Buffer): number {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
      c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    }
    return (c ^ 0xffffffff) >>> 0;
  }

  function buildZipArchive(entries: { name: string; data: Buffer }[]): Buffer {
    const localParts: Buffer[] = [];
    const centralParts: Buffer[] = [];
    let offset = 0;

    for (const entry of entries) {
      const nameBuf = Buffer.from(entry.name.replace(/\\/g, '/'), 'utf-8');
      const dataBuf = entry.data;
      const crc = crc32Buf(dataBuf);
      const size = dataBuf.length;

      // Local file header (30 bytes + name)
      const lh = Buffer.alloc(30 + nameBuf.length);
      lh.writeUInt32LE(0x04034b50, 0); // signature
      lh.writeUInt16LE(20, 4); // version needed
      lh.writeUInt16LE(0x0800, 6); // UTF-8 flag
      lh.writeUInt16LE(0, 8); // method 0 = STORE
      lh.writeUInt16LE(0, 10); // mod time
      lh.writeUInt16LE(0x5821, 12); // mod date
      lh.writeUInt32LE(crc, 14);
      lh.writeUInt32LE(size, 18);
      lh.writeUInt32LE(size, 22);
      lh.writeUInt16LE(nameBuf.length, 26);
      lh.writeUInt16LE(0, 28);
      nameBuf.copy(lh, 30);

      localParts.push(lh, dataBuf);

      // Central directory header (46 bytes + name)
      const ch = Buffer.alloc(46 + nameBuf.length);
      ch.writeUInt32LE(0x02014b50, 0);
      ch.writeUInt16LE(20, 4);
      ch.writeUInt16LE(20, 6);
      ch.writeUInt16LE(0x0800, 8); // UTF-8 flag
      ch.writeUInt16LE(0, 10); // STORE
      ch.writeUInt16LE(0, 12);
      ch.writeUInt16LE(0x5821, 14);
      ch.writeUInt32LE(crc, 16);
      ch.writeUInt32LE(size, 20);
      ch.writeUInt32LE(size, 24);
      ch.writeUInt16LE(nameBuf.length, 28);
      ch.writeUInt16LE(0, 30);
      ch.writeUInt16LE(0, 32);
      ch.writeUInt16LE(0, 34);
      ch.writeUInt16LE(0, 36);
      ch.writeUInt32LE(0, 38);
      ch.writeUInt32LE(offset, 42);
      nameBuf.copy(ch, 46);

      centralParts.push(ch);
      offset += lh.length + size;
    }

    const centralDir = Buffer.concat(centralParts);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(0, 4);
    eocd.writeUInt16LE(0, 6);
    eocd.writeUInt16LE(entries.length, 8);
    eocd.writeUInt16LE(entries.length, 10);
    eocd.writeUInt32LE(centralDir.length, 12);
    eocd.writeUInt32LE(offset, 16);
    eocd.writeUInt16LE(0, 20);

    return Buffer.concat([...localParts, centralDir, eocd]);
  }

  app.get('/api/download-project.zip', (_req, res) => {
    const relFiles = [
      'package.json',
      'tsconfig.json',
      'vite.config.ts',
      'index.html',
      'metadata.json',
      'server.ts',
      'src/main.tsx',
      'src/index.css',
      'src/App.tsx',
      'src/utils/nightwatchEngine.ts',
      'src/utils/nightwatchEngine.test.ts',
      'src/utils/haloParams.ts',
      'src/components/CombatHudDock.tsx',
      'src/components/ConsoleDrawer.tsx',
      'src/components/BridgeModal.tsx',
      'src/components/HostLinkModal.tsx',
      'scripts/web_bridge.py',
      'docs/haloflux/nightwatch-halo.html',
      'docs/haloflux/nightwatch-halo-v1.html',
    ];

    const entries: { name: string; data: Buffer }[] = [];
    for (const rel of relFiles) {
      const abs = path.join(__dirname, rel);
      if (fs.existsSync(abs) && fs.statSync(abs).isFile()) {
        entries.push({
          name: `nightwatch-haloflux/${rel}`,
          data: fs.readFileSync(abs),
        });
      }
    }

    const standaloneHtmlPath = path.join(__dirname, 'docs', 'haloflux', 'nightwatch-halo.html');
    if (fs.existsSync(standaloneHtmlPath)) {
      entries.push({
        name: 'nightwatch-haloflux/双击直接打开-红蓝双球攻防大屏V2.html',
        data: fs.readFileSync(standaloneHtmlPath),
      });
    }

    const batContent = `@echo off
chcp 65001 >nul
echo ========================================================
echo   NIGHTWATCH // HALOFLUX 红蓝对称双球攻防作战室
echo ========================================================
where node >nul 2>nul
if %errorlevel% equ 0 (
  echo [1/2] 检测到 Node.js，正在启动完整本地服务...
  if not exist node_modules call npm install
  start http://localhost:3000
  call npm run dev
) else (
  echo [提示] 未检测到 Node.js，直接为您在浏览器中打开免安装单文件版...
  start "" "双击直接打开-红蓝双球攻防大屏V2.html"
)
pause
`;
    entries.push({
      name: 'nightwatch-haloflux/Windows一键启动.bat',
      data: Buffer.from(batContent, 'utf-8'),
    });

    const readmeContent = `# NIGHTWATCH // HALOFLUX 红蓝双阵营对称球攻防作战室 (V2 + V1)

## 方式一：免安装直接预览（发给任何人解压即可用！）

别人收到压缩包解压后，**不需要安装任何软件或环境**：
- 直接双击根目录下的 **\`双击直接打开-红蓝双球攻防大屏V2.html\`**（或 \`docs/haloflux/nightwatch-halo.html\`），即可在 Chrome / Edge 浏览器中直接全屏运行完整的「对称双球 V2 + 双方血量 + 具体操作指令框 + V1 八栏切换」！

## 方式二：Windows 一键脚本或开发者模式

- 双击 **\`Windows一键启动.bat\`**（有 Node 环境会自动启动 \`http://localhost:3000\`，没有 Node 环境会自动打开免安装 HTML）。
- 如需修改 React 源码：
  \`\`\`bash
  npm install
  npm run dev
  \`\`\`
`;
    entries.push({
      name: 'nightwatch-haloflux/README-本地运行指南.md',
      data: Buffer.from(readmeContent, 'utf-8'),
    });

    const zipBuf = buildZipArchive(entries);
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader(
      'Content-Disposition',
      'attachment; filename="nightwatch-haloflux-v2.zip"'
    );
    res.setHeader('Content-Length', String(zipBuf.length));
    res.send(zipBuf);
  });

  app.get('/events', (req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
    });

    const snap = getSnapshot();
    let lastId = Math.max(0, snap.max_id - 15);
    res.write(`event: snapshot\ndata: ${JSON.stringify(snap)}\n\n`);

    const flushEvents = () => {
      const fresh = eventsTable.filter((e) => e.id > lastId);
      for (const ev of fresh) {
        lastId = Math.max(lastId, ev.id);
        if (ev.kind === 'http_request' || ev.kind === 'parse_error') continue;
        res.write(`event: nw_event\ndata: ${JSON.stringify(ev)}\n\n`);
      }
    };
    flushEvents();

    const pollInterval = setInterval(flushEvents, 350);
    const snapInterval = setInterval(() => {
      res.write(`event: snapshot\ndata: ${JSON.stringify(getSnapshot())}\n\n`);
    }, 2000);

    req.on('close', () => {
      clearInterval(pollInterval);
      clearInterval(snapInterval);
    });
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = Number(process.env.PORT || 3000);
  // 预览服务只绑本机，避免把无鉴权的模拟/解封接口暴露到局域网
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`[Nightwatch x HALOFLUX] Server listening on http://127.0.0.1:${PORT}`);
  });
}

startServer();
