import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ipToAngle,
  ipToRedAngle,
  evalCubicBezier,
  computeBattleMomentum,
  applyCombatHp,
  deriveCombatOperation,
  validateIpv4,
  computeDefcon,
  calculateEps,
  matchRuleRowIndex,
  parseEvidence,
} from './nightwatchEngine';

test('ipToAngle deterministically maps IPv4 within [-thS*0.72, +thS*0.72]', () => {
  const thS = 0.8;
  const maxSpan = thS * 0.72;
  const a1 = ipToAngle('10.2.31.236', thS);
  const a2 = ipToAngle('10.2.31.236', thS);
  const a3 = ipToAngle('185.220.101.4', thS);

  assert.equal(a1, a2);
  assert.notEqual(a1, a3);
  assert.ok(a1 >= -maxSpan && a1 <= maxSpan);
  assert.ok(a3 >= -maxSpan && a3 <= maxSpan);
});

test('ipToRedAngle deterministically maps IPv4 around Math.PI (left-facing Red sector)', () => {
  const thRed = 0.68;
  const a = ipToRedAngle('10.2.31.236', thRed);
  assert.ok(a >= Math.PI - thRed && a <= Math.PI + thRed);
});

test('evalCubicBezier interpolates start, midpoint, and end accurately', () => {
  const p0 = { x: 1000, y: 400 };
  const p1 = { x: 750, y: 200 };
  const p2 = { x: 450, y: 200 };
  const p3 = { x: 200, y: 400 };

  const start = evalCubicBezier(p0, p1, p2, p3, 0);
  const end = evalCubicBezier(p0, p1, p2, p3, 1);
  const mid = evalCubicBezier(p0, p1, p2, p3, 0.5);

  assert.deepEqual(start, p0);
  assert.deepEqual(end, p3);
  assert.equal(mid.x, 600);
  assert.ok(mid.y < 400);
});

test('computeBattleMomentum balances Blue defense vs Red strikes', () => {
  const m1 = computeBattleMomentum(10, 2, 1, 0.1);
  assert.ok(m1.bluePct > 50);
  assert.equal(m1.bluePct + m1.redPct, 100);

  const m2 = computeBattleMomentum(0, 0, 20, 0.9);
  assert.ok(m2.redPct > 50);
  assert.equal(m2.bluePct + m2.redPct, 100);
});

test('applyCombatHp applies damage and healing while clamping within [0, maxHp]', () => {
  const r1 = applyCombatHp(10000, 10000, -280, -680, 10000);
  assert.equal(r1.blueHp, 9720);
  assert.equal(r1.redHp, 9320);

  const r2 = applyCombatHp(9900, 300, 500, -500, 10000);
  assert.equal(r2.blueHp, 10000);
  assert.equal(r2.redHp, 0);
});

test('deriveCombatOperation formats concrete commands and HP deltas for Red attacks and Blue bans', () => {
  const sqliHit = deriveCombatOperation(
    {
      kind: 'waf_alert',
      ip: '10.2.31.236',
      rule_id: 'WAF_SQLI.v1',
      evidence_json: { uri: "/lab/item?id=1' UNION SELECT 1,2--" },
    },
    false,
    '10.2.102.143',
    1
  );
  assert.equal(sqliHit.actorCamp, 'red');
  assert.ok(sqliHit.commandLine.includes('10.2.102.143'));
  assert.ok(sqliHit.blueDeltaHp < 0);

  const sqliBlocked = deriveCombatOperation(
    {
      kind: 'waf_alert',
      ip: '10.2.31.236',
      rule_id: 'WAF_SQLI.v1',
    },
    true,
    '10.2.102.143',
    2
  );
  assert.equal(sqliBlocked.blueDeltaHp, 0);
  assert.ok(sqliBlocked.redDeltaHp < 0);

  const banCounter = deriveCombatOperation(
    {
      kind: 'decision',
      ip: '10.2.31.236',
      rule_id: 'WAF_SQLI.v1',
      evidence_json: { ttl: 3600 },
    },
    true,
    '10.2.102.143',
    3
  );
  assert.equal(banCounter.actorCamp, 'blue');
  assert.ok(banCounter.commandLine.includes('nft add element'));
  assert.ok(banCounter.blueDeltaHp > 0);
  assert.ok(banCounter.redDeltaHp < -500);
});

test('validateIpv4 validates strict IPv4 strings', () => {
  assert.equal(validateIpv4('10.2.31.236'), true);
  assert.equal(validateIpv4('127.0.0.1'), true);
  assert.equal(validateIpv4('255.255.255.255'), true);
  assert.equal(validateIpv4('256.0.0.1'), false);
  assert.equal(validateIpv4('10.2.31'), false);
  assert.equal(validateIpv4('10.02.31.1'), false);
  assert.equal(validateIpv4('not-an-ip'), false);
});

test('computeDefcon escalates properly based on active bans and threat energy', () => {
  assert.equal(computeDefcon(0, 0.1), 'DEFCON 3');
  assert.equal(computeDefcon(1, 0.1), 'DEFCON 2');
  assert.equal(computeDefcon(0, 0.5), 'DEFCON 2');
  assert.equal(computeDefcon(3, 0.1), 'DEFCON 1');
  assert.equal(computeDefcon(0, 0.85), 'DEFCON 1');
});

test('calculateEps computes sliding window rate accurately', () => {
  const now = 10000;
  const timestamps = [2000, 5500, 6200, 8100, 9500];
  const res = calculateEps(timestamps, now, 5000);
  assert.equal(res.filtered.length, 4);
  assert.equal(res.eps, 0.8);
});

test('matchRuleRowIndex maps Nightwatch rules to 11-detector matrix rows', () => {
  assert.equal(matchRuleRowIndex('WAF_SQLI.v1'), 2);
  assert.equal(matchRuleRowIndex('NET_DOS.v1'), 1);
  assert.equal(matchRuleRowIndex('HONEYPOT.v1'), 5);
  assert.equal(matchRuleRowIndex('BRUTE_FORCE.v1'), 6);
  assert.equal(matchRuleRowIndex('AI_BAN'), 9);
  assert.equal(matchRuleRowIndex('UNKNOWN_RULE'), 10);
});

test('parseEvidence handles both JSON strings and objects safely', () => {
  assert.deepEqual(parseEvidence('{"action":"ban","ttl_seconds":600}'), {
    action: 'ban',
    ttl_seconds: 600,
  });
  assert.deepEqual(parseEvidence({ tool: 'attack_chain' }), {
    tool: 'attack_chain',
  });
  assert.deepEqual(parseEvidence('invalid-json'), {});
});
