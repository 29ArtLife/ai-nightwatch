import React from 'react';
import {
  ActiveBan,
  CombatOperationLog,
  MAX_CAMP_HP,
  RedBlueHostConfig,
  RedNodeInfo,
} from '../utils/nightwatchEngine';

interface CombatHudDockProps {
  blueHp: number;
  redHp: number;
  hostConfig: RedBlueHostConfig;
  blueBlocksCount: number;
  redStrikesCount: number;
  activeBansList: ActiveBan[];
  redNodesList: RedNodeInfo[];
  combatOps: CombatOperationLog[];
  onResetHp: () => void;
  onUnbanIp: (ip: string) => void;
  onUnbanAll: () => void;
  onOpenHostModal: () => void;
}

export const CombatHudDock: React.FC<CombatHudDockProps> = ({
  blueHp,
  redHp,
  hostConfig,
  blueBlocksCount,
  redStrikesCount,
  activeBansList,
  redNodesList,
  combatOps,
  onResetHp,
  onUnbanIp,
  onUnbanAll,
  onOpenHostModal,
}) => {
  const bluePct = Math.max(0, Math.min(100, Math.round((blueHp / MAX_CAMP_HP) * 100)));
  const redPct = Math.max(0, Math.min(100, Math.round((redHp / MAX_CAMP_HP) * 100)));
  const currentOp = combatOps[combatOps.length - 1] || {
    id: 0,
    ts: '--:--:--',
    actorCamp: 'blue' as const,
    directionLabel: 'READY // 双球对称交火就绪',
    actionTitle: '左右红蓝核心已同步，点击上方攻击按钮或接入双方电脑即可实时展示跨屏攻防过程',
    commandLine: './nightwatch daemon --wal-mode & python3 scripts/web_bridge.py',
    detailDesc:
      '左侧蓝方核心（Ubuntu 防线）与右侧红方核心（Kali 攻击矩阵）对称运转，实时呈现每一发攻击载荷与反制指令。',
    hpEffectText: '双方满血 10,000 HP',
    blueDeltaHp: 0,
    redDeltaHp: 0,
    blocked: false,
    srcIp: hostConfig.blueHostIp,
    dstIp: hostConfig.redPrimaryIp,
  };

  const recentHistory = combatOps.slice(-4, -1).reverse();
  const lockedNodesCount = redNodesList.filter((n) => n.locked).length;

  return (
    <section className="combat-dock" aria-label="双方血量与实时攻防具体操作展示舱">
      {/* Left: Blue Camp HP & Defense Status */}
      <div className="camp-hp-card blue">
        <div className="hp-card-top">
          <div className="hp-camp-title" onClick={onOpenHostModal} title="点击配置蓝方电脑 IP">
            <span className="hp-badge blue">🛡️ 蓝方防守阵营</span>
            <span className="hp-host-ip">{hostConfig.blueHostIp}</span>
          </div>
          <div className="hp-num-wrap">
            <span className="hp-num blue">{blueHp.toLocaleString()}</span>
            <span className="hp-max">/ {MAX_CAMP_HP.toLocaleString()} HP</span>
          </div>
        </div>

        <div className="hp-bar-outer blue" role="progressbar" aria-valuenow={bluePct} aria-valuemin={0} aria-valuemax={100}>
          <div className="hp-bar-fill blue" style={{ width: `${bluePct}%` }} />
          <div className="hp-bar-grid" />
          <span className="hp-bar-pct left">{bluePct}% 护盾完整度</span>
        </div>

        <div className="hp-sub-metrics">
          <div className="hp-metric">
            <span className="k">护盾格挡</span>
            <span className="v cyan">{blueBlocksCount} 次</span>
          </div>
          <div className="hp-metric">
            <span className="k">NFT 封锁源</span>
            <span className="v teal">{activeBansList.length} 个</span>
          </div>
          <div className="hp-metric">
            <span className="k">主机标识</span>
            <span className="v">{hostConfig.blueHostName}</span>
          </div>
        </div>

        {activeBansList.length > 0 ? (
          <div className="hp-ban-strip">
            <span className="strip-label">生效护盾封禁:</span>
            <div className="strip-chips">
              {activeBansList.slice(0, 3).map((b) => (
                <button
                  key={b.ip}
                  type="button"
                  className="ban-chip"
                  onClick={() => onUnbanIp(b.ip)}
                  title={`点击解封 ${b.ip} (${b.rule})`}
                >
                  🔒 {b.ip} <em>×解封</em>
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="hp-ban-strip idle">
            <span>外环 NFTABLES 护盾实时监听中 · 零误报拦截就绪</span>
          </div>
        )}
      </div>

      {/* Center: Live Concrete Operation & Payload Showcase */}
      <div className={`combat-op-center ${currentOp.actorCamp}`}>
        <div className="op-header-row">
          <div className="op-title-group">
            <span className={`op-dir-tag ${currentOp.actorCamp}`}>
              {currentOp.directionLabel}
            </span>
            <h2 className="op-main-title">{currentOp.actionTitle}</h2>
          </div>
          <div className="op-right-controls">
            <span className={`op-hp-delta ${currentOp.actorCamp}`}>
              {currentOp.hpEffectText}
            </span>
            <button
              type="button"
              className="op-reset-btn"
              onClick={onResetHp}
              title="将红蓝双方血量恢复至 10,000 HP"
            >
              ↺ 重置血量
            </button>
          </div>
        </div>

        <div className="op-terminal-box">
          <div className="op-cmd-line">
            <span className="cmd-prompt">
              {currentOp.actorCamp === 'red'
                ? `root@kali(${currentOp.srcIp})#`
                : currentOp.actorCamp === 'ai'
                  ? `deepseek@nightwatch#`
                  : `root@bastion(${currentOp.srcIp})#`}
            </span>
            <code className="cmd-code">{currentOp.commandLine}</code>
          </div>
          <div className="op-desc-line">{currentOp.detailDesc}</div>
        </div>

        <div className="op-history-strip">
          <span className="hist-label">最近交火步骤:</span>
          <div className="hist-items">
            {recentHistory.length === 0 ? (
              <span className="hist-empty">
                等待后续攻防指令...（点击右上角「SQLi 注入」「SYN Flood」「/admin 蜜罐」立即发射）
              </span>
            ) : (
              recentHistory.map((item) => (
                <div key={item.id} className={`hist-pill ${item.actorCamp}`}>
                  <span className="hist-tag">#{String(item.id).padStart(3, '0')}</span>
                  <span className="hist-dir">{item.directionLabel}</span>
                  <span className="hist-text">{item.actionTitle}</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Right: Red Camp HP & Offensive Matrix Status */}
      <div className="camp-hp-card red">
        <div className="hp-card-top">
          <div className="hp-num-wrap">
            <span className="hp-num red">{redHp.toLocaleString()}</span>
            <span className="hp-max">/ {MAX_CAMP_HP.toLocaleString()} HP</span>
          </div>
          <div className="hp-camp-title right" onClick={onOpenHostModal} title="点击配置红方电脑 IP">
            <span className="hp-host-ip">{hostConfig.redPrimaryIp}</span>
            <span className="hp-badge red">⚔️ 红方攻击阵营</span>
          </div>
        </div>

        <div className="hp-bar-outer red" role="progressbar" aria-valuenow={redPct} aria-valuemin={0} aria-valuemax={100}>
          <div className="hp-bar-fill red" style={{ width: `${redPct}%` }} />
          <div className="hp-bar-grid" />
          <span className="hp-bar-pct right">{redPct}% 矩阵能量</span>
        </div>

        <div className="hp-sub-metrics right">
          <div className="hp-metric">
            <span className="k">主机标识</span>
            <span className="v">{hostConfig.redHostName}</span>
          </div>
          <div className="hp-metric">
            <span className="k">红方节点</span>
            <span className="v amber">
              {redNodesList.length} 台 ({lockedNodesCount} 锁死)
            </span>
          </div>
          <div className="hp-metric">
            <span className="k">跨屏打击</span>
            <span className="v red">{redStrikesCount} 次</span>
          </div>
        </div>

        <div className="hp-ban-strip right">
          {lockedNodesCount > 0 ? (
            <>
              <span className="strip-label">被反制锁死节点: {lockedNodesCount} 台</span>
              <button type="button" className="ban-chip red-unban" onClick={onUnbanAll}>
                ⚡ 一键解除全部锁死
              </button>
            </>
          ) : (
            <span>右侧红方粒子球核心全功率运转 · 随时发射跨屏攻击线</span>
          )}
        </div>
      </div>
    </section>
  );
};
