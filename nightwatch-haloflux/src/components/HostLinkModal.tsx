import React, { useState } from 'react';
import { RedBlueHostConfig, RedNodeInfo, validateIpv4 } from '../utils/nightwatchEngine';

interface HostLinkModalProps {
  open: boolean;
  config: RedBlueHostConfig;
  redNodes: RedNodeInfo[];
  onSaveConfig: (next: RedBlueHostConfig) => void;
  onTriggerCustomStrike: (ip: string, vector: string) => void;
  onClose: () => void;
}

export const HostLinkModal: React.FC<HostLinkModalProps> = ({
  open,
  config,
  redNodes,
  onSaveConfig,
  onTriggerCustomStrike,
  onClose,
}) => {
  const [blueHostName, setBlueHostName] = useState(config.blueHostName);
  const [blueHostIp, setBlueHostIp] = useState(config.blueHostIp);
  const [redHostName, setRedHostName] = useState(config.redHostName);
  const [redPrimaryIp, setRedPrimaryIp] = useState(config.redPrimaryIp);
  const [customVector, setCustomVector] = useState('sqli');
  const [errorMsg, setErrorMsg] = useState('');
  const [savedToast, setSavedToast] = useState(false);

  if (!open) return null;

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateIpv4(blueHostIp)) {
      setErrorMsg('蓝方防守主机 IP 格式无效（需为合法 IPv4，如 10.2.102.143）');
      return;
    }
    if (!validateIpv4(redPrimaryIp)) {
      setErrorMsg('红方主攻主机 IP 格式无效（需为合法 IPv4，如 10.2.31.236）');
      return;
    }
    setErrorMsg('');
    onSaveConfig({
      blueHostName: blueHostName.trim() || 'BLUE BASTION // UBUNTU',
      blueHostIp: blueHostIp.trim(),
      redHostName: redHostName.trim() || 'RED STRIKE // KALI',
      redPrimaryIp: redPrimaryIp.trim(),
    });
    setSavedToast(true);
    setTimeout(() => setSavedToast(false), 1800);
  };

  const handleFireTest = () => {
    if (!validateIpv4(redPrimaryIp)) {
      setErrorMsg('红方主攻主机 IP 格式无效');
      return;
    }
    setErrorMsg('');
    onSaveConfig({
      blueHostName: blueHostName.trim() || 'BLUE BASTION // UBUNTU',
      blueHostIp: blueHostIp.trim(),
      redHostName: redHostName.trim() || 'RED STRIKE // KALI',
      redPrimaryIp: redPrimaryIp.trim(),
    });
    onTriggerCustomStrike(redPrimaryIp.trim(), customVector);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-label="红蓝双方电脑接入与阵营配置"
    >
      <div className="flex max-h-[88vh] w-full max-w-3xl flex-col border border-[#3a3e46] bg-[#0e0f12] text-[#cfd2d8]">
        <div className="flex items-center justify-between border-b border-[#25282e] px-4 py-2.5">
          <strong className="text-xs tracking-widest text-[#f4f5f7]">
            ⇄ 红蓝双阵营电脑接入配置 // RED TEAM vs BLUE TEAM LINK
          </strong>
          <button
            type="button"
            onClick={onClose}
            className="pill"
            aria-label="关闭双方主机接入窗口"
          >
            ✕ 关闭
          </button>
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto p-4 text-xs">
          <form onSubmit={handleSave} className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {/* Blue Team Config */}
            <div className="border border-[#38bdf8]/40 bg-[#08090b] p-3">
              <div className="mb-2 flex items-center justify-between">
                <span className="font-bold tracking-wider text-[#38bdf8]">
                  🛡️ 蓝方防守阵营（左环 · Nightwatch 守夜人）
                </span>
                <span className="text-[10px] text-[#98e0cf]">DEFENSE CORE</span>
              </div>
              <label className="mb-1 block text-[10px] text-[#6b6f78]" htmlFor="blue-name-input">
                蓝方主机代号 / 节点名称
              </label>
              <input
                id="blue-name-input"
                type="text"
                value={blueHostName}
                onChange={(e) => setBlueHostName(e.target.value)}
                className="mb-2.5 w-full border border-[#25282e] bg-[#0e0f12] px-2 py-1 text-xs text-[#f4f5f7]"
              />
              <label className="mb-1 block text-[10px] text-[#6b6f78]" htmlFor="blue-ip-input">
                蓝方防守电脑 IP（Ubuntu 宿主机 / 靶机）
              </label>
              <input
                id="blue-ip-input"
                type="text"
                value={blueHostIp}
                onChange={(e) => setBlueHostIp(e.target.value)}
                className="w-full border border-[#25282e] bg-[#0e0f12] px-2 py-1 text-xs text-[#38bdf8]"
              />
            </div>

            {/* Red Team Config */}
            <div className="border border-[#ff3b5c]/40 bg-[#08090b] p-3">
              <div className="mb-2 flex items-center justify-between">
                <span className="font-bold tracking-wider text-[#ff3b5c]">
                  ⚔️ 红方攻击阵营（右环 · Kali 渗透主机）
                </span>
                <span className="text-[10px] text-[#ffaa2b]">STRIKE MATRIX</span>
              </div>
              <label className="mb-1 block text-[10px] text-[#6b6f78]" htmlFor="red-name-input">
                红方主机代号 / 节点名称
              </label>
              <input
                id="red-name-input"
                type="text"
                value={redHostName}
                onChange={(e) => setRedHostName(e.target.value)}
                className="mb-2.5 w-full border border-[#25282e] bg-[#0e0f12] px-2 py-1 text-xs text-[#f4f5f7]"
              />
              <label className="mb-1 block text-[10px] text-[#6b6f78]" htmlFor="red-ip-input">
                红方攻击电脑 IP（Kali / 渗透端主 IP）
              </label>
              <input
                id="red-ip-input"
                type="text"
                value={redPrimaryIp}
                onChange={(e) => setRedPrimaryIp(e.target.value)}
                className="w-full border border-[#25282e] bg-[#0e0f12] px-2 py-1 text-xs text-[#ff3b5c]"
              />
            </div>

            {errorMsg && (
              <div className="col-span-full border border-[#ff3b5c] bg-[#ff3b5c]/10 px-3 py-1.5 text-[11px] text-[#ff3b5c]">
                {errorMsg}
              </div>
            )}

            <div className="col-span-full flex flex-wrap items-center justify-between gap-2 border border-[#25282e] bg-[#08090b] p-3">
              <div className="flex items-center gap-2">
                <button type="submit" className="pill on">
                  {savedToast ? '✓ 已保存双方阵营配置' : '保存双方阵营配置'}
                </button>
              </div>
              <div className="flex items-center gap-2">
                <label htmlFor="custom-vector-select" className="text-[10px] text-[#6b6f78]">
                  以红方主 IP 发射跨屏打击：
                </label>
                <select
                  id="custom-vector-select"
                  value={customVector}
                  onChange={(e) => setCustomVector(e.target.value)}
                  className="border border-[#3a3e46] bg-[#0e0f12] px-2 py-1 text-[11px] text-[#f4f5f7]"
                >
                  <option value="sqli">SQLi 注入 (ModSec CRS)</option>
                  <option value="syn">SYN Flood 洪泛 (Suricata)</option>
                  <option value="honeypot">/admin 蜜罐诱捕 (Zero-FP)</option>
                  <option value="brute">SSH/Web 暴力破解 ×5</option>
                </select>
                <button
                  type="button"
                  onClick={handleFireTest}
                  className="pill"
                  style={{ borderColor: '#ff3b5c', color: '#ff3b5c' }}
                >
                  🚀 立即从该红方 IP 发起齐射
                </button>
              </div>
            </div>
          </form>

          {/* Real Machine Connection Instructions */}
          <div className="border border-[#25282e] bg-[#08090b] p-3">
            <h4 className="mb-1.5 text-[11px] font-bold text-[#f4f5f7]">
              如何将你们两台电脑的真实攻防实时映射到红蓝双环？
            </h4>
            <p className="mb-2 text-[11px] text-[#cfd2d8]">
              1. <strong>自动识别（零配置）</strong>：当蓝方电脑运行{' '}
              <code>scripts/web_bridge.py</code> 并开启顶部 <code>● LIVE SQLITE</code> 时，红方电脑（如{' '}
              <code>{redPrimaryIp}</code>）对蓝方电脑（<code>{blueHostIp}</code>）发起的任何{' '}
              <code>sqlmap</code>、<code>hping3</code>、<code>hydra</code>、<code>nmap</code> 或访问{' '}
              <code>/admin</code>，都会被 Suricata / ModSecurity / 蜜罐写入{' '}
              <code>nightwatch.db</code>，大屏会自动将该来源 IP 挂载到右侧<strong>红方攻击阵列节点</strong>，发射跨屏流光弹道轰向左侧<strong>蓝方守夜人护盾</strong>！
            </p>
            <p className="mb-1.5 text-[11px] text-[#cfd2d8]">
              2. <strong>红方电脑主动 Webhook 投送（支持远程演练）</strong>：红方电脑也可以直接执行以下{' '}
              <code>curl</code> 命令触发实时跨屏飞跃交火：
            </p>
            <pre className="overflow-x-auto border border-[#25282e] bg-[#0c0e12] p-2 text-[10px] text-[#98e0cf]">
{`# 在红方 Kali 电脑执行（触发针对蓝方靶机的实时跨屏弹道）：
curl -X POST http://${blueHostIp}:8765/api/sim \\
  -H "Content-Type: application/json" \\
  -d '{"scenario":"sqli","ip":"${redPrimaryIp}"}'`}
            </pre>
          </div>

          {/* Active Red Nodes Roster */}
          <div className="border border-[#25282e] bg-[#08090b] p-3">
            <h4 className="mb-2 text-[11px] font-bold text-[#ffaa2b]">
              当前已捕获的红方攻击源节点列表（右侧红方环挂载点）
            </h4>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {redNodes.map((rn) => (
                <div
                  key={rn.ip}
                  className="flex items-center justify-between border border-[#25282e] bg-[#12141a] px-2.5 py-1.5 text-[11px]"
                >
                  <div>
                    <span className="font-bold text-[#f4f5f7]">{rn.ip}</span>
                    <span className="ml-2 text-[10px] text-[#ffaa2b]">{rn.lastTool}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-[#6b6f78]">打击 {rn.strikes} 次</span>
                    <span
                      className="text-[10px] font-bold"
                      style={{ color: rn.locked ? '#38bdf8' : '#ff3b5c' }}
                    >
                      {rn.locked ? 'LOCKED (已封锁)' : 'ACTIVE (交火中)'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
