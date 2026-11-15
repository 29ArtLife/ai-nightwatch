import React, { useEffect, useState } from 'react';

interface BridgeModalProps {
  open: boolean;
  onClose: () => void;
}

export const BridgeModal: React.FC<BridgeModalProps> = ({ open, onClose }) => {
  const [tab, setTab] = useState<'py' | 'html' | 'guide'>('guide');
  const [pyCode, setPyCode] = useState<string>('Loading scripts/web_bridge.py...');
  const [htmlCode, setHtmlCode] = useState<string>('Loading docs/haloflux/nightwatch-halo.html...');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open) return;
    fetch('/api/bridge-files')
      .then((r) => r.json())
      .then((d) => {
        if (d.web_bridge_py) setPyCode(d.web_bridge_py);
        if (d.nightwatch_halo_html) setHtmlCode(d.nightwatch_halo_html);
      })
      .catch(() => {});
  }, [open]);

  if (!open) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard?.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  const handleDownload = (filename: string, content: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadProjectZip = async () => {
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
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-label="部署与源码导出"
    >
      <div className="flex max-h-[86vh] w-full max-w-4xl flex-col border border-[#3a3e46] bg-[#0e0f12] text-[#cfd2d8]">
        <div className="flex items-center justify-between border-b border-[#25282e] px-4 py-2.5">
          <div className="flex items-center gap-3">
            <strong className="text-xs tracking-widest text-[#f4f5f7]">
              NIGHTWATCH × HALOFLUX // 零侵入部署包与源码导出
            </strong>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleDownloadProjectZip}
              className="pill on"
            >
              ⬇ 一键下载完整工程 (.zip)
            </button>
            <button
              type="button"
              onClick={() => setTab('guide')}
              className={`pill ${tab === 'guide' ? 'on' : ''}`}
            >
              部署指南
            </button>
            <button
              type="button"
              onClick={() => setTab('py')}
              className={`pill ${tab === 'py' ? 'on' : ''}`}
            >
              scripts/web_bridge.py
            </button>
            <button
              type="button"
              onClick={() => setTab('html')}
              className={`pill ${tab === 'html' ? 'on' : ''}`}
            >
              nightwatch-halo.html
            </button>
            <button
              type="button"
              onClick={onClose}
              className="pill"
              aria-label="关闭导出窗口"
            >
              ✕ 关闭
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 text-xs leading-relaxed">
          {tab === 'guide' && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 border border-[#38bdf8] bg-[#0c1520] p-3.5">
                <div>
                  <h4 className="mb-1 text-xs font-extrabold text-[#38bdf8]">
                    📦 一键打包下载完整项目到本地电脑 (nightwatch-haloflux-v2.zip)
                  </h4>
                  <p className="text-[11px] text-[#cfd2d8]">
                    包含最新「对称双球 V2 + 双方血量与具体操作框」与保留的「经典八栏 V1」全套 React/Express 源码及 Python 桥接脚本。解压后执行 <code>npm install &amp;&amp; npm run dev</code> 即可在本地运行。
                  </p>
                </div>
                <button
                  type="button"
                  onClick={handleDownloadProjectZip}
                  className="pill on px-4 py-2 text-xs font-extrabold"
                >
                  ⬇ 立即下载 nightwatch-haloflux-v2.zip
                </button>
              </div>

              <div className="border border-[#25282e] bg-[#08090b] p-3">
                <h4 className="mb-1.5 text-[11px] font-bold text-[#38bdf8]">
                  1. 架构亮点：零侵入 SQLite WAL 只读轮询 + 实时 SSE
                </h4>
                <p className="text-[11px] text-[#cfd2d8]">
                  无需改动 Nightwatch <code>daemon</code> 或 <code>battle --tui</code> 核心代码。
                  <code>scripts/web_bridge.py</code> 以只读 URI 模式（<code>?mode=ro</code>）每 0.35s 轮询{' '}
                  <code>data/nightwatch.db</code> 的 <code>events</code> 与 <code>bans</code> 表，通过{' '}
                  <code>/events</code> SSE 实时推送给前端，并提供严格校验 IPv4 的{' '}
                  <code>POST /api/unban</code> 与 <code>POST /api/sim</code>。
                </p>
              </div>

              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <div className="border border-[#25282e] bg-[#08090b] p-3">
                  <h4 className="mb-1.5 text-[11px] font-bold text-[#98e0cf]">
                    玩法一：Windows / 本机直接双击离线演习
                  </h4>
                  <p className="mb-2 text-[11px] text-[#6b6f78]">
                    保存 <code>docs/haloflux/nightwatch-halo.html</code> 后直接用浏览器打开：
                  </p>
                  <ul className="list-disc space-y-1 pl-4 text-[11px] text-[#cfd2d8]">
                    <li>自动进入 <code>DEMO REPLAY</code> 模式，每 4.2s 循环演示完整攻防剧本</li>
                    <li>支持右上角 6 个手动战术演习按钮 + 快捷键 C / M / S / H / F</li>
                  </ul>
                  <button
                    type="button"
                    onClick={() =>
                      handleDownload('nightwatch-halo.html', htmlCode, 'text/html;charset=utf-8')
                    }
                    className="pill on mt-3"
                  >
                    ⤓ 下载 nightwatch-halo.html
                  </button>
                </div>

                <div className="border border-[#25282e] bg-[#08090b] p-3">
                  <h4 className="mb-1.5 text-[11px] font-bold text-[#f0a6c6]">
                    玩法二：Ubuntu 24.04 实机联动 Kali 攻防演示
                  </h4>
                  <pre className="overflow-x-auto bg-[#0c0e12] p-2 text-[10px] text-[#f4f5f7]">
{`# 1. 在守夜人宿主机启动只读 SSE 桥接
cd ~/nightwatch
.venv/bin/python scripts/web_bridge.py --host 127.0.0.1 --port 8765

# 2. 本机 SSH 端口转发安全访问
ssh -L 8765:127.0.0.1:8765 li@10.2.102.143`}
                  </pre>
                  <button
                    type="button"
                    onClick={() =>
                      handleDownload('web_bridge.py', pyCode, 'text/x-python;charset=utf-8')
                    }
                    className="pill on mt-3"
                  >
                    ⤓ 下载 scripts/web_bridge.py
                  </button>
                </div>
              </div>
            </div>
          )}

          {tab === 'py' && (
            <div>
              <div className="mb-2 flex items-center justify-between">
                <span className="text-[11px] text-[#6b6f78]">
                  文件路径：<code>scripts/web_bridge.py</code>（Python 3.12 零第三方依赖）
                </span>
                <div className="flex gap-2">
                  <button type="button" onClick={() => handleCopy(pyCode)} className="pill">
                    {copied ? '✓ 已复制' : '复制代码'}
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      handleDownload('web_bridge.py', pyCode, 'text/x-python;charset=utf-8')
                    }
                    className="pill on"
                  >
                    ⤓ 下载 .py
                  </button>
                </div>
              </div>
              <pre className="max-h-[58vh] overflow-auto border border-[#25282e] bg-[#08090b] p-3 text-[10.5px] leading-snug text-[#f4f5f7]">
                {pyCode}
              </pre>
            </div>
          )}

          {tab === 'html' && (
            <div>
              <div className="mb-2 flex items-center justify-between">
                <span className="text-[11px] text-[#6b6f78]">
                  文件路径：<code>docs/haloflux/nightwatch-halo.html</code>（完整单文件前端）
                </span>
                <div className="flex gap-2">
                  <button type="button" onClick={() => handleCopy(htmlCode)} className="pill">
                    {copied ? '✓ 已复制' : '复制代码'}
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      handleDownload('nightwatch-halo.html', htmlCode, 'text/html;charset=utf-8')
                    }
                    className="pill on"
                  >
                    ⤓ 下载 .html
                  </button>
                </div>
              </div>
              <pre className="max-h-[58vh] overflow-auto border border-[#25282e] bg-[#08090b] p-3 text-[10.5px] leading-snug text-[#f4f5f7]">
                {htmlCode}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
