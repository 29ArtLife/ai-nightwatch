# NIGHTWATCH × HALOFLUX

AI 守夜人的浏览器攻防作战室。V2 以红蓝双球显示攻击、告警和处置过程，并提供 V1 八栏视图。可以使用内置演练，也可以接入已部署的守夜人实验机。

## 离线预览

下载或克隆仓库后，在 Chrome 或 Edge 中打开本目录的 `双击直接打开-红蓝双球攻防大屏V2.html`。这个页面自带演练数据，无需启动 Node.js 服务。
`docs/haloflux/nightwatch-halo.html` 是同一份 V2 页面，`docs/haloflux/nightwatch-halo-v1.html` 是独立 V1 页面。

## 启动开发环境

安装 Node.js 和 npm，在仓库根目录运行以下命令，然后访问 `http://localhost:3000/`。

```bash
cd nightwatch-haloflux
npm install
npm run dev
```

Windows 也可以双击本目录的 `Windows一键启动.bat`。修改前端后可运行 `npm run build` 生成 `dist/`。

## 连接守夜人实验机

桥接脚本按守夜人部署目录定位 `data/nightwatch.db`，以只读方式查询账本并通过 SSE 推送事件。网页上的解封操作由桥接服务调用守夜人 CLI。
在已部署守夜人的实验机上，从仓库根目录运行以下命令，将桥接脚本和页面放到部署目录对应位置。若守夜人部署在其他目录，将命令中的目标路径改为实际部署路径，并在该目录启动桥接。

```bash
mkdir -p docs/haloflux
cp nightwatch-haloflux/scripts/web_bridge.py scripts/web_bridge.py
cp nightwatch-haloflux/docs/haloflux/nightwatch-halo*.html docs/haloflux/
.venv/bin/python scripts/web_bridge.py --host 127.0.0.1 --port 8765
```

从另一台电脑访问时，将 `user@nightwatch-host` 替换为实验机的 SSH 登录地址，在本机运行下面的命令，然后打开 `http://127.0.0.1:8765/`。

```bash
ssh -N -L 8765:127.0.0.1:8765 user@nightwatch-host
```

## 第三方署名

光环视觉基于 HALOFLUX by Ryder191，原始作品按 PolyForm Noncommercial License 1.0.0 授权。[原始许可及版权声明](https://github.com/Ryder191/haloflux/blob/02174503d0f391b1bb2537b8cad75e8e5f9997f2/LICENSE)

```text
Required Notice: Copyright (c) 2026 Ryder191 (RYDER CODE / Ms MAIKEBAIs CAT) - https://github.com/Ryder191/haloflux
Required Notice: Noncommercial use only. Any commercial use is strictly prohibited. No commercial licenses are offered.
```
