@echo off
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
