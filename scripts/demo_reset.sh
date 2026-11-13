#!/usr/bin/env bash
# 演示前一键重置：解封全部、清 nft、清 AI WAF 规则、暂停 daemon autopilot。
set -euo pipefail
cd "$(dirname "$0")/.."

./nightwatch bans --json 2>/dev/null | python3 -c "
import json,sys,subprocess
for b in json.load(sys.stdin):
    subprocess.run(['./nightwatch','unban',b['ip']], capture_output=True)
" 2>/dev/null || true

./nightwatch flush >/dev/null 2>&1 || true
sudo /usr/local/sbin/nw-waf clear >/dev/null 2>&1 || true
./nightwatch autopilot off >/dev/null 2>&1 || true

echo "=== demo reset ==="
./nightwatch status | head -6
echo "active bans:"; ./nightwatch bans
echo "waf rules:"; sudo /usr/local/sbin/nw-waf list 2>/dev/null || true
