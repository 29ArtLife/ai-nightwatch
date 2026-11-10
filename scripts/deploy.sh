#!/usr/bin/env bash
# 在目标机 /home/li/nightwatch 已上传代码后执行：bash scripts/deploy.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[1/9] venv + deps"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q -U pip
.venv/bin/pip install -q -r requirements.txt

echo "[2/9] dirs"
mkdir -p data logs osv
chmod 700 data

echo "[3/9] nftables wrapper + sudoers + allowlist"
if command -v nft >/dev/null; then
  sudo install -d -m 755 /etc/nftables.d /etc/nightwatch
  sudo install -m 644 deploy/nftables-nightwatch.nft /etc/nftables.d/nightwatch.nft
  sudo install -m 755 deploy/nw-fw /usr/local/sbin/nw-fw
  sudo install -m 644 deploy/fw-allow /etc/nightwatch/fw-allow
  sudo install -m 440 deploy/sudoers.d/nightwatch /etc/sudoers.d/nightwatch
  sudo visudo -c >/dev/null
  sudo /usr/local/sbin/nw-fw init
else
  echo "WARN: nftables 未安装，跳过（apt install nftables）"
fi

echo "[4/9] nginx + ModSecurity 配置"
if command -v nginx >/dev/null; then
  sudo install -m 644 deploy/nginx/nightwatch.conf /etc/nginx/sites-available/nightwatch
  sudo ln -sf /etc/nginx/sites-available/nightwatch /etc/nginx/sites-enabled/nightwatch
  sudo install -d -m 755 /etc/nginx/modsec /var/lib/modsecurity/data /tmp/modsecurity
  sudo install -m 644 deploy/nginx/modsec/main.conf /etc/nginx/modsec/main.conf
  sudo install -m 644 deploy/nginx/modsec/crs-overrides.conf /etc/nginx/modsec/crs-overrides.conf
  sudo touch /var/log/nginx/modsec_audit.log /var/log/nginx/nw_access.log
  sudo chown www-data:adm /var/log/nginx/modsec_audit.log /var/log/nginx/nw_access.log
  sudo chmod 640 /var/log/nginx/modsec_audit.log /var/log/nginx/nw_access.log
  sudo nginx -t
  sudo systemctl reload nginx || true
else
  echo "WARN: nginx 未安装，跳过"
fi

echo "[5/9] logrotate + suricata local rules"
sudo install -m 644 deploy/logrotate.d/nightwatch /etc/logrotate.d/nightwatch
if [ -d /var/lib/suricata/rules ]; then
  sudo install -m 644 deploy/suricata/local.rules /var/lib/suricata/rules/local.rules
  [ -f /var/lib/suricata/rules/suricata.rules ] || \
    echo "WARN: 缺少 suricata.rules，请先下载 ET Open 规则"
fi

echo "[6/9] install units"
sudo install -m 644 deploy/nightwatch.service deploy/nightwatch-demo.service \
  deploy/nightwatch-fakessh.service /etc/systemd/system/

echo "[7/9] reload + enable"
sudo systemctl daemon-reload
sudo systemctl enable nightwatch nightwatch-demo nightwatch-fakessh
command -v nginx >/dev/null && sudo systemctl enable nginx || true
command -v suricata >/dev/null && sudo systemctl enable suricata || true

echo "[8/9] restart"
sudo systemctl restart nightwatch nightwatch-demo nightwatch-fakessh
command -v nginx >/dev/null && sudo systemctl restart nginx || true
if command -v suricata >/dev/null && [ -f /var/lib/suricata/rules/suricata.rules ]; then
  sudo systemctl restart suricata || echo "WARN: suricata 启动失败（查看 journal）"
fi
sleep 2

echo "[9/9] verify"
systemctl is-active nightwatch nightwatch-demo nightwatch-fakessh || true
ss -lntp | grep -E ':(8080|8081|8082|2222)\b' || true
curl -s http://127.0.0.1:8080/api/health && echo
echo "token: $(cat data/token.txt)"
