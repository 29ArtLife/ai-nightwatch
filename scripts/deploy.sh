#!/usr/bin/env bash
# 在目标机 /home/li/nightwatch 已上传代码后执行：bash scripts/deploy.sh
set -euo pipefail
cd "$(dirname "$0")/.."
echo "[1/6] venv + deps"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q -U pip
.venv/bin/pip install -q -r requirements.txt

echo "[2/6] dirs"
mkdir -p data logs osv
chmod 700 data

echo "[3/6] install units"
sudo install -m 644 deploy/nightwatch.service deploy/nightwatch-demo.service \
  deploy/nightwatch-fakessh.service /etc/systemd/system/

echo "[4/6] reload + enable"
sudo systemctl daemon-reload
sudo systemctl enable nightwatch nightwatch-demo nightwatch-fakessh

echo "[5/6] restart"
sudo systemctl restart nightwatch nightwatch-demo nightwatch-fakessh
sleep 2

echo "[6/6] verify"
systemctl is-active nightwatch nightwatch-demo nightwatch-fakessh
ss -lntp | grep -E ':(8080|8081|2222)\b' || true
curl -s http://127.0.0.1:8080/api/health && echo
echo "token: $(cat data/token.txt)"
