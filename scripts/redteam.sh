#!/usr/bin/env bash
# 红队自测：每个用例只打实验网授权资产，产出攻击→检测→封禁→证据矩阵。
set -uo pipefail
cd "$(dirname "$0")/.."
CLI=./nightwatch
OUT=data/reports
mkdir -p "$OUT" data/wordlists
printf 'wrong1\nwrong2\nwrong3\nwrong4\nwrong5\nwrong6\nwrong7\nwrong8\nwrong9\nwrong10\n' \
  > data/wordlists/lab10.txt

if ! ip netns list | grep -q '^nw-attacker'; then
  sudo bash scripts/lab_netns.sh up
fi

clear_bans() {
  "$CLI" bans --json 2>/dev/null | python3 -c "
import json,sys,subprocess
for b in json.load(sys.stdin):
    subprocess.run(['./nightwatch','unban',b['ip']],capture_output=True)
" 2>/dev/null || true
  "$CLI" flush >/dev/null 2>&1 || true
  sleep 0.5
}

base_id() {
  "$CLI" events --json --limit 1 2>/dev/null \
    | python3 -c "import json,sys;d=json.load(sys.stdin);print(d[-1]['id'] if d else 0)" 2>/dev/null || echo 0
}

nft_ips() {
  "$CLI" fw-status --json 2>/dev/null | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
print(','.join(str(e.get('ip','')) for e in d.get('entries',[]) if e.get('ip')))
"
}

md="$OUT/redteam-matrix.md"
json="$OUT/redteam-matrix.json"
echo "# 红队验证矩阵" > "$md"
echo "" >> "$md"
echo "生成时间：$(date '+%F %T %Z')" >> "$md"
echo "" >> "$md"
echo "| # | 用例 | 工具/命令 | 目标 | 期望 | 观测 rule_id | 处置 | 账本事件 | nft 命中 | 链校验 |" >> "$md"
echo "|---|---|---|---|---|---|---|---|---|---|" >> "$md"
json_items=()

run_case() {
  local id=$1 name=$2 expected=$3 tool=$4
  echo "== $id $name =="
  clear_bans
  local base
  base=$(base_id)
  timeout 90 bash scripts/lab_run.sh "$tool" >/tmp/red_$id.log 2>&1 || true
  sleep 2
  local ev
  ev=$("$CLI" events --json --since "$base" --limit 200 2>/dev/null || echo '[]')
  local rule_txt act_txt id_txt
  rule_txt=$(echo "$ev" | python3 -c "
import json,sys
rules=[]
for r in json.load(sys.stdin):
    e=r.get('evidence',{})
    if e.get('signature'): rules.append(e['signature'][:40])
    if e.get('reason_code'): rules.append(e['reason_code'])
    if e.get('crs_rule'): rules.append('CRS-'+str(e['crs_rule']))
print(' / '.join(dict.fromkeys(rules)) or '-')
" 2>/dev/null)
  act_txt=$(echo "$ev" | python3 -c "
import json,sys
a=[]
for r in json.load(sys.stdin):
    e=r.get('evidence',{})
    if e.get('action'): a.append(e['action'])
print(' / '.join(dict.fromkeys(a)) or '-')
" 2>/dev/null)
  id_txt=$(echo "$ev" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(','.join(str(r['id']) for r in d[-6:]) or '-')
" 2>/dev/null)
  local nft hit ch
  nft=$(nft_ips)
  hit=$(echo "$nft" | grep -q '10.200.0.2' && echo yes || echo no)
  ch=$("$CLI" chain --json 2>/dev/null | python3 -c "import json,sys;print('ok' if json.load(sys.stdin).get('ok') else 'bad')" 2>/dev/null)
  echo "| $id | $name | $tool | 10.200.0.1 | $expected | $rule_txt | $act_txt | $id_txt | $hit | $ch |" >> "$md"
  json_items+=("{\"id\":\"$id\",\"name\":\"$name\",\"tool\":\"$tool\",\"expected\":\"$expected\",\"rules\":\"$rule_txt\",\"actions\":\"$act_txt\",\"events\":\"$id_txt\",\"nft_hit\":\"$hit\",\"chain\":\"$ch\"}")
  echo "  rules=$rule_txt | action=$act_txt | nft=$hit | chain=$ch"
}

run_case T1 "端口扫描" "NET_SCAN" t1
run_case T2 "Web 扫描器" "WAF_SCANNER / NET_SCAN" t2
run_case T3 "HTTP 爆破" "BRUTE_FORCE / WAF_SCANNER" t3
run_case T4 "SQL 注入" "WAF_SQLI / WAF_SCANNER" t4
run_case T5 "反射 XSS" "WAF_XSS" t5
run_case T6 "SYN Flood" "NET_DOS / NET_SCAN" t6
run_case T7 "HTTP Flood" "HTTP_FLOOD" t7

# T8：显式封禁 10.200.0.2，再验证 22 仍可达
clear_bans
sudo -n /usr/local/sbin/nw-fw ban 10.200.0.2 120 >/dev/null 2>&1 || true
ssh_ok=$(bash scripts/lab_run.sh t8 2>/dev/null | grep -c SSH_REACHABLE || true)
nft_hit=$(nft_ips | grep -c '10.200.0.2' || true)
echo "| T8 | SSH 永可达 | t8 | 10.200.0.1:22 | 封禁中仍连通 | - | - | - | hit=$nft_hit | - |" >> "$md"
json_items+=("{\"id\":\"T8\",\"name\":\"SSH reachable\",\"ssh_ok\":$ssh_ok,\"nft_hit\":$nft_hit}")
echo "== T8 SSH == ssh_ok=$ssh_ok nft_hit=$nft_hit"

# T9：回滚后 nft 清空
clear_bans
sleep 0.5
after=$("$CLI" fw-status --json 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin).get('count',-1))" 2>/dev/null)
echo "| T9 | 一键回滚 | cli unban+flush | - | nft 集合为空 | - | rollback | - | count=$after | - |" >> "$md"
json_items+=("{\"id\":\"T9\",\"name\":\"rollback\",\"nft_count\":$after}")
printf '[%s]\n' "$(IFS=,; echo "${json_items[*]}")" > "$json"
echo "矩阵：$md"
