"""把 Suricata 默认配置改成实验网可用：HOME_NET、接口、仅 alert 输出、local.rules。"""
import sys

P = "/etc/suricata/suricata.yaml"
lines = open(P, encoding="utf-8").read().splitlines()


def replace_in_section(name, old, new, limit=150):
    try:
        i = next(k for k, l in enumerate(lines) if l.strip() == name)
    except StopIteration:
        return
    for j in range(i, min(i + limit, len(lines))):
        if lines[j].strip() == old:
            lines[j] = new
            return


def replace_block(name, next_name, text):
    try:
        i = next(k for k, l in enumerate(lines) if l.strip() == name)
        j = next(k for k in range(i + 1, len(lines)) if lines[k].strip() == next_name)
    except StopIteration:
        return
    lines[i:j] = text.splitlines()


# wlp1s0 的 AF_PACKET ring 在该无线网卡上初始化失败，改用 pcap；
# veth/lo 用 AF_PACKET，避免抓不到实验网流量。
replace_block("af-packet:", "pcap:",
              "af-packet:\n"
              "  - interface: nw-kali0\n"
              "    cluster-id: 97\n"
              "    cluster-type: cluster_flow\n")
replace_block("pcap:", "pcap-file:",
              "pcap:\n  - interface: wlp1s0\n  - interface: nw-kali0\n")

s = "\n".join(lines)
for old in ('HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"',
            'HOME_NET: "[10.2.102.143/32,127.0.0.1/32,10.200.0.1/32]"'):
    s = s.replace(old, 'HOME_NET: "[10.2.102.143/32,172.20.10.0/28,'
                       '127.0.0.1/32,10.200.0.1/32]"')
s = s.replace('HTTP_PORTS: "80"', 'HTTP_PORTS: "[80,8081,8082]"')
if "- local.rules" not in s and "- suricata.rules" in s:
    s = s.replace("- suricata.rules", "- suricata.rules\n  - local.rules", 1)

lines = s.splitlines()
start = None
for i, l in enumerate(lines):
    if l.strip() == "- eve-log:" and l.startswith("  - "):
        for j in range(i, min(i + 250, len(lines))):
            if lines[j].strip() == "types:" and lines[j].startswith("      "):
                start = j
                break
        break
if start is not None:
    end = start + 1
    while end < len(lines):
        l = lines[end]
        if l.strip() and (len(l) - len(l.lstrip())) <= 6:
            break
        end += 1
    lines[start:end] = ["      types:", "        - alert:",
                        "            tagged-packets: yes"]

open(P, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("patched", P)
