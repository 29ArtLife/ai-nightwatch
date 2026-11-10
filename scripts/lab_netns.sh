#!/usr/bin/env bash
# 授权实验网：veth 对 + 独立 netns，攻击侧没有默认路由，物理上打不到外网。
set -euo pipefail
NS=nw-attacker
HOST_IF=nw-kali0
PEER_IF=nw-peer
HOST_IP=10.200.0.1/30
PEER_IP=10.200.0.2/30

need_root() { [[ $(id -u) -eq 0 ]] || { echo "需要 root：sudo $0 $*" >&2; exit 2; }; }

up() {
    need_root up
    if ip netns list | grep -q "^${NS}\b"; then echo "already up"; return; fi
    ip netns add "$NS"
    ip link add "$HOST_IF" type veth peer name "$PEER_IF"
    ip link set "$PEER_IF" netns "$NS"
    ip addr add "$HOST_IP" dev "$HOST_IF"
    ip link set "$HOST_IF" up
    ip netns exec "$NS" ip addr add "$PEER_IP" dev "$PEER_IF"
    ip netns exec "$NS" ip link set "$PEER_IF" up
    ip netns exec "$NS" ip link set lo up
    echo "up: $HOST_IF=$(echo "$HOST_IP" | cut -d/ -f1) <-> $NS:$PEER_IF=$(echo "$PEER_IP" | cut -d/ -f1)"
}

down() {
    need_root down
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true
    echo "down"
}

status() {
    ip netns list | grep "^${NS}" || true
    echo "--- host if ---"
    ip -br addr show "$HOST_IF" 2>/dev/null || true
    echo "--- attacker routes (must have no default) ---"
    ip netns exec "$NS" ip route 2>/dev/null || true
    echo "--- default route count ---"
    ip netns exec "$NS" ip route 2>/dev/null | grep -c "^default" || true
}

case ${1:-} in
    up) up ;;
    down) down ;;
    status) status ;;
    *) echo "用法: $0 {up|down|status}" >&2; exit 2 ;;
esac
