#!/usr/bin/env bash
# ===========================================================================
# setup_namespaces.sh  —  Build the 3-host lab topology (report §2.1, §2.2)
# Owner: ANISA (foundation — nothing runs until this works)
#
#   client(10.0.0.1) ---\
#   server(10.0.0.2) ----[ br-lab bridge ]---- attacker(10.0.0.3)
#
# All three are Linux network namespaces on ONE machine, joined by veth pairs
# to a virtual bridge. The Attacker sits on the same bridge but is kept
# OFF-PATH: it can send spoofed packets but cannot sniff/ARP-spoof the real
# Client<->Server traffic (that "off-path" property is the whole point).
#
# Run as root:  sudo ./setup_namespaces.sh
# ===========================================================================
set -euo pipefail

# --- read the names/IPs from the ONE config so nothing drifts -------------
# (kept as plain values here so the script is standalone; must match config.py)
CLIENT=client;   SERVER=server;   ATTACKER=attacker
IP_CL=10.0.0.1;  IP_SV=10.0.0.2;  IP_AT=10.0.0.3
BR=br-lab

echo "[*] Creating namespaces..."
for ns in "$CLIENT" "$SERVER" "$ATTACKER"; do
    ip netns add "$ns"
done

echo "[*] Creating bridge on the host..."
ip link add "$BR" type bridge
ip link set "$BR" up

# helper: connect one namespace to the bridge with a veth pair
attach() {           # $1 = namespace, $2 = ip/prefix, $3 = inner ifname
    local ns="$1" ip_addr="$2" inner="$3" outer="v-${1}"
    ip link add "$inner" netns "$ns" type veth peer name "$outer"
    ip link set "$outer" master "$BR" up            # host end -> bridge
    ip netns exec "$ns" ip addr add "$ip_addr/24" dev "$inner"
    ip netns exec "$ns" ip link set "$inner" up
    ip netns exec "$ns" ip link set lo up
}

echo "[*] Attaching client, server, attacker..."
attach "$CLIENT"   "$IP_CL" veth-cl
attach "$SERVER"   "$IP_SV" veth-sv
attach "$ATTACKER" "$IP_AT" veth-at

echo "[+] Topology up. Quick check:"
ip netns exec "$CLIENT" ping -c1 -W1 "$IP_SV" && echo "    client<->server OK"

# TODO(Anisa): to make the attacker truly OFF-PATH for Attack 2's PMTU story,
# add a router namespace so client<->server traffic transits it while the
# attacker hangs off a side interface. For a first demo the shared bridge is
# enough to show blind spoofing. Document this choice in the final report §2.2.
