#!/usr/bin/env bash
set -uo pipefail

ALIAS_CLIENT_SUFFIX=201
ALIAS_SERVER_SUFFIX=202

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

STEP=0

step() {
    STEP=$((STEP+1))
    echo
    echo "⦿ STEP $STEP: $1"
}

ok() {
    echo "    ✓ OK: $1"
}

fail() {
    echo "    ✗ FAILED: $1"
    echo
    echo "Stopped at STEP $STEP."
    exit 1
}


CLIENT_PORT="${1:-}"
DURATION="${2:-120}"
TARGET_MTU="${3:-68}"
INTERVAL="${4:-2}"


step "Checking arguments"

if [[ -z "$CLIENT_PORT" ]]; then
    fail "no client port given.

Usage:
    sudo ./run_attack2_wifi.sh <client_port> [duration_s] [target_mtu] [interval_s]

The client port is printed by run_cs_wifi.sh on the other machine."
fi

ok "client port = $CLIENT_PORT"
ok "duration = ${DURATION}s"
ok "target MTU = $TARGET_MTU"
ok "interval = ${INTERVAL}s"


step "Checking root privileges"

if [[ $EUID -ne 0 ]]; then
    fail "must run as root:
sudo ./run_attack2_wifi.sh $CLIENT_PORT"
fi

ok "running as root"


step "Checking python3"

if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 not found."
fi

ok "python3 found"


step "Checking scapy"

if ! python3 -c "import scapy.all" >/dev/null 2>&1; then
    fail "scapy not installed for this python3."
fi

ok "scapy import OK"


if [[ -z "${CLIENT_IP:-}" || -z "${SERVER_IP:-}" ]]; then

    step "Detecting network interface and subnet"

    IFACE="$(ip route show default | awk '/default/ {print $5; exit}')"

    if [[ -z "$IFACE" ]]; then
        fail "could not detect default network interface. Are you connected to WiFi?"
    fi

    OWN_IP="$(
        ip -4 -brief addr show "$IFACE" |
        awk '{print $3}' |
        cut -d/ -f1
    )"

    if [[ -z "$OWN_IP" ]]; then
        fail "could not detect an IP on $IFACE."
    fi

    PREFIX="$(echo "$OWN_IP" | cut -d. -f1-3)"

    CLIENT_IP="${PREFIX}.${ALIAS_CLIENT_SUFFIX}"
    SERVER_IP="${PREFIX}.${ALIAS_SERVER_SUFFIX}"

    ok "interface=$IFACE"
    ok "own IP=$OWN_IP"
    ok "client=$CLIENT_IP"
    ok "server=$SERVER_IP"

else

    step "Using CLIENT_IP/SERVER_IP from environment"

    ok "client=$CLIENT_IP"
    ok "server=$SERVER_IP"

fi


step "Checking reachability to $CLIENT_IP"

if ! ping -c2 -W1 "$CLIENT_IP" >/dev/null 2>&1; then
    fail "$CLIENT_IP unreachable. Check the WiFi connection and make sure run_cs_wifi.sh is running."
fi

ok "$CLIENT_IP reachable"


step "Checking reachability to $SERVER_IP"

if ! ping -c2 -W1 "$SERVER_IP" >/dev/null 2>&1; then
    fail "$SERVER_IP unreachable."
fi

ok "$SERVER_IP reachable"


step "Locating attack2_pmtu_wifi.py"

ATTACK_SCRIPT="$SCRIPT_DIR/attack2_pmtu_wifi.py"

if [[ ! -f "$ATTACK_SCRIPT" ]]; then
    fail "attack2_pmtu_wifi.py not found in $SCRIPT_DIR."
fi

ok "found $ATTACK_SCRIPT"


step "Launching attack"

echo
echo "⦿ Attack configuration:"
echo "    Client      : $CLIENT_IP"
echo "    Server      : $SERVER_IP"
echo "    Client port : $CLIENT_PORT"
echo "    Duration    : ${DURATION}s"
echo "    Target MTU  : $TARGET_MTU"
echo "    Interval    : ${INTERVAL}s"
echo

python3 "$ATTACK_SCRIPT" \
    "$CLIENT_PORT" \
    "$DURATION" \
    "$TARGET_MTU" \
    "$INTERVAL" \
    "$CLIENT_IP" \
    "$SERVER_IP"

STATUS=$?

echo

if [[ $STATUS -ne 0 ]]; then
    fail "attack2_pmtu_wifi.py exited with status $STATUS."
fi

ok "attack finished"
echo "⦿ Check the iperf3 client's terminal on the other machine for the throughput reduction %."