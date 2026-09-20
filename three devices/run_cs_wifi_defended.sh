#!/usr/bin/env bash
set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
PURPLE='\033[38;5;135m'
GRAY='\033[38;5;245m'
RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_SCRIPT="$SCRIPT_DIR/run_cs_wifi.sh"

DURATION="${1:-120}"
MIN_PMTU_FLOOR="${2:-1200}"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${RESET} Please run this script as root."
    echo -e "${GRAY}        sudo ./run_cs_wifi_defended.sh [duration] [min_pmtu_floor]${RESET}"
    exit 1
fi

if [[ ! -f "$REAL_SCRIPT" ]]; then
    echo -e "${RED}[ERROR]${RESET} run_cs_wifi.sh was not found."
    echo -e "${GRAY}        Expected location: $REAL_SCRIPT${RESET}"
    exit 1
fi

# sysctl lets us read and change Linux kernel runtime parameters.
ORIG_MIN_PMTU="$(sysctl -n net.ipv4.route.min_pmtu 2>/dev/null || echo 552)"

restore() {
    echo
    echo -e "${YELLOW}[CLEANUP]${RESET} Restoring PMTU floor"
    echo -e "          ${GRAY}$MIN_PMTU_FLOOR -> $ORIG_MIN_PMTU${RESET}"

    sysctl -w \
        net.ipv4.route.min_pmtu="$ORIG_MIN_PMTU" \
        >/dev/null 2>&1

    echo -e "${GREEN}Original PMTU floor restored${RESET} "
}

# Restore the original value when the script exits,
# including Ctrl+C / termination
trap restore EXIT INT TERM

echo
echo -e "${PURPLE}============================================================${RESET}"
echo -e "${WHITE}              PMTU FLOOR DEFENSE ENABLED${RESET}"
echo -e "${PURPLE}============================================================${RESET}"

echo
echo -e "Current PMTU floor : ${YELLOW}$ORIG_MIN_PMTU${RESET}"
echo -e "New PMTU floor     : ${GREEN}$MIN_PMTU_FLOOR${RESET}"
echo

if ! sysctl -w \
    net.ipv4.route.min_pmtu="$MIN_PMTU_FLOOR" \
    >/dev/null; then

    echo -e "${RED}Could not set net.ipv4.route.min_pmtu${RESET} "
    exit 1
fi

echo -e "${GREEN}PMTU floor defense applied${RESET}"


echo
echo -e "${BLUE}[RUN]${RESET} Starting run_cs_wifi.sh"
echo -e "      Duration : ${YELLOW}${DURATION}s${RESET}"

"$REAL_SCRIPT" "" "$DURATION"