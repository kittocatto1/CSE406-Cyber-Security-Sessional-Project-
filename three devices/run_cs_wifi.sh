#!/usr/bin/env bash
set -euo pipefail


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
RESET='\033[0m'
LAVENDER='\033[38;5;183m'
PINK='\033[38;5;205m'


# SERVER_IP="192.168.0.102"     # iPad IP
SERVER_IP="10.249.138.192"
DURATION="${2:-300}"    # 5 minutes by default 
SERVER_PORT=5201
BASELINE_SECONDS=10 # Clean baseline period   
MIDPOINT_SECONDS=60 

CLIENT_LOG="/tmp/iperf_client.log"

TAIL_PID=""
MID_SNAPSHOT_PID=""
PMTU_MONITOR_PID=""

cleanup() {
    [[ -n "$TAIL_PID" ]] && kill "$TAIL_PID" 2>/dev/null || true
    [[ -n "$MID_SNAPSHOT_PID" ]] && kill "$MID_SNAPSHOT_PID" 2>/dev/null || true
    [[ -n "$PMTU_MONITOR_PID" ]] && kill "$PMTU_MONITOR_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM


if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}✗ Please run this script with sudo.${RESET}"
    echo "  Example: sudo ./run_cs_wifi.sh"
    exit 1
fi

if ! command -v iperf3 >/dev/null; then
    echo -e "${RED}✗ iperf3 is not installed.${RESET}"
    exit 1
fi

echo "iPad server : $SERVER_IP:$SERVER_PORT"
echo "Duration    : ${DURATION}s"
echo

# -----------------------------
# TEST CONNECTION
# -----------------------------

echo -e "${BLUE}⦿${RESET} Checking connection to the iPad"

if ! ping -c 2 -W 1 "$SERVER_IP" >/dev/null 2>&1; then
    echo -e "${RED}Cannot reach the iPad${RESET}"
    exit 1
fi

echo -e "${GREEN}iPad is reachable.${RESET}"
echo

echo -e "${BLUE}⦿${RESET} Clearing cached routing/PMTU state"

ip route flush cache

echo -e "${BLUE}⦿${RESET} Starting the TCP connection"

iperf3 \
    -c "$SERVER_IP" \
    -p "$SERVER_PORT" \
    -t "$DURATION" \
    -i 1 \
    > "$CLIENT_LOG" 2>&1 &

CLIENT_PID=$!
CONN_START="$(date +%s)"

sleep 2

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo -e "${RED}iperf3 failed to start.${RESET}"
    cat "$CLIENT_LOG"
    exit 1
fi


echo "    TCP connection is running."
echo

echo -e "${BLUE}⦿${RESET} Finding the client's TCP port..."

CLIENT_PORT=""

for i in {1..10}; do

    CLIENT_PORT="$(
        ss -tnp 2>/dev/null |
        awk -v server="$SERVER_IP:$SERVER_PORT" '
            $5 ~ server {
                split($4,a,":")
                print a[length(a)]
                exit
            }
        '
    )"

    [[ -n "$CLIENT_PORT" ]] && break

    sleep 1
done

if [[ -z "$CLIENT_PORT" ]]; then
    echo -e "${RED}Could not find the TCP connection.${RESET}"
    exit 1
fi

echo -e "${GREEN}Client port:${RESET} ${CYAN}$CLIENT_PORT${RESET}"
echo

(
    while kill -0 "$CLIENT_PID" 2>/dev/null; do
        ROUTE="$(ip route get "$SERVER_IP" 2>&1)" || true
        SS_OUT="$(ss -tin "( sport = :$CLIENT_PORT )" 2>&1)" || true

        IFACE="$(ip route get "$SERVER_IP" | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')"

        # If Linux has a PMTU exception, show it
        MTU="$(echo "$ROUTE" | grep -oE 'mtu[a-z ]*[0-9]+' | grep -oE '[0-9]+$' | head -1)" || true

        # Otherwise show the actual interface MTU
        if [[ -z "$MTU" ]]; then
            MTU="$(ip link show "$IFACE" | grep -oE 'mtu [0-9]+' | awk '{print $2}')"
        fi
        MSS="$(echo "$SS_OUT" | grep -oE 'mss:[0-9]+' | head -1)" || true

        echo -e "$(date '+%H:%M:%S')  ${PINK}pmtu:${MTU:-mtu n/a}  ${LAVENDER}${MSS:-mss n/a}${RESET}"

        sleep 2
    done
) &
PMTU_MONITOR_PID=$!


echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${WHITE}              CONNECTION READY${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo
echo -e "  ${CYAN}SERVER_IP${RESET}   = $SERVER_IP"
echo -e "  ${CYAN}CLIENT_PORT${RESET} = $CLIENT_PORT"
echo -e "  ${CYAN}SERVER_PORT${RESET} = $SERVER_PORT"
echo

echo -e "${YELLOW}The TCP connection is now live${RESET}"
echo

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo

# -----------------------------
# BASELINE
# -----------------------------

echo -e "${YELLOW}Waiting ${BASELINE_SECONDS}s to collect a clean baseline...${RESET}"
sleep "$BASELINE_SECONDS"

echo
echo -e "${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║            BASELINE COMPLETE             ║${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${RESET}"
echo

echo -e "${YELLOW}⚡ Start the attack now${RESET}"
echo

echo -e "${BLUE}Current TCP connection:${RESET}"
ss -tin | grep -A2 "$SERVER_IP:$SERVER_PORT" || true
echo

echo -e "${CYAN}────────────── LIVE THROUGHPUT ──────────────${RESET}"
echo

tail -f "$CLIENT_LOG" &
TAIL_PID=$!

wait "$CLIENT_PID" || true

kill "$TAIL_PID" 2>/dev/null || true

echo
echo -e "${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║               TEST FINISHED              ║${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${RESET}"

# -----------------------------
# THROUGHPUT BEFORE/AFTER ANALYSIS
# Splits iperf3's 1-second interval lines at BASELINE_SECONDS and averages
# each side.
# -----------------------------

if [[ -s "$CLIENT_LOG" ]]; then
    echo
    echo -e "${CYAN}────────────── THROUGHPUT ──────────────────${RESET}"
    echo

    awk -v baseline="$BASELINE_SECONDS" '
        $3 ~ /^[0-9.]+-[0-9.]+$/ && $4 == "sec" {
            split($3, t, "-")
            dur = t[2] - t[1]
            if (dur > 0.9 && dur < 1.1) {
                rate = $7; unit = $8
                if (unit == "Gbits/sec") rate *= 1000
                else if (unit == "Kbits/sec") rate /= 1000
                if (t[1] < baseline) { base_sum += rate; base_n++ }
                else                 { atk_sum  += rate; atk_n++  }
            }
        }
        END {
            if (base_n == 0 || atk_n == 0) {
                print "    not enough interval samples on both sides of the "baseline"s mark to compare"
                exit
            }
            base_avg = base_sum / base_n
            atk_avg  = atk_sum  / atk_n
            reduction = (base_avg - atk_avg) / base_avg * 100
            printf "    Baseline avg (%d samples): %.1f Mbits/sec\n", base_n, base_avg
            printf "    Attacked avg (%d samples): %.1f Mbits/sec\n", atk_n, atk_avg
            printf "    Throughput reduction: %.1f%%\n", reduction
        }
    ' "$CLIENT_LOG"

echo
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${WHITE}Full iperf3 log:${RESET}"
echo -e "${CYAN}$CLIENT_LOG${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
fi

echo
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${WHITE}Full iperf3 log:${RESET}"
echo -e "${CYAN}$CLIENT_LOG${RESET}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"