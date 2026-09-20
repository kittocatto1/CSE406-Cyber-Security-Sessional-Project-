#!/usr/bin/env bash
set -uo pipefail

DURATION="${1:-600}"
SERVER_PORT=5201
ALIAS_CLIENT_SUFFIX=201
ALIAS_SERVER_SUFFIX=202
BASELINE_SECONDS=15
MIDPOINT_SECONDS=120

LOG_DIR="$(mktemp -d /tmp/wifi_attack1.XXXXXX)"
CLIENT_LOG="$LOG_DIR/client.log"
SERVER_LOG="$LOG_DIR/server.log"

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


ADDED_CLIENT_ALIAS=0
ADDED_SERVER_ALIAS=0
SET_ACCEPT_LOCAL=0
ORIG_ACCEPT_LOCAL_IFACE=""
ORIG_ACCEPT_LOCAL_ALL=""
SERVER_PID=""
CLIENT_PID=""
MID_SNAPSHOT_PID=""
IFACE=""
CLIENT_IP=""
SERVER_IP=""


cleanup() {
    echo
    echo "⦿ Cleaning up..."

    [[ -n "$CLIENT_PID" ]] && kill "$CLIENT_PID" 2>/dev/null
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
    [[ -n "$MID_SNAPSHOT_PID" ]] && kill "$MID_SNAPSHOT_PID" 2>/dev/null

    if [[ "$ADDED_CLIENT_ALIAS" == 1 ]]; then
        ip addr del "${CLIENT_IP}/24" dev "$IFACE" 2>/dev/null
    fi

    if [[ "$ADDED_SERVER_ALIAS" == 1 ]]; then
        ip addr del "${SERVER_IP}/24" dev "$IFACE" 2>/dev/null
    fi

    if [[ "$SET_ACCEPT_LOCAL" == 1 ]]; then
        sysctl -w \
            "net.ipv4.conf.${IFACE}.accept_local=${ORIG_ACCEPT_LOCAL_IFACE}" \
            >/dev/null 2>&1

        sysctl -w \
            "net.ipv4.conf.all.accept_local=${ORIG_ACCEPT_LOCAL_ALL}" \
            >/dev/null 2>&1
    fi

    echo "⦿ Cleanup done."
}

trap cleanup EXIT INT TERM


step "Checking root privileges"

if [[ $EUID -ne 0 ]]; then
    fail "must run as root: sudo ./run_cs_wifi.sh"
fi

ok "running as root"


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

GATEWAY="$(ip route show default | awk '/default/ {print $3; exit}')"

if [[ -z "$OWN_IP" || -z "$GATEWAY" ]]; then
    fail "could not detect IP/gateway on $IFACE."
fi

PREFIX="$(echo "$OWN_IP" | cut -d. -f1-3)"

CLIENT_IP="${PREFIX}.${ALIAS_CLIENT_SUFFIX}"
SERVER_IP="${PREFIX}.${ALIAS_SERVER_SUFFIX}"

ok "interface=$IFACE"
ok "own IP=$OWN_IP"
ok "gateway=$GATEWAY"

echo "    planned aliases:"
echo "        client = $CLIENT_IP"
echo "        server = $SERVER_IP"
echo "    (assumes a /24 subnet)"


step "Checking alias IPs are not already in use"

for ip_to_check in "$CLIENT_IP" "$SERVER_IP"; do
    if ping -c1 -W1 "$ip_to_check" >/dev/null 2>&1; then
        fail "$ip_to_check already responds to ping. Pick different alias suffixes."
    fi
done

ok "both alias IPs are free"


step "Adding IP aliases to $IFACE"

if ! ip addr add \
    "${CLIENT_IP}/24" \
    dev "$IFACE" \
    label "${IFACE}:client" \
    2>/dev/null; then

    fail "could not add $CLIENT_IP to $IFACE"
fi

ADDED_CLIENT_ALIAS=1


if ! ip addr add \
    "${SERVER_IP}/24" \
    dev "$IFACE" \
    label "${IFACE}:server" \
    2>/dev/null; then

    fail "could not add $SERVER_IP to $IFACE"
fi

ADDED_SERVER_ALIAS=1

ok "aliases added"

ip -brief addr show "$IFACE"


step "Enabling accept_local on $IFACE"

ORIG_ACCEPT_LOCAL_IFACE="$(
    sysctl -n \
        "net.ipv4.conf.${IFACE}.accept_local" \
        2>/dev/null || echo 0
)"

ORIG_ACCEPT_LOCAL_ALL="$(
    sysctl -n \
        net.ipv4.conf.all.accept_local \
        2>/dev/null || echo 0
)"

if ! sysctl -w \
    "net.ipv4.conf.${IFACE}.accept_local=1" \
    >/dev/null 2>&1 || \
   ! sysctl -w \
    "net.ipv4.conf.all.accept_local=1" \
    >/dev/null 2>&1; then

    fail "could not set accept_local on $IFACE"
fi

SET_ACCEPT_LOCAL=1

ok "accept_local enabled on $IFACE and all"
ok "original values will be restored on exit"


step "Clearing stale route/PMTU cache"

ip route flush cache

ok "route cache flushed"


step "Checking firewall"

if command -v ufw >/dev/null 2>&1 &&
   ufw status | grep -q "Status: active"; then

    ufw allow "$SERVER_PORT"/tcp >/dev/null
    ufw allow proto icmp from any >/dev/null 2>&1 || true

    ok "ufw active - opened tcp/$SERVER_PORT and icmp"
else
    ok "ufw not active"
fi


step "Checking iperf3"

if ! command -v iperf3 >/dev/null 2>&1; then
    fail "iperf3 not found. Install it with: sudo apt install iperf3"
fi

ok "iperf3 found"


step "Starting iperf3 server"

iperf3 \
    -s \
    -B "$SERVER_IP" \
    -p "$SERVER_PORT" \
    > "$SERVER_LOG" 2>&1 &

SERVER_PID=$!

sleep 1

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "    --- server log ---"
    cat "$SERVER_LOG"
    echo "    -----------------"

    SERVER_PID=""

    fail "iperf3 server exited immediately"
fi

ok "server running (pid $SERVER_PID)"
ok "server log: $SERVER_LOG"


step "Starting iperf3 client"

iperf3 \
    -c "$SERVER_IP" \
    -p "$SERVER_PORT" \
    -B "$CLIENT_IP" \
    -t "$DURATION" \
    > "$CLIENT_LOG" 2>&1 &

CLIENT_PID=$!
CONN_START="$(date +%s)"

sleep 2

if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    echo "    --- client log ---"
    cat "$CLIENT_LOG"
    echo "    -----------------"

    CLIENT_PID=""

    fail "iperf3 client exited immediately"
fi

ok "client running (pid $CLIENT_PID)"


step "Extracting client ephemeral port"

CLIENT_PORT=""

for i in 1 2 3 4 5; do

    CLIENT_PORT="$(
        ss -tnp 2>/dev/null |
        awk -v ip="$CLIENT_IP" -v port=":$SERVER_PORT" \
        '$4 ~ ip && $5 ~ port {
            split($4,a,":")
            print a[2]
            exit
        }'
    )"

    [[ -n "$CLIENT_PORT" ]] && break

    sleep 1
done

if [[ -z "$CLIENT_PORT" ]]; then
    fail "could not find the established connection in ss output. Check $CLIENT_LOG"
fi

ok "client ephemeral port = $CLIENT_PORT"


echo
echo "⦿ Connection ready"
echo
echo "    Client IP   : $CLIENT_IP"
echo "    Server IP   : $SERVER_IP"
echo "    Client port : $CLIENT_PORT"
echo "    Server port : $SERVER_PORT"
echo
echo "    Friend can run:"
echo "        sudo ./run_attack1_wifi.sh $CLIENT_PORT"
echo "        sudo ./run_attack2_wifi.sh $CLIENT_PORT"
echo

echo "⦿ Client log: $CLIENT_LOG"
echo "⦿ Waiting ${BASELINE_SECONDS}s for a clean baseline..."

sleep "$BASELINE_SECONDS"


BEFORE_ROUTE="$(ip route get "$SERVER_IP" from "$CLIENT_IP" 2>&1)"
BEFORE_SS="$(ss -tin "( sport = :$CLIENT_PORT )" 2>&1)"

BEFORE_MTU="$(
    echo "$BEFORE_ROUTE" |
    grep -oE 'mtu[a-z ]*[0-9]+' |
    head -1
)"

BEFORE_MSS="$(
    echo "$BEFORE_SS" |
    grep -oE 'mss:[0-9]+' |
    head -1
)"


echo
echo "⦿ PMTU/MSS BEFORE attack:"
echo "    ${BEFORE_MTU:-mtu n/a}  ${BEFORE_MSS:-mss n/a}"
echo
echo "    Tell your friend to start the attack now."
echo


(
    NOW="$(date +%s)"
    REMAIN=$((MIDPOINT_SECONDS - (NOW - CONN_START)))

    if (( REMAIN > 0 )); then
        sleep "$REMAIN"
    fi

    MID_ROUTE="$(ip route get "$SERVER_IP" from "$CLIENT_IP" 2>&1)"
    MID_SS="$(ss -tin "( sport = :$CLIENT_PORT )" 2>&1)"

    MID_MTU="$(
        echo "$MID_ROUTE" |
        grep -oE 'mtu[a-z ]*[0-9]+' |
        head -1
    )"

    MID_MSS="$(
        echo "$MID_SS" |
        grep -oE 'mss:[0-9]+' |
        head -1
    )"

    echo
    echo "⦿ PMTU/MSS UNDER ATTACK (~${MIDPOINT_SECONDS}s):"
    echo "    ${MID_MTU:-mtu n/a}  ${MID_MSS:-mss n/a}"

) &

MID_SNAPSHOT_PID=$!


echo
echo "⦿ Tailing iperf3 client output..."
echo "    Press Ctrl+C when you're done."
echo


tail -f "$CLIENT_LOG" &

TAIL_PID=$!

wait "$CLIENT_PID" 2>/dev/null

kill "$TAIL_PID" 2>/dev/null


echo
echo "⦿ iperf3 client finished."


AFTER_ROUTE="$(ip route get "$SERVER_IP" from "$CLIENT_IP" 2>&1)"
AFTER_SS="$(ss -tin "( sport = :$CLIENT_PORT )" 2>&1)"

AFTER_MTU="$(
    echo "$AFTER_ROUTE" |
    grep -oE 'mtu[a-z ]*[0-9]+' |
    head -1
)"

AFTER_MSS="$(
    echo "$AFTER_SS" |
    grep -oE 'mss:[0-9]+' |
    head -1
)"


echo
echo "⦿ PMTU/MSS comparison:"
echo "    BEFORE: ${BEFORE_MTU:-mtu n/a}  ${BEFORE_MSS:-mss n/a}"
echo "    AFTER : ${AFTER_MTU:-mtu n/a}  ${AFTER_MSS:-mss n/a}"


if [[ -s "$CLIENT_LOG" ]]; then

    echo
    echo "⦿ Throughput analysis:"
    echo "    Baseline = first ${BASELINE_SECONDS}s"
    echo "    Attacked  = remaining time"

    awk -v baseline="$BASELINE_SECONDS" '
        $3 ~ /^[0-9.]+-[0-9.]+$/ && $4 == "sec" {
            split($3, t, "-")
            dur = t[2] - t[1]

            if (dur > 0.9 && dur < 1.1) {
                rate = $7
                unit = $8

                if (unit == "Gbits/sec")
                    rate *= 1000
                else if (unit == "Kbits/sec")
                    rate /= 1000

                if (t[1] < baseline) {
                    base_sum += rate
                    base_n++
                }
                else {
                    atk_sum += rate
                    atk_n++
                }
            }
        }

        END {
            if (base_n == 0 || atk_n == 0) {
                print "    Not enough interval samples on both sides of the baseline."
                exit
            }

            base_avg = base_sum / base_n
            atk_avg = atk_sum / atk_n

            reduction = (base_avg - atk_avg) / base_avg * 100

            printf "    Baseline avg (%d samples): %.1f Mbits/sec\n",
                   base_n, base_avg

            printf "    Attacked avg (%d samples): %.1f Mbits/sec\n",
                   atk_n, atk_avg

            printf "    Throughput reduction: %.1f%%\n",
                   reduction
        }
    ' "$CLIENT_LOG"

fi