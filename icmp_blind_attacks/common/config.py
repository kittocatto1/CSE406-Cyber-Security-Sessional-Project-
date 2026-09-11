"""
config.py  —  Single source of truth for the whole lab.
Owner: ANISA (foundation — everything else imports from here)

Every IP, port, interface name and MTU value used by the attacks and the
setup scripts lives HERE. If you change the topology, change it in ONE place.
This matches the topology in the design report (§2.1) and Attack fields (§3).
"""

# ---------------------------------------------------------------------------
# Network namespaces (see setup/setup_namespaces.sh which creates these)
# Three hosts live as isolated netns on ONE machine, joined by a bridge.
# ---------------------------------------------------------------------------
NS_CLIENT   = "client"    # Victim A — opens the long-lived TCP connection
NS_SERVER   = "server"    # Victim B — accepts the connection, sends bulk data
NS_ATTACKER = "attacker"  # Off-path — can only send spoofed packets

# IP addresses on the shared bridge subnet 10.0.0.0/24
IP_CLIENT   = "10.0.0.1"
IP_SERVER   = "10.0.0.2"
IP_ATTACKER = "10.0.0.3"
IP_ROUTER   = "10.0.0.254"   # spoofed source for the PMTU attack (§3.3)

# Interface names (veth ends that live INSIDE each namespace)
VETH_CLIENT   = "veth-cl"
VETH_SERVER   = "veth-sv"
VETH_ATTACKER = "veth-at"
BRIDGE        = "br-lab"

# ---------------------------------------------------------------------------
# TCP connection under attack
# The victim connection is Client -> Server on a well-known service port.
# Off-path attacker KNOWS both IPs + server port, but must GUESS client port.
# ---------------------------------------------------------------------------
SERVER_PORT = 5201            # iperf3 default — the "well-known" port (§3.2)
CLIENT_PORT_RANGE = (32768, 60999)  # Linux ephemeral range to brute-force (§Phase 3)

# ---------------------------------------------------------------------------
# Attack-specific values
# ---------------------------------------------------------------------------
# Attack 1 (Blind Reset): embedded TCP seq must look in-window (§3.2).
# On the stock kernel this is validated; on custom-5.15 the check is relaxed.
GUESSED_SEQ = 0              # TODO: sweep a range; see attack1_reset/infer_tuple.py

# Attack 2a (PMTU): a deliberately tiny Next-Hop MTU forces the sender to
# shrink its MSS -> fragmentation/overhead -> throughput drops (§3.3).
SPOOFED_MTU = 68             # smallest legal IPv4 MTU; report suggests 68-500

# Defense (Attack 2a): min_pmtu floor the Client will refuse to go below (§6).
PMTU_FLOOR = 1200
