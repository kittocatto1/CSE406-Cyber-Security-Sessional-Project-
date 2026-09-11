# Lab Topology (report §2.1)

```
        +------------------- br-lab (virtual bridge) -------------------+
        |                        |                          |
   veth-cl                   veth-sv                     veth-at
   [ client ns ]            [ server ns ]              [ attacker ns ]
   10.0.0.1                 10.0.0.2                   10.0.0.3
   (Victim A)               (Victim B)                 (off-path)
```

- **Client** opens a long-lived TCP flow to **Server** (iperf3, port 5201).
- **Attacker** can only inject *spoofed* ICMP; it cannot see the real flow.
- Spoofed source IPs used: Server (Attack 1 / 2b) and Router `10.0.0.254` (Attack 2a).

## Kernel note (report §1 "Kernel strategy")
- **Attack 1** needs the *custom-5.15* kernel (relaxed seq check) to succeed.
- **Attack 2** works on the *stock* kernel (soft errors aren't seq-gated).
- Since namespaces share the host kernel, reboot between the two, OR use two laptops.
