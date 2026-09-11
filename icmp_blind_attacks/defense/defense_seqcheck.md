# Defense for Attack 1 — Sequence-in-Window Check
Owner: ANISA (pairs with attack1_reset/)  — report §6

Attack 1 has NO code-based defense to write: the defense already lives in the
Linux kernel, in `tcp_v4_err()` (net/ipv4/tcp_ipv4.c). Before honoring an ICMP
hard error, a compliant kernel checks the embedded TCP sequence number is
inside `[SND.UNA, SND.NXT]`. A blind attacker can't know that number, so the
spoofed packet is dropped.

## How we DEMONSTRATE it (before/after comparison)
Run the *exact same* `attack1_reset` against two kernels:

| Kernel            | Seq check | Expected result        |
|-------------------|-----------|------------------------|
| custom-5.15       | relaxed   | connection RESETS (attack works) |
| stock (unpatched) | active    | packet IGNORED (attack fails)    |

Steps:
1. Boot custom-5.15 -> run `run_attack1.sh` -> capture teardown as evidence.
2. Boot stock kernel -> run the identical attack -> show it does nothing.
3. Put both pcaps / `ss` logs side by side in the report (deliverable d).

## Also test the CONTRAST (report §1)
- Run Attack 2 against the patched kernel too: it should STILL succeed,
  because the seq check only guards hard errors, not soft errors.
