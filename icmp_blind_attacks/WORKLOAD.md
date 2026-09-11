# Workload Split — Anisa (2105036) & Debashri (2105035)

Rule: **Anisa builds the foundation first**, which unblocks Debashri. The split
is fair — each owns roughly half the modules AND owns the defense for their own
attack.

## Anisa — foundation + Attack 1 (do these first, in order)
1. `setup/` — namespaces, veth, bridge, teardown, topology  *(everything waits on this)*
2. `common/config.py` + `common/packet_utils.py` — shared config & packet builders
3. `baseline/` — victim iperf3 flow + capture helper
4. `attack1_reset/` — off-path tuple inference + blind reset + orchestration
5. `defense/defense_seqcheck.md` — Attack-1 before/after kernel comparison

> Debashri cannot start the attacks until #1-#2 exist (both attacks import
> `common/`). That is the intended dependency.

## Debashri — Attack 2 + defense + analysis (starts once common/ is ready)
1. `attack2_throughput/pmtu_attack.py` — Attack 2a (PMTU), the primary vector
2. `attack2_throughput/source_quench.py` — Attack 2b (secondary / may be a no-op)
3. `attack2_throughput/run_attack2.sh` — orchestration + ss timeline
4. `defense/defense_pmtu_floor.sh` (+ `plpmtud.sh` stretch) — Attack-2 defense
5. `analysis/` — collect_metrics + plot_results (graphs for the whole report)

## Handoff point
When Anisa finishes `common/` + `setup/`, Debashri can build and test Attack 2
in parallel while Anisa finishes Attack 1. Shared files (`README`, `WORKLOAD`)
edited by whoever touches them.

Rough balance: Anisa ≈ 10 files (setup-heavy, Attack 1), Debashri ≈ 8 files
(both Attack-2 vectors, defense, all analysis/plotting).
