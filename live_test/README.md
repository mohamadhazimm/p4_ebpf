# Live tests: P4 (Tofino model) + eBPF on one machine

Scripts to run the hybrid monitor on the real components of this machine
(the compiled `basic.p4` on `tofino-model` + `bf_switchd`, and the eBPF
monitors) and to check what they measure. Everything here is benign:
synthetic packets, a synthetic PCAP, and the repository's `testers/`.

All commands run from the repository root and need root. Outputs go to
`live_test/run/` (process logs) and `live_test/results/` (git-ignored).

## 1. Build

```sh
make -C libbpf-bootstrap/examples/c hostmon modelmon
cd thesis-hybrid-ebpf-p4 && $SDE_INSTALL/bin/p4c --target tofino --arch tna --std p4-16 -g \
    --log-hashes --bf-rt-schema basic.tofino/bf-rt.json -o basic.tofino basic.p4 && cd ..
```

The compiled hash must equal `flow_index.py` (bf-p4c 9.13.4 names hash tables
`exact hashtable N`, the checker expects `Hash N`):

```sh
mkdir -p /tmp/hc/pipe/logs
sed -E 's/^exact hashtable ([0-9]+)$/Hash \1/' thesis-hybrid-ebpf-p4/basic.tofino/pipe/logs/mau.hashes.log \
    > /tmp/hc/pipe/logs/mau.hashes.log
python3 perf/tools/hash_block_identify.py /tmp/hc      # every slice: "flow index" / "new-conn dst index"
```

## 2. Testbed

```sh
sudo live_test/testbed.sh up            # ~45 s: veths, model, bf_switchd, ports 0-2, forwarding 0<->1, mirror -> port 2
sudo live_test/testbed.sh status
sudo live_test/testbed.sh mode live     # namespaces p4int (10.0.0.1) / p4ext (10.0.0.2) + servers
sudo live_test/testbed.sh mode replay   # host ends without IPs, for injecting frames
python3 thesis-hybrid-ebpf-p4/python/reset_registers.py   # ~200 s on the model; the collector runs it itself
sudo live_test/testbed.sh down
```

`up` starts bf_switchd with `--skip-port-add` and adds only ports 0-2
(`P4_FAST=0` adds all 288 model ports: 35 minutes here). The model and
bf_switchd busy-poll about 2.3 CPU cores while up. `P4_BUILD=/path/to/basic.tofino`
starts another compiled build. The release repo's validations use its
`p4/basic.tofino` this way (see [RESULTS.md](RESULTS.md), 2026-11-04).

The collector clears all registers at the start of every run (~200 s on the
model, `--no-register-reset` skips it); before that fix, flows landing in buckets
left from the previous run were never reported and never read. Register reads on
the model take 10-45 s
(`--p4-snapshot sync`) or ~0.27 s per active bucket (`hw`), so use windows of
40-60 s with `--p4-snapshot hw --clear-idle-windows 0`; the default 10 s windows
overrun on the model (not on the switch).

Model ports: 0 = `veth1` (internal), 1 = `veth3` (external), 2 = `veth5`
(CPU reports). Frames enter port 0 when sent on `veth0`, port 1 when sent on
`veth2`. In `live` mode, `veth0` is in netns `p4int` and `veth2` in netns
`p4ext`, so traffic from a workload started with `ip netns exec p4int ...` to
10.0.0.2 crosses the pipeline both ways, and daemons of the root namespace
(avahi, systemd-resolved) add nothing to the P4 counters.

## 3. Tests

| Script | What it checks |
| --- | --- |
| `p4_known_answer.py` | crafted flows: forwarding, CPU reports (fields, `flow_index`), all registers, `reg_newconn_dst`, clear and re-report |
| `ebpf_known_answer.py` | `modelmon` and `hostmon` counts per syscall variant, against matched baseline runs |
| `run_pcap_test.sh` (`make_benign_pcap.py`, `collector_probe.py`, `analyze_run.py`) | the collector in PCAP mode on a synthetic benign capture with exact ground truth; per-flow, per-window and offline-extractor parity |
| `run_command_test.sh` (`benign_workload.sh`, `gate.py`, `collector_probe.py --modelmon-gate`) | the collector in command mode on benign testers whose traffic crosses the switch, with `modelmon` on the workload tree |
| `check_live_export.py` | `live_feature_export.summarize_register_window` on a run's real register reads |
| `analyze_host.py` | which processes a run's host features come from |

```sh
sudo env WIN=60 INTERVAL=0.1 EXTRA="--p4-snapshot hw --clear-idle-windows 0" live_test/run_pcap_test.sh
sudo env WIN=40 EXTRA="--p4-snapshot hw --clear-idle-windows 0" live_test/run_command_test.sh mixed
python3 live_test/analyze_host.py --run-dir live_test/results/cmd_mixed_w40_...
```

`collector_probe.py` runs `hybrid_collector.main()` unchanged and only logs
what the CSV leaves out (window origin, register snapshot times, rows, process
PIDs); it also stops the hostmon the collector leaves running. Results are in
[RESULTS.md](RESULTS.md). On 2026-11-03 that was this repo's collector. On 2026-11-04 it was the
release repo's three validations, with the commands used on this VM.
