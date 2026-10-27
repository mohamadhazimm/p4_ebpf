# P4_Code - DNS water-torture detector for Intel Tofino

This is the detector source version used for the successful physical NETLAB Tofino tests, including the normal-path drop-flag initialization fix and ASIC timestamp instrumentation. The project folder is P4_Code and the top-level program is basic.p4, matching the original names. Baseline programs, old build products, raw results and backup files are excluded.

The P4 executable logic is unchanged from the instrumented detector package. Code comments and Python documentation strings have been removed; required compiler directives and the shell interpreter line remain. The top-level filename and build/loader references use basic. Recompile to generate artifacts and the bfrt.basic namespace for this name. No renamed binaries are supplied.

## Files

- p4src/basic.p4 and its eight accompanying P4 source files.
- bfrt_python/setup.py: two IPv4 forwarding routes, two score-to-tier rules and the 42 scoring rows.
- bfrt_python/score_entries_ratio.py: the same scoring rows used in the tests.
- scripts/build.sh: NETLAB SDE compilation helper.
- scripts/send_probes.py, collect_reports.py and probe_format.py: the tested packet generation, decoding and collection code.
- SOURCE_MANIFEST.json: source provenance and file checksums.

## Compile on NETLAB SDE 9.6.0

Extract P4_Code.zip into /root so the folder is /root/P4_Code. In a switch Linux shell:

```bash
cd /root/P4_Code
source /root/P4_labs/lab2/config_env.sh
bash scripts/build.sh
```

The helper invokes bf-p4c for p4src/basic.p4 and installs basic.conf and its BFRT/pipeline artifacts. For a source-only compiler invocation from p4src, the original form is bf-p4c -b tofino basic.p4; installing and loading the complete SDE program requires the generated configuration and artifacts.

## Load and configure

For an isolated NETLAB run, source the SDE environment, then start /root/bf-sde-9.6.0/run_switchd.sh -p basic. In bfshell use ucli, configure the same physical ports, then return to bfshell and enter bfrt_python. The verified port mapping in this experiment was front-panel 1/0 -> device 132 and front-panel 2/0 -> device 140, both 100G RS FEC. Verify the mapping before reusing it.

In UCLI, run these separately:

```text
pm port-add 1/- 100G RS
pm port-add 2/- 100G RS
pm port-enb 1/-
pm port-enb 2/-
pm show
```

At bfrt_root, load the detector tables with this single line:

```python
import os; os.environ["P4_CODE_ROOT"] = "/root/P4_Code"; os.environ["P4_SOURCE_PORT"] = "132"; os.environ["P4_SINK_PORT"] = "140"; exec(compile(open("/root/P4_Code/bfrt_python/setup.py").read(), "/root/P4_Code/bfrt_python/setup.py", "exec"))
```

For another deployment set P4_CODE_ROOT and the two actual device ports. The setup script uses the new bfrt.basic namespace and does not access the unused drop_policy table eliminated by the compiler.

## Packet measurement

Copy scripts to PC1 and PC2. Start the collector on PC2, wait for READY, then run the sender on PC1. Use the verified PC2 eth1 MAC address (the example below is the tested NETLAB value).

PC2:

```bash
sudo python3 collect_reports.py --iface eth1 --expected-count 1010 --warmup 10 --seconds 60 --out detector_run1
```

PC1:

```bash
sudo python3 send_probes.py --iface eth1 --dst-mac 04:3f:72:d2:ec:5f --count 1010 --rate 100 --log sent_run1.jsonl
```

The collector writes packet_latencies.csv, reports.pcap and summary.json. The probe payload and report format retain their tested names and layout so decoding remains unchanged. Use fresh output directories.

## Measurement scope

This version keeps the instrumented detector: an 8-byte internal timestamp bridge and 20-byte output report. The ASIC supplies two 48-bit timestamps in nanoseconds; subtraction wraps modulo2^48. The boundary is ingress-parser arrival to egress-parser arrival, including ingress processing and intervening traffic-manager buffering. It excludes remaining egress processing, output MAC, links and BlueField. Units do not establish 1 ns accuracy.

UDP output uses lab EtherType 0x88BC and is a measurement report, rather than an ordinary DNS packet for a resolver. No qualified BlueField service heartbeat was used in the physical tests; suspicious traffic followed direct forwarding. This ZIP contains the P4-side code and NETLAB loader/probes, not the full BlueField implementation. It uses no recirculation. The forwarding baseline used for the comparison is intentionally not included.
