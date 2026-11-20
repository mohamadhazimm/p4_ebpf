# sockowner: which process and cgroup each flow belongs to

The dataset joined the switch's view and the host's view **by time window**: the network features of
an execution are computed from every flow the host had in the same windows. That is exact when one
program runs at a time, and wrong as soon as other programs share the host (see the committee
analysis, `committee-eval-20261113/REPORT.md` section 4: one malicious co-runner makes 46-58% of the
benign programs beside it look malicious). `sockowner` gives the collector a **socket-level join**:
for every TCP/UDP 5-tuple a local socket sends or receives, the socket, its cgroup and the process
that created it.

## How it works

Four eBPF programs attached to one cgroup v2 (the root by default, so every process is seen):

| Program | Runs | Records |
|---|---|---|
| `cgroup_skb/egress` | for each IPv4 packet a socket in the cgroup sends | first packet of each 5-tuple on a socket: `FLOW` (5-tuple, socket cookie, the socket's cgroup id) |
| `cgroup_skb/ingress` | for each IPv4 packet delivered to a socket in the cgroup | the same; copies delivered to raw sockets are ignored |
| `cgroup/sock_create` | in the creating process, at `socket()` | `SOCK` (cookie, tgid, tid, the task's cgroup, comm) |
| `cgroup/sock_release` | at the socket's release | `REL` |

The 5-tuple is taken from the packet itself, so it is the key the switch's flow table uses (raw
sockets included: a raw-socket SYN flood is attributed to the process that opened the raw socket).
Later packets of a known 5-tuple on the same socket cost one hash lookup and emit nothing, so the
event rate is the new-flow rate, not the packet rate. The cgroup of a flow is the socket's cgroup, so
when the collector puts each monitored execution in its own cgroup (as it does for `hostmon_agg`),
`FLOW` alone attributes the flow to the execution; `SOCK` adds the process.

Not covered: accepted TCP sockets are created by the kernel, so they have no `SOCK` event (their
`FLOW` events carry the listener's cgroup); packets the kernel sends without a full socket (RSTs for
closed ports, ICMP errors, TIME_WAIT replies) belong to no process and are not recorded; IPv6 is not
parsed (the switch program parses IPv4 only).

## Output

```
SOCKOWNER_READY,<cgroup id>
SOCK,<ns>,<cookie>,<tgid>,<tid>,<cgroup id>,<family>,<type>,<protocol>,<comm>
REL,<ns>,<cookie>,<tgid>,<tid>,<cgroup id>,<comm>
FLOW,<ns>,<cookie>,<socket cgroup id>,<egress|ingress>,<tcp|udp>,<saddr>,<sport>,<daddr>,<dport>
SOCKOWNER_HEALTH,<ring-buffer drops>,<flow-map errors>,<failed>
```

`<ns>` is CLOCK_MONOTONIC, the clock of `hostmon_agg`'s windows. A kernel that refuses the socket
programs gets `SOCKOWNER_WARNING,no-socket-programs` and the per-packet programs only.

## Build and run

```sh
./build.sh                                   # no root; same toolchain as ../build.sh
sudo build/sockowner [/sys/fs/cgroup]        # Ctrl-C to stop
```

The join itself is `collector/sockjoin.py` (tests: `tests/test_sockjoin.py`).
`hybrid_collector.py --sockowner build/sockowner --hostmon-cgroup <dir>` runs it during a live run and
writes a second CSV with the network features of the cgroup's own flows (`--socket-join-csv`).
