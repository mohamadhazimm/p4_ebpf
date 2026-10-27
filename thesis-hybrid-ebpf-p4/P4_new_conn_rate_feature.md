# Add data-plane feature: per-destination new-connection rate (connection-flood detector)

**Target:** `p4_ebpf/thesis-hybrid-ebpf-p4/ingress.p4` (TNA, bf-p4c 9.6.0). Matches the existing
`Register`/`RegisterAction`/`Hash<CRC16>` style and `FLOW_BUCKETS = 65536`.

## Why (one paragraph, keep the ML out of the data plane)
The existing `reg_syn` counts SYNs **per flow** (5-tuple bucket). A connection flood (e.g. GoldenEye)
opens thousands of *distinct* 5-tuples to one server, so each flow bucket sees ~1 SYN and the flood is
invisible. This feature adds a counter that aggregates new-connection attempts **per (client, server,
server-port)** — i.e. "how many new connections is one source opening to one service this window."
Offline this feature separated GoldenEye (~1,400 new-conn/s) from all benign web traffic (<=100/s) with
zero false positives. The data plane only **exports the count**; the threshold/decision stays in the
model, exactly like the other P4 features.

## 1. Declarations — add beside the other Register/RegisterAction/Hash decls

```p4
/* ---- per-destination new-connection (SYN & !ACK) counter ---- */
const bit<32> DST_BUCKETS = 65536;

/* DIRECTIONAL hash over (client, server, server-port, proto), WITHOUT the source port.
 * Excluding l4_sport is what makes every ephemeral connection from one client to one
 * service collapse into ONE bucket (that is the whole point). Do NOT add @symmetric here
 * and do NOT reuse crc16_hasher (it is @symmetric + 5-tuple). Field list is plain fields
 * only -- bf-p4c 9.6.0 drops arithmetic inside a Hash field list. */
Hash<bit<16>>(HashAlgorithm_t.CRC16) crc16_dsthash;

Register<bit<32>, bit<16>>(DST_BUCKETS) reg_newconn_dst;
RegisterAction<bit<32>, bit<16>, bit<32>>(reg_newconn_dst) newconn_dst_inc = {
    void apply(inout bit<32> v, out bit<32> rv) {
        v  = v + 32w1;   /* <= ~10^6 per window for any in-window flood; no 32-bit wrap */
        rv = v;
    }
};
```

## 2. Apply logic — inside the existing `if (hdr.tcp.isValid())` flags block
Right next to where `syn_inc.execute(idx)` already runs. Note the mask is **SYN set AND ACK clear**
(a *new* connection attempt), which is stricter than the existing `reg_syn` test `(f & 9w0x002) != 0`:

```p4
if (hdr.tcp.isValid()) {
    bit<9> f = hdr.tcp.flags;

    // ... existing syn_inc / rst_inc / ack_inc stay as they are ...

    /* new-connection attempt = SYN set, ACK clear */
    if ((f & 9w0x012) == 9w0x002) {
        bit<16> ndx = crc16_dsthash.get({ hdr.ipv4.srcAddr,
                                          hdr.ipv4.dstAddr,
                                          meta.l4_dport,
                                          hdr.ipv4.protocol });
        newconn_dst_inc.execute(ndx);
    }
}
```

## 3. Control-plane export (mirror `reg_syn` exactly)
Wherever the control plane snapshots **and zeroes** the per-flow registers at each collection-window
boundary (the same sweep that produces `syn_count` from `reg_syn`):
- read + clear `reg_newconn_dst` the same way;
- export it as a new per-window feature, e.g. `p4_new_conn_dst` (raw count per window). If you want a
  rate, `rate = count / window_seconds` (0.5 s windows -> multiply by 2); the model can also just use
  the raw per-window count.

## 4. REQUIRED parity on the offline/training side (do not skip)
The host-side training/inference features are reconstructed offline from PCAPs
(`p4_ebpf/analyze_p4_pcap_ablation.py`, `python/flow_index.py`). Add the **identical** computation
there so training and data-plane features match: per window, count TCP segments with
`SYN set & ACK clear`, grouped by key `(srcAddr, dstAddr, dstPort, protocol)` (NOT the symmetric
5-tuple), and emit the same `p4_new_conn_dst` column. If the two definitions drift, the model sees a
different feature at train vs deploy.

## 5. Resources / fit
One register (65536 x 32b = 256 KB SRAM), one stateful ALU, one CRC16 hash unit, ~1 ingress stage.
Measured headroom is ample (5/12 ingress stages, 20.5% SRAM, 14/48 stateful ALUs used). Hash-collision
aliasing is identical to the existing 65,536-bucket design: two keys in one bucket only ever *over*-count
toward "attack," never hide one, which is harmless for a flood detector.

**Note on the bucket count (measured 2026-10-27; 65,536 kept for now).** The register costs two ingress
stages, not one. At 32 bits, 65,536 entries need 17 map RAMs, and none of stages 0–4 has that many free,
so the compiler moves 8 flow registers one or two stages later. 16,384 buckets (a 14-bit index: the low
14 bits of the same CRC) need 5 map RAMs and fit into stage 0 without moving anything:

| Destination buckets | Ingress stages | Map RAM | Latency estimate (ingress) |
|---|---|---|---|
| none (deployed `basic_fix`) | 5 | 196 | 131 cycles |
| 65,536 (this spec, kept) | 7 | 213 | 158 cycles |
| 16,384 | 5 | 201 | 131 cycles |

The cost of 16,384 is aliasing: of K active keys, a key shares its bucket with probability about
K/16,384 instead of K/65,536 (about 1–2% at a few hundred keys), and a shared bucket only adds counts.
Both sizes passed 12/12 checks on the switch (`p4_perf.md` §5.4). To switch: `DST_BUCKETS = 16384` and
`bit<14>` for the four index types in `ingress.p4` (hash, register, register action, `ndx`), the low 14
bits in `flow_index.compute_newconn_dst_index()`, and `DST_BUCKETS` in `read_registers_with_index.py`.

## 6. Compile + validate
- `bf-p4c` compile; confirm it fits (expect +1 stage, no table/SRAM pressure).
- Sanity on the model/hardware or against the offline reconstruction over the existing flood captures:
  - GoldenEye: ~700 new-conns per 0.5 s window (~1,400/s).
  - SYN floods: far higher.
  - Benign bulk/session/beacon/DNS: <= ~50 per window (<=100/s).
  A window threshold around 75 separates GoldenEye with zero benign false positives (the model learns this;
  the number is just a sanity check).

## Scope note (honest)
This closes the **connection-flood** gap (GoldenEye; and un-capped SYN/HTTP connection floods). It does
NOT solve a deliberately low-and-slow HTTP GET flood whose connection rate matches a real client — that is
the irreducible L7/flash-crowd case and no payload-free feature separates it.
