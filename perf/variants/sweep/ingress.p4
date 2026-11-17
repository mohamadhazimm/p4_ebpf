#ifndef P4_ENABLE_FEATURES
#define P4_ENABLE_FEATURES 1
#endif

#ifndef P4_ENABLE_CPU_REPORTS
#define P4_ENABLE_CPU_REPORTS 1
#endif

#if P4_ENABLE_CPU_REPORTS && !P4_ENABLE_FEATURES
#error CPU reports require feature collection
#endif

/* perf/variants/sweep: basic_gtot_ba (perf/variants/gtot -DP4_GLOBAL_TOTALS_SPLIT=1, the deployed bucket table
 * plus seven one-entry totals) whose registers the data plane reads itself.
 *
 * Why. The control plane reads a bucket in ~0.55 ms (14 registers through BF Runtime), so a 0.5 s window
 * covers ~500 buckets; a flood keeps ~30,000 active and the per-flow features become a sample (p4_perf.md
 * 5.6, PC1.md part 4c). Offline (perf/results/exact_gap_analysis), this bucket table read in full at
 * each window boundary, with the frame minimum toward the dataset's guest counted (frame_len), matches
 * the published rows as often as the exact build's 4-way flow table (106 of 110, the same 4 floods
 * failing): the exact build's gain comes from reading every flow at the boundary, not from its table.
 *
 * Probes. A probe (headers.p4: EtherType ETHERTYPE_SWEEP from a port in sweep_ports) names one bucket in
 * the low 16 bits of its destination MAC, where the packet generator writes its packet id. It reads that
 * bucket's 14 registers (and, for bucket 0, the seven totals and the sweep number) into its sweep_t and
 * leaves through sweep_export to the export port, a host that turns the records into the 29 window
 * features (sweep_features.py). A probe changes no register except reg_sweep_seq. A probe of a bucket
 * that was never used (dir_valid 0) is dropped, except bucket 0's, so every sweep exports at least one
 * record (its seq and totals).
 *   - Deployment: the generator's periodic timer sends 65,536 probes (packet ids 0..65535) per window, one
 *     sweep (sweep_reader.py --generator start). The probes of one sweep pass in under 1 ms at the
 *     generator's rate; a bucket is read when its probe passes.
 *   - Replay: the replay host sends the probes itself, in order with the capture's frames, at each
 *     window boundary (replay_absolute.py --probes), as the exact build's window markers: the cut is then
 *     where the probes sit in the packet sequence, whatever the replay's timing.
 *
 * Data packets are counted exactly as in basic_gtot_ba: -DP4_ENABLE_SWEEP=0 -DP4_FRAME_LEN=0 compiles
 * basic_gtot_ba's program (apart from the unused sweep_t declarations).
 *
 * Register indexes. By default the data path addresses the registers straight from the hash unit, as
 * basic_gtot_ba does, and a probe from its destination MAC: two index sources for one register, in
 * mutually exclusive branches. If bf-p4c rejects that, -DSWEEP_SHARED_INDEX=1 puts both indexes into
 * meta.ridx first (the exact build's way of addressing); that may cost the data path a stage. */

/* P4_ENABLE_SWEEP: headers.p4 (default 1) */

#ifndef P4_FRAME_LEN
#define P4_FRAME_LEN 1
#endif

#ifndef SWEEP_SHARED_INDEX
#define SWEEP_SHARED_INDEX 0
#endif

/* -DP4_ENABLE_GLOBAL_TOTALS=0 drops the seven totals (the probes then read none). */
#ifndef P4_ENABLE_GLOBAL_TOTALS
#define P4_ENABLE_GLOBAL_TOTALS 1
#endif

#if P4_ENABLE_GLOBAL_TOTALS && !P4_ENABLE_FEATURES
#error global totals require feature collection
#endif

#if P4_ENABLE_SWEEP && !P4_ENABLE_FEATURES
#error the sweep reads the feature registers
#endif

/* The totals of basic_gtot_ba: B->A in place of the packet and byte totals (gtot's -DP4_GLOBAL_TOTALS_SPLIT=1). */
#ifndef P4_GLOBAL_TOTALS_SPLIT
#define P4_GLOBAL_TOTALS_SPLIT 1
#endif

#if P4_ENABLE_SWEEP && P4_ENABLE_GLOBAL_TOTALS && !P4_GLOBAL_TOTALS_SPLIT
#error the probes read the split totals of basic_gtot_ba
#endif

#if SWEEP_SHARED_INDEX
#define DIDX meta.ridx
#define PIDX meta.ridx
#else
#define DIDX idx
#define PIDX hdr.ethernet.dst[15:0]
#endif

#if P4_ENABLE_FEATURES
const bit<32> FLOW_BUCKETS = 65536;
#endif

control Ingress(
    inout my_headers_t hdr,
    inout my_ingress_metadata_t meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
#if P4_ENABLE_FEATURES
    /* Symmetric flow index: both directions of a connection share a bucket.
     * bf-p4c 9.6.0 drops arithmetic inside a Hash field list (the former
     * {sip^dip, sip+dip, sp^dp, sp+dp, pr} input compiled to a plain CRC of
     * the raw 5-tuple), so the symmetry comes from @symmetric instead. The
     * compiled function is CRC-16/ARC over (0, sip^dip, 0, sp^dp, proto);
     * python/flow_index.py computes the same value. */
    @symmetric("hdr.ipv4.srcAddr", "hdr.ipv4.dstAddr")
    @symmetric("meta.l4_sport", "meta.l4_dport")
    Hash<bit<16>>(HashAlgorithm_t.CRC16) crc16_hasher;

    /* The same index again, for the CPU report. The register addresses take
     * idx straight from the hash unit, and bf-p4c 9.6.0 then never writes idx
     * into a PHV field: copying it into the report would always send 0. */
    @symmetric("hdr.ipv4.srcAddr", "hdr.ipv4.dstAddr")
    @symmetric("meta.l4_sport", "meta.l4_dport")
    Hash<bit<16>>(HashAlgorithm_t.CRC16) crc16_report_hasher;

    /* -------- Core per-flow primitives kept in data plane -------- */
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_pkts;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_bytes;

    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_pkts_ab;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_bytes_ab;

    Register<bit<16>, bit<16>>(FLOW_BUCKETS) reg_ref_src_port;
    Register<bit<16>, bit<16>>(FLOW_BUCKETS) reg_ref_dst_port;
    Register<bit<8>,  bit<16>>(FLOW_BUCKETS) reg_dir_valid;

    Register<bit<16>, bit<16>>(FLOW_BUCKETS) reg_min_len;
    Register<bit<16>, bit<16>>(FLOW_BUCKETS) reg_max_len;

    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_first_ts;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_last_ts;

    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_syn;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_ack;
    Register<bit<32>, bit<16>>(FLOW_BUCKETS) reg_rst;

    /* -------- Counter updates -------- */
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_pkts) pkts_rw = {
        void apply(inout bit<32> v, out bit<32> old) {
            old = v;
            v = v + 32w1;
        }
    };

    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_bytes) bytes_rw = {
        void apply(inout bit<32> v, out bit<32> old) {
            old = v;
            v = v + (bit<32>) meta.pkt_len;
        }
    };

    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_pkts_ab) pkts_ab_update = {
        void apply(inout bit<32> v, out bit<32> old) {
            old = v;
            if (meta.dir_ab == 1w1) {
                v = v + 32w1;
            }
        }
    };

    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_bytes_ab) bytes_ab_update = {
        void apply(inout bit<32> v, out bit<32> old) {
            old = v;
            if (meta.dir_ab == 1w1) {
                v = v + (bit<32>) meta.pkt_len;
            }
        }
    };

    /* -------- Direction reference -------- */
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_dir_valid) dir_valid_rw = {
        void apply(inout bit<8> v, out bit<8> old) {
            old = v;
            if (v == 8w0) {
                v = 8w1;
            }
        }
    };

    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_ref_src_port) ref_src_set = {
        void apply(inout bit<16> v) {
            v = meta.l4_sport;
        }
    };

    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_ref_dst_port) ref_dst_set = {
        void apply(inout bit<16> v) {
            v = meta.l4_dport;
        }
    };

    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_ref_src_port) ref_src_read = {
        void apply(inout bit<16> v, out bit<16> old) {
            old = v;
        }
    };

    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_ref_dst_port) ref_dst_read = {
        void apply(inout bit<16> v, out bit<16> old) {
            old = v;
        }
    };

    /* -------- Packet length min/max -------- */
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_min_len) min_len_update = {
        void apply(inout bit<16> v) {
            bit<16> L = meta.pkt_len;
            if (v == 0 || L < v) {
                v = L;
            }
        }
    };

    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_max_len) max_len_update = {
        void apply(inout bit<16> v) {
            bit<16> L = meta.pkt_len;
            if (L > v) {
                v = L;
            }
        }
    };

    /* -------- Timestamps -------- */
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_first_ts) first_ts_set_if0 = {
        void apply(inout bit<32> v) {
            if (v == 0) {
                v = (bit<32>) ig_intr_md.ingress_mac_tstamp;
            }
        }
    };

    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_last_ts) last_ts_rw = {
        void apply(inout bit<32> v, out bit<32> old) {
            old = v;
            v = (bit<32>) ig_intr_md.ingress_mac_tstamp;
        }
    };

    /* -------- TCP flag counters -------- */
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_syn) syn_inc = {
        void apply(inout bit<32> v, out bit<32> old) {
            old = v;
            v = v + 32w1;
        }
    };

    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_ack) ack_inc = {
        void apply(inout bit<32> v, out bit<32> old) {
            old = v;
            v = v + 32w1;
        }
    };

    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_rst) rst_inc = {
        void apply(inout bit<32> v, out bit<32> old) {
            old = v;
            v = v + 32w1;
        }
    };

#if P4_ENABLE_GLOBAL_TOTALS
    /* -------- Global totals (test build "gtot", PC1.md part 4d) -------- */
    /* One entry each, updated by every packet the flow registers count, with
     * the same values (pkt_len, dir_ab, the TCP flags). A window's totals are
     * the difference of two snapshots, so they stay exact when a flood keeps
     * more buckets active than the control plane can read in a window; in
     * the other windows they equal the sum over the buckets. 32-bit: the byte
     * counters wrap after 4.3 GB per pipe, below the read interval only above
     * ~69 Gb/s per pipe at 0.5 s windows. */
#if P4_GLOBAL_TOTALS_SPLIT
    Register<bit<32>, bit<1>>(1) reg_g_pkts_ba;
    Register<bit<32>, bit<1>>(1) reg_g_bytes_ba;
#else
    Register<bit<32>, bit<1>>(1) reg_g_pkts;
    Register<bit<32>, bit<1>>(1) reg_g_bytes;
#endif
    Register<bit<32>, bit<1>>(1) reg_g_pkts_ab;
    Register<bit<32>, bit<1>>(1) reg_g_bytes_ab;
    Register<bit<32>, bit<1>>(1) reg_g_syn;
    Register<bit<32>, bit<1>>(1) reg_g_ack;
    Register<bit<32>, bit<1>>(1) reg_g_rst;

#if P4_GLOBAL_TOTALS_SPLIT
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_pkts_ba) g_pkts_inc = {
        void apply(inout bit<32> v) {
            if (meta.dir_ab == 1w0) {
                v = v + 32w1;
            }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_bytes_ba) g_bytes_add = {
        void apply(inout bit<32> v) {
            if (meta.dir_ab == 1w0) {
                v = v + (bit<32>) meta.pkt_len;
            }
        }
    };
#else
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_pkts) g_pkts_inc = {
        void apply(inout bit<32> v) { v = v + 32w1; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_bytes) g_bytes_add = {
        void apply(inout bit<32> v) { v = v + (bit<32>) meta.pkt_len; }
    };
#endif
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_pkts_ab) g_pkts_ab_update = {
        void apply(inout bit<32> v) {
            if (meta.dir_ab == 1w1) {
                v = v + 32w1;
            }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_bytes_ab) g_bytes_ab_update = {
        void apply(inout bit<32> v) {
            if (meta.dir_ab == 1w1) {
                v = v + (bit<32>) meta.pkt_len;
            }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_syn) g_syn_inc = {
        void apply(inout bit<32> v) { v = v + 32w1; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_ack) g_ack_inc = {
        void apply(inout bit<32> v) { v = v + 32w1; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_rst) g_rst_inc = {
        void apply(inout bit<32> v) { v = v + 32w1; }
    };
#endif
#endif

#if P4_ENABLE_SWEEP
    /* -------- Sweep: probe reads (headers.p4, sweep_t) -------- */
    /* Each register once per probe, read only; every action here has the probe as its only caller. */
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_ref_src_port) ref_src_get = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
    };
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_ref_dst_port) ref_dst_get = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_pkts) pkts_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_bytes) bytes_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_pkts_ab) pkts_ab_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_bytes_ab) bytes_ab_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(reg_dir_valid) dir_valid_get = {
        void apply(inout bit<8> v, out bit<8> rv) { rv = v; }
    };
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_min_len) min_len_get = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
    };
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_max_len) max_len_get = {
        void apply(inout bit<16> v, out bit<16> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_first_ts) first_ts_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_last_ts) last_ts_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_syn) syn_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_ack) ack_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_rst) rst_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };

#if P4_ENABLE_GLOBAL_TOTALS
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_pkts_ab) g_pkts_ab_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_bytes_ab) g_bytes_ab_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_pkts_ba) g_pkts_ba_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_bytes_ba) g_bytes_ba_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_syn) g_syn_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_ack) g_ack_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_g_rst) g_rst_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
#endif

    /* The sweep number: a probe of bucket 0 starts the next sweep (the generator's packet id 0 comes first in
     * every batch; a replay sends bucket 0 first at every boundary). Every probe carries the number. */
    Register<bit<32>, bit<1>>(1) reg_sweep_seq;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_sweep_seq) seq_next = {
        void apply(inout bit<32> v, out bit<32> rv) { v = v + 32w1; rv = v; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_sweep_seq) seq_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };

    /* every probe / the probes sent to the export port (the others were empty buckets) */
    Counter<bit<32>, bit<1>>(1, CounterType_t.PACKETS) sweep_probes;
    Counter<bit<32>, bit<1>>(1, CounterType_t.PACKETS) sweep_exported;

    /* The export port: the table's default action, set by the control plane (sweep_reader.py --export-port);
     * until then every probe is dropped. */
    action export_to(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.bypass_egress     = 0;
    }

    action export_drop() {
        ig_dprsr_md.drop_ctl       = 3w1;
        ig_tm_md.bypass_egress     = 1w1;
    }

    table sweep_export {
        actions = {
            export_to;
            export_drop;
        }
        default_action = export_drop();
    }
#endif

#if P4_FRAME_LEN
    /* -------- Packet length counted (the exact build's frame_len) -------- */
    /* The dataset counted frames as the monitored guest's own capture saw them: received frames padded to the
     * 60-byte minimum. An entry (sweep_reader.py --frame-min DST/PREFIX) counts packets toward DST as at least
     * 46 B of IPv4; the control plane adds the 14-byte Ethernet header. Empty by default: IPv4 totalLen. */
    action len_set(bit<16> len) {
        meta.pkt_len = len;
    }

    table frame_len {
        key = {
            hdr.ipv4.dstAddr  : ternary;
            hdr.ipv4.totalLen : range;
        }
        actions = {
            len_set;
            NoAction;
        }
        default_action = NoAction();
        size = 64;
    }
#endif

    /* -------- Forwarding -------- */
    action send_using_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.bypass_egress     = 0;
    }

    action drop() {
        ig_dprsr_md.drop_ctl       = 3w1;
        ig_tm_md.bypass_egress     = 1w1;
    }

    table forwarding {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            send_using_port;
            drop;
        }
        const default_action = drop();
        size = 256;
    }

    apply {
#if P4_ENABLE_FEATURES
        meta.dir_ab = 1w1;
#endif

#if P4_ENABLE_CPU_REPORTS
        ig_dprsr_md.mirror_type = 0;

        meta.cpu_mirror_sid       = 0;
        meta.cpu_report.magic     = 16w0;
        meta.cpu_report.src_ip    = 32w0;
        meta.cpu_report.dst_ip    = 32w0;
        meta.cpu_report.src_port  = 16w0;
        meta.cpu_report.dst_port  = 16w0;
        meta.cpu_report.proto     = 8w0;
        meta.cpu_report.reason    = 8w0;
        meta.cpu_report.flow_index = 16w0;
#endif

#if P4_ENABLE_SWEEP
        if (meta.is_probe == 1w1) {
            /* -------- a probe: read one bucket, export it -------- */
#if SWEEP_SHARED_INDEX
            meta.ridx = hdr.ethernet.dst[15:0];
#endif
            hdr.sweep.idx   = hdr.ethernet.dst[15:0];
            hdr.sweep.gen   = hdr.ethernet.dst[47:32];
            hdr.sweep.batch = hdr.ethernet.dst[31:16];
            hdr.sweep.t     = ig_intr_md.ingress_mac_tstamp[31:0];
            sweep_probes.count(0);

            if (hdr.ethernet.dst[15:0] == 16w0) {
                hdr.sweep.seq = seq_next.execute(1w0);
#if P4_ENABLE_GLOBAL_TOTALS
                hdr.sweep.g_pkts_ab  = g_pkts_ab_get.execute(1w0);
                hdr.sweep.g_bytes_ab = g_bytes_ab_get.execute(1w0);
                hdr.sweep.g_pkts_ba  = g_pkts_ba_get.execute(1w0);
                hdr.sweep.g_bytes_ba = g_bytes_ba_get.execute(1w0);
                hdr.sweep.g_syn      = g_syn_get.execute(1w0);
                hdr.sweep.g_ack      = g_ack_get.execute(1w0);
                hdr.sweep.g_rst      = g_rst_get.execute(1w0);
#endif
            } else {
                hdr.sweep.seq = seq_get.execute(1w0);
            }

            hdr.sweep.dir_valid = dir_valid_get.execute(PIDX);
            hdr.sweep.ref_sp    = ref_src_get.execute(PIDX);
            hdr.sweep.ref_dp    = ref_dst_get.execute(PIDX);
            hdr.sweep.pkts      = pkts_get.execute(PIDX);
            hdr.sweep.bytes     = bytes_get.execute(PIDX);
            hdr.sweep.pkts_ab   = pkts_ab_get.execute(PIDX);
            hdr.sweep.bytes_ab  = bytes_ab_get.execute(PIDX);
            hdr.sweep.min_len   = min_len_get.execute(PIDX);
            hdr.sweep.max_len   = max_len_get.execute(PIDX);
            hdr.sweep.first_ts  = first_ts_get.execute(PIDX);
            hdr.sweep.last_ts   = last_ts_get.execute(PIDX);
            hdr.sweep.syn       = syn_get.execute(PIDX);
            hdr.sweep.ack       = ack_get.execute(PIDX);
            hdr.sweep.rst       = rst_get.execute(PIDX);

            if (hdr.sweep.dir_valid == 8w0 && hdr.ethernet.dst[15:0] != 16w0) {
                /* a bucket never used since the reset: nothing to export */
                ig_dprsr_md.drop_ctl   = 3w1;
                ig_tm_md.bypass_egress = 1w1;
            } else {
                sweep_exported.count(0);
                sweep_export.apply();
            }
        } else {
#endif

#if P4_ENABLE_FEATURES
        if (hdr.ipv4.isValid() && (hdr.tcp.isValid() || hdr.udp.isValid())) {
#if P4_FRAME_LEN
            frame_len.apply();
#endif
            bit<32> sip = hdr.ipv4.srcAddr;
            bit<32> dip = hdr.ipv4.dstAddr;
            bit<16> sp  = meta.l4_sport;
            bit<16> dp  = meta.l4_dport;
            bit<8>  pr  = hdr.ipv4.protocol;

            bit<16> idx = crc16_hasher.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                                             meta.l4_sport, meta.l4_dport,
                                             hdr.ipv4.protocol });
            meta.flow_index = idx;
#if SWEEP_SHARED_INDEX
            meta.ridx = idx;
#endif

            bit<8>  dir_old_valid = dir_valid_rw.execute(DIDX);
            bit<16> ref_sp = 16w0;
            bit<16> ref_dp = 16w0;

            if (dir_old_valid == 8w0) {
                ref_src_set.execute(DIDX);
                ref_dst_set.execute(DIDX);
                meta.dir_ab = 1w1;

                /* First-seen flow report to CPU */
#if P4_ENABLE_CPU_REPORTS
                meta.cpu_report.setValid();
                meta.cpu_report.magic     = CPU_REPORT_MAGIC;
                meta.cpu_report.src_ip    = sip;
                meta.cpu_report.dst_ip    = dip;
                meta.cpu_report.src_port  = sp;
                meta.cpu_report.dst_port  = dp;
                meta.cpu_report.proto     = pr;
                meta.cpu_report.reason    = 8w1;
                meta.cpu_report.flow_index = crc16_report_hasher.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                                                                       meta.l4_sport, meta.l4_dport,
                                                                       hdr.ipv4.protocol });

                meta.cpu_mirror_sid       = 1;
                ig_dprsr_md.mirror_type   = FLOW_REPORT_MIRROR;
#endif
            } else {
                ref_sp = ref_src_read.execute(DIDX);
                ref_dp = ref_dst_read.execute(DIDX);

                if ((sp == ref_sp) && (dp == ref_dp)) {
                    meta.dir_ab = 1w1;
                } else if ((sp == ref_dp) && (dp == ref_sp)) {
                    meta.dir_ab = 1w0;
                } else {
                    /* Collision / ambiguity fallback */
                    meta.dir_ab = 1w1;
                }
            }

            /* Core counters */
            pkts_ab_update.execute(DIDX);
            bytes_ab_update.execute(DIDX);

            pkts_rw.execute(DIDX);
            bytes_rw.execute(DIDX);

            min_len_update.execute(DIDX);
            max_len_update.execute(DIDX);

            first_ts_set_if0.execute(DIDX);
            last_ts_rw.execute(DIDX);

#if P4_ENABLE_GLOBAL_TOTALS
            g_pkts_inc.execute(1w0);
            g_bytes_add.execute(1w0);
            g_pkts_ab_update.execute(1w0);
            g_bytes_ab_update.execute(1w0);
#endif

            /* TCP flags */
            if (hdr.tcp.isValid()) {
                bit<9> f = hdr.tcp.flags;

                if ((f & 9w0x002) != 0) {
                    syn_inc.execute(DIDX);
#if P4_ENABLE_GLOBAL_TOTALS
                    g_syn_inc.execute(1w0);
#endif
                }
                if ((f & 9w0x004) != 0) {
                    rst_inc.execute(DIDX);
#if P4_ENABLE_GLOBAL_TOTALS
                    g_rst_inc.execute(1w0);
#endif
                }
                if ((f & 9w0x010) != 0) {
                    ack_inc.execute(DIDX);
#if P4_ENABLE_GLOBAL_TOTALS
                    g_ack_inc.execute(1w0);
#endif
                }
            }
        }
#endif

        forwarding.apply();
#if P4_ENABLE_SWEEP
        }
#endif
    }
}

/*
Off-switch features to compute from this reduced P4 collector (as basic_fix; the sweep's records carry the
same registers, sweep_features.py):

Raw primitives exported / readable per flow bucket:
- pkts_total        = reg_pkts
- bytes_total       = reg_bytes
- pkts_ab           = reg_pkts_ab
- bytes_ab          = reg_bytes_ab
- min_len           = reg_min_len
- max_len           = reg_max_len
- first_ts          = reg_first_ts
- last_ts           = reg_last_ts
- syn_count         = reg_syn
- ack_count         = reg_ack
- rst_count         = reg_rst

Derived off-switch features:
- pkts_ba           = pkts_total - pkts_ab
- bytes_ba          = bytes_total - bytes_ab
- flow_duration     = last_ts - first_ts
- down_up_ratio     = bytes_ba / bytes_ab              (guard divide-by-zero)
- avg_pkt_size      = bytes_total / pkts_total         (guard divide-by-zero)
- avg_pkt_size_ab   = bytes_ab / pkts_ab               (guard divide-by-zero)
- avg_pkt_size_ba   = bytes_ba / pkts_ba               (guard divide-by-zero)
- bytes_per_sec     = bytes_total / flow_duration      (guard divide-by-zero)
- pkts_per_sec      = pkts_total / flow_duration       (guard divide-by-zero)
*/
