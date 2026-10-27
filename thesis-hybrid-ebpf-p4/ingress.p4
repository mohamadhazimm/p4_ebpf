#ifndef P4_ENABLE_FEATURES
#define P4_ENABLE_FEATURES 1
#endif

#ifndef P4_ENABLE_CPU_REPORTS
#define P4_ENABLE_CPU_REPORTS 1
#endif

#if P4_ENABLE_CPU_REPORTS && !P4_ENABLE_FEATURES
#error CPU reports require feature collection
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

#if P4_ENABLE_FEATURES
        if (hdr.ipv4.isValid() && (hdr.tcp.isValid() || hdr.udp.isValid())) {
            bit<32> sip = hdr.ipv4.srcAddr;
            bit<32> dip = hdr.ipv4.dstAddr;
            bit<16> sp  = meta.l4_sport;
            bit<16> dp  = meta.l4_dport;
            bit<8>  pr  = hdr.ipv4.protocol;

            bit<16> idx = crc16_hasher.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                                             meta.l4_sport, meta.l4_dport,
                                             hdr.ipv4.protocol });
            meta.flow_index = idx;

            bit<8>  dir_old_valid = dir_valid_rw.execute(idx);
            bit<16> ref_sp = 16w0;
            bit<16> ref_dp = 16w0;

            if (dir_old_valid == 8w0) {
                ref_src_set.execute(idx);
                ref_dst_set.execute(idx);
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
                ref_sp = ref_src_read.execute(idx);
                ref_dp = ref_dst_read.execute(idx);

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
            pkts_ab_update.execute(idx);
            bytes_ab_update.execute(idx);

            pkts_rw.execute(idx);
            bytes_rw.execute(idx);

            min_len_update.execute(idx);
            max_len_update.execute(idx);

            first_ts_set_if0.execute(idx);
            last_ts_rw.execute(idx);

            /* TCP flags */
            if (hdr.tcp.isValid()) {
                bit<9> f = hdr.tcp.flags;

                if ((f & 9w0x002) != 0) {
                    syn_inc.execute(idx);
                }
                if ((f & 9w0x004) != 0) {
                    rst_inc.execute(idx);
                }
                if ((f & 9w0x010) != 0) {
                    ack_inc.execute(idx);
                }
            }
        }
#endif

        forwarding.apply();
    }
}

/*
Off-switch features to compute from this reduced P4 collector:

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

Recommended final hybrid-network feature families:
- volume            : pkts_total, bytes_total, pkts_ab, bytes_ab, pkts_ba, bytes_ba
- size              : min_len, max_len, avg_pkt_size
- timing            : flow_duration, bytes_per_sec, pkts_per_sec
- tcp_behavior      : syn_count, ack_count, rst_count
*/