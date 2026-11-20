/* ASIC latency instrumentation around an unmodified program (Phase 2.5).
 *
 * Include after the inner program's types and controls. They must use the
 * names IngressParser, Ingress, IngressDeparser, EgressParser, Egress and
 * EgressDeparser, and the types my_headers_t, my_ingress_metadata_t,
 * my_egress_headers_t and my_egress_metadata_t. Both thesis-hybrid-ebpf-p4 and
 * perf/variants/baseline.p4 do. The inner parsers and controls run unchanged as
 * sub-parsers/sub-controls (instance name "det"); the wrapper only adds:
 *
 *   ingress  a 9-byte bridge header (type 0x5A, then the low 32 bits of the
 *            ingress MAC timestamp and of the ingress parser timestamp),
 *            emitted in front of the inner program's headers;
 *   egress   parse and strip the bridge (it never leaves the switch), and for
 *            packets whose egress port has an entry in table lat_calc record
 *            egress-parser time minus each ingress timestamp (ns, mod 2^32)
 *            into count/min/max registers, 8 ns histograms (1024 bins,
 *            indexed by latency bits [12:3]) and overflow counters for
 *            latencies >= 8192 ns. The histogram is exact when the overflow
 *            counter is 0 (equivalently max < 8192).
 *
 * The subtraction runs in the action of a lat_calc hit on purpose: bf-p4c
 * 9.6.0 folds an unconditional assignment into the expression's uses (gateway
 * condition, register index), which cannot compute a difference. For the same
 * reason range checks are done inside the stateful ALUs.
 *
 * Mirrored copies (the detector's CPU reports start with 0xBE: magic 0xBEF1, or 0xBEEF in older builds) carry no
 * leading 0x5A, so they are neither parsed nor measured.
 */

const bit<8> LAT_BRIDGE_TYPE = 0x5A;

header lat_bridge_t {
    bit<8>  type;
    bit<32> ig_mac_ts;
    bit<32> ig_prsr_ts;
}

struct lat_ig_headers_t {
    lat_bridge_t bridge;
    my_headers_t det;
}

struct lat_eg_headers_t {
    lat_bridge_t        bridge;
    my_egress_headers_t det;
}

struct lat_eg_metadata_t {
    my_egress_metadata_t det;
    bit<32> lat_mac;
    bit<32> lat_prsr;
    bit<10> mac_bin;
    bit<10> prsr_bin;
}

parser LatIngressParser(
    packet_in pkt,
    out lat_ig_headers_t hdr,
    out my_ingress_metadata_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    IngressParser() det;

    state start {
        det.apply(pkt, hdr.det, meta, ig_intr_md);
        transition accept;
    }
}

control LatIngress(
    inout lat_ig_headers_t hdr,
    inout my_ingress_metadata_t meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    Ingress() det;

    apply {
        det.apply(hdr.det, meta, ig_intr_md, ig_prsr_md, ig_dprsr_md, ig_tm_md);

        hdr.bridge.setValid();
        hdr.bridge.type       = LAT_BRIDGE_TYPE;
        hdr.bridge.ig_mac_ts  = ig_intr_md.ingress_mac_tstamp[31:0];
        hdr.bridge.ig_prsr_ts = ig_prsr_md.global_tstamp[31:0];
    }
}

control LatIngressDeparser(
    packet_out pkt,
    inout lat_ig_headers_t hdr,
    in    my_ingress_metadata_t meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    IngressDeparser() det;

    apply {
        pkt.emit(hdr.bridge);
        det.apply(pkt, hdr.det, meta, ig_dprsr_md);
    }
}

parser LatEgressParser(
    packet_in pkt,
    out lat_eg_headers_t            hdr,
    out lat_eg_metadata_t           meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    EgressParser() det;

    state start {
        det.apply(pkt, hdr.det, meta.det, eg_intr_md);
        meta.lat_mac  = 0;
        meta.lat_prsr = 0;
        meta.mac_bin  = 0;
        meta.prsr_bin = 0;
        transition select(pkt.lookahead<bit<8>>()) {
            LAT_BRIDGE_TYPE: parse_bridge;
            default: accept;
        }
    }

    state parse_bridge {
        pkt.extract(hdr.bridge);
        transition accept;
    }
}

control LatEgress(
    inout lat_eg_headers_t                             hdr,
    inout lat_eg_metadata_t                            meta,
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    Egress() det;

    Register<bit<32>, bit<1>>(1)     lat_count;
    Register<bit<32>, bit<1>>(1)     lat_mac_min;
    Register<bit<32>, bit<1>>(1)     lat_mac_max;
    Register<bit<32>, bit<1>>(1)     lat_prsr_min;
    Register<bit<32>, bit<1>>(1)     lat_prsr_max;
    Register<bit<32>, bit<10>>(1024) lat_mac_hist;
    Register<bit<32>, bit<10>>(1024) lat_prsr_hist;
    Register<bit<32>, bit<1>>(1)     lat_mac_ovf;
    Register<bit<32>, bit<1>>(1)     lat_prsr_ovf;

    RegisterAction<bit<32>, bit<1>, bit<32>>(lat_count) count_inc = {
        void apply(inout bit<32> v) {
            v = v + 32w1;
        }
    };

    /* Minimum with 0 meaning "empty", like reg_min_len in ingress.p4. */
    RegisterAction<bit<32>, bit<1>, bit<32>>(lat_mac_min) mac_min_upd = {
        void apply(inout bit<32> v) {
            if (v == 0 || meta.lat_mac < v) {
                v = meta.lat_mac;
            }
        }
    };

    RegisterAction<bit<32>, bit<1>, bit<32>>(lat_mac_max) mac_max_upd = {
        void apply(inout bit<32> v) {
            if (meta.lat_mac > v) {
                v = meta.lat_mac;
            }
        }
    };

    RegisterAction<bit<32>, bit<1>, bit<32>>(lat_prsr_min) prsr_min_upd = {
        void apply(inout bit<32> v) {
            if (v == 0 || meta.lat_prsr < v) {
                v = meta.lat_prsr;
            }
        }
    };

    RegisterAction<bit<32>, bit<1>, bit<32>>(lat_prsr_max) prsr_max_upd = {
        void apply(inout bit<32> v) {
            if (meta.lat_prsr > v) {
                v = meta.lat_prsr;
            }
        }
    };

    RegisterAction<bit<32>, bit<10>, bit<32>>(lat_mac_hist) mac_hist_inc = {
        void apply(inout bit<32> v) {
            v = v + 32w1;
        }
    };

    RegisterAction<bit<32>, bit<10>, bit<32>>(lat_prsr_hist) prsr_hist_inc = {
        void apply(inout bit<32> v) {
            v = v + 32w1;
        }
    };

    RegisterAction<bit<32>, bit<1>, bit<32>>(lat_mac_ovf) mac_ovf_inc = {
        void apply(inout bit<32> v) {
            if (meta.lat_mac > 32w8191) {
                v = v + 32w1;
            }
        }
    };

    RegisterAction<bit<32>, bit<1>, bit<32>>(lat_prsr_ovf) prsr_ovf_inc = {
        void apply(inout bit<32> v) {
            if (meta.lat_prsr > 32w8191) {
                v = v + 32w1;
            }
        }
    };

    action compute_lat() {
        meta.lat_mac  = eg_prsr_md.global_tstamp[31:0] - hdr.bridge.ig_mac_ts;
        meta.lat_prsr = eg_prsr_md.global_tstamp[31:0] - hdr.bridge.ig_prsr_ts;
    }

    /* One entry per egress port to measure (e.g. 140 = towards PC2). */
    table lat_calc {
        key = {
            eg_intr_md.egress_port : exact;
        }
        actions = { compute_lat; @defaultonly NoAction; }
        const default_action = NoAction();
        size = 16;
    }

    apply {
        det.apply(hdr.det, meta.det, eg_intr_md, eg_prsr_md, eg_dprsr_md, eg_oport_md);

        if (hdr.bridge.isValid()) {
            if (lat_calc.apply().hit) {
                meta.mac_bin  = meta.lat_mac[12:3];
                meta.prsr_bin = meta.lat_prsr[12:3];

                count_inc.execute(0);
                mac_min_upd.execute(0);
                mac_max_upd.execute(0);
                prsr_min_upd.execute(0);
                prsr_max_upd.execute(0);
                mac_hist_inc.execute(meta.mac_bin);
                prsr_hist_inc.execute(meta.prsr_bin);
                mac_ovf_inc.execute(0);
                prsr_ovf_inc.execute(0);
            }
        }
    }
}

control LatEgressDeparser(packet_out pkt,
    inout lat_eg_headers_t                          hdr,
    in    lat_eg_metadata_t                         meta,
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    EgressDeparser() det;

    /* The bridge header is not emitted, so it is stripped before transmit. */
    apply {
        det.apply(pkt, hdr.det, meta.det, eg_dprsr_md);
    }
}

Pipeline(
    LatIngressParser(),
    LatIngress(),
    LatIngressDeparser(),
    LatEgressParser(),
    LatEgress(),
    LatEgressDeparser()
) pipe;
Switch(pipe) main;
