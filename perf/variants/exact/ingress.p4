/* perf/variants/exact: the 29 window features of features/switch_model.py computed in the data plane,
 * so that no window depends on when or how much the control plane reads.
 *
 * Windows. A window marker frame (headers.p4, ETHERTYPE_WINDOW, carrying the new window's number; taken
 * only from the ports in the parser's marker_ports) or, in a deployment build, a timer packet of the packet
 * generator (local port TIMER_LOCAL_PORT of the pipe) starts the next window: reg_epoch
 * holds its number. Every window register has two banks, bank = epoch & 1: while window e counts into
 * bank e & 1, the other bank holds window e - 1 unchanged, and the control plane (window_reader.py)
 * reads it at any time before window e + 1 starts. The cut is where the marker is in the packet
 * sequence, the same for all registers.
 *
 * Flows. A flow is the model's: the protocol and the two (address, port) endpoints, unordered. The
 * key orders the endpoints (canon), so flows that differ only in how the ports pair with the
 * addresses are told apart. Four ways of 2^WAY_BITS slots hold a 32-bit signature each; a flow takes
 * the first way whose slot is empty or holds its signature, and keeps that slot for the run (the
 * model forgets no flow). A flow that finds no slot is counted in the totals, as A->B, at found 0 of
 * reg_w_tot: the control plane then knows that the window's flow features are not exact.
 *
 * Direction. A->B is the direction of the flow's first packet: reg_ref keeps whether its source was
 * the lower endpoint, and later packets compare.
 *
 * Window features. A flow is active in window e if its last packet is in windows e-3..e (the model's
 * TTL of 3). The model's per-flow values (min / max length, duration, has had B->A) change only with
 * the flow's packets. Per window e:
 *   Change_e   every packet adds the change of its flow's value;
 *   Carry_e[c] a flow's first packet in e (a touch) adds the flow's value before it, under the
 *              class c = the windows since its previous packet (1..3), or 0 for a new flow or one idle
 *              for longer (its previous window's slot no longer counts);
 *   cnt_e      the touches by class, B->A before and direction, and the flows' first B->A packets.
 * A new flow counts its first packet's values as "before" and adds no change. The control plane then
 * has In_j = sum_c Carry_j[c] + Change_j (the window's flows at their values at its end) and
 * Out_k[d] = Carry_k[d] (the values flows took away from window k - d), and the sum over the active
 * flows is S(e) = sum_{j=e-3..e} (In_j - sum_{k=j+1..e} Out_k[k-j]) (window_features.py). The minimum
 * and maximum length over the active flows are the extremes over windows e-3..e of reg_w_pa (the
 * flows' values before each packet) and reg_w_pb (the packets' lengths); the maximum duration that of
 * reg_w_pd (after each packet).
 *
 * Bytes are counted as L = the IPv4 totalLen, or what frame_len sets: the frame minimum toward a host
 * whose own capture saw received frames padded (the dataset's guest); the control plane adds the 14 B
 * Ethernet header. Times are ingress_mac_tstamp[47:16] (65.536 us). Additive registers wrap modulo
 * 2^32 and are differenced: a window's duration sum over its active flows must stay below 2^32 units
 * (281,475 s; the dataset's largest is below 115,000 s). */

#define WAY_SLOTS (1 << WAY_BITS)

/* The packet generator's local port whose timer packets tick the window clock, on any pipe (each pipe has its
 * own clock and its own generator): a deployment build sets -DTIMER_LOCAL_PORT=68 (tested on pipe 1, dev_port
 * 196; sw_window_timer.py). The default, 127, is no port: the line-rate tests' generator (sw_pktgen_run.py,
 * local ports 68-70) then sends traffic, and only window markers move the clock. */
#ifndef TIMER_LOCAL_PORT
#define TIMER_LOCAL_PORT 127
#endif
#define FLOW_SLOTS (4 * WAY_SLOTS)

control Ingress(
    inout my_headers_t hdr,
    inout my_ingress_metadata_t meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    /* ---------------- window clock ---------------- */
    Register<bit<32>, bit<1>>(1) reg_epoch;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_epoch) epoch_set = {
        void apply(inout bit<32> v) { v = hdr.marker.epoch; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_epoch) epoch_tick = {
        void apply(inout bit<32> v) { v = v + 32w1; }
    };
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_epoch) epoch_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };

    /* window marker frames from ports outside marker_ports, dropped */
    Counter<bit<32>, bit<1>>(1, CounterType_t.PACKETS) rejected_markers;

    /* ---------------- packet length ---------------- */
    action len_ip(bit<16> extra) { meta.L16 = hdr.ipv4.totalLen + extra; }
    action len_set(bit<16> len) { meta.L16 = len; }

    table frame_len {
        key = {
            hdr.vlan[0].isValid() : exact;
            hdr.vlan[1].isValid() : exact;
            hdr.ipv4.dstAddr      : ternary;
            hdr.ipv4.totalLen     : range;
        }
        actions = { len_ip; len_set; }
        default_action = len_ip(0);
        size = 64;
    }

    /* ---------------- flow key ---------------- */
    action prep() {
        meta.ip_gt   = hdr.ipv4.srcAddr |-| hdr.ipv4.dstAddr;
        meta.ip_lt   = hdr.ipv4.dstAddr |-| hdr.ipv4.srcAddr;
        meta.port_lt = meta.l4_dport |-| meta.l4_sport;
        meta.t       = ig_intr_md.ingress_mac_tstamp[47:16];
    }

    action canon_src_low() {
        meta.sm = 8w1;
        meta.k_ip1 = hdr.ipv4.srcAddr; meta.k_p1 = meta.l4_sport;
        meta.k_ip2 = hdr.ipv4.dstAddr; meta.k_p2 = meta.l4_dport;
    }
    action canon_dst_low() {
        meta.sm = 8w0;
        meta.k_ip1 = hdr.ipv4.dstAddr; meta.k_p1 = meta.l4_dport;
        meta.k_ip2 = hdr.ipv4.srcAddr; meta.k_p2 = meta.l4_sport;
    }

    /* The lower endpoint: ip_lt != 0 (dst address higher), else ip_gt == 0 (same address) and
     * port_lt != 0 (dst port higher). Equal endpoints take canon_dst_low (sm 0) both ways, so a
     * flow to itself is A->B in both directions, as in the model. */
    table canon {
        key = {
            meta.ip_lt   : ternary;
            meta.ip_gt   : ternary;
            meta.port_lt : ternary;
        }
        actions = { canon_src_low; canon_dst_low; }
        default_action = canon_src_low();
        const entries = {
            (32w0, 32w0, 16w0) : canon_dst_low();
            (32w0, 32w0, _)    : canon_src_low();
            (32w0, _, _)       : canon_dst_low();
        }
        size = 4;
    }

    /* Signature: direction-free (symmetric) CRC-32 of the 5-tuple. Flows that differ only in how
     * the ports pair with the addresses get the same signature but, from the ordered key, different
     * slots. */
    @symmetric("hdr.ipv4.srcAddr", "hdr.ipv4.dstAddr")
    @symmetric("meta.l4_sport", "meta.l4_dport")
    Hash<bit<32>>(HashAlgorithm_t.CRC32) sig_hash;

    CRCPolynomial<bit<16>>(16w0x1021, true, false, false, 16w0xFFFF, 16w0x0000) poly2;
    CRCPolynomial<bit<16>>(16w0x3D65, true, false, false, 16w0x0000, 16w0xFFFF) poly3;
    CRCPolynomial<bit<16>>(16w0x8BB7, false, false, false, 16w0x0000, 16w0x0000) poly4;
    Hash<bit<WAY_BITS>>(HashAlgorithm_t.CRC16) way1_hash;
    Hash<bit<WAY_BITS>>(HashAlgorithm_t.CRC16) way1_copy;
    Hash<bit<WAY_BITS>>(HashAlgorithm_t.CUSTOM, poly2) way2_hash;
    Hash<bit<WAY_BITS>>(HashAlgorithm_t.CUSTOM, poly3) way3_hash;
    Hash<bit<WAY_BITS>>(HashAlgorithm_t.CUSTOM, poly4) way4_hash;

    /* An action moves at most 32 bits of hash results into the PHV: two indexes per action. */
    action way_indexes_12() {
        meta.h1 = (bit<16>) way1_copy.get({ meta.k_ip1, meta.k_p1, meta.k_ip2, meta.k_p2, hdr.ipv4.protocol });
        meta.h2 = (bit<16>) way2_hash.get({ meta.k_ip1, meta.k_p1, meta.k_ip2, meta.k_p2, hdr.ipv4.protocol });
    }
    action way_indexes_34() {
        meta.h3 = (bit<16>) way3_hash.get({ meta.k_ip1, meta.k_p1, meta.k_ip2, meta.k_p2, hdr.ipv4.protocol });
        meta.h4 = (bit<16>) way4_hash.get({ meta.k_ip1, meta.k_p1, meta.k_ip2, meta.k_p2, hdr.ipv4.protocol });
    }

    /* ---------------- flow table: claim or match ---------------- */
    Register<bit<32>, bit<WAY_BITS>>(WAY_SLOTS) reg_way1;
    Register<bit<32>, bit<WAY_BITS>>(WAY_SLOTS) reg_way2;
    Register<bit<32>, bit<WAY_BITS>>(WAY_SLOTS) reg_way3;
    Register<bit<32>, bit<WAY_BITS>>(WAY_SLOTS) reg_way4;

#define WAY_PROBE(N) \
    RegisterAction<bit<32>, bit<WAY_BITS>, bit<8>>(reg_way##N) way##N##_probe = { \
        void apply(inout bit<32> v, out bit<8> rv) { \
            if (v == 32w0) { v = meta.sig; rv = 8w2; } \
            else if (v == meta.sig) { rv = 8w1; } \
            else { rv = 8w0; } \
        } \
    };
    WAY_PROBE(1)
    WAY_PROBE(2)
    WAY_PROBE(3)
    WAY_PROBE(4)

    /* The slot is set speculatively for the next way before its probe; a hit or a claim keeps it. */
    action slot_way1() { meta.slot = (slot_t) meta.h1; }
    action slot_way2() { meta.slot = (slot_t) meta.h2 | (slot_t) (1 << WAY_BITS); }
    action slot_way3() { meta.slot = (slot_t) meta.h3 | (slot_t) (2 << WAY_BITS); }
    action slot_way4() { meta.slot = (slot_t) meta.h4 | (slot_t) (3 << WAY_BITS); }

    /* ---------------- per-flow state ---------------- */
    Register<bit<8>, slot_t>(FLOW_SLOTS) reg_ref;     /* 1: the first packet's source was the lower endpoint */
    Register<bit<16>, slot_t>(FLOW_SLOTS) reg_seen;    /* the window of the flow's last packet (16 bits) */
    Register<bit<8>, slot_t>(FLOW_SLOTS) reg_ba;      /* 1: the flow has had a B->A packet */
    Register<bit<16>, slot_t>(FLOW_SLOTS) reg_min;     /* min / max length */
    Register<bit<16>, slot_t>(FLOW_SLOTS) reg_max;
    Register<bit<32>, slot_t>(FLOW_SLOTS) reg_first;   /* time of the first / last packet */
    Register<bit<32>, slot_t>(FLOW_SLOTS) reg_last;

    RegisterAction<bit<8>, slot_t, bit<1>>(reg_ref) ref_set = {
        void apply(inout bit<8> v) { v = meta.sm; }
    };
    RegisterAction<bit<8>, slot_t, bit<1>>(reg_ref) ref_dir = {
        void apply(inout bit<8> v, out bit<1> rv) {
            if (v == meta.sm) { rv = 1w1; } else { rv = 1w0; }
        }
    };
    RegisterAction<bit<16>, slot_t, bit<16>>(reg_seen) seen_set = {
        void apply(inout bit<16> v) { v = meta.epoch[15:0]; }
    };
    /* code: 0 the flow's previous packet was in this window (no touch); 1..3 it was that many windows
     * before (the flow moves from that window's slot); 4 longer ago (the flow enters) */
    RegisterAction<bit<16>, slot_t, bit<16>>(reg_seen) seen_rw = {
        void apply(inout bit<16> v, out bit<16> rv) {
            if (meta.epoch[15:0] - v > 16w3) {
                rv = 16w4;
            } else {
                rv = meta.epoch[15:0] - v;
            }
            v = meta.epoch[15:0];
        }
    };
    RegisterAction<bit<8>, slot_t, bit<8>>(reg_ba) ba_rw = {
        void apply(inout bit<8> v, out bit<8> rv) {
            rv = v;
            if (meta.dir_ab == 1w0) { v = 8w1; }
        }
    };
    /* a new flow's "previous" min / max / last are its first packet's: its changes are 0 */
    RegisterAction<bit<16>, slot_t, bit<16>>(reg_min) min_set = {
        void apply(inout bit<16> v, out bit<16> rv) { v = meta.L16; rv = meta.L16; }
    };
    RegisterAction<bit<16>, slot_t, bit<16>>(reg_min) min_rw = {
        void apply(inout bit<16> v, out bit<16> rv) {
            rv = v;
            if (meta.L16 < v) { v = meta.L16; }
        }
    };
    RegisterAction<bit<16>, slot_t, bit<16>>(reg_max) max_set = {
        void apply(inout bit<16> v, out bit<16> rv) { v = meta.L16; rv = meta.L16; }
    };
    RegisterAction<bit<16>, slot_t, bit<16>>(reg_max) max_rw = {
        void apply(inout bit<16> v, out bit<16> rv) {
            rv = v;
            if (meta.L16 > v) { v = meta.L16; }
        }
    };
    RegisterAction<bit<32>, slot_t, bit<32>>(reg_first) first_set = {
        void apply(inout bit<32> v, out bit<32> rv) { v = meta.t; rv = meta.t; }
    };
    RegisterAction<bit<32>, slot_t, bit<32>>(reg_first) first_get = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; }
    };
    RegisterAction<bit<32>, slot_t, bit<32>>(reg_last) last_set = {
        void apply(inout bit<32> v, out bit<32> rv) { v = meta.t; rv = meta.t; }
    };
    RegisterAction<bit<32>, slot_t, bit<32>>(reg_last) last_rw = {
        void apply(inout bit<32> v, out bit<32> rv) { rv = v; v = meta.t; }
    };

    /* ---------------- window registers (two banks, index bank = epoch & 1 first) ----------------
     * Additive registers are never cleared: a window's value is the difference of the reads of its
     * bank before and after it. The extremes (reg_w_pa, reg_w_pb, reg_w_pd) are cleared by the reader
     * after it has read the bank, before the bank's next window starts. Minima are kept as maxima of
     * 0xFFFF - x, so that a cleared (zero) entry is the identity of both. */

    /* totals: index {bank, found, dir_ab}; lo packets, hi bytes (L). found 0: packets of flows
     * without a slot (the window's flow features are then not exact). */
    Register<pair_t, bit<3>>(8) reg_w_tot;
    RegisterAction<pair_t, bit<3>, bit<32>>(reg_w_tot) tot_add = {
        void apply(inout pair_t v) { v.lo = v.lo + 32w1; v.hi = v.hi + meta.L; }
    };
    /* lo SYN, hi ACK */
    Register<pair_t, bit<1>>(2) reg_w_flags;
    RegisterAction<pair_t, bit<1>, bit<32>>(reg_w_flags) flags_add = {
        void apply(inout pair_t v) {
            if (meta.f_syn == 1w1) { v.lo = v.lo + 32w1; }
            if (meta.f_ack == 1w1) { v.hi = v.hi + 32w1; }
        }
    };
    Register<bit<32>, bit<1>>(2) reg_w_rst;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_w_rst) rst_add = {
        void apply(inout bit<32> v) {
            if (meta.f_rst == 1w1) { v = v + 32w1; }
        }
    };
    /* flows: index {bank, code, ba_old, dir_ab}. A touch (code 1..4: the flow's first packet in the
     * window) counts the flow with its class; a later packet (code 0) that is the flow's first B->A
     * counts at {bank, 0, 0, 0}. */
    Register<bit<32>, bit<6>>(64) reg_w_cnt;
    RegisterAction<bit<32>, bit<6>, bit<32>>(reg_w_cnt) cnt_inc = {
        void apply(inout bit<32> v) { v = v + 32w1; }
    };
    /* Change: every packet adds the change of its flow's value: lo min length (-dec), hi max length
     * (+inc); duration (+gap). */
    Register<pair_t, bit<1>>(2) reg_w_chg_len;
    RegisterAction<pair_t, bit<1>, bit<32>>(reg_w_chg_len) chg_len_add = {
        void apply(inout pair_t v) { v.lo = v.lo - (bit<32>) meta.dec; v.hi = v.hi + (bit<32>) meta.inc; }
    };
    Register<bit<32>, bit<1>>(2) reg_w_chg_dur;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_w_chg_dur) chg_dur_add = {
        void apply(inout bit<32> v) { v = v + meta.gap; }
    };
    /* Carry: a touch adds the flow's value before the packet, at index {bank, cls = code & 3}. In_e is the sum
     * over cls of Carry_e plus Change_e; Out_e[d] is Carry_e[d]. */
    Register<pair_t, bit<3>>(8) reg_w_carry_len;
    RegisterAction<pair_t, bit<3>, bit<32>>(reg_w_carry_len) carry_len_add = {
        void apply(inout pair_t v) { v.lo = v.lo + (bit<32>) meta.old_min; v.hi = v.hi + (bit<32>) meta.old_max; }
    };
    Register<bit<32>, bit<3>>(8) reg_w_carry_dur;
    RegisterAction<bit<32>, bit<3>, bit<32>>(reg_w_carry_dur) carry_dur_add = {
        void apply(inout bit<32> v) { v = v + meta.dur_old; }
    };
    /* Extremes of the window: pa over the flows' values before each packet (lo 0xFFFF - min, hi
     * max), pb over the packets' lengths, pd over the flows' durations after each packet. */
    Register<pair_t, bit<1>>(2) reg_w_pa;
    RegisterAction<pair_t, bit<1>, bit<32>>(reg_w_pa) pa_upd = {
        void apply(inout pair_t v) {
            if ((bit<32>) meta.nmin > v.lo) { v.lo = (bit<32>) meta.nmin; }
            if ((bit<32>) meta.old_max > v.hi) { v.hi = (bit<32>) meta.old_max; }
        }
    };
    Register<pair_t, bit<1>>(2) reg_w_pb;
    RegisterAction<pair_t, bit<1>, bit<32>>(reg_w_pb) pb_upd = {
        void apply(inout pair_t v) {
            if ((bit<32>) meta.nL > v.lo) { v.lo = (bit<32>) meta.nL; }
            if ((bit<32>) meta.L16 > v.hi) { v.hi = (bit<32>) meta.L16; }
        }
    };
    Register<bit<32>, bit<1>>(2) reg_w_pd;
    RegisterAction<bit<32>, bit<1>, bit<32>>(reg_w_pd) pd_upd = {
        void apply(inout bit<32> v) {
            if (meta.dur_new > v) { v = meta.dur_new; }
        }
    };

    /* ---------------- per-packet arithmetic, one action per dependency level ---------------- */
    action set_len32()   { meta.L = (bit<32>) meta.L16; meta.nL = ~meta.L16; }
    action set_bank()    { meta.bank = meta.epoch[0:0]; }
    action tcp_flags()   {
        meta.f_syn = hdr.tcp.flags[1:1];
        meta.f_ack = hdr.tcp.flags[4:4];
        meta.f_rst = hdr.tcp.flags[2:2];
    }
    action no_flags()    { meta.f_syn = 1w0; meta.f_ack = 1w0; meta.f_rst = 1w0; }
    action set_sig()     {
        meta.sig = sig_hash.get({ hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, meta.l4_sport, meta.l4_dport,
                                  hdr.ipv4.protocol });
    }
    action new_code()    { meta.code = 16w4; }
    action set_found()   { meta.found = 1w1; }
    action len_steps()   {
        meta.dec  = meta.old_min |-| meta.L16;
        meta.inc  = meta.L16 |-| meta.old_max;
        meta.nmin = ~meta.old_min;
    }
    action durations()   {
        meta.dur_new = meta.t - meta.first;
        meta.gap     = meta.t - meta.old_last;
        meta.dur_old = meta.old_last - meta.first;
    }

    /* ---------------- forwarding ---------------- */
    action send_using_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.bypass_egress     = 0;
    }
    action drop() {
        ig_dprsr_md.drop_ctl   = 3w1;
        ig_tm_md.bypass_egress = 1w1;
    }
    table forwarding {
        key = { ig_intr_md.ingress_port : exact; }
        actions = { send_using_port; drop; }
        const default_action = drop();
        size = 256;
    }

    apply {
        meta.found = 1w0;
        meta.dir_ab = 1w1;
        meta.code = 16w0;

        if (hdr.marker.isValid()) {
            if (hdr.marker.magic == WINDOW_MAGIC) {
                epoch_set.execute(0);
            }
            ig_dprsr_md.drop_ctl = 3w1;
        } else if (meta.bad_marker == 1w1) {
            rejected_markers.count(0);
            ig_dprsr_md.drop_ctl = 3w1;
        } else if (ig_intr_md.ingress_port[6:0] == TIMER_LOCAL_PORT) {
            epoch_tick.execute(0);
            ig_dprsr_md.drop_ctl = 3w1;
        } else {
            forwarding.apply();
            meta.epoch = epoch_get.execute(0);
            if (meta.is_flow == 1w1) {
                prep();
                frame_len.apply();
                set_len32();
                set_bank();
                if (hdr.tcp.isValid()) { tcp_flags(); } else { no_flags(); }
                set_sig();
                canon.apply();
                way_indexes_12();
                way_indexes_34();

                /* claim or match, way after way: st 0 miss, 1 hit, 2 claimed */
                meta.st = way1_probe.execute(way1_hash.get({ meta.k_ip1, meta.k_p1, meta.k_ip2, meta.k_p2,
                                                             hdr.ipv4.protocol }));
                if (meta.st == 8w0) {
                    slot_way2();
                    meta.st = way2_probe.execute((bit<WAY_BITS>) meta.h2);
                } else {
                    slot_way1();
                }
                if (meta.st == 8w0) {
                    slot_way3();
                    meta.st = way3_probe.execute((bit<WAY_BITS>) meta.h3);
                }
                if (meta.st == 8w0) {
                    slot_way4();
                    meta.st = way4_probe.execute((bit<WAY_BITS>) meta.h4);
                }

                if (meta.st != 8w0) {
                    set_found();
                    if (meta.st == 8w2) {
                        ref_set.execute(meta.slot);
                        seen_set.execute(meta.slot);
                        meta.old_min = min_set.execute(meta.slot);
                        meta.old_max = max_set.execute(meta.slot);
                        meta.first = first_set.execute(meta.slot);
                        meta.old_last = last_set.execute(meta.slot);
                        new_code();
                    } else {
                        meta.dir_ab = ref_dir.execute(meta.slot);
                        meta.code = seen_rw.execute(meta.slot);
                        meta.old_min = min_rw.execute(meta.slot);
                        meta.old_max = max_rw.execute(meta.slot);
                        meta.first = first_get.execute(meta.slot);
                        meta.old_last = last_rw.execute(meta.slot);
                    }
                    meta.ba_old = ba_rw.execute(meta.slot);
                    len_steps();
                    durations();

                    chg_len_add.execute(meta.bank);
                    chg_dur_add.execute(meta.bank);
                    if (meta.code != 16w0) {
                        carry_len_add.execute(meta.bank ++ meta.code[1:0]);
                        carry_dur_add.execute(meta.bank ++ meta.code[1:0]);
                        cnt_inc.execute(meta.bank ++ meta.code[2:0] ++ meta.ba_old[0:0] ++ meta.dir_ab);
                    } else if (meta.ba_old == 8w0 && meta.dir_ab == 1w0) {
                        cnt_inc.execute(meta.bank ++ 5w0);
                    }
                    pa_upd.execute(meta.bank);
                    pd_upd.execute(meta.bank);
                }
                pb_upd.execute(meta.bank);
                tot_add.execute(meta.bank ++ meta.found ++ meta.dir_ab);
                flags_add.execute(meta.bank);
                rst_add.execute(meta.bank);
            }
        }
    }
}
