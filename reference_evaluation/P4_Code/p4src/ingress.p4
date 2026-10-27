control SwitchIngress(inout Parsed_packet hdr,
                inout ig_metadata_t ig_md,
                in    ingress_intrinsic_metadata_t ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    calc_hash_248(coeff = 0x1021) subdomain_hasher;
    calc_hash_304(coeff = 0x1021) zone_hasher;

    Hash<bit<16>>(HashAlgorithm_t.CRC16) h_sub;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) h_clizone;

    Register<bit<32>, bit<16>>(NUM_ZONES) zone_rate_reg;
    RegisterAction<bit<32>, bit<16>, bit<32>>(zone_rate_reg) zone_rate_upd = {
        void apply(inout bit<32> v, out bit<32> r) { v = v + 1; r = v; }
    };

    Register<bit<8>, bit<16>>(NUM_SUB_SEEN) sub_seen_reg;
    RegisterAction<bit<8>, bit<16>, bit<1>>(sub_seen_reg) sub_seen_chk = {
        void apply(inout bit<8> v, out bit<1> first) {
            if (v == 0) { first = 1; } else { first = 0; }
            v = 1;
        }
    };

    Register<bit<32>, bit<16>>(NUM_ZONES) distinct_reg;
    RegisterAction<bit<32>, bit<16>, bit<32>>(distinct_reg) distinct_upd = {
        void apply(inout bit<32> v, out bit<32> r) { v = v + 1; r = v; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(distinct_reg) distinct_get = {
        void apply(inout bit<32> v, out bit<32> r) { r = v; }
    };

    Register<bit<8>, bit<16>>(NUM_CLIENT_SEEN) cli_seen_reg;
    RegisterAction<bit<8>, bit<16>, bit<1>>(cli_seen_reg) cli_seen_chk = {
        void apply(inout bit<8> v, out bit<1> first) {
            if (v == 0) { first = 1; } else { first = 0; }
            v = 1;
        }
    };

    Register<bit<32>, bit<16>>(NUM_ZONES) spread_reg;
    RegisterAction<bit<32>, bit<16>, bit<32>>(spread_reg) spread_upd = {
        void apply(inout bit<32> v, out bit<32> r) { v = v + 1; r = v; }
    };
    RegisterAction<bit<32>, bit<16>, bit<32>>(spread_reg) spread_get = {
        void apply(inout bit<32> v, out bit<32> r) { r = v; }
    };

    Register<bit<32>, bit<16>>(NUM_CLIENTS) client_rate_reg;
    RegisterAction<bit<32>, bit<16>, bit<32>>(client_rate_reg) client_rate_upd = {
        void apply(inout bit<32> v, out bit<32> r) { v = v + 1; r = v; }
    };

    Register<bit<32>, bit<16>>(NUM_CLIENT_ZONE) client_zone_reg;
    RegisterAction<bit<32>, bit<16>, bit<32>>(client_zone_reg) client_zone_upd = {
        void apply(inout bit<32> v, out bit<32> r) { v = v + 1; r = v; }
    };

    Register<bit<32>, bit<16>>(NUM_ZONES) zone_nxd_reg;
    RegisterAction<bit<32>, bit<16>, bit<32>>(zone_nxd_reg) zone_nxd_upd = {
        void apply(inout bit<32> v, out bit<32> r) { v = v + 1; r = v; }
    };

    Register<bit<32>, bit<16>>(NUM_ZONES) bigram_obs_reg;
    RegisterAction<bit<32>, bit<16>, bit<32>>(bigram_obs_reg) bigram_obs_set = {
        void apply(inout bit<32> v, out bit<32> r) {
            v = (bit<32>)ig_md.bigram_k;
            r = v;
        }
    };

    Register<bit<32>, bit<16>>(NUM_ZONES) score_obs_reg;
    RegisterAction<bit<32>, bit<16>, bit<32>>(score_obs_reg) score_obs_set = {
        void apply(inout bit<32> v, out bit<32> r) {
            v = (bit<32>)ig_md.suspicion_score;
            r = v;
        }
    };

    Register<bit<32>, bit<16>>(NUM_ZONES) tier_obs_reg;
    RegisterAction<bit<32>, bit<16>, bit<32>>(tier_obs_reg) tier_obs_set = {
        void apply(inout bit<32> v, out bit<32> r) {
            v = (bit<32>)ig_md.risk_tier;
            r = v;
        }
    };

    action send(PortId_t port) { ig_tm_md.ucast_egress_port = port; }
    action drop()              { ig_dprsr_md.drop_ctl = 1; }
    table ipv4_host {
        key     = { hdr.ipv4.dst : exact; }
        actions = { send; NoAction; }
        size    = 1024;
        default_action = NoAction();
    }

    action wtr1_ok() { }
    table wtr1_validate {
        key = {
            ig_intr_md.ingress_port    : exact;
            hdr.inline_outer.src       : exact;
            hdr.inline_outer.etherType : exact;
            hdr.inline_ctrl.magic      : exact;
            hdr.inline_ctrl.version    : exact;
            hdr.inline_ctrl.header_len : exact;
            hdr.inline_ctrl.code       : exact;
            hdr.inline_ctrl.flags      : exact;
            hdr.ethernet.etherType     : exact;
            ig_md.is_ip                : exact;
            hdr.ipv4.version           : exact;
            hdr.ipv4.ihl               : exact;
            hdr.ipv4.proto             : exact;
        }
        actions = { wtr1_ok; drop; }
        const default_action = drop();
        const entries = {
            ((PortId_t)3, 48w0xCC40F380019B, 16w0x88B8,
             32w0x57545231, 8w1, 8w8, 8w1, 8w0,
             16w0x0800, 1w1, 4w4, 4w5, 8w17) : wtr1_ok();
        }
        size = 1;
    }

    action heartbeat_ok() { ig_md.heartbeat_valid = 1; }
    table heartbeat_validate {
        key = {
            ig_intr_md.ingress_port    : exact;
            hdr.inline_outer.src       : exact;
            hdr.inline_outer.etherType : exact;
            hdr.inline_ctrl.magic      : exact;
            hdr.inline_ctrl.version    : exact;
            hdr.inline_ctrl.header_len : exact;
            hdr.inline_ctrl.code       : exact;
            hdr.inline_ctrl.flags      : exact;
        }
        actions = { heartbeat_ok; NoAction; }
        const default_action = NoAction();
        const entries = {
            ((PortId_t)3, 48w0xCC40F380019B, 16w0x88BA,
             32w0x57544831, 8w1, 8w8, 8w1, 8w0) : heartbeat_ok();
        }
        size = 1;
    }

    bit<32> heartbeat_now_tick = 0;
    bit<32> heartbeat_min_tick  = 0;
    bit<8>  heartbeat_pulse_count = 0;
    bit<1>  heartbeat_ready = 0;

    action heartbeat_sample_time() {
        heartbeat_now_tick = ig_prsr_md.global_tstamp[47:16];
        heartbeat_min_tick = ig_prsr_md.global_tstamp[47:16] - 32w22889;
    }

    Register<bit<32>, bit<1>>(1, 0) heartbeat_last_tick;

    RegisterAction<bit<32>, bit<1>, bit<1>>(heartbeat_last_tick)
        heartbeat_touch_fresh = {
        void apply(inout bit<32> v, out bit<1> r) {
            if (v >= heartbeat_min_tick && v <= heartbeat_now_tick) {
                r = 1;
            } else { r = 0; }
            v = heartbeat_now_tick;
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<1>>(heartbeat_last_tick)
        heartbeat_peek_fresh = {
        void apply(inout bit<32> v, out bit<1> r) {
            if (v >= heartbeat_min_tick && v <= heartbeat_now_tick) {
                r = 1;
            } else { r = 0; }
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<1>>(heartbeat_last_tick)
        heartbeat_touch_wrapped = {
        void apply(inout bit<32> v, out bit<1> r) {
            if (v >= heartbeat_min_tick || v <= heartbeat_now_tick) {
                r = 1;
            } else { r = 0; }
            v = heartbeat_now_tick;
        }
    };
    RegisterAction<bit<32>, bit<1>, bit<1>>(heartbeat_last_tick)
        heartbeat_peek_wrapped = {
        void apply(inout bit<32> v, out bit<1> r) {
            if (v >= heartbeat_min_tick || v <= heartbeat_now_tick) {
                r = 1;
            } else { r = 0; }
        }
    };

    action heartbeat_select_touch_fresh() {
        ig_md.heartbeat_prev_fresh = heartbeat_touch_fresh.execute((bit<1>)0);
    }
    action heartbeat_select_peek_fresh() {
        ig_md.heartbeat_prev_fresh = heartbeat_peek_fresh.execute((bit<1>)0);
    }
    action heartbeat_select_touch_wrapped() {
        ig_md.heartbeat_prev_fresh = heartbeat_touch_wrapped.execute((bit<1>)0);
    }
    action heartbeat_select_peek_wrapped() {
        ig_md.heartbeat_prev_fresh = heartbeat_peek_wrapped.execute((bit<1>)0);
    }
    table heartbeat_window_select {
        key = {
            ig_md.heartbeat_valid : exact;
            heartbeat_now_tick[31:16] : range @name("heartbeat_tick_hi");
            heartbeat_now_tick[15:0]  : range @name("heartbeat_tick_lo");
        }
        actions = {
            heartbeat_select_touch_fresh;
            heartbeat_select_peek_fresh;
            heartbeat_select_touch_wrapped;
            heartbeat_select_peek_wrapped;
            NoAction;
        }
        const default_action = NoAction();
        const entries = {
            (1w0, 16w0 .. 16w0, 16w0 .. 16w22888) : heartbeat_select_peek_wrapped();
            (1w1, 16w0 .. 16w0, 16w0 .. 16w22888) : heartbeat_select_touch_wrapped();
            (1w0, 16w0 .. 16w0, 16w22889 .. 16w65535) : heartbeat_select_peek_fresh();
            (1w1, 16w0 .. 16w0, 16w22889 .. 16w65535) : heartbeat_select_touch_fresh();
            (1w0, 16w1 .. 16w65535, 16w0 .. 16w65535) : heartbeat_select_peek_fresh();
            (1w1, 16w1 .. 16w65535, 16w0 .. 16w65535) : heartbeat_select_touch_fresh();
        }
        size = 6;
    }

    Register<bit<8>, bit<1>>(1, 0) heartbeat_streak;
    RegisterAction<bit<8>, bit<1>, bit<8>>(heartbeat_streak)
        heartbeat_streak_update = {
        void apply(inout bit<8> v, out bit<8> r) {
            if (ig_md.heartbeat_prev_fresh == 0) {
                v = 1;
            } else if (v < 3) {
                v = v + 1;
            }
            r = v;
        }
    };

    RegisterAction<bit<8>, bit<1>, bit<8>>(heartbeat_streak)
        heartbeat_streak_observe = {
        void apply(inout bit<8> v, out bit<8> r) {
            if (ig_md.heartbeat_prev_fresh == 0) { v = 0; }
            r = v;
        }
    };

    action set_score(bit<8> score) { ig_md.suspicion_score = score; }
    table score_contribution {
        key = {
            ig_md.zone_rate_k        : range;
            ig_md.distinct_est_k     : range;
            ig_md.src_spread_k       : range;
            ig_md.client_zone_rate_k : range;
            ig_md.nxd_count_k        : range;
            ig_md.bigram_k           : range;
        }
        actions = { set_score; NoAction; }
        size = 64;
        const default_action = NoAction();
    }

    action set_tier(bit<8> tier) { ig_md.risk_tier = tier; }
    table score_to_tier {
        key = { ig_md.suspicion_score : range; }
        actions = { set_tier; NoAction; }
        size = 16;
        const default_action = NoAction();
    }

    Random<bit<16>>() rng;

    action divert_to_nic() {
        ig_tm_md.ucast_egress_port = (PortId_t)2;
        hdr.inline_outer.setValid();
        hdr.inline_outer.dst = 48w0xFFFFFFFFFFFF;
        hdr.inline_outer.src = hdr.ethernet.src;
        hdr.inline_outer.etherType = 16w0x88B9;
        hdr.inline_ctrl.setValid();
        hdr.inline_ctrl.magic = 32w0x57545131;
        hdr.inline_ctrl.version = 8w1;
        hdr.inline_ctrl.header_len = 8w8;
        hdr.inline_ctrl.code = ig_md.risk_tier;
        hdr.inline_ctrl.flags = (bit<8>)ig_md.overflow_flag;
    }

    table drop_policy {
        key     = { ig_md.rng_val : range; }
        actions = { drop; NoAction; }
        default_action = NoAction();
        size = 2;
    }

    bit<304> zone_bytes = 0;
    action mark_confirmed_zone() { ig_md.confirmed_zone_inspect = 1; }
    table confirmed_zone_policy {
        key = {
            zone_bytes : ternary @name("zone_policy_bytes");
            hdr.label2.label_len : exact @name("zone_label2_len");
            hdr.label3.label_len : exact @name("zone_label3_len");
        }
        actions = { mark_confirmed_zone; NoAction; }
        size = 256;
        const default_action = NoAction();
    }

    apply {

        ig_dprsr_md.drop_ctl = 0;

        hdr.hw_bridge.setValid();
        hdr.hw_bridge.ingress_ns = ig_prsr_md.global_tstamp;
        hdr.hw_bridge.score = 0;
        hdr.hw_bridge.tier = 0;

        bit<248> sub_bytes = 0;
        zone_bytes = 0;
        if (ig_md.is_dns == 1) {
            if (hdr.q1_part1.isValid()) sub_bytes[7:0]    = hdr.q1_part1.part;
            if (hdr.q1_part2.isValid()) sub_bytes[23:8]   = hdr.q1_part2.part;
            if (hdr.q1_part4.isValid()) sub_bytes[55:24]  = hdr.q1_part4.part;
            if (hdr.q1_part8.isValid()) sub_bytes[119:56] = hdr.q1_part8.part;
            if (hdr.q1_part16.isValid()) {
                sub_bytes[247:184] = hdr.q1_part16.first;
                sub_bytes[183:120] = hdr.q1_part16.second;
            }

            if (hdr.q2_part1.isValid()) zone_bytes[7:0]    = hdr.q2_part1.part;
            if (hdr.q2_part2.isValid()) zone_bytes[23:8]   = hdr.q2_part2.part;
            if (hdr.q2_part4.isValid()) zone_bytes[55:24]  = hdr.q2_part4.part;
            if (hdr.q2_part8.isValid()) zone_bytes[119:56] = hdr.q2_part8.part;
            if (hdr.q2_part16.isValid()) {
                zone_bytes[247:184] = hdr.q2_part16.first;
                zone_bytes[183:120] = hdr.q2_part16.second;
            }
            if (hdr.q3_part1.isValid()) zone_bytes[255:248] = hdr.q3_part1.part;
            if (hdr.q3_part2.isValid()) zone_bytes[271:256] = hdr.q3_part2.part;
            if (hdr.q3_part4.isValid()) zone_bytes[303:272] = hdr.q3_part4.part;
        }

        if (ig_md.is_dns == 1 && ig_md.is_response == 0 &&
                ig_md.parsed_query == 1 && ig_md.overflow_flag == 0) {
            if (hdr.label_last.isValid() && hdr.label_last.label_len == 0) {
                confirmed_zone_policy.apply();
            }
        }

        if (ig_md.is_ip == 1) { ipv4_host.apply(); }

        heartbeat_ready = 0;
        if (ig_md.is_heartbeat == 1) { heartbeat_validate.apply(); }
        heartbeat_sample_time();
        heartbeat_window_select.apply();
        if (ig_md.heartbeat_valid == 1) {
            heartbeat_pulse_count      = heartbeat_streak_update.execute((bit<1>)0);
        } else {
            heartbeat_pulse_count      = heartbeat_streak_observe.execute((bit<1>)0);
        }
        if (ig_md.heartbeat_prev_fresh == 1 && heartbeat_pulse_count >= 8w3) {
            heartbeat_ready = 1;
        }

        if (ig_md.is_heartbeat == 1) {
            drop();

        } else if (ig_md.is_inline_return == 1) {
            wtr1_validate.apply();

            hdr.inline_outer.setInvalid();
            hdr.inline_ctrl.setInvalid();
        } else if (ig_intr_md.ingress_port == (PortId_t)3 ||
                   hdr.ethernet.etherType == 16w0x88B9 ||
                   hdr.ethernet.etherType == 16w0x88B8 ||
                   hdr.ethernet.etherType == 16w0x88BA) {

            drop();
        } else {
        if (ig_md.is_dns == 1) {

            subdomain_hasher.apply(sub_bytes, ig_md.subdomain_hash);
            zone_hasher.apply(zone_bytes, ig_md.zone_hash);

            if (hdr.query_tc.isValid()) { ig_md.qtype = hdr.query_tc.tc_query.type; }

            if (hdr.label1.isValid() && hdr.label1.label_len != 0) {
                ig_md.num_labels = ig_md.num_labels + 1;
                ig_md.domain_len = ig_md.domain_len + hdr.label1.label_len;
            }
            if (hdr.label2.isValid() && hdr.label2.label_len != 0) {
                ig_md.num_labels = ig_md.num_labels + 1;
                ig_md.domain_len = ig_md.domain_len + hdr.label2.label_len;
            }
            if (hdr.label3.isValid() && hdr.label3.label_len != 0) {
                ig_md.num_labels = ig_md.num_labels + 1;
                ig_md.domain_len = ig_md.domain_len + hdr.label3.label_len;
            }
            if (hdr.label_last.isValid() && hdr.label_last.label_len != 0) {
                ig_md.num_labels = ig_md.num_labels + 1;
                ig_md.domain_len = ig_md.domain_len + hdr.label_last.label_len;
            }

            ig_md.sub_idx    = h_sub.get({ ig_md.zone_hash, ig_md.subdomain_hash });
            ig_md.clizone_ix = h_clizone.get({ hdr.ipv4.src, ig_md.zone_hash });

            ig_md.client_ix  = hdr.ipv4.src[15:0];

            if (ig_md.is_response == 0) {

                ig_md.zone_rate        = zone_rate_upd.execute(ig_md.zone_hash);
                ig_md.client_rate      = client_rate_upd.execute(ig_md.client_ix);
                ig_md.client_zone_rate = client_zone_upd.execute(ig_md.clizone_ix);

                ig_md.new_subdomain = sub_seen_chk.execute(ig_md.sub_idx);
                if (ig_md.new_subdomain == 1) {
                    ig_md.distinct_est = distinct_upd.execute(ig_md.zone_hash);
                } else {
                    ig_md.distinct_est = distinct_get.execute(ig_md.zone_hash);
                }

                ig_md.new_client = cli_seen_chk.execute(ig_md.clizone_ix);
                if (ig_md.new_client == 1) {
                    ig_md.src_spread = spread_upd.execute(ig_md.zone_hash);
                } else {
                    ig_md.src_spread = spread_get.execute(ig_md.zone_hash);
                }
            }
            else {

                if (hdr.dns_header.resp_code == NXDomain) {
                    ig_md.nxd_count = zone_nxd_upd.execute(ig_md.zone_hash);
                }
            }

            if (ig_md.zone_policy == 0) {

                ig_md.zone_rate_k        = ig_md.zone_rate[15:0];
                ig_md.distinct_est_k     = ig_md.distinct_est[15:0];
                ig_md.src_spread_k       = ig_md.src_spread[15:0];
                ig_md.client_zone_rate_k = ig_md.client_zone_rate[15:0];
                ig_md.nxd_count_k        = ig_md.nxd_count[15:0];

                bigram_obs_set.execute(ig_md.zone_hash);

                score_contribution.apply();

                if (ig_md.overflow_flag == 1) {
                    ig_md.suspicion_score = ig_md.suspicion_score + 1;
                }

                score_to_tier.apply();

                score_obs_set.execute(ig_md.zone_hash);
                tier_obs_set.execute(ig_md.zone_hash);

                if (ig_md.is_response == 0 &&
                        (ig_md.risk_tier == 2 || ig_md.risk_tier == 1 ||
                         ig_md.overflow_flag == 1 ||
                         ig_md.confirmed_zone_inspect == 1)) {

                    if (heartbeat_ready == 1) {
                        divert_to_nic();
                    }
                }
            }
        }
        }

        hdr.hw_bridge.score = ig_md.suspicion_score;
        hdr.hw_bridge.tier = ig_md.risk_tier;
    }
}
