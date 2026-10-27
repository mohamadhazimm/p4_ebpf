parser SwitchIngressParser(packet_in pkt,
           out Parsed_packet p,
           out ig_metadata_t ig_md,
           out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(64);
        ig_md.is_inline_return = 0;
        ig_md.is_heartbeat = 0; ig_md.heartbeat_valid = 0;
        ig_md.heartbeat_prev_fresh = 0;
        ig_md.is_ip = 0; ig_md.is_dns = 0; ig_md.is_response = 0;
        ig_md.parsed_query = 0; ig_md.overflow_flag = 0;
        ig_md.digest_to_nic = 0; ig_md.qtype = 0;
        ig_md.zone_hash = 0; ig_md.subdomain_hash = 0;
        ig_md.sub_idx = 0; ig_md.clizone_ix = 0; ig_md.client_ix = 0;
        ig_md.num_labels = 0; ig_md.domain_len = 0;
        ig_md.zone_rate = 0; ig_md.distinct_est = 0;
        ig_md.client_rate = 0; ig_md.client_zone_rate = 0;
        ig_md.src_spread = 0; ig_md.nxd_count = 0;
        ig_md.zone_rate_k = 0; ig_md.distinct_est_k = 0; ig_md.src_spread_k = 0;
        ig_md.client_zone_rate_k = 0; ig_md.nxd_count_k = 0; ig_md.bigram_k = 0;
        ig_md.new_subdomain = 0; ig_md.new_client = 0;
        ig_md.bigram = 0;
        ig_md.suspicion_score = 0; ig_md.risk_tier = 0; ig_md.rng_val = 0;
        ig_md.zone_policy = 0; ig_md.confirmed_zone_inspect = 0;
        ig_md.drop_limit = 0;
        transition select(ig_intr_md.ingress_port) {
            (PortId_t)3: parse_dpu_outer;
            default: parse_ethernet;
        }
    }
    state parse_ethernet {
        pkt.extract(p.ethernet);
        transition select(p.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_dpu_outer {
        pkt.extract(p.inline_outer);
        transition select(p.inline_outer.etherType) {
            0x88B8: parse_inline_return;
            0x88BA: parse_heartbeat;
            default: accept;
        }
    }
    state parse_heartbeat {
        pkt.extract(p.inline_ctrl);
        ig_md.is_heartbeat = 1;
        transition accept;
    }
    state parse_inline_return {
        pkt.extract(p.inline_ctrl);
        pkt.extract(p.ethernet);
        ig_md.is_inline_return = 1;
        transition select(p.ethernet.etherType) {
            0x0800: parse_return_ipv4;
            default: accept;
        }
    }
    state parse_return_ipv4 {
        pkt.extract(p.ipv4);
        ig_md.is_ip = 1;
        transition accept;
    }
    state parse_ipv4 {
        pkt.extract(p.ipv4); ig_md.is_ip = 1;
        transition select(p.ipv4.proto) { 17: parse_udp; default: accept; }
    }
    state parse_udp {
        pkt.extract(p.udp);
        transition select(p.udp.dport) { 53: parse_dns_header; default: parse_udp_sport; }
    }
    state parse_udp_sport {
        transition select(p.udp.sport) { 53: parse_dns_header; default: accept; }
    }
    state parse_dns_header {
        pkt.extract(p.dns_header);
        ig_md.is_dns = 1;
        ig_md.is_response = p.dns_header.is_response;
        transition parse_label1;
    }

    state parse_label1 {
        pkt.extract(p.label1);
        transition select(p.label1.label_len) {
            0: parse_query_tc;
            1: l1_1; 2: l1_2; 3: l1_3; 4: l1_4; 5: l1_5; 6: l1_6; 7: l1_7; 8: l1_8;
            9: l1_9; 10: l1_10; 11: l1_11; 12: l1_12; 13: l1_13; 14: l1_14; 15: l1_15; 16: l1_tail16;
            17: l1_17; 18: l1_18; 19: l1_19; 20: l1_20; 21: l1_21; 22: l1_22; 23: l1_23; 24: l1_24;
            25: l1_25; 26: l1_26; 27: l1_27; 28: l1_28; 29: l1_29; 30: l1_30; 31: l1_31;
            0x20 &&& 0x20: l1_gr31;
            default: accept;
        }
    }
    state l1_1 { pkt.extract(p.q1_part1); transition parse_label2; }
    state l1_2 { pkt.extract(p.q1_part2); transition parse_label2; }
    state l1_3 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part2); transition parse_label2; }
    state l1_4 { pkt.extract(p.q1_part4); transition parse_label2; }
    state l1_5 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part4); transition parse_label2; }
    state l1_6 { pkt.extract(p.q1_part2); pkt.extract(p.q1_part4); transition parse_label2; }
    state l1_7 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part2); pkt.extract(p.q1_part4); transition parse_label2; }
    state l1_8 { pkt.extract(p.q1_part8); transition parse_label2; }
    state l1_9 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part8); transition parse_label2; }
    state l1_10 { pkt.extract(p.q1_part2); pkt.extract(p.q1_part8); transition parse_label2; }
    state l1_11 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part2); pkt.extract(p.q1_part8); transition parse_label2; }
    state l1_12 { pkt.extract(p.q1_part4); pkt.extract(p.q1_part8); transition parse_label2; }
    state l1_13 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part4); pkt.extract(p.q1_part8); transition parse_label2; }
    state l1_14 { pkt.extract(p.q1_part2); pkt.extract(p.q1_part4); pkt.extract(p.q1_part8); transition parse_label2; }
    state l1_15 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part2); pkt.extract(p.q1_part4); pkt.extract(p.q1_part8); transition parse_label2; }
    state l1_17 { pkt.extract(p.q1_part1); transition l1_tail16; }
    state l1_18 { pkt.extract(p.q1_part2); transition l1_tail16; }
    state l1_19 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part2); transition l1_tail16; }
    state l1_20 { pkt.extract(p.q1_part4); transition l1_tail16; }
    state l1_21 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part4); transition l1_tail16; }
    state l1_22 { pkt.extract(p.q1_part2); pkt.extract(p.q1_part4); transition l1_tail16; }
    state l1_23 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part2); pkt.extract(p.q1_part4); transition l1_tail16; }
    state l1_24 { pkt.extract(p.q1_part8); transition l1_tail16; }
    state l1_25 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part8); transition l1_tail16; }
    state l1_26 { pkt.extract(p.q1_part2); pkt.extract(p.q1_part8); transition l1_tail16; }
    state l1_27 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part2); pkt.extract(p.q1_part8); transition l1_tail16; }
    state l1_28 { pkt.extract(p.q1_part4); pkt.extract(p.q1_part8); transition l1_tail16; }
    state l1_29 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part4); pkt.extract(p.q1_part8); transition l1_tail16; }
    state l1_30 { pkt.extract(p.q1_part2); pkt.extract(p.q1_part4); pkt.extract(p.q1_part8); transition l1_tail16; }
    state l1_31 { pkt.extract(p.q1_part1); pkt.extract(p.q1_part2); pkt.extract(p.q1_part4); pkt.extract(p.q1_part8); transition l1_tail16; }
    state l1_tail16 {
        pkt.extract(p.q1_part16);
        transition parse_label2;
    }

    state l1_gr31 {
        pkt.extract(p.q1_part1); pkt.extract(p.q1_part2); pkt.extract(p.q1_part4); pkt.extract(p.q1_part8);
        ig_md.overflow_flag = 1;
        transition l1_overflow_tail16;
    }
    state l1_overflow_tail16 {
        pkt.extract(p.q1_part16);
        transition accept;
    }

    state parse_label2 {
        pkt.extract(p.label2);
        transition select(p.label2.label_len) {
            0: parse_query_tc;
            1: l2_1; 2: l2_2; 3: l2_3; 4: l2_4; 5: l2_5; 6: l2_6; 7: l2_7; 8: l2_8;
            9: l2_9; 10: l2_10; 11: l2_11; 12: l2_12; 13: l2_13; 14: l2_14; 15: l2_15; 16: l2_tail16;
            17: l2_17; 18: l2_18; 19: l2_19; 20: l2_20; 21: l2_21; 22: l2_22; 23: l2_23; 24: l2_24;
            25: l2_25; 26: l2_26; 27: l2_27; 28: l2_28; 29: l2_29; 30: l2_30; 31: l2_31;
            0x20 &&& 0x20: l2_gr31;
            default: accept;
        }
    }
    state l2_1 { pkt.extract(p.q2_part1); transition parse_label3; }
    state l2_2 { pkt.extract(p.q2_part2); transition parse_label3; }
    state l2_3 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part2); transition parse_label3; }
    state l2_4 { pkt.extract(p.q2_part4); transition parse_label3; }
    state l2_5 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part4); transition parse_label3; }
    state l2_6 { pkt.extract(p.q2_part2); pkt.extract(p.q2_part4); transition parse_label3; }
    state l2_7 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part2); pkt.extract(p.q2_part4); transition parse_label3; }
    state l2_8 { pkt.extract(p.q2_part8); transition parse_label3; }
    state l2_9 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part8); transition parse_label3; }
    state l2_10 { pkt.extract(p.q2_part2); pkt.extract(p.q2_part8); transition parse_label3; }
    state l2_11 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part2); pkt.extract(p.q2_part8); transition parse_label3; }
    state l2_12 { pkt.extract(p.q2_part4); pkt.extract(p.q2_part8); transition parse_label3; }
    state l2_13 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part4); pkt.extract(p.q2_part8); transition parse_label3; }
    state l2_14 { pkt.extract(p.q2_part2); pkt.extract(p.q2_part4); pkt.extract(p.q2_part8); transition parse_label3; }
    state l2_15 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part2); pkt.extract(p.q2_part4); pkt.extract(p.q2_part8); transition parse_label3; }
    state l2_17 { pkt.extract(p.q2_part1); transition l2_tail16; }
    state l2_18 { pkt.extract(p.q2_part2); transition l2_tail16; }
    state l2_19 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part2); transition l2_tail16; }
    state l2_20 { pkt.extract(p.q2_part4); transition l2_tail16; }
    state l2_21 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part4); transition l2_tail16; }
    state l2_22 { pkt.extract(p.q2_part2); pkt.extract(p.q2_part4); transition l2_tail16; }
    state l2_23 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part2); pkt.extract(p.q2_part4); transition l2_tail16; }
    state l2_24 { pkt.extract(p.q2_part8); transition l2_tail16; }
    state l2_25 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part8); transition l2_tail16; }
    state l2_26 { pkt.extract(p.q2_part2); pkt.extract(p.q2_part8); transition l2_tail16; }
    state l2_27 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part2); pkt.extract(p.q2_part8); transition l2_tail16; }
    state l2_28 { pkt.extract(p.q2_part4); pkt.extract(p.q2_part8); transition l2_tail16; }
    state l2_29 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part4); pkt.extract(p.q2_part8); transition l2_tail16; }
    state l2_30 { pkt.extract(p.q2_part2); pkt.extract(p.q2_part4); pkt.extract(p.q2_part8); transition l2_tail16; }
    state l2_31 { pkt.extract(p.q2_part1); pkt.extract(p.q2_part2); pkt.extract(p.q2_part4); pkt.extract(p.q2_part8); transition l2_tail16; }
    state l2_tail16 {
        pkt.extract(p.q2_part16);
        transition parse_label3;
    }

    state l2_gr31 { ig_md.overflow_flag = 1; transition accept; }

    state parse_label3 {
        pkt.extract(p.label3);
        transition select(p.label3.label_len) {
            0: parse_query_tc;
            1: l3_1; 2: l3_2; 3: l3_3; 4: l3_4; 5: l3_5; 6: l3_6; 7: l3_7;
            8: l3_gr7; 9: l3_gr7;
            10: l3_gr7; 11: l3_gr7; 12: l3_gr7; 13: l3_gr7; 14: l3_gr7; 15: l3_gr7;
            0x10 &&& 0x10: l3_gr7;
            0x20 &&& 0x20: l3_gr7;
            default: accept;
        }
    }
    state l3_1 { pkt.extract(p.q3_part1); transition parse_label_last; }
    state l3_2 { pkt.extract(p.q3_part2); transition parse_label_last; }
    state l3_3 { pkt.extract(p.q3_part1); pkt.extract(p.q3_part2); transition parse_label_last; }
    state l3_4 { pkt.extract(p.q3_part4); transition parse_label_last; }
    state l3_5 { pkt.extract(p.q3_part1); pkt.extract(p.q3_part4); transition parse_label_last; }
    state l3_6 { pkt.extract(p.q3_part2); pkt.extract(p.q3_part4); transition parse_label_last; }
    state l3_7 { pkt.extract(p.q3_part1); pkt.extract(p.q3_part2); pkt.extract(p.q3_part4); transition parse_label_last; }

    state l3_gr7 { ig_md.overflow_flag = 1; transition accept; }

    state parse_label_last {
        pkt.extract(p.label_last);
        transition select(p.label_last.label_len) {
            0: parse_query_tc;
            default: set_overflow;
        }
    }
    state set_overflow { ig_md.overflow_flag = 1; transition accept; }

    state parse_query_tc {
        pkt.extract(p.query_tc);
        ig_md.parsed_query = 1;

        transition select(ig_md.is_response, p.dns_header.answer_count) {
            (1, 0): accept;
            (1, _): parse_dns_answer;
            default: accept;
        }
    }
    state parse_dns_answer {
        pkt.extract(p.dns_answer);
        transition select(p.dns_answer.tc_ans.type) { 1: parse_a_ip; default: accept; }
    }
    state parse_a_ip { pkt.extract(p.dns_ip); transition accept; }
}
