parser IngressParser(
    packet_in pkt,
    out my_headers_t hdr,
    out my_ingress_metadata_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md
) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);

        meta.flow_index = 16w0;

        meta.l4_sport   = 16w0;
        meta.l4_dport   = 16w0;

        meta.iat_valid  = 1w0;
        meta.cur_iat    = 32w0;

        meta.do_report  = 1w0;

        meta.pkt_len    = 16w0;

        meta.f_syn      = 1w0;
        meta.f_ack      = 1w0;
        meta.f_fin      = 1w0;
        meta.f_rst      = 1w0;

        meta.len_bad    = 1w0;
        meta.syn_noack  = 1w0;
        meta.rule_mask  = 8w0;
        meta.tcp_dport_allowed = 1w0;
        meta.udp_dport_allowed = 1w0;

        meta.dir_ab        = 1w1;
        meta.from_internal = 1w0;

        meta.cpu_mirror_sid       = 0;
        meta.cpu_report.setInvalid();
        meta.cpu_report.magic     = 16w0;
        meta.cpu_report.src_ip    = 32w0;
        meta.cpu_report.dst_ip    = 32w0;
        meta.cpu_report.src_port  = 16w0;
        meta.cpu_report.dst_port  = 16w0;
        meta.cpu_report.proto     = 8w0;
        meta.cpu_report.reason    = 8w0;
        meta.cpu_report.flow_index = 16w0;

        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.eth_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.pkt_len = hdr.ipv4.totalLen;
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.l4_sport = hdr.tcp.srcPort;
        meta.l4_dport = hdr.tcp.dstPort;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.l4_sport = hdr.udp.src_port;
        meta.l4_dport = hdr.udp.dst_port;
        transition accept;
    }
}