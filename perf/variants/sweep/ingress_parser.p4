/* perf/variants/sweep: the parser of basic_fix (perf/variants/gtot) plus the probe of headers.p4. A frame of
 * EtherType ETHERTYPE_SWEEP is a probe only from the ports in sweep_ports, a value set the control plane
 * fills (sweep_reader.py --sweep-ports): the packet generator's port, or the replay host's port for an
 * in-band replay. From any other port it is an ordinary frame (not IPv4: forwarded, not counted), so a
 * monitored host cannot read the registers. */
parser IngressParser(
    packet_in pkt,
    out my_headers_t hdr,
    out my_ingress_metadata_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md
) {
#if P4_ENABLE_SWEEP
    value_set<bit<9>>(8) sweep_ports;
#endif

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

#if P4_ENABLE_SWEEP
        meta.is_probe   = 1w0;
        meta.ridx       = 16w0;
        meta.dir_old    = 8w0;
        meta.ref_sp     = 16w0;
        meta.ref_dp     = 16w0;
#endif

        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.eth_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
#if P4_ENABLE_SWEEP
            ETHERTYPE_SWEEP: check_sweep_port;
#endif
            default: accept;
        }
    }

#if P4_ENABLE_SWEEP
    state check_sweep_port {
        transition select(ig_intr_md.ingress_port) {
            sweep_ports: parse_sweep;
            default: accept;
        }
    }

    state parse_sweep {
        pkt.extract(hdr.sweep);
        meta.is_probe = 1w1;
        transition accept;
    }
#endif

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
