/* Flow packets as features/switch_model.py parse_flow_packet() takes them: up to two VLAN tags,
 * IPv4 version 4 with IHL >= 5, fragment offset 0, TCP or UDP. Anything else is forwarded without
 * being counted. IPv4 options are extracted (ipv4_opts) so that they are forwarded. A window marker
 * frame (ETHERTYPE_WINDOW) is parsed as such. */
parser IngressParser(
    packet_in pkt,
    out my_headers_t hdr,
    out my_ingress_metadata_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md
) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.l4_sport = 16w0;
        meta.l4_dport = 16w0;
        meta.is_flow = 1w0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.eth_type) {
            ETHERTYPE_IPV4:   parse_ipv4;
            ETHERTYPE_VLAN:   parse_vlan0;
            ETHERTYPE_QINQ:   parse_vlan0;
            ETHERTYPE_WINDOW: parse_marker;
            default: accept;
        }
    }

    state parse_vlan0 {
        pkt.extract(hdr.vlan[0]);
        transition select(hdr.vlan[0].eth_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_VLAN: parse_vlan1;
            ETHERTYPE_QINQ: parse_vlan1;
            default: accept;
        }
    }

    state parse_vlan1 {
        pkt.extract(hdr.vlan[1]);
        transition select(hdr.vlan[1].eth_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_marker {
        pkt.extract(hdr.marker);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.fragOffset, hdr.ipv4.protocol) {
            (4, 5, 0, IP_PROTO_TCP): parse_tcp;
            (4, 5, 0, IP_PROTO_UDP): parse_udp;
            (4, 6, 0, _):  opt1;
            (4, 7, 0, _):  opt2;
            (4, 8, 0, _):  opt3;
            (4, 9, 0, _):  opt4;
            (4, 10, 0, _): opt5;
            (4, 11, 0, _): opt6;
            (4, 12, 0, _): opt7;
            (4, 13, 0, _): opt8;
            (4, 14, 0, _): opt9;
            (4, 15, 0, _): opt10;
            default: accept;
        }
    }

    state opt10 { pkt.extract(hdr.ipv4_opts.next); transition opt9; }
    state opt9 { pkt.extract(hdr.ipv4_opts.next); transition opt8; }
    state opt8 { pkt.extract(hdr.ipv4_opts.next); transition opt7; }
    state opt7 { pkt.extract(hdr.ipv4_opts.next); transition opt6; }
    state opt6 { pkt.extract(hdr.ipv4_opts.next); transition opt5; }
    state opt5 { pkt.extract(hdr.ipv4_opts.next); transition opt4; }
    state opt4 { pkt.extract(hdr.ipv4_opts.next); transition opt3; }
    state opt3 { pkt.extract(hdr.ipv4_opts.next); transition opt2; }
    state opt2 { pkt.extract(hdr.ipv4_opts.next); transition opt1; }
    state opt1 { pkt.extract(hdr.ipv4_opts.next); transition l4; }

    state l4 {
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
        meta.is_flow = 1w1;
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.l4_sport = hdr.udp.src_port;
        meta.l4_dport = hdr.udp.dst_port;
        meta.is_flow = 1w1;
        transition accept;
    }
}
