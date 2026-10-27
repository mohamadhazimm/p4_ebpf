parser SwitchEgressParser(
        packet_in pkt,
        out Parsed_packet p,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        pkt.extract(p.hw_bridge);
        eg_md.is_ip = 0; eg_md.is_dns = 0;
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(p.ethernet);
        transition select(p.ethernet.etherType) { 0x0800: parse_ipv4; default: accept; }
    }
    state parse_ipv4 {
        pkt.extract(p.ipv4);
        eg_md.is_ip = 1;
        transition accept;
    }
}
