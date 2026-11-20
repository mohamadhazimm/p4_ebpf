control IngressDeparser(
    packet_out pkt,
    inout my_headers_t hdr,
    in    my_ingress_metadata_t meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan);
        pkt.emit(hdr.marker);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv4_opts);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}
