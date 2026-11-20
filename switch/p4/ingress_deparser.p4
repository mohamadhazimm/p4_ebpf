control IngressDeparser(
    packet_out pkt,
    inout my_headers_t hdr,
    in    my_ingress_metadata_t meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Mirror() flow_report_mirror;

    apply {
        if (ig_dprsr_md.mirror_type == FLOW_REPORT_MIRROR) {
            flow_report_mirror.emit<cpu_report_t>(meta.cpu_mirror_sid, meta.cpu_report);
        }

        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}