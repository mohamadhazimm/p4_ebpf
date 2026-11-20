control SwitchEgressDeparser(
        packet_out pkt,
        inout Parsed_packet hdr,
        in    eg_metadata_t eg_md,
        in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply { pkt.emit(hdr); }
}
