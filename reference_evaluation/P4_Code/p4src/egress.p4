control SwitchEgress(
        inout Parsed_packet headers,
        inout eg_metadata_t eg_md,
        in    egress_intrinsic_metadata_t eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply {

        if (eg_md.is_ip == 1 && headers.ipv4.proto == 8w17) {
            headers.hw_report.setValid();
            headers.hw_report.magic = 32w0x48574C31;
            headers.hw_report.original_ether_type = headers.ethernet.etherType;
            headers.hw_report.ingress_ns = headers.hw_bridge.ingress_ns;
            headers.hw_report.egress_ns = eg_prsr_md.global_tstamp;
            headers.hw_report.score = headers.hw_bridge.score;
            headers.hw_report.tier = headers.hw_bridge.tier;
            headers.ethernet.etherType = 16w0x88BC;
        }

        headers.hw_bridge.setInvalid();
    }
}
