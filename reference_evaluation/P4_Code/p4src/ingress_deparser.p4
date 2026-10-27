control SwitchIngressDeparser(
        packet_out pkt,
        inout Parsed_packet hdr,
        in    ig_metadata_t ig_md,
        in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr.hw_bridge);
        pkt.emit(hdr.inline_outer);
        pkt.emit(hdr.inline_ctrl);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.dns_header);
        pkt.emit(hdr.label1);
        pkt.emit(hdr.q1_part1);
        pkt.emit(hdr.q1_part2);
        pkt.emit(hdr.q1_part4);
        pkt.emit(hdr.q1_part8);
        pkt.emit(hdr.q1_part16);
        pkt.emit(hdr.label2);
        pkt.emit(hdr.q2_part1);
        pkt.emit(hdr.q2_part2);
        pkt.emit(hdr.q2_part4);
        pkt.emit(hdr.q2_part8);
        pkt.emit(hdr.q2_part16);
        pkt.emit(hdr.label3);
        pkt.emit(hdr.q3_part1);
        pkt.emit(hdr.q3_part2);
        pkt.emit(hdr.q3_part4);
        pkt.emit(hdr.q3_part8);
        pkt.emit(hdr.label_last);
        pkt.emit(hdr.query_tc);
        pkt.emit(hdr.dns_answer);
        pkt.emit(hdr.dns_ip);
    }
}
