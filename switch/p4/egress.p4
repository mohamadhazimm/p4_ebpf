
/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

/***************** M A T C H - A C T I O N  *********************/
control Egress(
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    /* Direct counter attached to the table */
    DirectCounter<bit<32>>(CounterType_t.PACKETS) packet_size_stats;

    action just_count() {
        packet_size_stats.count();
    }

    table packet_size_hist {
        key = {
            eg_intr_md.pkt_length : range;
        }
        actions = { just_count; @defaultonly NoAction; }
        counters = packet_size_stats;
        const default_action = NoAction();   // default should NOT count for histogram
        size = 512;
    }

    apply {
        packet_size_hist.apply();
    }
}