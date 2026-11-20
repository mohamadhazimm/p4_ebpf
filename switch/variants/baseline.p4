/* Forwarding-only baseline for the hardware benchmarks; not part of the
 * detector. The forwarding table, its actions and its default are copied from
 * thesis-hybrid-ebpf-p4/ingress.p4, with the same control names, so one
 * control-plane script programs both (pipe.Ingress.forwarding). The parsers
 * extract intrinsic metadata only and egress is empty, so every byte of the
 * packet passes through unparsed.
 *
 *   bf-p4c --target tofino --arch tna baseline.p4
 */
#include <core.p4>
#include <tna.p4>

struct my_headers_t {}
struct my_ingress_metadata_t {}
struct my_egress_headers_t {}
struct my_egress_metadata_t {}

parser IngressParser(
    packet_in pkt,
    out my_headers_t hdr,
    out my_ingress_metadata_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md
) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

control Ingress(
    inout my_headers_t hdr,
    inout my_ingress_metadata_t meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action send_using_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.bypass_egress     = 0;
    }

    action drop() {
        ig_dprsr_md.drop_ctl       = 3w1;
        ig_tm_md.bypass_egress     = 1w1;
    }

    table forwarding {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            send_using_port;
            drop;
        }
        const default_action = drop();
        size = 256;
    }

    apply {
        forwarding.apply();
    }
}

control IngressDeparser(
    packet_out pkt,
    inout my_headers_t hdr,
    in    my_ingress_metadata_t meta,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

parser EgressParser(
    packet_in pkt,
    out my_egress_headers_t         hdr,
    out my_egress_metadata_t        meta,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control Egress(
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

control EgressDeparser(packet_out pkt,
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;
Switch(pipe) main;
