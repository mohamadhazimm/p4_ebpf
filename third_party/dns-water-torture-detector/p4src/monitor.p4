#include <core.p4>
#include <tna.p4>
#include "headers.p4"

header ethernet_t {
    bit<48> dst;
    bit<48> src;
    bit<16> eth_type;
}
header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  fragOffset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdrChecksum;
    bit<32>  srcAddr;
    bit<32>  dstAddr;
}
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}
struct meta_t {
    bit<1>  is_tcp;
    bit<1>  is_https;
    bit<16> flow_idx;
    bit<16> pkt_len;
}

parser IngressParser(packet_in        pkt,

    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,

    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.eth_type) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

control IngressDeparser(packet_out pkt,

    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,

    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

control Ingress(

    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,

    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

    apply {
        if (hdr.ipv4.isValid()) {

        }
    }
}

parser EgressParser(packet_in        pkt,

    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,

    out egress_intrinsic_metadata_t  eg_intr_md)
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
