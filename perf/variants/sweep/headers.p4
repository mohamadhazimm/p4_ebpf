/* perf/variants/sweep: -DP4_ENABLE_SWEEP=0 leaves out the probe path (parser, ingress); the parser is included
 * before ingress.p4, so the default is set here. */
#ifndef P4_ENABLE_SWEEP
#define P4_ENABLE_SWEEP 1
#endif

const bit<16> ETHERTYPE_IPV4 = 0x0800;

const bit<8> IP_PROTO_TCP = 6;
const bit<8> IP_PROTO_UDP = 17;

const MirrorType_t FLOW_REPORT_MIRROR = 1;

header ethernet_t {
    bit<48> dst;
    bit<48> src;
    bit<16> eth_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
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

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

/* Report payload mirrored to CPU/host (18 bytes, magic CPU_REPORT_MAGIC).
 * flow_index is the register bucket the data plane chose, so the collector
 * reads it from the report instead of recomputing the hash. */
const bit<16> CPU_REPORT_MAGIC = 0xBEF1;

header cpu_report_t {
    bit<16> magic;
    bit<32> src_ip;
    bit<32> dst_ip;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8>  proto;
    bit<8>  reason;
    bit<16> flow_index;
}

/* perf/variants/sweep: a probe asks for one bucket and leaves as its export (ingress.p4).
 *
 * A probe is a frame of EtherType ETHERTYPE_SWEEP from a port in the parser's sweep_ports (the packet
 * generator's port, or the replay host's for an in-band replay), with a sweep_t after Ethernet. Its first
 * 6 bytes are where the generator writes its header (pipe, app, batch id, packet id): the packet id,
 * the low 16 bits of the destination MAC, is the bucket the probe reads. An in-band probe puts the
 * bucket there itself. The program fills sweep_t with the bucket's 14 registers (probe 0 also with the
 * seven totals) and sends the frame to the export port; the sweep_t fields are the registers as they
 * were when the probe passed, in network byte order, 90 bytes. */
const bit<16> ETHERTYPE_SWEEP = 0x88B6;
const bit<16> SWEEP_MAGIC     = 0x5357;   /* "SW": set by whoever sends the probe; not checked */

header sweep_t {
    bit<16> magic;
    bit<16> idx;        /* the bucket read: packet id */
    bit<16> gen;        /* destination MAC bits 47:32 (generator: pad, pipe, app, pad) */
    bit<16> batch;      /* destination MAC bits 31:16 (generator: batch id) */
    bit<32> seq;        /* the pipe's count of probes for bucket 0: the sweep this probe belongs to */
    bit<32> t;          /* ingress_mac_tstamp[31:0] of the probe, ns */
    bit<32> pkts;
    bit<32> bytes;
    bit<32> pkts_ab;
    bit<32> bytes_ab;
    bit<32> first_ts;
    bit<32> last_ts;
    bit<32> syn;
    bit<32> ack;
    bit<32> rst;
    bit<16> ref_sp;
    bit<16> ref_dp;
    bit<16> min_len;
    bit<16> max_len;
    bit<8>  dir_valid;
    bit<8>  coll;       /* the bucket's colliding packets (reg_coll), saturating at 255 */
    bit<32> g_pkts_ab;  /* the seven one-entry totals, read by probe 0 only (0 in the others) */
    bit<32> g_bytes_ab;
    bit<32> g_pkts_ba;
    bit<32> g_bytes_ba;
    bit<32> g_syn;
    bit<32> g_ack;
    bit<32> g_rst;
}

struct my_headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
    sweep_t    sweep;
}

struct my_ingress_metadata_t {
    bit<16> flow_index;

    bit<16> l4_sport;
    bit<16> l4_dport;

    bit<1>  f_syn;
    bit<1>  f_ack;
    bit<1>  f_fin;
    bit<1>  f_rst;

    bit<1>  iat_valid;
    bit<32> cur_iat;

    bit<1>  do_report;

    bit<16> pkt_len;

    bit<1>  len_bad;
    bit<1>  syn_noack;

    bit<8>  rule_mask;
    bit<1>  tcp_dport_allowed;
    bit<1>  udp_dport_allowed;
    bit<1>  dir_ab;
    bit<1>  from_internal;

    MirrorId_t  cpu_mirror_sid;
    cpu_report_t cpu_report;

    bit<1>  is_probe;   /* a probe from a port in sweep_ports (ingress_parser.p4) */
    bit<16> ridx;       /* -DSWEEP_SHARED_INDEX=1: the register index of both paths, in the PHV */
    bit<8>  dir_old;    /* merged layout: reg_dir_valid before this packet (data path) */
    bit<16> ref_sp;     /* merged layout: the bucket's reference ports (data path) */
    bit<16> ref_dp;
}

struct my_egress_headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

struct my_egress_metadata_t {
}
