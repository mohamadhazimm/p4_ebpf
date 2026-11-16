/* perf/variants/exact: headers and metadata. */

/* The flow table: four ways of 2^WAY_BITS slots (ingress.p4); a slot number is the way (2 bits) and the
 * index in it. */
#ifndef WAY_BITS
#define WAY_BITS 14
#endif
#define SLOT_BITS (WAY_BITS + 2)
typedef bit<SLOT_BITS> slot_t;

const bit<16> ETHERTYPE_IPV4   = 0x0800;
const bit<16> ETHERTYPE_VLAN   = 0x8100;
const bit<16> ETHERTYPE_QINQ   = 0x88A8;
/* Window marker (IEEE 802 local experimental EtherType 1): the frame that ends a window and starts
 * the next one. The replayer sends one at each window boundary of the capture, in order with the
 * capture's frames; in deployment the packet generator's timer does the same (window_clock). */
const bit<16> ETHERTYPE_WINDOW = 0x88B5;
const bit<16> WINDOW_MAGIC     = 0x5745;

const bit<8> IP_PROTO_TCP = 6;
const bit<8> IP_PROTO_UDP = 17;

header ethernet_t {
    bit<48> dst;
    bit<48> src;
    bit<16> eth_type;
}

header vlan_t {
    bit<3>  pcp;
    bit<1>  dei;
    bit<12> vid;
    bit<16> eth_type;
}

header window_marker_t {
    bit<16> magic;
    bit<32> epoch;      /* the window that starts with this marker */
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

header ipv4_opt_t {
    bit<32> word;
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

struct my_headers_t {
    ethernet_t      ethernet;
    vlan_t[2]       vlan;
    window_marker_t marker;
    ipv4_t          ipv4;
    ipv4_opt_t[10]  ipv4_opts;
    tcp_t           tcp;
    udp_t           udp;
}

/* Two 32-bit halves of one register entry. */
struct pair_t {
    bit<32> lo;
    bit<32> hi;
}

struct my_ingress_metadata_t {
    bit<16> l4_sport;
    bit<16> l4_dport;
    bit<1>  is_flow;        /* IPv4 (first fragment or unfragmented) TCP or UDP, as the model counts */
    bit<1>  bad_marker;     /* a window marker frame from a port not in marker_ports */

    bit<32> epoch;          /* the window this packet counts in */
    bit<1>  bank;           /* epoch & 1: which of the two banks of the window registers */
    bit<32> t;              /* ingress_mac_tstamp[47:16] (units of 65.536 us) */
    bit<32> L;              /* the packet's length as counted: IPv4 totalLen, or the frame minimum (frame_len) */
    bit<16> L16;

    /* endpoint order: src (address, port) < dst (address, port) */
    bit<32> ip_gt;          /* srcAddr |-| dstAddr */
    bit<32> ip_lt;          /* dstAddr |-| srcAddr */
    bit<16> port_lt;        /* dport |-| sport */
    bit<8>  sm;             /* 1: the source is the lower endpoint */
    bit<32> k_ip1;          /* the flow key with the lower endpoint first */
    bit<16> k_p1;
    bit<32> k_ip2;
    bit<16> k_p2;

    /* flow table */
    bit<32> sig;
    bit<16> h2;
    bit<16> h3;
    bit<16> h4;
    bit<16> h1;
    bit<8>  st;             /* way status: 0 miss, 1 hit, 2 claimed */
    slot_t slot;
    bit<1>  found;
    bit<1>  dir_ab;

    /* per-flow values before this packet */
    bit<16> code;           /* 0 repeat, 1..3 windows since the flow's previous one, 4 enter (or new) */
    bit<8>  ba_old;
    bit<16> old_min;
    bit<16> old_max;
    bit<32> first;
    bit<32> old_last;

    /* per-window contributions */
    bit<16> dec;            /* old_min |-| L16 */
    bit<16> inc;            /* L16 |-| old_max */
    bit<16> nmin;           /* 0xFFFF - old_min */
    bit<16> nL;             /* 0xFFFF - L16 */
    bit<32> dur_new;        /* t - first */
    bit<32> gap;            /* t - old_last */
    bit<32> dur_old;        /* old_last - first */

    bit<1>  f_syn;
    bit<1>  f_ack;
    bit<1>  f_rst;
}

struct my_egress_headers_t {
}

struct my_egress_metadata_t {
}
