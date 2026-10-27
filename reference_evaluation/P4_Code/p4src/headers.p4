#define HASH_LENGTH_C    16
#define LABEL_LENGTH_C   56
#define NXDomain         3

#define NUM_ZONES        65536
#define NUM_CLIENTS      65536
#define NUM_CLIENT_ZONE  65536
#define NUM_SUB_SEEN     65536
#define NUM_CLIENT_SEEN  65536

typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;
typedef bit<32> BigramVal;

#define NUM_STATIC_BIGRAMS  3000

header ethernet_h {
    MacAddress dst;
    MacAddress src;
    bit<16>    etherType;
}
header ipv4_h {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      tos;
    bit<16>     len;
    bit<16>     id;
    bit<3>      flags;
    bit<13>     frag;
    bit<8>      ttl;
    bit<8>      proto;
    bit<16>     chksum;
    IPv4Address src;
    IPv4Address dst;
}
header udp_h {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> chksum;
}
header dns_h {
    bit<16> id;
    bit<1>  is_response;
    bit<4>  opcode;
    bit<1>  auth_answer;
    bit<1>  trunc;
    bit<1>  recur_desired;
    bit<1>  recur_avail;
    bit<1>  reserved;
    bit<1>  authentic_data;
    bit<1>  checking_disabled;
    bit<4>  resp_code;
    bit<16> q_count;
    bit<16> answer_count;
    bit<16> auth_rec;
    bit<16> addn_rec;
}

header dns_q_label { bit<8> label_len; }

header dns_q_part_1 { bit<8>  part; }
header dns_q_part_2 { bit<16> part; }
header dns_q_part_4 { bit<32> part; }
header dns_q_part_8 { bit<64> part; }
header dns_q_part_16 { bit<64> first; bit<64> second; }

struct dns_qtype_class { bit<16> type; bit<16> class; }
header dns_query_tc { dns_qtype_class tc_query; }
header dns_a {
    bit<16>         qname_pointer;
    dns_qtype_class tc_ans;
    bit<32>         ttl;
    bit<8>          rd_length_1;
    bit<8>          rd_length_2;
}
header dns_a_ip { bit<32> rdata; }

header inline_ctrl_h {
    bit<32> magic;
    bit<8>  version;
    bit<8>  header_len;
    bit<8>  code;
    bit<8>  flags;
}

header hw_latency_bridge_h {
    bit<48> ingress_ns;
    bit<8> score;
    bit<8> tier;
}

header hw_latency_report_h {
    bit<32> magic;
    bit<16> original_ether_type;
    bit<48> ingress_ns;
    bit<48> egress_ns;
    bit<8> score;
    bit<8> tier;
}

struct Parsed_packet {
    hw_latency_bridge_h hw_bridge;
    ethernet_h    inline_outer;
    inline_ctrl_h inline_ctrl;
    ethernet_h    ethernet;
    hw_latency_report_h hw_report;
    ipv4_h        ipv4;
    udp_h         udp;
    dns_h         dns_header;

    dns_q_label   label1;
    dns_q_part_1  q1_part1;
    dns_q_part_2  q1_part2;
    dns_q_part_4  q1_part4;
    dns_q_part_8  q1_part8;
    dns_q_part_16 q1_part16;

    dns_q_label   label2;
    dns_q_part_1  q2_part1;
    dns_q_part_2  q2_part2;
    dns_q_part_4  q2_part4;
    dns_q_part_8  q2_part8;
    dns_q_part_16 q2_part16;

    dns_q_label   label3;
    dns_q_part_1  q3_part1;
    dns_q_part_2  q3_part2;
    dns_q_part_4  q3_part4;
    dns_q_part_8  q3_part8;

    dns_q_label   label_last;
    dns_query_tc  query_tc;
    dns_a         dns_answer;
    dns_a_ip      dns_ip;
}

struct ig_metadata_t {
    bit<1>  is_inline_return;
    bit<1>  is_heartbeat;
    bit<1>  heartbeat_valid;
    bit<1>  heartbeat_prev_fresh;
    bit<1>  is_ip;
    bit<1>  is_dns;
    bit<1>  is_response;
    bit<1>  confirmed_zone_inspect;
    bit<1>  parsed_query;
    bit<1>  overflow_flag;

    bit<16> zone_hash;
    bit<16> subdomain_hash;
    bit<16> qtype;

    bit<16> sub_idx;
    bit<16> clizone_ix;
    bit<16> client_ix;

    bit<8>  num_labels;
    bit<8>  domain_len;

    bit<32> zone_rate;
    bit<32> distinct_est;
    bit<32> client_rate;
    bit<32> client_zone_rate;
    bit<32> src_spread;
    bit<32> nxd_count;

    bit<16> zone_rate_k;
    bit<16> distinct_est_k;
    bit<16> src_spread_k;
    bit<16> client_zone_rate_k;
    bit<16> nxd_count_k;
    bit<16> bigram_k;

    bit<1>  new_subdomain;
    bit<1>  new_client;
    bit<1>  digest_to_nic;
    MirrorId_t mirror_session_id;
    bit<32> mirror_magic;
    bit<8>  mirror_version;
    bit<8>  mirror_metadata_len;

    bit<32> bigram;

    bit<8>  suspicion_score;
    bit<8>  risk_tier;
    bit<16> rng_val;
    bit<2>  zone_policy;
    bit<16> drop_limit;
}

struct eg_metadata_t {
    bit<1>  is_ip;
    bit<1>  is_dns;
}

struct digest_t {
    bit<32> src_ip;
    bit<16> zone_hash;
    bit<16> subdomain_hash;
    bit<16> qtype;
    bit<8>  overflow_flag;
    bit<32> zone_rate;
    bit<32> distinct_est;
    bit<32> src_spread;
    bit<32> client_zone_rate;
    bit<32> nxd_count;
}

control calc_hash_248 (in bit<248> data, out bit<16> hash) (bit<16> coeff) {
    CRCPolynomial<bit<16>>(coeff = coeff, reversed = false, msb = false, extended = false,
                           init = 0xFFFF, xor = 0xFFFF) poly;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;
    action do_hash() { hash = hash_algo.get({data}); }
    apply { do_hash(); }
}
control calc_hash_304 (in bit<304> data, out bit<16> hash) (bit<16> coeff) {
    CRCPolynomial<bit<16>>(coeff = coeff, reversed = false, msb = false, extended = false,
                           init = 0xFFFF, xor = 0xFFFF) poly;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;
    action do_hash() { hash = hash_algo.get({data}); }
    apply { do_hash(); }
}
