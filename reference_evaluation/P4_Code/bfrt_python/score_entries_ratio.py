sc = bfrt.basic.pipe.SwitchIngress.score_contribution
sc.clear()

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=10, distinct_est_k_end=14,
    src_spread_k_start=0, src_spread_k_end=2,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=1,
    score=10)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=15, distinct_est_k_end=19,
    src_spread_k_start=0, src_spread_k_end=3,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=2,
    score=10)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=20, distinct_est_k_end=34,
    src_spread_k_start=0, src_spread_k_end=4,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=3,
    score=10)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=35, distinct_est_k_end=49,
    src_spread_k_start=0, src_spread_k_end=7,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=4,
    score=10)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=50, distinct_est_k_end=99,
    src_spread_k_start=0, src_spread_k_end=10,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=5,
    score=10)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=100, distinct_est_k_end=149,
    src_spread_k_start=0, src_spread_k_end=20,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=6,
    score=10)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=150, distinct_est_k_end=199,
    src_spread_k_start=0, src_spread_k_end=30,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=7,
    score=10)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=200, distinct_est_k_end=65535,
    src_spread_k_start=0, src_spread_k_end=40,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=8,
    score=10)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=10, distinct_est_k_end=14,
    src_spread_k_start=0, src_spread_k_end=5,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=9,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=15, distinct_est_k_end=19,
    src_spread_k_start=0, src_spread_k_end=7,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=10,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=20, distinct_est_k_end=34,
    src_spread_k_start=0, src_spread_k_end=10,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=11,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=35, distinct_est_k_end=49,
    src_spread_k_start=0, src_spread_k_end=17,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=12,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=50, distinct_est_k_end=99,
    src_spread_k_start=0, src_spread_k_end=25,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=13,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=100, distinct_est_k_end=149,
    src_spread_k_start=0, src_spread_k_end=50,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=14,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=150, distinct_est_k_end=199,
    src_spread_k_start=0, src_spread_k_end=75,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=15,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=200, distinct_est_k_end=65535,
    src_spread_k_start=0, src_spread_k_end=100,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=16,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=0, distinct_est_k_end=65535,
    src_spread_k_start=0, src_spread_k_end=65535,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=5, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=17,
    score=7)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=100, distinct_est_k_end=104,
    src_spread_k_start=0, src_spread_k_end=66,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=18,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=105, distinct_est_k_end=109,
    src_spread_k_start=0, src_spread_k_end=70,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=19,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=110, distinct_est_k_end=124,
    src_spread_k_start=0, src_spread_k_end=73,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=20,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=125, distinct_est_k_end=139,
    src_spread_k_start=0, src_spread_k_end=83,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=21,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=140, distinct_est_k_end=189,
    src_spread_k_start=0, src_spread_k_end=93,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=22,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=190, distinct_est_k_end=239,
    src_spread_k_start=0, src_spread_k_end=126,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=23,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=240, distinct_est_k_end=289,
    src_spread_k_start=0, src_spread_k_end=160,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=24,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=290, distinct_est_k_end=65535,
    src_spread_k_start=0, src_spread_k_end=193,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=25,
    score=8)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=50, distinct_est_k_end=54,
    src_spread_k_start=0, src_spread_k_end=33,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=26,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=55, distinct_est_k_end=59,
    src_spread_k_start=0, src_spread_k_end=36,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=27,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=60, distinct_est_k_end=74,
    src_spread_k_start=0, src_spread_k_end=40,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=28,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=75, distinct_est_k_end=89,
    src_spread_k_start=0, src_spread_k_end=50,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=29,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=90, distinct_est_k_end=139,
    src_spread_k_start=0, src_spread_k_end=60,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=30,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=140, distinct_est_k_end=189,
    src_spread_k_start=0, src_spread_k_end=93,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=31,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=190, distinct_est_k_end=239,
    src_spread_k_start=0, src_spread_k_end=126,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=32,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=240, distinct_est_k_end=65535,
    src_spread_k_start=0, src_spread_k_end=160,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=33,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=40, distinct_est_k_end=65535,
    src_spread_k_start=0, src_spread_k_end=65535,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=34,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=5, distinct_est_k_end=9,
    src_spread_k_start=0, src_spread_k_end=2,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=35,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=10, distinct_est_k_end=14,
    src_spread_k_start=0, src_spread_k_end=5,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=36,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=15, distinct_est_k_end=29,
    src_spread_k_start=0, src_spread_k_end=7,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=37,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=30, distinct_est_k_end=44,
    src_spread_k_start=0, src_spread_k_end=15,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=38,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=45, distinct_est_k_end=94,
    src_spread_k_start=0, src_spread_k_end=22,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=39,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=95, distinct_est_k_end=144,
    src_spread_k_start=0, src_spread_k_end=47,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=40,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=145, distinct_est_k_end=194,
    src_spread_k_start=0, src_spread_k_end=72,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=41,
    score=4)

sc.add_with_set_score(
    zone_rate_k_start=0, zone_rate_k_end=65535,
    distinct_est_k_start=195, distinct_est_k_end=65535,
    src_spread_k_start=0, src_spread_k_end=97,
    client_zone_rate_k_start=0, client_zone_rate_k_end=65535,
    nxd_count_k_start=0, nxd_count_k_end=65535,
    bigram_k_start=0, bigram_k_end=65535,
    MATCH_PRIORITY=42,
    score=4)

print('inserted 42 entries into score_contribution')
