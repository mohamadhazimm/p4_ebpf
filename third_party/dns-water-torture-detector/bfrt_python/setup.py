import os
from ipaddress import ip_address

source_port = int(os.environ['P4_SOURCE_PORT'])
sink_port = int(os.environ['P4_SINK_PORT'])
if not (0 <= source_port < 512 and 0 <= sink_port < 512) or source_port == sink_port:
    raise ValueError('Set distinct verified Tofino device ports in [0, 511]')
if source_port == 3:
    raise ValueError('The retained detector reserves ingress device port 3 for DPU service frames')
p4 = bfrt.basic.pipe.SwitchIngress
p4.ipv4_host.clear()
p4.ipv4_host.add_with_send(dst=int(ip_address('192.168.0.2')), port=sink_port)
p4.ipv4_host.add_with_send(dst=int(ip_address('192.168.0.1')), port=source_port)
p4.score_to_tier.clear()
p4.score_to_tier.add_with_set_tier(suspicion_score_start=3, suspicion_score_end=5,
                                 MATCH_PRIORITY=2, tier=1)
p4.score_to_tier.add_with_set_tier(suspicion_score_start=6, suspicion_score_end=255,
                                 MATCH_PRIORITY=1, tier=2)
p4.confirmed_zone_policy.clear()

project_root = os.environ.get('P4_CODE_ROOT', os.path.expanduser('~/P4_Code'))
score_path = os.path.join(project_root, 'bfrt_python', 'score_entries_ratio.py')
with open(score_path) as score_file:
    exec(compile(score_file.read(), score_path, 'exec'))
bfrt.complete_operations()
print('Forwarding and score rows: verify the following readback.')
p4.ipv4_host.dump(table=True)
p4.score_contribution.dump(table=True)
p4.score_to_tier.dump(table=True)
