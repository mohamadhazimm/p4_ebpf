#include <core.p4>
#include <tna.p4>

#include "headers.p4"

#include "ingress_parser.p4"
#include "ingress.p4"
#include "ingress_deparser.p4"

#include "egress_parser.p4"
#include "egress.p4"
#include "egress_deparser.p4"

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
        ) pipe;

Switch(pipe) main;
