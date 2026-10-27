/* Latency-measuring copy of the detector (Phase 2.5); a benchmark variant only.
 * The detector's own files are included unmodified; compile with
 *   bf-p4c --target tofino --arch tna -I <thesis-hybrid-ebpf-p4 dir> basic_lat.p4
 * See lat_wrapper.p4 for what the wrapper adds.
 */
#include <core.p4>
#include <tna.p4>
#include "headers.p4"
#include "ingress_parser.p4"
#include "ingress.p4"
#include "ingress_deparser.p4"
#include "egress_parser.p4"
#include "egress.p4"
#include "egress_deparser.p4"
#include "lat_wrapper.p4"
