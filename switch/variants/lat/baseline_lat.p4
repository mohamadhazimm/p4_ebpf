/* Latency-measuring copy of the forwarding-only baseline (Phase 2.5).
 * baseline_body.p4 is perf/variants/baseline.p4 without its Pipeline/Switch
 * lines, generated at build time (make_lat_sources.sh), so the baseline source
 * itself stays as it was measured in Phase 2.3. See lat_wrapper.p4.
 */
#include "baseline_body.p4"
#include "lat_wrapper.p4"
