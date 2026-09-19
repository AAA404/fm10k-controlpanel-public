#ifndef FM10K_CONGESTION_COUNTERS_H
#define FM10K_CONGESTION_COUNTERS_H

#include <stdint.h>
#include <fm_sdk.h>

typedef struct {
    uint64_t rx, tx;
} fm10k_congestion_counts;

static inline fm10k_congestion_counts fm10k_decode_congestion(const fm_portCounters *cnt) {
    /* FM10000 RX forwarding bank 2 includes all-destination TX-hog drops.
     * Individual egress drops come from CM_APPLY_DROP_COUNT. The similarly
     * named FM6000 fields are unpopulated here; cntStatsDropCountTx is missed
     * statistics updates on FM4000, not dropped data packets. */
    return (fm10k_congestion_counts){
        .rx = cnt->cntCmPrivDropPkts + cnt->cntSmp0DropPkts + cnt->cntSmp1DropPkts +
              cnt->cntRxHog0DropPkts + cnt->cntRxHog1DropPkts +
              cnt->cntTxHog0DropPkts + cnt->cntTxHog1DropPkts,
        .tx = cnt->cntTxCMDropPkts
    };
}

#endif
