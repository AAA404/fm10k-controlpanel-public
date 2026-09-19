#include "../vendor/netlab/sbin/switchd/fm10k_congestion_counters.h"
#include <assert.h>
#include <stdio.h>

int main(void) {
    fm_portCounters raw = {0};
    raw.cntCmPrivDropPkts = 1;
    raw.cntSmp0DropPkts = 2; raw.cntSmp1DropPkts = 3;
    raw.cntRxHog0DropPkts = 4; raw.cntRxHog1DropPkts = 5;
    raw.cntTxHog0DropPkts = 6; raw.cntTxHog1DropPkts = 7;
    raw.cntTxCMDropPkts = 29;
    raw.cntGlobalWMDropPkts = raw.cntRXMPDropPkts = raw.cntRxHogDropPkts = 100000;
    raw.cntTxHogDropPkts = raw.cntStatsDropCountTx = 200000;
    fm10k_congestion_counts result = fm10k_decode_congestion(&raw);
    assert(result.rx == 28 && result.tx == 29);
    raw.cntRxHog1DropPkts += UINT64_C(1) << 40;
    result = fm10k_decode_congestion(&raw);
    assert(result.rx == 28 + (UINT64_C(1) << 40) && result.tx == 29);
    puts("FM10000 SMP0/SMP1 drops include RX and egress decisions, excluding legacy counters");
    return 0;
}
