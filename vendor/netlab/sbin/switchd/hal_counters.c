#include "netlab/log.h"
#include "netlab/hal.h"
#include <fm_sdk.h>

int hal_get_port_counters(int sw, int port,
                          u64 *rx_bytes, u64 *tx_bytes,
                          u64 *rx_pkts, u64 *tx_pkts,
                          u64 *rx_errs) {
    fm_portCounters cnt;
    fm_status st = fmGetPortCounters((fm_int)sw, (fm_int)port, &cnt);
    if (st != FM_OK) return -1;

    *rx_bytes = cnt.cntRxGoodOctets;
    *tx_bytes = cnt.cntTxOctets;
    *rx_pkts  = cnt.cntRxUcstPkts + cnt.cntRxBcstPkts + cnt.cntRxMcstPkts;
    *tx_pkts  = cnt.cntTxUcstPkts + cnt.cntTxBcstPkts + cnt.cntTxMcstPkts;
    *rx_errs  = cnt.cntRxFCSErrors + cnt.cntRxSymbolErrors +
                cnt.cntRxFrameSizeErrors + cnt.cntRxFramingErrorPkts;
    return 0;
}
