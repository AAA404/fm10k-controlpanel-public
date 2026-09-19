/* Use the pytest-owned working directory, never an installed state path. */
#define NETLAB_QOS_WATERMARK_PROVENANCE_PATH "./qos-watermark-provenance-test.v1"
#include "../vendor/netlab/tests/integration/switchd_transaction_snapshot_test.c"

fm_status fmGetSwitchAttribute(fm_int sw, fm_int attr, void *out) {
    if (sw != 0 || attr != FM_MTU_LIST || !out) return FM_ERR_INVALID_ARGUMENT;
    fm_mtuEntry *entry = out;
    if (entry->index >= 8) return FM_ERR_INVALID_ARGUMENT;
    entry->mtu = 1540;
    return FM_OK;
}
