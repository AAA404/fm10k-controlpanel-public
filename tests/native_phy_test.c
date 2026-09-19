/* Diagnostic reads must remain bounded, fail closed and honor the cache. */
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_regs.h>
#include <api/internal/fm10000/fm10000_api_regs_int.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static bool native = true, split, field_failure;
static int reads, now_seconds = 1;
bool fm10k_native_profile(void) { return native; }
static int fake_clock(clockid_t id, struct timespec *ts) {
    assert(id == CLOCK_MONOTONIC);
    ts->tv_sec = now_seconds; ts->tv_nsec = 0; return 0;
}
fm_status fmGetPortAttribute(fm_int sw, fm_int port, fm_int attr, void *out) {
    assert(sw == 0 && (port == 1 || port == 5)); ++reads;
    if (attr == FM_PORT_ETHERNET_INTERFACE_MODE)
        *(fm_ethMode *)out = split ? FM_ETH_MODE_25GBASE_SR : FM_ETH_MODE_100GBASE_SR4;
    else { assert(attr == FM_PORT_SPEED); *(fm_int *)out = 100000; }
    return FM_OK;
}
fm_status fmGetNumPortLanes(fm_int sw, fm_int port, fm_int mac, fm_int *out) {
    assert(sw == 0 && (port == 1 || port == 5) && mac == 0); ++reads;
    *out = 4; return FM_OK;
}
fm_status fmGetPortState(fm_int sw, fm_int port, fm_int *mode, fm_int *state, fm_int *info) {
    assert(sw == 0 && (port == 1 || port == 5)); ++reads;
    *mode = FM_PORT_MODE_UP; *state = FM_PORT_STATE_DOWN;
    for (int i = 0; i < 4; ++i) info[i] = i ? 7 : 39;
    return FM_OK;
}
fm_status fmGetPortAttributeV2(fm_int sw, fm_int port, fm_int mac, fm_int lane,
                               fm_int attr, void *out) {
    assert(sw == 0 && (port == 1 || port == 5) && mac == 0 && lane >= 0 && lane < 4);
    ++reads;
    *(fm_uint32 *)out = attr == FM_PORT_TX_LANE_PRECURSOR ? (fm_uint32)-2 : 0;
    if (field_failure && attr == FM_PORT_RX_LANE_POLARITY) {
        *(fm_uint32 *)out = 0xdeadbeef;
        return FM_ERR_INVALID_ARGUMENT;
    }
    return FM_OK;
}
fm_status fmReadUncachedUINT32(fm_int sw, fm_uint reg, fm_uint32 *out) {
    assert(sw == 0); ++reads;
    bool allowed = false;
    for (int epl = 0; epl <= 1; ++epl) {
        allowed |= reg == (fm_uint)FM10000_PCS_ML_BASER_CFG(epl) ||
                   reg == (fm_uint)FM10000_PCS_ML_BASER_RX_STATUS(epl);
        for (int lane = 0; lane < 4; ++lane)
            allowed |= reg == (fm_uint)FM10000_LANE_CFG(epl, lane) ||
                       reg == (fm_uint)FM10000_LANE_SERDES_STATUS(epl, lane);
    }
    assert(allowed); /* No arbitrary, interrupt or counter register access. */
    *out = 0; return FM_OK;
}
#define clock_gettime fake_clock
#include "../vendor/netlab/sbin/switchd/fm10k_phy.c"
#undef clock_gettime

int main(void) {
    const char *bad[] = {"", "0", "2", "24", "25", "-1", "+1", "1 5", "1;5", "1/0", "999999999999"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
        assert(fm10k_phy_port_parse(bad[i]) < 0);
    assert(fm10k_phy_port_parse("1") == 1 && fm10k_phy_port_parse("21") == 21);
    char out[8192], cached[8192];
    assert(fm10k_phy_snapshot(0, 2, out, sizeof(out)) != 0 && reads == 0);
    assert(fm10k_phy_snapshot(1, 1, out, sizeof(out)) != 0 && reads == 0);
    assert(fm10k_phy_snapshot(0, 1, out, sizeof(out)) == 0);
    assert(reads < 64 && strstr(out, "value=\"-2\" raw=\"0xfffffffe\""));
    assert(strstr(out, "pcs_ml_baser_rx_status") && strstr(out, "</fm10k-phy>"));
    int before = reads;
    assert(fm10k_phy_snapshot(0, 1, cached, sizeof(cached)) == 0);
    assert(reads == before && strcmp(out, cached) == 0);
    native = false;
    assert(fm10k_phy_snapshot(0, 1, out, sizeof(out)) != 0 && reads == before);
    native = true; now_seconds += 5; field_failure = true;
    assert(fm10k_phy_snapshot(0, 1, out, sizeof(out)) == 0 && reads > before);
    assert(!strstr(out, "deadbeef"));
    char *failed = strstr(out, "name=\"rx_polarity\"");
    assert(failed && strstr(failed, "/>") < strstr(failed, "value="));
    split = true;
    before = reads;
    assert(fm10k_phy_snapshot(0, 5, out, sizeof(out)) != 0 && reads == before + 1);
    puts("native PHY diagnostic: bounded reads, cache, invalid targets and partial failures passed");
    return 0;
}
