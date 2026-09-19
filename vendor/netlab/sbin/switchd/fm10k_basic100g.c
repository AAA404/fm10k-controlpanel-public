/* Explicit installation baseline for isolated 100G connectivity testing.
 * Runs once on the SDK owner after the verified closed-port/fan bootstrap.
 * No runtime RPC invokes this, and it does not grant full configd binding. */
#include "fm10k_basic100g.h"
#include "fm10k_startup.h"
#include "hal_port_xcvr_sdk_adapter.h"
#include "netlab/hal.h"
#include "netlab/log.h"
#include <api/fm_api_attr.h>
#include <string.h>

static const fm_int ports[] = {1, 5, 9, 13, 17, 21};

static fm_status bool_attribute(int sw, int port, fm_int attr, fm_bool value) {
    fm_bool actual = !value;
    fm_status st = fmSetPortAttribute(sw, port, attr, &value);
    if (st == FM_OK) st = fmGetPortAttribute(sw, port, attr, &actual);
    return st != FM_OK ? st : actual == value ? FM_OK : FM_ERR_INVALID_VALUE;
}

static fm_status wide_mask(int sw, int port) {
    fm_bitArray target = {0}, actual = {0};
    fm_status st = fmCreateBitArray(&target, 30);
    if (st != FM_OK) return st;
    st = fmCreateBitArray(&actual, 30);
    if (st != FM_OK) { (void)fmDeleteBitArray(&target); return st; }
    for (size_t i = 0; st == FM_OK && i < sizeof(ports) / sizeof(*ports); ++i)
        st = fmSetBitArrayBit(&target, ports[i], TRUE);
    if (st == FM_OK) st = fmSetPortAttribute(sw, port, FM_PORT_MASK_WIDE, &target);
    if (st == FM_OK) st = fmGetPortAttribute(sw, port, FM_PORT_MASK_WIDE, &actual);
    if (st == FM_OK && !fmCompareBitArrays(&target, &actual)) st = FM_ERR_INVALID_VALUE;
    fm_status a = fmDeleteBitArray(&actual), b = fmDeleteBitArray(&target);
    return st != FM_OK ? st : a != FM_OK ? a : b;
}

int fm10k_basic100g_start(int sw) {
    if (!fm10k_startup_basic100g()) return FM10K_INVALID;
    fm_status st;
    int port = 0;
#define CHECK(call) do { st = (call); if (st != FM_OK) { \
    NL_LOG_ERR("basic100g port %d: %s: %s", port, #call, fmErrorMsg(st)); goto fail; } } while (0)
    st = fmCreateVlan(sw, 1);
    if (st != FM_OK && st != FM_ERR_VLAN_ALREADY_EXISTS) goto fail;
    for (int i = 0; i < 6; ++i) {
        fm10k_group group;
        int epl = i < 3 ? i : i + 2;
        port = ports[i];
        if (netlab_fm10k_group_sdk_get(sw, epl, &group) || group.mode != 100 || group.enabled)
            goto fail;
        CHECK(fmAddVlanPort(sw, 1, port, FALSE));
        fm_uint32 pvid = 1, actual_pvid = 0;
        CHECK(fmSetPortAttribute(sw, port, FM_PORT_DEF_VLAN, &pvid));
        CHECK(fmGetPortAttribute(sw, port, FM_PORT_DEF_VLAN, &actual_pvid));
        if (actual_pvid != 1) goto fail;
        CHECK(bool_attribute(sw, port, FM_PORT_DROP_BV, TRUE));
        CHECK(bool_attribute(sw, port, FM_PORT_DROP_TAGGED, TRUE));
        CHECK(bool_attribute(sw, port, FM_PORT_DROP_UNTAGGED, FALSE));
        CHECK(bool_attribute(sw, port, FM_PORT_LEARNING, TRUE));
        if (hal_port_set_mtu(sw, port, 1518)) goto fail;
        int mtu, frame;
        if (hal_port_get_mtu(sw, port, &mtu, &frame) || frame != hal_port_mtu_to_max_frame(1518))
            goto fail;
        CHECK(wide_mask(sw, port));
        CHECK(fmSetVlanPortState(sw, 1, port, FM_STP_STATE_FORWARDING));
        fm_int forwarding = -1;
        fm_bool tagged = TRUE;
        CHECK(fmGetVlanPortState(sw, 1, port, &forwarding));
        CHECK(fmGetVlanPortTag(sw, 1, port, &tagged));
        if (forwarding != FM_STP_STATE_FORWARDING || tagged) goto fail;
    }
    /* Every forwarding dependency is verified before enabling optical TX. */
    for (int i = 0; i < 6; ++i) {
        port = ports[i];
        if (hal_port_set_admin_state(sw, port, FM_PORT_MODE_UP)) goto fail;
        fm10k_group group;
        if (netlab_fm10k_group_sdk_get(sw, i < 3 ? i : i + 2, &group) ||
            group.mode != 100 || group.enabled != 1) goto fail;
        NL_LOG_NOTICE("basic100g verified: port=%d EPL=%d 100G admin=up VLAN=1 untagged TX=0xf", port, group.epl);
    }
    return FM10K_OK;
fail:
    NL_LOG_ERR("basic100g baseline failed at port %d; closing the test ports", port);
    return netlab_fm10k_bootstrap_closed(sw) ? FM10K_ROLLBACK_FAILED : FM10K_IO;
#undef CHECK
}
