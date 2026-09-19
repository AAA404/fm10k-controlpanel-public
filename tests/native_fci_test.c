#define FM10K_BUS_FIXTURE_ONLY
#include "native_sdk_bus_test.c"
#include "netlab/interface_id.h"
#include "netlab/log.h"

static nl_port_entry inventory[24];
static fm_platformCfgPort cfg_ports[30];
static fm_platformCfgSwitch cfg_switch;
static fm_platXcvrInfo fixture_cache[30];
static fm_int admin_modes[30];
static fm_ethMode runtime_modes[30];
static int sdk_admin_calls, unexpected_xcvr_writer, fail_admin_after_write;
static int group_write_base, mode_calls, fail_mode_call, fail_mode_from, drop_mode_call;
static bool mode_fail_after;

static fm_int profile(nl_port_entry *out, fm_int size) {
    assert(size >= 24); memcpy(out, inventory, sizeof(inventory)); return 24;
}
static fm_int fixture_port_index(fm_int sw, fm_int port) { assert(sw == 0); return port; }
static fm_status map_port(fm_int sw, fm_int port, fm_int *physical, fm_int *platform,
                           fm_uint32 *resource, fm_platformCfgPort **cfg) {
    assert(sw == 0 && port >= 1 && port <= 24);
    *physical = *platform = 0; *cfg = &cfg_ports[port]; *resource = cfg_ports[port].hwResourceId;
    return FM_OK;
}
static fm_status ethernet_mode(fm_int sw, fm_int port, fm_ethMode *out) {
    assert(sw == 0); *out = runtime_modes[port]; return FM_OK;
}
static fm_status fixture_set_ethernet_mode(fm_int sw, fm_int port, fm_ethMode *mode) {
    assert(sw == 0 && !lock_stage && admin_modes[port] == FM_PORT_MODE_ADMIN_PWRDOWN);
    if (group_write_base) assert(port >= group_write_base && port < group_write_base + 4);
    int base = (port - 1) / 4 * 4 + 1;
    assert(fixture_cache[port].disabled);
    ++mode_calls;
    bool fail = mode_calls == fail_mode_call || (fail_mode_from && mode_calls >= fail_mode_from);
    if (fail && !mode_fail_after) return FM_FAIL;
    if (mode_calls == drop_mode_call) return FM_OK;
    if (*mode == FM_ETH_MODE_100GBASE_SR4 || *mode == FM_ETH_MODE_40GBASE_SR4) {
        assert(port == base);
        for (int lane = 1; lane < 4; ++lane) assert(runtime_modes[base + lane] == FM_ETH_MODE_DISABLED);
    } else if (*mode != FM_ETH_MODE_DISABLED) {
        for (int lane = 0; lane < 4; ++lane)
            assert(runtime_modes[base + lane] != FM_ETH_MODE_100GBASE_SR4 &&
                   runtime_modes[base + lane] != FM_ETH_MODE_40GBASE_SR4);
    }
    runtime_modes[port] = *mode;
    fixture_cache[port].ethMode = *mode;
    /* The boot configuration intentionally remains unchanged. */
    return fail ? FM_FAIL : FM_OK;
}
#define NETLAB_XCVR_FCI_PROFILE() true
#define NETLAB_XCVR_PROFILE_GET_ALL profile
#define NETLAB_XCVR_PORT_INDEX fixture_port_index
#define NETLAB_XCVR_MAP_PORT map_port
#define NETLAB_XCVR_ETHERNET_MODE ethernet_mode
#define NETLAB_XCVR_SET_ETHERNET_MODE fixture_set_ethernet_mode
#define NETLAB_XCVR_SWITCH_CFG(sw) ((void)(sw), &cfg_switch)
#define NETLAB_XCVR_CACHE_INFO(sw) ((void)(sw), fixture_cache)
#include "../vendor/netlab/sbin/switchd/hal_port_xcvr_sdk_adapter.c"

fm_status fmGetPortState(fm_int sw, fm_int port, fm_int *mode, fm_int *state, fm_int *info) {
    assert(sw == 0 && port >= 1 && port <= 24);
    *mode = admin_modes[port]; *state = 0; memset(info, 0, 8 * sizeof(*info));
    return FM_OK;
}
fm_status fmSetPortState(fm_int sw, fm_int port, fm_int mode, fm_int submode) {
    assert(sw == 0 && submode == 0 && !lock_stage);
    if (group_write_base) assert(port >= group_write_base && port < group_write_base + 4);
    ++sdk_admin_calls;
    /* The vendor callback must see the already-reconciled disabled cache.
     * Otherwise it would invoke its legacy whole-module optical writer. */
    if (fixture_cache[port].disabled != (mode == FM_PORT_MODE_ADMIN_PWRDOWN)) {
        ++unexpected_xcvr_writer;
        return FM_FAIL;
    }
    admin_modes[port] = mode;
    if (fail_admin_after_write) { --fail_admin_after_write; return FM_FAIL; }
    return FM_OK;
}
const char *fmErrorMsg(fm_int error) { (void)error; return "fixture"; }
void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)format;
}
#include "../vendor/netlab/sbin/switchd/hal_port.c"

static void configure(void) {
    static const int epls[] = {0, 1, 2, 5, 6, 7};
    memset(inventory, 0, sizeof(inventory));
    memset(cfg_ports, 0, sizeof(cfg_ports));
    memset(&cfg_switch, 0, sizeof(cfg_switch));
    memset(fixture_cache, 0, sizeof(fixture_cache));
    group_write_base = mode_calls = fail_mode_call = fail_mode_from = drop_mode_call = 0;
    mode_fail_after = false;
    sdk_admin_calls = unexpected_xcvr_writer = fail_admin_after_write = 0;
    fail_after_write = drop_writes = 0;
    cfg_switch.numPorts = 30; cfg_switch.ports = cfg_ports;
    for (int i = 0; i < 24; ++i) {
        nl_port_entry *p = &inventory[i];
        p->switch_id = 0; p->port_index = p->logical_port = i + 1;
        p->flags = NL_PORT_FLAG_EXTERNAL; p->epl_port = epls[i / 4]; p->lane = i % 4;
        p->hw_resource_id = ((i % 4) << 8) | (i / 4);
        snprintf(p->interface_type, sizeof(p->interface_type), "QSFP_LANE%d", i % 4);
        cfg_ports[i + 1].port = cfg_ports[i + 1].portIdx = i + 1;
        cfg_ports[i + 1].hwResourceId = (fm_uint32)p->hw_resource_id;
        cfg_ports[i + 1].epl = p->epl_port;
        cfg_ports[i + 1].intfType = (fm_platIntfType)(FM_PLAT_INTF_TYPE_QSFP_LANE0 + p->lane);
        cfg_ports[i + 1].ethMode = FM_ETH_MODE_25GBASE_SR;
        runtime_modes[i + 1] = FM_ETH_MODE_25GBASE_SR;
        cfg_switch.epls[p->epl_port].laneToPortIdx[p->lane] = i + 1;
        admin_modes[i + 1] = FM_PORT_MODE_UP;
    }
    fake_lib.I2cWriteRead = raw_transfer;
    for (int mpo = 1; mpo <= 2; ++mpo) {
        registers[mpo][0x50][56] = 0xaf;
        registers[mpo][0x50][57] = 0xff;
        registers[mpo][0x50][86] = 0x69;
    }
}
static uint16_t enabled(int mpo) {
    return (uint16_t)(((registers[mpo][0x50][56] & 15) << 8) | registers[mpo][0x50][57]);
}
#ifndef FM10K_FCI_FIXTURE_ONLY
int main(void) {
    configure();
    for (int resource = 0; resource < 6; ++resource) {
        const int base = resource * 4 + 1, mpo = resource / 3 + 1, shift = resource % 3 * 4;
        for (int lane = 0; lane < 4; ++lane) {
            int port = base + lane;
            hal_port_admin_transaction_snapshot before = hal_port_admin_transaction_snapshot_get(0, port);
            assert(before.state == HAL_TRANSACTION_SNAPSHOT_PRESENT && before.xcvr_lane_mask == (1U << lane));
            assert(!hal_port_admin_transaction_apply(0, port, FM_PORT_MODE_ADMIN_DOWN, &before));
            assert(enabled(mpo) == (0xfffU & ~(1U << (shift + lane))) && enabled(3 - mpo) == 0xfff);
            assert(fixture_cache[port].disabled && admin_modes[port] == FM_PORT_MODE_ADMIN_PWRDOWN);
            assert(!hal_port_admin_transaction_restore(0, port, &before));
            assert(enabled(mpo) == 0xfff && !fixture_cache[port].disabled && !unexpected_xcvr_writer);
        }
        runtime_modes[base] = FM_ETH_MODE_100GBASE_SR4;
        for (int lane = 1; lane < 4; ++lane) runtime_modes[base + lane] = FM_ETH_MODE_DISABLED;
        hal_port_admin_transaction_snapshot before = hal_port_admin_transaction_snapshot_get(0, base);
        assert(before.state == HAL_TRANSACTION_SNAPSHOT_PRESENT && before.xcvr_lane_mask == 15);
        assert(!hal_port_admin_transaction_apply(0, base, FM_PORT_MODE_ADMIN_PWRDOWN, &before));
        assert(enabled(mpo) == (0xfffU & ~(15U << shift)));
        for (int lane = 0; lane < 4; ++lane) assert(fixture_cache[base + lane].disabled);
        assert(!hal_port_admin_transaction_restore(0, base, &before));
        netlab_port_xcvr_sdk_snapshot inactive;
        assert(netlab_port_xcvr_sdk_snapshot_get(0, base + 1, &inactive) == FM_ERR_UNSUPPORTED);
        for (int lane = 0; lane < 4; ++lane) runtime_modes[base + lane] = FM_ETH_MODE_25GBASE_SR;
        assert((registers[mpo][0x50][56] & 0xf0) == 0xa0 && registers[mpo][0x50][86] == 0x69);
        assert(fake_mux == 4 && !lock_stage);
    }
    /* A reported ASIC error after the write must compensate both states. */
    hal_port_admin_transaction_snapshot before = hal_port_admin_transaction_snapshot_get(0, 1);
    fail_admin_after_write = 1;
    assert(hal_port_admin_transaction_apply(0, 1, FM_PORT_MODE_ADMIN_PWRDOWN, &before) != 0);
    assert(enabled(1) == 0xfff && admin_modes[1] == FM_PORT_MODE_UP && !fixture_cache[1].disabled);
    drop_register = 57; fail_after_write = 1;
    assert(hal_port_admin_transaction_apply(0, 1, FM_PORT_MODE_ADMIN_PWRDOWN, &before) != 0);
    assert(enabled(1) == 0xfff && admin_modes[1] == FM_PORT_MODE_UP);
    /* Finite retry budget, readback of non-latching writes, and no scope leak. */
    drop_writes = 12;
    assert(hal_port_admin_transaction_apply(0, 1, FM_PORT_MODE_ADMIN_PWRDOWN, &before) != 0);
    assert(drop_writes == 0 && enabled(1) == 0xfff && !unexpected_xcvr_writer);
    inventory[7].hw_resource_id ^= 1;
    int n = transfers;
    assert(hal_port_admin_transaction_apply(0, 1, FM_PORT_MODE_ADMIN_PWRDOWN, &before) != 0);
    assert(transfers == n);
    puts("all fixed FCI slots, six EPL masks, SDK cache reconciliation and admin compensation passed");
    return 0;
}
#endif
