#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <fm_sdk_int.h>
#include "netlab/interface_id.h"

#define TEST_SWITCH 0
#define TEST_PORT 1
#define MAX_TEST_PORTS 32

typedef struct {
    fm_byte eeprom_byte86;
    fm_bool present;
    fm_bool present_valid;
    fm_int admin_mode[MAX_TEST_PORTS];

    fm_status port_get_status;
    fm_status admin_set_status;
    fm_status switch_take_status;
    fm_status switch_drop_status;
    fm_status capture_status;
    fm_status release_status;
    fm_status select_state_status;
    fm_status select_eeprom_status;
    fm_status presence_status;
    fm_status i2c_read_status;
    fm_status i2c_write_status;

    fm_int port_get_fail_on_call;
    fm_int i2c_read_fail_on_call;
    fm_int i2c_write_fail_on_call;
    fm_int i2c_write_mutate_then_fail_on_call;
    fm_int i2c_write_third_then_fail_on_call;
    fm_byte i2c_write_third_byte;
    fm_int admin_set_mutate_then_fail_on_call;
    fm_int admin_set_third_then_fail_on_call;
    fm_int admin_set_third_mode;
    fm_int release_fail_on_call;
    fm_bool ignore_admin_write;
    fm_bool ignore_i2c_write;

    fm_int port_get_calls;
    fm_int admin_set_calls;
    fm_int switch_take_calls;
    fm_int switch_drop_calls;
    fm_int capture_calls;
    fm_int release_calls;
    fm_int select_state_calls;
    fm_int select_eeprom_calls;
    fm_int presence_calls;
    fm_int i2c_read_calls;
    fm_int i2c_write_calls;
    fm_int nested_vendor_xcvr_writes;
    fm_uint32 last_selected_hw_resource;
    fm_int last_selected_bus;
} port_simulator;

static port_simulator g_sim;
static nl_port_entry g_profile[MAX_TEST_PORTS];
static fm_int g_profile_count;
static fm_platformCfgPort g_sdk_ports[MAX_TEST_PORTS];
static fm_platformCfgSwitch g_sdk_switch;
static fm_platformState g_platform_state[1];
static fm_platXcvrInfo g_xcvr_cache[MAX_TEST_PORTS];
static fm_platformProcessState g_process_state[1];
static fm_rootPlatform g_root;
static fm_platformLib g_lib;
static int g_failed;

fm_rootPlatform *fmRootPlatform = &g_root;
fm_platformProcessState *fmPlatformProcessState = g_process_state;

static int test_profile_get_all(nl_port_entry *entries, int max);
static fm_status test_map_port(
    fm_int sw, fm_int port, fm_int *physical_sw, fm_int *platform_sw,
    fm_uint32 *hw_resource, fm_platformCfgPort **port_cfg);
static fm_int test_port_index(fm_int sw, fm_int port);
static fm_platformCfgSwitch *test_switch_cfg(fm_int sw);
static fm_platXcvrInfo *test_cache_info(fm_int sw);
static fm_status test_switch_lock_take(fm_int sw);
static fm_status test_switch_lock_drop(fm_int sw);
static fm_status test_capture_lock(fm_lock *lock);
static fm_status test_release_lock(fm_lock *lock);
static void test_delay(fm_int sec, fm_int nsec);

#define NETLAB_XCVR_PROFILE_GET_ALL test_profile_get_all
#define NETLAB_XCVR_MAP_PORT test_map_port
#define NETLAB_XCVR_PORT_INDEX test_port_index
#define NETLAB_XCVR_SWITCH_CFG(sw) test_switch_cfg((sw))
#define NETLAB_XCVR_CACHE_INFO(sw) test_cache_info((sw))
#define NETLAB_XCVR_LIB_FUNCS(sw) (&g_lib)
#define NETLAB_XCVR_SWITCH_LOCK_TAKE test_switch_lock_take
#define NETLAB_XCVR_SWITCH_LOCK_DROP test_switch_lock_drop
#define NETLAB_XCVR_CAPTURE_LOCK(lock) test_capture_lock((lock))
#define NETLAB_XCVR_RELEASE_LOCK(lock) test_release_lock((lock))
#define NETLAB_XCVR_DELAY(sec, nsec) test_delay((sec), (nsec))
#define NETLAB_PORT_RETRAIN_DELAY(usec) test_delay(0, (usec) * 1000)
#include "../../sbin/switchd/hal_port_xcvr_sdk_adapter.c"
#include "../../sbin/switchd/hal_port.c"

static void expect(const char *name, bool condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition)
        g_failed++;
}

static bool all_acquired_lock_releases_attempted(void) {
    return g_sim.switch_take_calls == g_sim.switch_drop_calls &&
           g_sim.capture_calls == g_sim.release_calls;
}

static void clear_call_evidence(void) {
    g_sim.port_get_calls = 0;
    g_sim.admin_set_calls = 0;
    g_sim.switch_take_calls = 0;
    g_sim.switch_drop_calls = 0;
    g_sim.capture_calls = 0;
    g_sim.release_calls = 0;
    g_sim.select_state_calls = 0;
    g_sim.select_eeprom_calls = 0;
    g_sim.presence_calls = 0;
    g_sim.i2c_read_calls = 0;
    g_sim.i2c_write_calls = 0;
    g_sim.nested_vendor_xcvr_writes = 0;
    g_sim.last_selected_hw_resource = 0;
    g_sim.last_selected_bus = -1;
}

static void clear_faults(void) {
    g_sim.port_get_status = FM_OK;
    g_sim.admin_set_status = FM_OK;
    g_sim.switch_take_status = FM_OK;
    g_sim.switch_drop_status = FM_OK;
    g_sim.capture_status = FM_OK;
    g_sim.release_status = FM_OK;
    g_sim.select_state_status = FM_OK;
    g_sim.select_eeprom_status = FM_OK;
    g_sim.presence_status = FM_OK;
    g_sim.i2c_read_status = FM_OK;
    g_sim.i2c_write_status = FM_OK;
    g_sim.port_get_fail_on_call = 0;
    g_sim.i2c_read_fail_on_call = 0;
    g_sim.i2c_write_fail_on_call = 0;
    g_sim.i2c_write_mutate_then_fail_on_call = 0;
    g_sim.i2c_write_third_then_fail_on_call = 0;
    g_sim.i2c_write_third_byte = 0;
    g_sim.admin_set_mutate_then_fail_on_call = 0;
    g_sim.admin_set_third_then_fail_on_call = 0;
    g_sim.admin_set_third_mode = 0;
    g_sim.release_fail_on_call = 0;
    g_sim.ignore_admin_write = FALSE;
    g_sim.ignore_i2c_write = FALSE;
}

static void add_qsfp_profile_port(
    fm_int logical_port, fm_int resource, fm_int epl, fm_int lane) {
    nl_port_entry *profile = &g_profile[g_profile_count];
    fm_platformCfgPort *sdk = &g_sdk_ports[logical_port];

    memset(profile, 0, sizeof(*profile));
    profile->switch_id = TEST_SWITCH;
    profile->switch_number = TEST_SWITCH;
    profile->logical_port = logical_port;
    profile->port_index = logical_port;
    profile->hw_resource_id = resource;
    profile->epl_port = epl;
    profile->lane = lane;
    snprintf(profile->interface_type, sizeof(profile->interface_type),
             "QSFP_LANE%d", lane);
    g_profile_count++;

    memset(sdk, 0, sizeof(*sdk));
    sdk->portIdx = logical_port;
    sdk->port = logical_port;
    sdk->hwResourceId = (fm_uint32)resource;
    sdk->epl = epl;
    sdk->intfType =
        (fm_platIntfType)(FM_PLAT_INTF_TYPE_QSFP_LANE0 + lane);
    sdk->ethMode = FM_ETH_MODE_25GBASE_SR;
    g_sdk_switch.epls[epl].laneToPortIdx[lane] = logical_port;
    g_sdk_switch.numPorts = logical_port + 1;
    g_sdk_switch.maxLogicalPortValue = logical_port;
    g_sim.admin_mode[logical_port] =
        FM_PORT_MODE_ADMIN_PWRDOWN;
}

static void setup_sdk_slot_zero(void) {
    g_sdk_ports[0].portIdx = 0;
    g_sdk_ports[0].port = 0;
    g_sdk_switch.numPorts = 1;
    g_sdk_switch.maxLogicalPortValue = 0;
}

static void setup_split_module(void) {
    fm_int lane;

    g_profile_count = 0;
    memset(g_profile, 0, sizeof(g_profile));
    memset(g_sdk_ports, 0, sizeof(g_sdk_ports));
    memset(g_xcvr_cache, 0, sizeof(g_xcvr_cache));
    memset(&g_sdk_switch, 0, sizeof(g_sdk_switch));
    for (fm_int epl = 0; epl < FM_PLAT_NUM_EPL; epl++) {
        for (lane = 0; lane < NETLAB_PORT_XCVR_QSFP_LANES; lane++)
            g_sdk_switch.epls[epl].laneToPortIdx[lane] =
                FM_PLAT_UNDEFINED;
    }
    snprintf(g_sdk_switch.netDevName,
             sizeof(g_sdk_switch.netDevName), "fixture0");
    g_sdk_switch.ports = g_sdk_ports;
    setup_sdk_slot_zero();
    for (lane = 0; lane < NETLAB_PORT_XCVR_QSFP_LANES; lane++)
        add_qsfp_profile_port(lane + 1, 0, 0, lane);
}

static void setup_real_24_port_topology(void) {
    static const fm_int epls[6] = {0, 1, 2, 5, 6, 7};
    fm_int module;
    fm_int lane;

    g_profile_count = 0;
    memset(g_profile, 0, sizeof(g_profile));
    memset(g_sdk_ports, 0, sizeof(g_sdk_ports));
    memset(g_xcvr_cache, 0, sizeof(g_xcvr_cache));
    memset(&g_sdk_switch, 0, sizeof(g_sdk_switch));
    for (fm_int epl = 0; epl < FM_PLAT_NUM_EPL; epl++) {
        for (lane = 0; lane < NETLAB_PORT_XCVR_QSFP_LANES; lane++)
            g_sdk_switch.epls[epl].laneToPortIdx[lane] =
                FM_PLAT_UNDEFINED;
    }
    snprintf(g_sdk_switch.netDevName,
             sizeof(g_sdk_switch.netDevName), "fixture0");
    g_sdk_switch.ports = g_sdk_ports;
    setup_sdk_slot_zero();
    for (module = 0; module < 6; module++) {
        for (lane = 0; lane < NETLAB_PORT_XCVR_QSFP_LANES; lane++) {
            add_qsfp_profile_port(
                module * NETLAB_PORT_XCVR_QSFP_LANES + lane + 1,
                module, epls[module], lane);
        }
    }
}

static void reset_simulator(void) {
    memset(&g_sim, 0, sizeof(g_sim));
    memset(&g_root, 0, sizeof(g_root));
    memset(g_platform_state, 0, sizeof(g_platform_state));
    memset(g_process_state, 0, sizeof(g_process_state));
    memset(&g_lib, 0, sizeof(g_lib));

    fmRootPlatform = &g_root;
    fmPlatformProcessState = g_process_state;
    g_root.cfg.numSwitches = 1;
    g_root.cfg.switches = &g_sdk_switch;
    g_root.platformState = g_platform_state;
    g_platform_state[0].xcvrInfo = g_xcvr_cache;
    g_sim.eeprom_byte86 = 0x0f;
    g_sim.present = TRUE;
    g_sim.present_valid = TRUE;
    clear_faults();
    setup_split_module();

    g_lib.SelectBus = NULL;
    g_lib.GetPortXcvrState = NULL;
    g_lib.I2cWriteRead = NULL;
}

static fm_status loaded_select_bus(
    fm_int sw, fm_int bus, fm_uint32 hw_resource) {
    (void)sw;
    g_sim.last_selected_bus = bus;
    g_sim.last_selected_hw_resource = hw_resource;
    if (bus == FM_PLAT_BUS_XCVR_STATE) {
        g_sim.select_state_calls++;
        return g_sim.select_state_status;
    }
    if (bus == FM_PLAT_BUS_XCVR_EEPROM) {
        g_sim.select_eeprom_calls++;
        return g_sim.select_eeprom_status;
    }
    return FM_ERR_INVALID_ARGUMENT;
}

static fm_status loaded_get_xcvr_state(
    fm_int sw, fm_uint32 *resources, fm_int count,
    fm_uint32 *valid, fm_uint32 *state) {
    (void)sw;
    (void)resources;
    if (count != 1 || !valid || !state)
        return FM_ERR_INVALID_ARGUMENT;
    g_sim.presence_calls++;
    if (g_sim.presence_status != FM_OK)
        return g_sim.presence_status;
    *valid = g_sim.present_valid ? FM_PLAT_XCVR_PRESENT : 0;
    *state = g_sim.present ? FM_PLAT_XCVR_PRESENT : 0;
    return FM_OK;
}

static fm_status loaded_i2c_write_read(
    fm_int sw, fm_int address, fm_byte *data,
    fm_int write_len, fm_int read_len) {
    (void)sw;
    if (address != 0x50 || !data)
        return FM_ERR_INVALID_ARGUMENT;
    if (write_len == 1 && read_len == 1) {
        g_sim.i2c_read_calls++;
        if (data[0] != NETLAB_PORT_XCVR_TX_DISABLE_OFFSET)
            return FM_ERR_INVALID_ARGUMENT;
        if (g_sim.i2c_read_status != FM_OK ||
            (g_sim.i2c_read_fail_on_call > 0 &&
             g_sim.i2c_read_calls == g_sim.i2c_read_fail_on_call))
            return g_sim.i2c_read_status != FM_OK ?
                g_sim.i2c_read_status : FM_FAIL;
        data[0] = g_sim.eeprom_byte86;
        return FM_OK;
    }
    if (write_len == 2 && read_len == 0) {
        fm_bool mutate_then_fail;
        fm_bool third_then_fail;

        g_sim.i2c_write_calls++;
        if (data[0] != NETLAB_PORT_XCVR_TX_DISABLE_OFFSET)
            return FM_ERR_INVALID_ARGUMENT;
        if (g_sim.i2c_write_status != FM_OK ||
            (g_sim.i2c_write_fail_on_call > 0 &&
             g_sim.i2c_write_calls == g_sim.i2c_write_fail_on_call))
            return g_sim.i2c_write_status != FM_OK ?
                g_sim.i2c_write_status : FM_FAIL;
        mutate_then_fail =
            g_sim.i2c_write_mutate_then_fail_on_call > 0 &&
            g_sim.i2c_write_calls ==
                g_sim.i2c_write_mutate_then_fail_on_call;
        third_then_fail =
            g_sim.i2c_write_third_then_fail_on_call > 0 &&
            g_sim.i2c_write_calls ==
                g_sim.i2c_write_third_then_fail_on_call;
        if (!g_sim.ignore_i2c_write)
            g_sim.eeprom_byte86 = third_then_fail ?
                g_sim.i2c_write_third_byte : data[1];
        if (mutate_then_fail || third_then_fail)
            return FM_FAIL;
        return FM_OK;
    }
    return FM_ERR_INVALID_ARGUMENT;
}

static void install_loaded_table(void) {
    g_lib.SelectBus = loaded_select_bus;
    g_lib.GetPortXcvrState = loaded_get_xcvr_state;
    g_lib.I2cWriteRead = loaded_i2c_write_read;
}

static int test_profile_get_all(nl_port_entry *entries, int max) {
    fm_int count = g_profile_count < max ? g_profile_count : max;

    if (!entries || max <= 0)
        return 0;
    memcpy(entries, g_profile, (size_t)count * sizeof(entries[0]));
    return count;
}

static fm_int test_port_index(fm_int sw, fm_int port) {
    (void)sw;
    if (port < 0 || port >= g_sdk_switch.numPorts)
        return -1;
    return port;
}

static fm_platformCfgSwitch *test_switch_cfg(fm_int sw) {
    return sw == TEST_SWITCH ? &g_sdk_switch : NULL;
}

static fm_platXcvrInfo *test_cache_info(fm_int sw) {
    return sw == TEST_SWITCH ? g_xcvr_cache : NULL;
}

static fm_status test_map_port(
    fm_int sw, fm_int port, fm_int *physical_sw, fm_int *platform_sw,
    fm_uint32 *hw_resource, fm_platformCfgPort **port_cfg) {
    fm_int index = test_port_index(sw, port);

    if (index < 0)
        return FM_ERR_INVALID_PORT;
    *physical_sw = sw;
    *platform_sw = 0;
    *hw_resource = g_sdk_ports[index].hwResourceId;
    if (port_cfg)
        *port_cfg = &g_sdk_ports[index];
    return FM_OK;
}

static fm_status test_switch_lock_take(fm_int sw) {
    (void)sw;
    g_sim.switch_take_calls++;
    return g_sim.switch_take_status;
}

static fm_status test_switch_lock_drop(fm_int sw) {
    (void)sw;
    g_sim.switch_drop_calls++;
    return g_sim.switch_drop_status;
}

static fm_status test_capture_lock(fm_lock *lock) {
    (void)lock;
    g_sim.capture_calls++;
    return g_sim.capture_status;
}

static fm_status test_release_lock(fm_lock *lock) {
    (void)lock;
    g_sim.release_calls++;
    if (g_sim.release_fail_on_call > 0 &&
        g_sim.release_calls == g_sim.release_fail_on_call)
        return FM_FAIL;
    return g_sim.release_status;
}

static void test_delay(fm_int sec, fm_int nsec) {
    (void)sec;
    (void)nsec;
}

void nl_log_write(nl_log_level level, const char *file, int line,
                  const char *fmt, ...) {
    (void)level;
    (void)file;
    (void)line;
    (void)fmt;
}

const char *fmErrorMsg(fm_int error) {
    (void)error;
    return "injected SDK status";
}

fm_status fmGetPortState(fm_int sw, fm_int port, fm_int *mode,
                         fm_int *state, fm_int *info) {
    fm_int index = test_port_index(sw, port);

    g_sim.port_get_calls++;
    if (index < 0)
        return FM_ERR_INVALID_PORT;
    if (g_sim.port_get_status != FM_OK ||
        (g_sim.port_get_fail_on_call > 0 &&
         g_sim.port_get_calls == g_sim.port_get_fail_on_call))
        return g_sim.port_get_status != FM_OK ?
            g_sim.port_get_status : FM_FAIL;
    *mode = g_sim.admin_mode[index];
    *state = g_sim.admin_mode[index];
    if (info)
        info[0] = 0;
    return FM_OK;
}

fm_status fmSetPortState(fm_int sw, fm_int port, fm_int mode,
                         fm_int submode) {
    fm_int index = test_port_index(sw, port);
    fm_int applied_mode = mode;
    fm_bool disabled;
    fm_bool mutate_then_fail;
    fm_bool third_then_fail;

    (void)submode;
    g_sim.admin_set_calls++;
    if (index < 0)
        return FM_ERR_INVALID_PORT;
    if (g_sim.admin_set_status != FM_OK)
        return g_sim.admin_set_status;
    mutate_then_fail =
        g_sim.admin_set_mutate_then_fail_on_call > 0 &&
        g_sim.admin_set_calls ==
            g_sim.admin_set_mutate_then_fail_on_call;
    third_then_fail =
        g_sim.admin_set_third_then_fail_on_call > 0 &&
        g_sim.admin_set_calls ==
            g_sim.admin_set_third_then_fail_on_call;
    if (third_then_fail)
        applied_mode = g_sim.admin_set_third_mode;
    if (!g_sim.ignore_admin_write)
        g_sim.admin_mode[index] = applied_mode;

    /*
     * Model the pinned platform callback.  A cache mismatch would enter the
     * vendor fmPlatformMgmtEnableXcvr path and become a second XCVR writer.
     */
    disabled =
        applied_mode == FM_PORT_MODE_ADMIN_PWRDOWN ? TRUE : FALSE;
    if (g_xcvr_cache[index].disabled != disabled) {
        g_xcvr_cache[index].disabled = disabled;
        if (g_sim.present)
            g_sim.nested_vendor_xcvr_writes++;
    }
    if (mutate_then_fail || third_then_fail)
        return FM_FAIL;
    return FM_OK;
}

static bool caches_match_low_nibble(fm_byte value) {
    fm_int lane;

    for (lane = 0; lane < NETLAB_PORT_XCVR_QSFP_LANES; lane++) {
        bool expected = (value & (1U << lane)) != 0;
        if ((g_xcvr_cache[lane + 1].disabled != FALSE) != expected)
            return false;
    }
    return true;
}

static void test_read_only_reconcile_all_cache_combinations(void) {
    fm_int low;

    for (low = 0; low < 16; low++) {
        netlab_port_xcvr_sdk_snapshot snapshot;
        fm_status status;

        reset_simulator();
        install_loaded_table();
        g_sim.eeprom_byte86 = (fm_byte)(0xa0 | low);
        for (fm_int lane = 0;
             lane < NETLAB_PORT_XCVR_QSFP_LANES; lane++)
            g_xcvr_cache[lane + 1].disabled =
                (low & (1 << lane)) ? FALSE : TRUE;
        clear_call_evidence();

        status = netlab_port_xcvr_sdk_snapshot_get(
            TEST_SWITCH, 3, &snapshot);
        if (status != FM_OK || snapshot.tx_disable_byte !=
                (fm_byte)(0xa0 | low) ||
            snapshot.module_owner_port != 1 ||
            snapshot.lane_mask != 0x04 ||
            !caches_match_low_nibble((fm_byte)low) ||
            g_sim.i2c_write_calls != 0)
            break;
    }
    expect("all 16 stale cache combinations reconcile from byte86 "
           "with zero EEPROM writes", low == 16);
}

static void test_full_byte_and_four_lane_cas(void) {
    static const fm_byte values[] = {0x00, 0x0f, 0xa5, 0xff};
    bool ok = true;

    for (size_t v = 0; v < sizeof(values) / sizeof(values[0]); v++) {
        for (fm_int lane = 0;
             lane < NETLAB_PORT_XCVR_QSFP_LANES; lane++) {
            hal_port_admin_transaction_snapshot before;
            fm_byte initial = values[v];
            fm_byte mask = (fm_byte)(1U << lane);
            fm_byte expected;
            fm_int requested_mode;
            int status;

            reset_simulator();
            install_loaded_table();
            g_sim.eeprom_byte86 = initial;
            g_sim.admin_mode[lane + 1] =
                (initial & mask) ? FM_PORT_MODE_ADMIN_PWRDOWN
                                 : FM_PORT_MODE_UP;
            before = hal_port_admin_transaction_snapshot_get(
                TEST_SWITCH, lane + 1);
            requested_mode = (initial & mask) ?
                FM_PORT_MODE_UP : FM_PORT_MODE_ADMIN_PWRDOWN;
            expected = (initial & mask) ?
                (fm_byte)(initial & (fm_byte)~mask) :
                (fm_byte)(initial | mask);
            clear_call_evidence();

            status = hal_port_admin_transaction_apply(
                TEST_SWITCH, lane + 1, requested_mode, &before);
            if (status != 0 || g_sim.eeprom_byte86 != expected ||
                (g_sim.eeprom_byte86 & (fm_byte)~mask) !=
                    (initial & (fm_byte)~mask) ||
                g_sim.last_selected_hw_resource != 0 ||
                g_sim.nested_vendor_xcvr_writes != 0 ||
                g_sim.i2c_write_calls != 1 ||
                g_sim.admin_set_calls != 1) {
                ok = false;
                break;
            }
        }
    }
    expect("0x00/0x0f/0xa5/0xff CAS preserves every unowned bit "
           "for all four lanes", ok);
}

static void test_admin_byte_tuple_capture_boundary(void) {
    static const fm_byte bases[] = {0x00, 0x0f, 0xa5, 0xff};
    bool consistent_ok = true;
    bool inconsistent_ok = true;

    for (size_t value = 0;
         value < sizeof(bases) / sizeof(bases[0]); value++) {
        for (fm_int lane = 0;
             lane < NETLAB_PORT_XCVR_QSFP_LANES; lane++) {
            static const fm_int enabled_modes[] = {
                FM_PORT_MODE_UP,
                FM_PORT_MODE_ADMIN_DOWN,
            };
            fm_byte mask = (fm_byte)(1U << lane);

            for (size_t mode = 0;
                 mode < sizeof(enabled_modes) /
                            sizeof(enabled_modes[0]); mode++) {
                hal_port_admin_transaction_snapshot snapshot;
                fm_byte expected =
                    (fm_byte)(bases[value] & (fm_byte)~mask);

                reset_simulator();
                install_loaded_table();
                g_sim.eeprom_byte86 = expected;
                g_sim.admin_mode[lane + 1] = enabled_modes[mode];
                clear_call_evidence();
                snapshot = hal_port_admin_transaction_snapshot_get(
                    TEST_SWITCH, lane + 1);
                if (snapshot.state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
                    snapshot.xcvr_tx_disable_byte != expected ||
                    g_sim.i2c_write_calls != 0 ||
                    g_sim.admin_set_calls != 0) {
                    consistent_ok = false;
                    break;
                }
            }
            if (!consistent_ok)
                break;

            {
                hal_port_admin_transaction_snapshot snapshot;
                fm_byte expected = (fm_byte)(bases[value] | mask);

                reset_simulator();
                install_loaded_table();
                g_sim.eeprom_byte86 = expected;
                g_sim.admin_mode[lane + 1] =
                    FM_PORT_MODE_ADMIN_PWRDOWN;
                clear_call_evidence();
                snapshot = hal_port_admin_transaction_snapshot_get(
                    TEST_SWITCH, lane + 1);
                if (snapshot.state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
                    snapshot.xcvr_tx_disable_byte != expected ||
                    g_sim.i2c_write_calls != 0 ||
                    g_sim.admin_set_calls != 0) {
                    consistent_ok = false;
                    break;
                }
            }

            for (size_t mode = 0;
                 mode < sizeof(enabled_modes) /
                            sizeof(enabled_modes[0]); mode++) {
                hal_port_admin_transaction_snapshot snapshot;

                reset_simulator();
                install_loaded_table();
                g_sim.eeprom_byte86 = (fm_byte)(bases[value] | mask);
                g_sim.admin_mode[lane + 1] = enabled_modes[mode];
                clear_call_evidence();
                snapshot = hal_port_admin_transaction_snapshot_get(
                    TEST_SWITCH, lane + 1);
                if (snapshot.state != HAL_TRANSACTION_SNAPSHOT_READ_ERROR ||
                    g_sim.i2c_write_calls != 0 ||
                    g_sim.admin_set_calls != 0 ||
                    g_sim.nested_vendor_xcvr_writes != 0) {
                    inconsistent_ok = false;
                    break;
                }
            }
            if (!inconsistent_ok)
                break;

            {
                hal_port_admin_transaction_snapshot snapshot;

                reset_simulator();
                install_loaded_table();
                g_sim.eeprom_byte86 =
                    (fm_byte)(bases[value] & (fm_byte)~mask);
                g_sim.admin_mode[lane + 1] =
                    FM_PORT_MODE_ADMIN_PWRDOWN;
                clear_call_evidence();
                snapshot = hal_port_admin_transaction_snapshot_get(
                    TEST_SWITCH, lane + 1);
                if (snapshot.state != HAL_TRANSACTION_SNAPSHOT_READ_ERROR ||
                    g_sim.i2c_write_calls != 0 ||
                    g_sim.admin_set_calls != 0 ||
                    g_sim.nested_vendor_xcvr_writes != 0) {
                    inconsistent_ok = false;
                    break;
                }
            }
        }
        if (!consistent_ok || !inconsistent_ok)
            break;
    }

    expect("consistent UP/ADMIN_DOWN/PWRDOWN tuples accept every lane while "
           "preserving arbitrary high and sibling bits",
           consistent_ok);
    expect("inconsistent admin/owned Tx_Disable tuples fail capture with "
           "zero EEPROM/admin/vendor-callback writes",
           inconsistent_ok);
}

static void test_real_24_port_mapping(void) {
    static const fm_int epls[6] = {0, 1, 2, 5, 6, 7};
    fm_uint64 fingerprint = 0;
    bool ok = true;

    reset_simulator();
    setup_real_24_port_topology();
    install_loaded_table();
    g_sim.eeprom_byte86 = 0;
    clear_call_evidence();
    for (fm_int port = 1; port <= 24; port++) {
        netlab_port_xcvr_sdk_snapshot snapshot;
        fm_status status = netlab_port_xcvr_sdk_snapshot_get(
            TEST_SWITCH, port, &snapshot);
        fm_int module = (port - 1) / NETLAB_PORT_XCVR_QSFP_LANES;
        fm_int lane = (port - 1) % NETLAB_PORT_XCVR_QSFP_LANES;
        fm_int owner = module * NETLAB_PORT_XCVR_QSFP_LANES + 1;

        if (status != FM_OK || snapshot.module_owner_port != owner ||
            snapshot.module_hw_resource_id != (fm_uint32)module ||
            snapshot.lane_mask != (fm_byte)(1U << lane) ||
            test_port_index(TEST_SWITCH, port) != port ||
            g_sdk_ports[port].portIdx != port ||
            g_sdk_switch.epls[epls[module]]
                .laneToPortIdx[lane] != port ||
            (fingerprint != 0 &&
             snapshot.topology_fingerprint != fingerprint)) {
            ok = false;
            break;
        }
        fingerprint = snapshot.topology_fingerprint;
    }
    expect("real 24-port mapping binds every lane0..3 to six lane0 "
           "module owners with slot0 plus SDK indices 1..24 and one "
           "topology fingerprint",
           ok && fingerprint != 0 && g_sim.i2c_write_calls == 0);
}

static void test_stale_hardware_and_topology_are_zero_write(void) {
    hal_port_admin_transaction_snapshot before;
    int status;

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    g_sim.eeprom_byte86 = 0x0e;
    clear_call_evidence();
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    expect("full-byte drift blocks stale transaction before writes",
           status != 0 && g_sim.i2c_write_calls == 0 &&
           g_sim.admin_set_calls == 0);

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    snprintf(g_profile[1].interface_type,
             sizeof(g_profile[1].interface_type), "QSFP_LANE0");
    clear_call_evidence();
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    expect("profile topology drift blocks stale transaction before locks "
           "or writes",
           status != 0 && g_sim.switch_take_calls == 0 &&
           g_sim.i2c_write_calls == 0 && g_sim.admin_set_calls == 0);

    reset_simulator();
    install_loaded_table();
    g_profile[0].port_index++;
    clear_call_evidence();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("profile/RDI port-index drift fails before locks or I/O",
           before.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           g_sim.switch_take_calls == 0 &&
           g_sim.i2c_read_calls == 0 &&
           g_sim.i2c_write_calls == 0 &&
           g_sim.admin_set_calls == 0);

    reset_simulator();
    install_loaded_table();
    g_sdk_ports[TEST_PORT].portIdx++;
    clear_call_evidence();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("runtime portCfg index drift fails before locks or I/O",
           before.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           g_sim.switch_take_calls == 0 &&
           g_sim.i2c_read_calls == 0 &&
           g_sim.i2c_write_calls == 0 &&
           g_sim.admin_set_calls == 0);
}

static void test_sfp_is_fail_closed(void) {
    hal_port_admin_transaction_snapshot snapshot;

    reset_simulator();
    install_loaded_table();
    snprintf(g_profile[0].interface_type,
             sizeof(g_profile[0].interface_type), "SFPP");
    g_profile[0].lane = -1;
    g_sdk_ports[TEST_PORT].intfType = FM_PLAT_INTF_TYPE_SFPP;
    clear_call_evidence();
    snapshot = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("SFP without an exact CAS adapter fails closed with zero "
           "XCVR/admin writes",
           snapshot.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           g_sim.switch_take_calls == 0 &&
           g_sim.i2c_write_calls == 0 &&
           g_sim.admin_set_calls == 0);
}

static void test_lock_failures_release_every_acquired_layer(void) {
    netlab_port_xcvr_sdk_snapshot snapshot;
    fm_status status;

    reset_simulator();
    install_loaded_table();
    g_sim.switch_take_status = FM_FAIL;
    clear_call_evidence();
    status = netlab_port_xcvr_sdk_snapshot_get(
        TEST_SWITCH, TEST_PORT, &snapshot);
    expect("switch-lock acquisition failure releases nothing unowned",
           status != FM_OK && g_sim.switch_take_calls == 1 &&
           g_sim.switch_drop_calls == 0 && g_sim.capture_calls == 0);

    reset_simulator();
    install_loaded_table();
    clear_call_evidence();
    status = netlab_port_xcvr_sdk_snapshot_get(
        TEST_SWITCH, TEST_PORT, &snapshot);
    expect("switch and local I2C locks retain an exact snapshot",
           status == FM_OK && snapshot.present &&
           snapshot.tx_disable_valid &&
           g_sim.capture_calls == 1 && g_sim.release_calls == 1 &&
           g_sim.switch_take_calls == 1 && g_sim.switch_drop_calls == 1);

    reset_simulator();
    install_loaded_table();
    g_sim.capture_status = FM_FAIL;
    clear_call_evidence();
    status = netlab_port_xcvr_sdk_snapshot_get(
        TEST_SWITCH, TEST_PORT, &snapshot);
    expect("I2C-lock acquisition failure still releases switch lock",
           status != FM_OK && g_sim.capture_calls == 1 &&
           g_sim.release_calls == 0 && g_sim.switch_drop_calls == 1);

    reset_simulator();
    install_loaded_table();
    g_sim.select_state_status = FM_FAIL;
    clear_call_evidence();
    status = netlab_port_xcvr_sdk_snapshot_get(
        TEST_SWITCH, TEST_PORT, &snapshot);
    expect("loaded-table failure releases local I2C and switch locks",
           status != FM_OK &&
           g_sim.release_calls == 1 && g_sim.switch_drop_calls == 1);

    reset_simulator();
    install_loaded_table();
    g_sim.release_status = FM_FAIL;
    clear_call_evidence();
    status = netlab_port_xcvr_sdk_snapshot_get(
        TEST_SWITCH, TEST_PORT, &snapshot);
    expect("local I2C release failure still drops switch lock",
           status != FM_OK && g_sim.release_calls == 1 &&
           g_sim.switch_drop_calls == 1);

    reset_simulator();
    install_loaded_table();
    g_sim.switch_drop_status = FM_FAIL;
    clear_call_evidence();
    status = netlab_port_xcvr_sdk_snapshot_get(
        TEST_SWITCH, TEST_PORT, &snapshot);
    expect("switch-lock release failure is returned after lower locks drop",
           status != FM_OK && g_sim.release_calls == 1 &&
           g_sim.switch_drop_calls == 1);
}

static void test_write_and_readback_faults_compensate(void) {
    hal_port_admin_transaction_snapshot before;
    hal_port_admin_transaction_snapshot after;
    int status;

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.i2c_write_status = FM_FAIL;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    expect("failed byte86 dispatch is reread as unchanged without a blind "
           "write",
           status != 0 && g_sim.eeprom_byte86 == 0x0f &&
           g_sim.admin_set_calls == 0 && g_sim.i2c_write_calls == 1 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.i2c_write_mutate_then_fail_on_call = 1;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("byte86 mutate-then-error is reread as attempted and exactly "
           "compensated",
           status != 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 0 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.i2c_write_third_then_fail_on_call = 1;
    g_sim.i2c_write_third_byte = 0xaf;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    expect("byte86 third-state-then-error is OOS without an unsafe "
           "compensation write",
           status != 0 && g_sim.eeprom_byte86 == 0xaf &&
           g_sim.i2c_write_calls == 1 &&
           g_sim.admin_set_calls == 0 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.i2c_write_mutate_then_fail_on_call = 1;
    g_sim.i2c_read_fail_on_call = 3;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    expect("byte86 mutate-then-error with failed authoritative reread is "
           "OOS and releases every acquired lock layer",
           status != 0 && g_sim.eeprom_byte86 == 0x0e &&
           g_sim.i2c_write_calls == 1 &&
           g_sim.admin_set_calls == 0 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.i2c_read_fail_on_call = 3;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    g_sim.i2c_read_fail_on_call = 0;
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("post-write byte86 read failure compensates the attempted write",
           status != 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 0 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.release_fail_on_call = 2;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("post-readback lock-release failure preserves attempted ledger "
           "and compensates exactly",
           status != 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 0 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.ignore_i2c_write = TRUE;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    g_sim.ignore_i2c_write = FALSE;
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("successful-but-ignored byte86 write is rejected and already "
           "restored without a blind write",
           status != 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.i2c_write_calls == 1 &&
           g_sim.admin_set_calls == 0 &&
           all_acquired_lock_releases_attempted());
}

static void test_admin_and_final_read_faults_use_attempted_ledger(void) {
    hal_port_admin_transaction_snapshot before;
    hal_port_admin_transaction_snapshot after;
    int status;

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.admin_set_status = FM_FAIL;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    g_sim.admin_set_status = FM_OK;
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("admin dispatch error rereads unchanged admin and compensates "
           "the attempted byte86 write",
           status != 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 1 &&
           g_sim.nested_vendor_xcvr_writes == 0 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.admin_set_mutate_then_fail_on_call = 1;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("admin mutate-then-error is reread as attempted and exactly "
           "compensated after byte86",
           status != 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 2 &&
           g_sim.nested_vendor_xcvr_writes == 0 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.admin_set_third_then_fail_on_call = 1;
    g_sim.admin_set_third_mode = FM_PORT_MODE_ADMIN_DOWN;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    expect("admin third-state-then-error is OOS without an unsafe admin "
           "compensation write",
           status != 0 && g_sim.eeprom_byte86 == 0x0f &&
           g_sim.admin_mode[TEST_PORT] == FM_PORT_MODE_ADMIN_DOWN &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 1 &&
           g_sim.nested_vendor_xcvr_writes == 0 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.admin_set_mutate_then_fail_on_call = 1;
    g_sim.port_get_fail_on_call = 3;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    expect("admin mutate-then-error with failed authoritative reread is "
           "OOS after safe byte86 compensation",
           status != 0 && g_sim.eeprom_byte86 == 0x0f &&
           g_sim.admin_mode[TEST_PORT] == FM_PORT_MODE_UP &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 1 &&
           g_sim.nested_vendor_xcvr_writes == 0 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.ignore_admin_write = TRUE;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    g_sim.ignore_admin_write = FALSE;
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("ignored admin write is rejected while attempted byte86 write "
           "is compensated",
           status != 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 1);

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.i2c_read_fail_on_call = 4;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    g_sim.i2c_read_fail_on_call = 0;
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("final tuple read failure compensates XCVR then admin from "
           "attempted-write ledger",
           status != 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 2 &&
           g_sim.nested_vendor_xcvr_writes == 0);
}

static void test_compensation_faults_fail_closed(void) {
    hal_port_admin_transaction_snapshot before;
    hal_port_admin_transaction_snapshot after;
    int status;

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.admin_set_status = FM_FAIL;
    g_sim.i2c_write_fail_on_call = 2;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    expect("compensation write failure is reported and does not attempt "
           "unsafe admin compensation",
           status != 0 && g_sim.eeprom_byte86 == 0x0e &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 1 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.admin_set_status = FM_FAIL;
    g_sim.i2c_write_mutate_then_fail_on_call = 2;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("compensation byte mutate-then-error is authoritatively "
           "confirmed at the before-image",
           status != 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 1 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.admin_set_status = FM_FAIL;
    g_sim.i2c_read_fail_on_call = 6;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("compensation readback error is authoritatively confirmed after "
           "the physical byte was restored",
           status != 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 1 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.admin_set_status = FM_FAIL;
    g_sim.release_fail_on_call = 4;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("compensation post-readback lock-release error is "
           "authoritatively confirmed with every release path attempted",
           status != 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 1 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.admin_set_status = FM_FAIL;
    g_sim.i2c_write_mutate_then_fail_on_call = 2;
    g_sim.i2c_read_fail_on_call = 6;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    expect("compensation mutate-then-error with failed authoritative reread "
           "remains OOS despite the physical before-byte",
           status != 0 && g_sim.eeprom_byte86 == 0x0f &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 1 &&
           all_acquired_lock_releases_attempted());

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    g_sim.i2c_read_fail_on_call = 4;
    g_sim.admin_set_mutate_then_fail_on_call = 2;
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("compensation admin mutate-then-error is authoritatively "
           "confirmed at the before-image",
           status != 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.i2c_write_calls == 2 &&
           g_sim.admin_set_calls == 2 &&
           g_sim.nested_vendor_xcvr_writes == 0 &&
           all_acquired_lock_releases_attempted());
}

static void test_presence_and_loaded_table_fail_closed(void) {
    hal_port_admin_transaction_snapshot before;
    int status;

    reset_simulator();
    install_loaded_table();
    g_sim.present_valid = FALSE;
    clear_call_evidence();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("missing PRESENT authority is zero-write fail closed",
           before.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           g_sim.i2c_write_calls == 0 && g_sim.admin_set_calls == 0);

    reset_simulator();
    install_loaded_table();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    g_sim.present = FALSE;
    clear_call_evidence();
    status = hal_port_admin_transaction_apply(
        TEST_SWITCH, TEST_PORT, FM_PORT_MODE_UP, &before);
    expect("module removal drift blocks transaction with zero writes",
           status != 0 && g_sim.i2c_write_calls == 0 &&
           g_sim.admin_set_calls == 0);

    reset_simulator();
    install_loaded_table();
    g_lib.I2cWriteRead = NULL;
    clear_call_evidence();
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("missing loaded I2C function fails closed without public Mem API",
           before.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR &&
           g_sim.i2c_write_calls == 0 && g_sim.admin_set_calls == 0);
}

static void test_exact_retrain_quiesces_without_tx_disable(void) {
    hal_port_admin_transaction_snapshot before;
    hal_port_admin_transaction_snapshot after;
    int status;

    reset_simulator();
    install_loaded_table();
    g_sim.admin_mode[TEST_PORT] = FM_PORT_MODE_UP;
    g_sim.eeprom_byte86 = 0x0e;
    before = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    clear_call_evidence();
    status = hal_port_retrain(TEST_SWITCH, TEST_PORT);
    after = hal_port_admin_transaction_snapshot_get(
        TEST_SWITCH, TEST_PORT);
    expect("exact retrain performs admin down/up without Tx_Disable writes",
           status == 0 &&
           hal_port_admin_transaction_snapshot_equal(&before, &after) &&
           g_sim.admin_set_calls == 2 && g_sim.i2c_write_calls == 0 &&
           g_sim.nested_vendor_xcvr_writes == 0 &&
           all_acquired_lock_releases_attempted());
}

static void test_mac_address_type_projection(void) {
	expect("MAC snapshot distinguishes static and secure-static types",
	       mac_address_type_is_static(FM_ADDRESS_STATIC) &&
	       mac_address_type_is_static(FM_ADDRESS_SECURE_STATIC) &&
	       !mac_address_type_is_static(FM_ADDRESS_DYNAMIC) &&
	       !mac_address_type_is_static(FM_ADDRESS_SECURE_DYNAMIC));
}

int main(void) {
    test_read_only_reconcile_all_cache_combinations();
    test_full_byte_and_four_lane_cas();
    test_admin_byte_tuple_capture_boundary();
    test_real_24_port_mapping();
    test_stale_hardware_and_topology_are_zero_write();
    test_sfp_is_fail_closed();
    test_lock_failures_release_every_acquired_layer();
    test_write_and_readback_faults_compensate();
    test_admin_and_final_read_faults_use_attempted_ledger();
    test_compensation_faults_fail_closed();
    test_presence_and_loaded_table_fail_closed();
    test_exact_retrain_quiesces_without_tx_disable();
    test_mac_address_type_projection();

    if (g_failed != 0) {
        printf("FAIL: %d port/XCVR transaction assertions failed\n",
               g_failed);
        return 1;
    }
    printf("PASS: exact port admin/QSFP transaction fixture\n");
    return 0;
}
