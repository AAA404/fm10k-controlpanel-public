/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "hal_port_xcvr_sdk_adapter.h"
#include "fm10k_board_sdk.h"
#include "fm10k_board_runtime.h"

#include "netlab/interface_id.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <fm_sdk_int.h>

#ifndef NETLAB_XCVR_FCI_PROFILE
#define NETLAB_XCVR_FCI_PROFILE fm10k_native_profile
#endif
#ifndef NETLAB_XCVR_ETHERNET_MODE
#define NETLAB_XCVR_ETHERNET_MODE(sw, port, mode) \
    fmGetPortAttribute((sw), (port), FM_PORT_ETHERNET_INTERFACE_MODE, (mode))
#endif
#ifndef NETLAB_XCVR_SET_ETHERNET_MODE
#define NETLAB_XCVR_SET_ETHERNET_MODE(sw, port, mode) \
    fmSetPortAttribute((sw), (port), FM_PORT_ETHERNET_INTERFACE_MODE, (mode))
#endif

/*
 * These assertions deliberately make a vendor SDK update a compile-time
 * migration instead of silently reinterpreting private process/root state.
 * The project is pinned to the 64-bit LibertyTrail SDK described by
 * NETLAB_SDK_TREE in sbin/switchd/Makefile.
 */
_Static_assert(sizeof(void *) == 8,
               "LibertyTrail adapter requires the pinned 64-bit ABI");
_Static_assert(sizeof(fm_bool) == 1,
               "LibertyTrail fm_bool ABI changed");
_Static_assert(FM_PLAT_LANES_PER_EPL == NETLAB_PORT_XCVR_QSFP_LANES,
               "LibertyTrail QSFP lane count changed");
_Static_assert(FM_PLAT_INTF_TYPE_QSFP_LANE0 == 2 &&
               FM_PLAT_INTF_TYPE_QSFP_LANE1 == 3 &&
               FM_PLAT_INTF_TYPE_QSFP_LANE2 == 4 &&
               FM_PLAT_INTF_TYPE_QSFP_LANE3 == 5,
               "LibertyTrail interface type ABI changed");
_Static_assert(offsetof(fm_platXcvrInfo, disabled) == 4,
               "LibertyTrail xcvrInfo disabled offset changed");
_Static_assert(offsetof(fm_platformLib, I2cWriteRead) == 24 &&
               offsetof(fm_platformLib, SelectBus) == 32 &&
               offsetof(fm_platformLib, GetPortXcvrState) == 40,
               "LibertyTrail loaded function table ABI changed");
_Static_assert(sizeof(fm_platformLib) == 104,
               "LibertyTrail loaded function table size changed");

#ifndef NETLAB_XCVR_PROFILE_GET_ALL
#define NETLAB_XCVR_PROFILE_GET_ALL nl_ifid_get_all
#endif

#ifndef NETLAB_XCVR_MAP_PORT
#define NETLAB_XCVR_MAP_PORT fmPlatformMapLogicalPortToPlatform
#endif

#ifndef NETLAB_XCVR_PORT_INDEX
#define NETLAB_XCVR_PORT_INDEX fmPlatformCfgPortGetIndex
#endif

#ifndef NETLAB_XCVR_SWITCH_CFG
#define NETLAB_XCVR_SWITCH_CFG(sw) FM_PLAT_GET_SWITCH_CFG(sw)
#endif

#ifndef NETLAB_XCVR_CACHE_INFO
#define NETLAB_XCVR_CACHE_INFO(sw) GET_PLAT_STATE(sw)->xcvrInfo
#endif

#ifndef NETLAB_XCVR_LIB_FUNCS
#define NETLAB_XCVR_LIB_FUNCS(sw) FM_PLAT_GET_LIB_FUNCS_PTR(sw)
#endif

#ifndef NETLAB_XCVR_SWITCH_LOCK_TAKE
#define NETLAB_XCVR_SWITCH_LOCK_TAKE fmPlatformMgmtTakeSwitchLock
#endif

#ifndef NETLAB_XCVR_SWITCH_LOCK_DROP
#define NETLAB_XCVR_SWITCH_LOCK_DROP fmPlatformMgmtDropSwitchLock
#endif

#ifndef NETLAB_XCVR_CAPTURE_LOCK
#define NETLAB_XCVR_CAPTURE_LOCK(lock) \
    fmCaptureLock((lock), FM_WAIT_FOREVER)
#endif

#ifndef NETLAB_XCVR_RELEASE_LOCK
#define NETLAB_XCVR_RELEASE_LOCK(lock) fmReleaseLock((lock))
#endif

#ifndef NETLAB_XCVR_DELAY
#define NETLAB_XCVR_DELAY(sec, nsec) fmDelay((sec), (nsec))
#endif

typedef struct {
    fm_int logical_port;
    fm_int profile_port_index;
    fm_int epl;
    fm_int lane;
    fm_int sdk_port_index;
} netlab_port_xcvr_member;

typedef struct {
    fm_uint64 fingerprint;
    fm_uint32 hw_resource_id;
    fm_int owner_port;
    fm_int owner_sdk_port_index;
    fm_int platform_switch;
    fm_byte lane_mask;
    fm_int member_count;
    netlab_port_xcvr_member members[NETLAB_PORT_XCVR_QSFP_LANES];
} netlab_port_xcvr_topology;

typedef struct {
    fm_bool switch_locked;
    fm_bool i2c_locked;
} netlab_port_xcvr_lock_state;

static fm_uint64 fingerprint_byte(fm_uint64 hash, fm_byte value) {
    return (hash ^ (fm_uint64)value) * UINT64_C(1099511628211);
}

static fm_uint64 fingerprint_u32(fm_uint64 hash, fm_uint32 value) {
    fm_uint i;

    for (i = 0; i < sizeof(value); i++)
        hash = fingerprint_byte(
            hash, (fm_byte)((value >> (i * 8U)) & 0xffU));
    return hash;
}

static fm_uint64 fingerprint_text(fm_uint64 hash, const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;

    if (!cursor)
        return fingerprint_byte(hash, 0);
    while (*cursor)
        hash = fingerprint_byte(hash, (fm_byte)*cursor++);
    return fingerprint_byte(hash, 0);
}

static int profile_entry_compare(const void *left, const void *right) {
    const nl_port_entry *a = (const nl_port_entry *)left;
    const nl_port_entry *b = (const nl_port_entry *)right;

    if (a->switch_id != b->switch_id)
        return a->switch_id < b->switch_id ? -1 : 1;
    if (a->logical_port != b->logical_port)
        return a->logical_port < b->logical_port ? -1 : 1;
    return 0;
}

static fm_uint64 topology_fingerprint(
    nl_port_entry *entries, fm_int count) {
    fm_uint64 hash = UINT64_C(1469598103934665603);
    fm_int i;

    qsort(entries, (size_t)count, sizeof(entries[0]),
          profile_entry_compare);
    hash = fingerprint_u32(hash, (fm_uint32)count);
    for (i = 0; i < count; i++) {
        const nl_port_entry *entry = &entries[i];

        hash = fingerprint_u32(hash, (fm_uint32)entry->switch_id);
        hash = fingerprint_u32(hash, (fm_uint32)entry->switch_number);
        hash = fingerprint_u32(hash, (fm_uint32)entry->logical_port);
        hash = fingerprint_u32(hash, (fm_uint32)entry->port_index);
        hash = fingerprint_u32(hash, (fm_uint32)entry->epl_port);
        hash = fingerprint_u32(hash, (fm_uint32)entry->lane);
        hash = fingerprint_u32(hash, (fm_uint32)entry->hw_resource_id);
        hash = fingerprint_text(hash, entry->interface_type);
    }
    return hash;
}

static fm_int qsfp_lane_from_profile(const nl_port_entry *entry) {
    static const char *const names[NETLAB_PORT_XCVR_QSFP_LANES] = {
        "QSFP_LANE0", "QSFP_LANE1", "QSFP_LANE2", "QSFP_LANE3"
    };
    fm_int lane;

    if (!entry)
        return -1;
    for (lane = 0; lane < NETLAB_PORT_XCVR_QSFP_LANES; lane++) {
        if (strcmp(entry->interface_type, names[lane]) == 0)
            return entry->lane == lane ? lane : -1;
    }
    return -1;
}

static fm_status resolve_profile_topology(
    fm_int sw, fm_int port, netlab_port_xcvr_topology *topology) {
    nl_port_entry entries[NL_MAX_PORTS_PER_PROFILE];
    nl_port_entry requested;
    fm_bool requested_found = FALSE;
    fm_int lane_seen[NETLAB_PORT_XCVR_QSFP_LANES] = {0};
    fm_int count;
    fm_int i;
    fm_int requested_lane;

    if (!topology)
        return FM_ERR_INVALID_ARGUMENT;
    memset(topology, 0, sizeof(*topology));
    topology->owner_port = -1;
    topology->owner_sdk_port_index = -1;
    topology->platform_switch = -1;

    count = NETLAB_XCVR_PROFILE_GET_ALL(
        entries, NL_MAX_PORTS_PER_PROFILE);
    if (count <= 0 || count > NL_MAX_PORTS_PER_PROFILE)
        return FM_ERR_UNINITIALIZED;

    for (i = 0; i < count; i++) {
        if (entries[i].switch_id == sw &&
            entries[i].logical_port == port) {
            requested = entries[i];
            requested_found = TRUE;
            break;
        }
    }
    if (!requested_found)
        return FM_ERR_INVALID_PORT;

    requested_lane = qsfp_lane_from_profile(&requested);
    if (requested_lane < 0)
        return FM_ERR_UNSUPPORTED;
    if (requested.hw_resource_id < 0 || requested.epl_port < 0 ||
        requested.epl_port >= FM_PLAT_NUM_EPL)
        return FM_ERR_INVALID_ARGUMENT;

    topology->fingerprint = topology_fingerprint(entries, count);
    topology->hw_resource_id = (fm_uint32)requested.hw_resource_id;

    for (i = 0; i < count; i++) {
        netlab_port_xcvr_member *member;
        fm_int lane;

        if (entries[i].switch_id != sw ||
            entries[i].hw_resource_id != requested.hw_resource_id)
            continue;
        lane = qsfp_lane_from_profile(&entries[i]);
        if (lane < 0 || entries[i].epl_port != requested.epl_port ||
            lane_seen[lane] ||
            topology->member_count >= NETLAB_PORT_XCVR_QSFP_LANES)
            return FM_ERR_INVALID_ARGUMENT;

        lane_seen[lane] = 1;
        member = &topology->members[topology->member_count++];
        member->logical_port = entries[i].logical_port;
        member->profile_port_index = entries[i].port_index;
        member->epl = entries[i].epl_port;
        member->lane = lane;
        member->sdk_port_index = -1;
        if (lane == 0)
            topology->owner_port = entries[i].logical_port;
    }

    if (topology->owner_port <= 0)
        return FM_ERR_INVALID_ARGUMENT;
    if (topology->member_count == 1) {
        if (!lane_seen[0] || requested_lane != 0)
            return FM_ERR_INVALID_ARGUMENT;
        topology->lane_mask = NETLAB_PORT_XCVR_TX_DISABLE_MASK;
    } else if (topology->member_count ==
               NETLAB_PORT_XCVR_QSFP_LANES) {
        for (i = 0; i < NETLAB_PORT_XCVR_QSFP_LANES; i++) {
            if (!lane_seen[i])
                return FM_ERR_INVALID_ARGUMENT;
        }
        topology->lane_mask = (fm_byte)(1U << requested_lane);
    } else {
        return FM_ERR_UNSUPPORTED;
    }
    return FM_OK;
}

static fm_status validate_runtime_topology(
    fm_int sw, netlab_port_xcvr_topology *topology) {
    fm_platformCfgSwitch *switch_cfg;
    fm_platformCfgPort *owner_cfg = NULL;
    fm_int module_platform_switch = -1;
    fm_uint32 owner_hw_resource = 0;
    fm_int i;

    if (!topology || !fmRootPlatform || !fmRootPlatform->platformState ||
        !fmPlatformProcessState)
        return FM_ERR_UNINITIALIZED;
    if (sw < 0 || sw >= fmRootPlatform->cfg.numSwitches)
        return FM_ERR_INVALID_SWITCH;

    switch_cfg = NETLAB_XCVR_SWITCH_CFG(sw);
    if (!switch_cfg || !switch_cfg->ports ||
        !NETLAB_XCVR_CACHE_INFO(sw))
        return FM_ERR_UNINITIALIZED;

    for (i = 0; i < topology->member_count; i++) {
        netlab_port_xcvr_member *member = &topology->members[i];
        fm_platformCfgPort *port_cfg = NULL;
        fm_int physical_switch = -1;
        fm_int platform_switch = -1;
        fm_uint32 hw_resource = 0;
        fm_int port_index;
        fm_status status;

        status = NETLAB_XCVR_MAP_PORT(
            sw, member->logical_port, &physical_switch, &platform_switch,
            &hw_resource, &port_cfg);
        if (status != FM_OK)
            return status;
        port_index = NETLAB_XCVR_PORT_INDEX(sw, member->logical_port);
        if (physical_switch != sw || platform_switch < 0 ||
            hw_resource != topology->hw_resource_id || !port_cfg ||
            member->epl < 0 || member->epl >= FM_PLAT_NUM_EPL ||
            port_index < 0 || port_index >= switch_cfg->numPorts ||
            member->profile_port_index != port_index ||
            port_cfg != &switch_cfg->ports[port_index] ||
            port_cfg->port != member->logical_port ||
            port_cfg->portIdx != port_index ||
            port_cfg->hwResourceId != topology->hw_resource_id ||
            port_cfg->epl != member->epl ||
            port_cfg->intfType !=
                (fm_platIntfType)(FM_PLAT_INTF_TYPE_QSFP_LANE0 +
                                  member->lane) ||
            switch_cfg->epls[member->epl]
                    .laneToPortIdx[member->lane] != port_index)
            return FM_ERR_INVALID_ARGUMENT;

        if (module_platform_switch < 0)
            module_platform_switch = platform_switch;
        else if (platform_switch != module_platform_switch)
            return FM_ERR_INVALID_ARGUMENT;
        member->sdk_port_index = port_index;
        if (member->logical_port == topology->owner_port) {
            owner_cfg = port_cfg;
            topology->owner_sdk_port_index = port_index;
            owner_hw_resource = hw_resource;
        }
    }

    if (!owner_cfg || topology->owner_sdk_port_index < 0 ||
        owner_hw_resource != topology->hw_resource_id)
        return FM_ERR_INVALID_ARGUMENT;
    if (topology->member_count == 1 &&
        !(owner_cfg->ethMode & FM_ETH_MODE_MULTI_LANE_MASK))
        return FM_ERR_UNSUPPORTED;

    topology->platform_switch = module_platform_switch;
    return FM_OK;
}

static fm_status i2c_bus_lock(fm_int sw) {
    fm_lock *lock;

    if (!fmRootPlatform || !fmRootPlatform->platformState)
        return FM_ERR_UNINITIALIZED;

    lock = &fmRootPlatform->platformState[sw]
                .accessLocks[FM_PLAT_I2C_BUS];
    return NETLAB_XCVR_CAPTURE_LOCK(lock);
}

static fm_status i2c_bus_unlock(fm_int sw) {
    fm_lock *lock;

    if (!fmRootPlatform || !fmRootPlatform->platformState)
        return FM_ERR_UNINITIALIZED;

    lock = &fmRootPlatform->platformState[sw]
                .accessLocks[FM_PLAT_I2C_BUS];
    return NETLAB_XCVR_RELEASE_LOCK(lock);
}

static fm_status lock_adapter(
    fm_int sw, netlab_port_xcvr_lock_state *locks) {
    fm_status status;

    if (!locks)
        return FM_ERR_INVALID_ARGUMENT;
    memset(locks, 0, sizeof(*locks));
    status = NETLAB_XCVR_SWITCH_LOCK_TAKE(sw);
    if (status != FM_OK)
        return status;
    locks->switch_locked = TRUE;

    status = i2c_bus_lock(sw);
    if (status != FM_OK)
        return status;
    locks->i2c_locked = TRUE;
    return FM_OK;
}

static fm_status unlock_adapter(
    fm_int sw, netlab_port_xcvr_lock_state *locks,
    fm_status operation_status) {
    fm_status status = operation_status;
    fm_status unlock_status;

    if (!locks)
        return status;
    if (locks->i2c_locked) {
        unlock_status = i2c_bus_unlock(sw);
        locks->i2c_locked = FALSE;
        if (status == FM_OK && unlock_status != FM_OK)
            status = unlock_status;
    }
    if (locks->switch_locked) {
        unlock_status = NETLAB_XCVR_SWITCH_LOCK_DROP(sw);
        locks->switch_locked = FALSE;
        if (status == FM_OK && unlock_status != FM_OK)
            status = unlock_status;
    }
    return status;
}

static fm_status read_presence_locked(
    const netlab_port_xcvr_topology *topology, fm_bool *present) {
    fm_platformLib *lib;
    fm_uint32 valid = 0;
    fm_uint32 state = 0;
    fm_uint32 hw_resource;
    fm_status status;

    if (!topology || !present)
        return FM_ERR_INVALID_ARGUMENT;
    lib = NETLAB_XCVR_LIB_FUNCS(topology->platform_switch);
    if (!lib || !lib->SelectBus || !lib->GetPortXcvrState)
        return FM_ERR_UNSUPPORTED;

    hw_resource = topology->hw_resource_id;
    status = lib->SelectBus(
        topology->platform_switch, FM_PLAT_BUS_XCVR_STATE,
        hw_resource);
    if (status != FM_OK)
        return status;
    status = lib->GetPortXcvrState(
        topology->platform_switch, &hw_resource, 1, &valid, &state);
    if (status != FM_OK)
        return status;
    if (!(valid & FM_PLAT_XCVR_PRESENT))
        return FM_ERR_UNSUPPORTED;

    *present = (state & FM_PLAT_XCVR_PRESENT) ? TRUE : FALSE;
    return FM_OK;
}

static fm_status select_eeprom_locked(
    const netlab_port_xcvr_topology *topology) {
    fm_platformLib *lib;

    if (!topology)
        return FM_ERR_INVALID_ARGUMENT;
    lib = NETLAB_XCVR_LIB_FUNCS(topology->platform_switch);
    if (!lib || !lib->SelectBus || !lib->I2cWriteRead)
        return FM_ERR_UNSUPPORTED;
    return lib->SelectBus(
        topology->platform_switch, FM_PLAT_BUS_XCVR_EEPROM,
        topology->hw_resource_id);
}

static fm_status read_tx_disable_locked(
    const netlab_port_xcvr_topology *topology, fm_byte *value) {
    fm_platformLib *lib;
    fm_byte data = NETLAB_PORT_XCVR_TX_DISABLE_OFFSET;
    fm_status status;

    if (!topology || !value)
        return FM_ERR_INVALID_ARGUMENT;
    lib = NETLAB_XCVR_LIB_FUNCS(topology->platform_switch);
    if (!lib || !lib->I2cWriteRead)
        return FM_ERR_UNSUPPORTED;

    status = lib->I2cWriteRead(
        topology->platform_switch, 0x50, &data, 1, 1);
    if (status == FM_OK)
        *value = data;
    return status;
}

static fm_status write_tx_disable_locked(
    const netlab_port_xcvr_topology *topology, fm_byte value,
    fm_bool *write_attempted) {
    fm_platformLib *lib;
    fm_byte data[2];

    if (!topology || !write_attempted)
        return FM_ERR_INVALID_ARGUMENT;
    lib = NETLAB_XCVR_LIB_FUNCS(topology->platform_switch);
    if (!lib || !lib->I2cWriteRead)
        return FM_ERR_UNSUPPORTED;

    data[0] = NETLAB_PORT_XCVR_TX_DISABLE_OFFSET;
    data[1] = value;
    NETLAB_XCVR_DELAY(0, 5000 * 1000);
    *write_attempted = TRUE;
    return lib->I2cWriteRead(
        topology->platform_switch, 0x50, data, 2, 0);
}

static fm_status project_disabled_cache_locked(
    fm_int sw, const netlab_port_xcvr_topology *topology,
    fm_byte tx_disable) {
    fm_platXcvrInfo *cache = NETLAB_XCVR_CACHE_INFO(sw);
    fm_int i;

    if (!topology || !cache)
        return FM_ERR_UNINITIALIZED;
    if (topology->member_count == 1) {
        fm_byte low = tx_disable & NETLAB_PORT_XCVR_TX_DISABLE_MASK;

        if (low != 0 && low != NETLAB_PORT_XCVR_TX_DISABLE_MASK)
            return FM_ERR_UNSUPPORTED;
        cache[topology->owner_sdk_port_index].disabled =
            low == NETLAB_PORT_XCVR_TX_DISABLE_MASK ? TRUE : FALSE;
        return FM_OK;
    }

    for (i = 0; i < topology->member_count; i++) {
        const netlab_port_xcvr_member *member = &topology->members[i];

        cache[member->sdk_port_index].disabled =
            (tx_disable & (1U << member->lane)) ? TRUE : FALSE;
    }
    return FM_OK;
}

static fm_status read_snapshot_locked(
    fm_int sw, const netlab_port_xcvr_topology *topology,
    netlab_port_xcvr_sdk_snapshot *snapshot) {
    fm_bool present = FALSE;
    fm_byte tx_disable = 0;
    fm_status status;

    status = read_presence_locked(topology, &present);
    if (status != FM_OK)
        return status;

    snapshot->present = present;
    snapshot->tx_disable_valid = FALSE;
    if (!present)
        return FM_OK;

    status = select_eeprom_locked(topology);
    if (status != FM_OK)
        return status;
    status = read_tx_disable_locked(topology, &tx_disable);
    if (status != FM_OK)
        return status;
    status = project_disabled_cache_locked(sw, topology, tx_disable);
    if (status != FM_OK)
        return status;

    snapshot->tx_disable_byte = tx_disable;
    snapshot->tx_disable_valid = TRUE;
    return FM_OK;
}

#include "fm10k_port_fci.inc"

fm_status netlab_port_xcvr_sdk_snapshot_get(
    fm_int sw, fm_int port, netlab_port_xcvr_sdk_snapshot *snapshot) {
    if (NETLAB_XCVR_FCI_PROFILE()) return fci_snapshot_get(sw, port, snapshot);
    netlab_port_xcvr_topology topology;
    netlab_port_xcvr_lock_state locks;
    fm_status status;

    if (!snapshot)
        return FM_ERR_INVALID_ARGUMENT;
    memset(snapshot, 0, sizeof(*snapshot));

    status = resolve_profile_topology(sw, port, &topology);
    if (status != FM_OK)
        return status;
    status = validate_runtime_topology(sw, &topology);
    if (status != FM_OK)
        return status;

    snapshot->topology_fingerprint = topology.fingerprint;
    snapshot->module_hw_resource_id = topology.hw_resource_id;
    snapshot->module_owner_port = topology.owner_port;
    snapshot->lane_mask = topology.lane_mask;

    status = lock_adapter(sw, &locks);
    if (status == FM_OK)
        status = read_snapshot_locked(sw, &topology, snapshot);
    return unlock_adapter(sw, &locks, status);
}

static fm_bool topology_matches_snapshot(
    const netlab_port_xcvr_topology *topology,
    const netlab_port_xcvr_sdk_snapshot *snapshot) {
    return topology && snapshot &&
           topology->fingerprint == snapshot->topology_fingerprint &&
           topology->hw_resource_id == snapshot->module_hw_resource_id &&
           topology->owner_port == snapshot->module_owner_port &&
           topology->lane_mask == snapshot->lane_mask;
}

fm_status netlab_port_xcvr_sdk_tx_disable_cas(
    fm_int sw, fm_int port,
    const netlab_port_xcvr_sdk_snapshot *expected,
    fm_byte desired_byte,
    netlab_port_xcvr_sdk_cas_result *result) {
    if (NETLAB_XCVR_FCI_PROFILE())
        return fci_tx_disable_cas(sw, port, expected, desired_byte, result);
    netlab_port_xcvr_topology topology;
    netlab_port_xcvr_lock_state locks;
    fm_bool present = FALSE;
    fm_byte current = 0;
    fm_byte readback = 0;
    fm_status status;

    if (!result)
        return FM_ERR_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    result->status = FM_ERR_INVALID_ARGUMENT;

    if (!expected || !expected->present ||
        !expected->tx_disable_valid ||
        ((desired_byte ^ expected->tx_disable_byte) &
         (fm_byte)~expected->lane_mask) != 0) {
        result->status = FM_ERR_INVALID_ARGUMENT;
        return result->status;
    }

    status = resolve_profile_topology(sw, port, &topology);
    if (status != FM_OK)
        goto done;
    status = validate_runtime_topology(sw, &topology);
    if (status != FM_OK)
        goto done;
    if (!topology_matches_snapshot(&topology, expected)) {
        status = FM_FAIL;
        goto done;
    }

    status = lock_adapter(sw, &locks);
    if (status != FM_OK)
        goto unlock;
    status = read_presence_locked(&topology, &present);
    if (status != FM_OK || !present) {
        if (status == FM_OK)
            status = FM_FAIL;
        goto unlock;
    }
    status = select_eeprom_locked(&topology);
    if (status != FM_OK)
        goto unlock;
    status = read_tx_disable_locked(&topology, &current);
    if (status != FM_OK)
        goto unlock;

    if (current != expected->tx_disable_byte) {
        status = FM_FAIL;
        goto unlock;
    }

    status = write_tx_disable_locked(
        &topology, desired_byte, &result->write_attempted);
    if (status != FM_OK)
        goto unlock;

    /*
     * The pinned public MemWrite sleeps after a write.  Keep that settling
     * interval inside this one switch/I2C critical section, then read
     * the complete byte back through the already loaded table.
     */
    NETLAB_XCVR_DELAY(1, 0);
    status = read_tx_disable_locked(&topology, &readback);
    if (status != FM_OK)
        goto unlock;
    result->readback_completed = TRUE;
    result->readback_byte = readback;

    status = project_disabled_cache_locked(sw, &topology, readback);
    if (status != FM_OK)
        goto unlock;
    if (readback != desired_byte)
        status = FM_FAIL;

unlock:
    status = unlock_adapter(sw, &locks, status);
done:
    result->status = status;
    return status;
}
