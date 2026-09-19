/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/log.h"
#include "netlab/hal.h"
#include "netlab/hal_presence.h"
#include "hal_port_xcvr_sdk_adapter.h"
#include "fm10k_board_runtime.h"
#include <fm_sdk.h>
#include <api/fm_api_attr.h>
#include <api/fm_api_addr.h>
#include <api/fm_api_lag.h>
#include <api/fm_api_port.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NETLAB_PORT_MTU_SDK_OVERHEAD 22
#define NETLAB_PORT_RETRAIN_DOWN_HOLD_US 250000

#ifndef NETLAB_PORT_RETRAIN_DELAY
#define NETLAB_PORT_RETRAIN_DELAY(usec) usleep((usec))
#endif

int hal_port_effective_admin_mode(int mode) {
    if (mode == FM_PORT_MODE_ADMIN_DOWN)
        return FM_PORT_MODE_ADMIN_PWRDOWN;
    return mode;
}

static bool hal_port_admin_mode_restorable(int mode) {
    return mode == FM_PORT_MODE_UP ||
           mode == FM_PORT_MODE_ADMIN_DOWN ||
           mode == FM_PORT_MODE_ADMIN_PWRDOWN;
}

static bool hal_port_admin_xcvr_tuple_restorable(
    int admin_mode, const netlab_port_xcvr_sdk_snapshot *xcvr) {
    u8 owned_bits;

    if (!xcvr || !hal_port_admin_mode_restorable(admin_mode))
        return false;
    if (!xcvr->present)
        return !xcvr->tx_disable_valid;
    if (!xcvr->tx_disable_valid || xcvr->lane_mask == 0 ||
        (xcvr->lane_mask &
         (fm_byte)~NETLAB_PORT_XCVR_TX_DISABLE_MASK) != 0)
        return false;

    /*
     * fmSetPortState() always invokes the pinned platform callback.  That
     * callback treats ADMIN_PWRDOWN as disabled and both UP and ADMIN_DOWN as
     * enabled.  If the saved disable mask disagrees, restoring the admin mode
     * would enter its legacy EEPROM writer after our optical-mask CAS,
     * clobbering sibling and module-owned bits.  Reject such a tuple before
     * the transaction owns any write.
     */
    owned_bits = (u8)xcvr->tx_disable_byte & (u8)xcvr->lane_mask;
    if (admin_mode == FM_PORT_MODE_ADMIN_PWRDOWN)
        return owned_bits == (u8)xcvr->lane_mask;
    return owned_bits == 0;
}

static void hal_port_xcvr_sdk_snapshot_from_transaction(
    const hal_port_admin_transaction_snapshot *transaction,
    netlab_port_xcvr_sdk_snapshot *xcvr) {
    memset(xcvr, 0, sizeof(*xcvr));
    xcvr->topology_fingerprint =
        (fm_uint64)transaction->xcvr_topology_fingerprint;
    xcvr->module_hw_resource_id =
        (fm_uint32)transaction->xcvr_module_hw_resource_id;
    xcvr->module_owner_port =
        (fm_int)transaction->xcvr_module_owner_port;
    xcvr->lane_mask = (fm_byte)transaction->xcvr_lane_mask;
    xcvr->present = transaction->xcvr_present ? TRUE : FALSE;
    xcvr->tx_disable_valid =
        transaction->xcvr_tx_disable_valid ? TRUE : FALSE;
    xcvr->tx_disable_byte =
        (fm_byte)transaction->xcvr_tx_disable_byte;
}

static bool hal_port_xcvr_shape_equal(
    const hal_port_admin_transaction_snapshot *transaction,
    const netlab_port_xcvr_sdk_snapshot *xcvr) {
    return transaction && xcvr &&
           transaction->xcvr_topology_fingerprint ==
               (u64)xcvr->topology_fingerprint &&
           transaction->xcvr_module_hw_resource_id ==
               (u32)xcvr->module_hw_resource_id &&
           transaction->xcvr_module_owner_port ==
               (int)xcvr->module_owner_port &&
           transaction->xcvr_lane_mask == (u8)xcvr->lane_mask &&
           transaction->xcvr_present == (xcvr->present != FALSE) &&
           transaction->xcvr_tx_disable_valid ==
               (xcvr->tx_disable_valid != FALSE);
}

static bool hal_port_xcvr_exact_equal(
    const hal_port_admin_transaction_snapshot *transaction,
    const netlab_port_xcvr_sdk_snapshot *xcvr) {
    return hal_port_xcvr_shape_equal(transaction, xcvr) &&
           (!transaction->xcvr_tx_disable_valid ||
            transaction->xcvr_tx_disable_byte ==
                (u8)xcvr->tx_disable_byte);
}

hal_port_admin_transaction_snapshot
hal_port_admin_transaction_snapshot_get(int sw, int port) {
    hal_port_admin_transaction_snapshot snapshot;
    netlab_port_xcvr_sdk_snapshot xcvr;
    fm_int mode = 0;
    fm_int state = 0;
    fm_int info[NETLAB_PORT_STATE_INFO_SLOTS] = {0};
    fm_status status;

    memset(&snapshot, 0, sizeof(snapshot));
    snapshot.state = HAL_TRANSACTION_SNAPSHOT_READ_ERROR;
    snapshot.sdk_status = FM_ERR_UNINITIALIZED;

    status = fmGetPortState((fm_int)sw, (fm_int)port, &mode, &state, info);
    if (status != FM_OK) {
        snapshot.sdk_status = (int)status;
        NL_LOG_ERR("fmGetPortState transaction snapshot sw=%d port=%d: %s",
                   sw, port, fmErrorMsg(status));
        return snapshot;
    }
    if (!hal_port_admin_mode_restorable((int)mode)) {
        snapshot.sdk_status = FM_ERR_UNSUPPORTED;
        NL_LOG_ERR("port %d transaction snapshot has unrestorable mode=%d",
                   port, (int)mode);
        return snapshot;
    }

    status = netlab_port_xcvr_sdk_snapshot_get(
        (fm_int)sw, (fm_int)port, &xcvr);
    if (status != FM_OK) {
        snapshot.sdk_status = (int)status;
        NL_LOG_ERR(
            "exact XCVR transaction snapshot sw=%d port=%d status=%d",
            sw, port, (int)status);
        return snapshot;
    }

    if ((xcvr.present && !xcvr.tx_disable_valid) ||
        (!xcvr.present && xcvr.tx_disable_valid)) {
        snapshot.sdk_status = FM_ERR_UNSUPPORTED;
        NL_LOG_ERR("port %d exact XCVR snapshot is internally incomplete",
                   port);
        return snapshot;
    }
    if (!hal_port_admin_xcvr_tuple_restorable((int)mode, &xcvr)) {
        snapshot.sdk_status = FM_ERR_UNSUPPORTED;
        NL_LOG_ERR(
            "port %d admin/XCVR tuple is not exactly restorable "
            "mode=%d present=%d lane-mask=0x%02x disable-mask=0x%02x",
            port, (int)mode, xcvr.present != FALSE,
            (unsigned int)xcvr.lane_mask,
            (unsigned int)xcvr.tx_disable_byte);
        return snapshot;
    }

    snapshot.state = HAL_TRANSACTION_SNAPSHOT_PRESENT;
    snapshot.sdk_status = FM_OK;
    snapshot.admin_mode = (int)mode;
    snapshot.xcvr_topology_fingerprint = (u64)xcvr.topology_fingerprint;
    snapshot.xcvr_module_hw_resource_id =
        (u32)xcvr.module_hw_resource_id;
    snapshot.xcvr_module_owner_port = (int)xcvr.module_owner_port;
    snapshot.xcvr_lane_mask = (u8)xcvr.lane_mask;
    snapshot.xcvr_tx_disable_byte = (u8)xcvr.tx_disable_byte;
    snapshot.xcvr_present = xcvr.present != FALSE;
    snapshot.xcvr_tx_disable_valid =
        xcvr.tx_disable_valid != FALSE;
    return snapshot;
}

bool hal_port_admin_transaction_snapshot_equal(
    const hal_port_admin_transaction_snapshot *left,
    const hal_port_admin_transaction_snapshot *right) {
    if (!left || !right ||
        left->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        right->state != HAL_TRANSACTION_SNAPSHOT_PRESENT)
        return false;
    return left->admin_mode == right->admin_mode &&
           left->xcvr_topology_fingerprint ==
               right->xcvr_topology_fingerprint &&
           left->xcvr_module_hw_resource_id ==
               right->xcvr_module_hw_resource_id &&
           left->xcvr_module_owner_port ==
               right->xcvr_module_owner_port &&
           left->xcvr_lane_mask == right->xcvr_lane_mask &&
           left->xcvr_present == right->xcvr_present &&
           left->xcvr_tx_disable_valid ==
               right->xcvr_tx_disable_valid &&
           (!left->xcvr_tx_disable_valid ||
            left->xcvr_tx_disable_byte ==
                right->xcvr_tx_disable_byte);
}

static bool hal_port_admin_transaction_shape_equal(
    const hal_port_admin_transaction_snapshot *left,
    const hal_port_admin_transaction_snapshot *right) {
    return left && right &&
           left->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           right->state == HAL_TRANSACTION_SNAPSHOT_PRESENT &&
           left->xcvr_topology_fingerprint ==
               right->xcvr_topology_fingerprint &&
           left->xcvr_module_hw_resource_id ==
               right->xcvr_module_hw_resource_id &&
           left->xcvr_module_owner_port ==
               right->xcvr_module_owner_port &&
           left->xcvr_lane_mask == right->xcvr_lane_mask &&
           left->xcvr_present == right->xcvr_present &&
           left->xcvr_tx_disable_valid ==
               right->xcvr_tx_disable_valid;
}

typedef struct {
    bool xcvr_attempted;
    bool admin_attempted;
} hal_port_admin_attempted_write_ledger;

static int hal_port_admin_mode_get_exact(
    int sw, int port, int *mode) {
    fm_int sdk_mode = 0;
    fm_int state = 0;
    fm_int info[NETLAB_PORT_STATE_INFO_SLOTS] = {0};
    fm_status status;

    if (!mode)
        return -1;
    status = fmGetPortState(
        (fm_int)sw, (fm_int)port, &sdk_mode, &state, info);
    if (status != FM_OK || !hal_port_admin_mode_restorable((int)sdk_mode))
        return -1;
    *mode = (int)sdk_mode;
    return 0;
}

static int hal_port_admin_mode_cas(
    int sw, int port, int expected_mode, int desired_mode,
    bool *write_attempted) {
    fm_status status;
    int live_mode = 0;

    if (write_attempted)
        *write_attempted = false;
    if (!hal_port_admin_mode_restorable(expected_mode) ||
        !hal_port_admin_mode_restorable(desired_mode) ||
        hal_port_admin_mode_get_exact(sw, port, &live_mode) != 0)
        return -1;
    if (live_mode != expected_mode)
        return -1;

    if (write_attempted)
        *write_attempted = true;
    status = fmSetPortState(
        (fm_int)sw, (fm_int)port, (fm_int)desired_mode, 0);
    if (status != FM_OK) {
        NL_LOG_ERR(
            "fmSetPortState CAS sw=%d port=%d expected=%d desired=%d: %s",
            sw, port, expected_mode, desired_mode, fmErrorMsg(status));
        return -1;
    }
    if (hal_port_admin_mode_get_exact(sw, port, &live_mode) != 0 ||
        live_mode != desired_mode)
        return -1;
    return 0;
}

static int hal_port_xcvr_cas(
    int sw, int port,
    const hal_port_admin_transaction_snapshot *expected,
    u8 desired_byte, bool *write_attempted) {
    netlab_port_xcvr_sdk_snapshot sdk_expected;
    netlab_port_xcvr_sdk_cas_result result;
    fm_status status;

    if (write_attempted)
        *write_attempted = false;
    if (!expected || !expected->xcvr_present ||
        !expected->xcvr_tx_disable_valid)
        return -1;

    hal_port_xcvr_sdk_snapshot_from_transaction(
        expected, &sdk_expected);
    status = netlab_port_xcvr_sdk_tx_disable_cas(
        (fm_int)sw, (fm_int)port, &sdk_expected,
        (fm_byte)desired_byte, &result);
    if (write_attempted)
        *write_attempted = result.write_attempted != FALSE;
    if (status != FM_OK) {
        NL_LOG_ERR(
            "XCVR disable-mask CAS sw=%d port=%d expected=0x%02x "
            "desired=0x%02x status=%d attempted=%d readback=%d "
            "readback-byte=0x%02x",
            sw, port, expected->xcvr_tx_disable_byte, desired_byte,
            (int)status, result.write_attempted != FALSE,
            result.readback_completed != FALSE,
            (unsigned int)result.readback_byte);
        return -1;
    }
    return 0;
}

static int hal_port_xcvr_compensate(
    int sw, int port,
    const hal_port_admin_transaction_snapshot *before,
    const hal_port_admin_transaction_snapshot *attempted) {
    netlab_port_xcvr_sdk_snapshot live;
    fm_status status;
    bool write_attempted = false;

    status = netlab_port_xcvr_sdk_snapshot_get(
        (fm_int)sw, (fm_int)port, &live);
    if (status != FM_OK || !hal_port_xcvr_shape_equal(before, &live))
        return -1;
    if (!before->xcvr_tx_disable_valid)
        return 0;
    if (hal_port_xcvr_exact_equal(before, &live))
        return 0;
    if ((u8)live.tx_disable_byte != attempted->xcvr_tx_disable_byte)
        return -1;

    if (hal_port_xcvr_cas(
            sw, port, attempted, before->xcvr_tx_disable_byte,
            &write_attempted) == 0)
        return 0;
    if (!write_attempted)
        return -1;

    /*
     * Compensation is also a non-idempotent write.  Its error return is not
     * proof that the byte stayed at the attempted value: accept it only when
     * a fresh authoritative read proves the original before-image landed.
     */
    status = netlab_port_xcvr_sdk_snapshot_get(
        (fm_int)sw, (fm_int)port, &live);
    return status == FM_OK &&
           hal_port_xcvr_exact_equal(before, &live) ? 0 : -1;
}

static int hal_port_admin_transaction_compensate(
    int sw, int port,
    const hal_port_admin_transaction_snapshot *before,
    const hal_port_admin_transaction_snapshot *attempted,
    const hal_port_admin_attempted_write_ledger *ledger) {
    hal_port_admin_transaction_snapshot after;
    bool write_attempted = false;
    int live_mode = 0;

    if (!before || !attempted || !ledger)
        return -1;

    /*
     * The pinned fmSetPortState(ADMIN_PWRDOWN) callback consults
     * xcvrInfo->disabled.  Restore the optical mask (and therefore its cache
     * projection) before restoring admin mode, otherwise that callback can
     * enter the vendor's non-transactional whole-nibble write path.
     */
    if (ledger->xcvr_attempted &&
        hal_port_xcvr_compensate(sw, port, before, attempted) != 0)
        return -1;
    if (ledger->admin_attempted) {
        if (hal_port_admin_mode_get_exact(sw, port, &live_mode) != 0)
            return -1;
        if (live_mode != before->admin_mode) {
            if (live_mode != attempted->admin_mode)
                return -1;
            if (hal_port_admin_mode_cas(
                    sw, port, attempted->admin_mode,
                    before->admin_mode, &write_attempted) != 0) {
                if (!write_attempted ||
                    hal_port_admin_mode_get_exact(
                        sw, port, &live_mode) != 0 ||
                    live_mode != before->admin_mode)
                    return -1;
            }
        }
    }

    after = hal_port_admin_transaction_snapshot_get(sw, port);
    if (!hal_port_admin_transaction_snapshot_equal(&after, before))
        return -1;
    return 0;
}

static int hal_port_admin_transaction_write(
    int sw, int port,
    const hal_port_admin_transaction_snapshot *current,
    const hal_port_admin_transaction_snapshot *target) {
    hal_port_admin_attempted_write_ledger ledger;
    hal_port_admin_transaction_snapshot after;
    bool write_attempted = false;

    memset(&ledger, 0, sizeof(ledger));
    if (!current || !target ||
        !hal_port_admin_mode_restorable(target->admin_mode) ||
        !hal_port_admin_transaction_shape_equal(current, target))
        return -1;

    /*
     * Always make the optical mask authoritative first. Its read-back
     * rebuilds all four disabled cache projections, making the vendor
     * fmSetPortState callback a no-op instead of a second XCVR writer.
     * The adapter uses QSFP byte 86 or this EPL's normalized FCI disable
     * nibble, backed by the module's 12-bit enable mask at offsets 56/57.
     */
    if (current->xcvr_tx_disable_valid &&
        current->xcvr_tx_disable_byte !=
            target->xcvr_tx_disable_byte) {
        if (hal_port_xcvr_cas(
                sw, port, current, target->xcvr_tx_disable_byte,
                &write_attempted) != 0) {
            ledger.xcvr_attempted = write_attempted;
            goto compensate;
        }
        ledger.xcvr_attempted = write_attempted;
    }

    write_attempted = false;
    if (current->admin_mode != target->admin_mode) {
        if (hal_port_admin_mode_cas(
                sw, port, current->admin_mode, target->admin_mode,
                &write_attempted) != 0) {
            ledger.admin_attempted = write_attempted;
            goto compensate;
        }
        ledger.admin_attempted = write_attempted;
    }

    after = hal_port_admin_transaction_snapshot_get(sw, port);
    if (hal_port_admin_transaction_snapshot_equal(&after, target))
        return 0;

    NL_LOG_ERR(
        "port %d transaction post-write tuple mismatch/read-error=%d",
        port,
        after.state == HAL_TRANSACTION_SNAPSHOT_READ_ERROR ? 1 : 0);

compensate:
    if (ledger.xcvr_attempted || ledger.admin_attempted) {
        if (hal_port_admin_transaction_compensate(
                sw, port, current, target, &ledger) != 0)
            NL_LOG_CRIT(
                "port %d: admin/XCVR attempted-write compensation failed",
                port);
    }
    return -1;
}

int hal_port_admin_transaction_restore(
    int sw, int port,
    const hal_port_admin_transaction_snapshot *snapshot) {
    hal_port_admin_transaction_snapshot current;

    if (!snapshot ||
        snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        !hal_port_admin_mode_restorable(snapshot->admin_mode))
        return -1;

    current = hal_port_admin_transaction_snapshot_get(sw, port);
    if (!hal_port_admin_transaction_shape_equal(&current, snapshot)) {
        /* Presence and profile topology are not writable transaction fields. */
        NL_LOG_ERR("port %d transaction restore XCVR shape drift", port);
        return -1;
    }
    if (hal_port_admin_transaction_snapshot_equal(&current, snapshot))
        return 0;
    return hal_port_admin_transaction_write(
        sw, port, &current, snapshot);
}

int hal_port_admin_transaction_apply(
    int sw, int port, int mode,
    const hal_port_admin_transaction_snapshot *before) {
    hal_port_admin_transaction_snapshot current;
    hal_port_admin_transaction_snapshot target;
    int effective_mode = hal_port_effective_admin_mode(mode);

    if (!before ||
        before->state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        !hal_port_admin_mode_restorable(effective_mode))
        return -1;

    current = hal_port_admin_transaction_snapshot_get(sw, port);
    if (!hal_port_admin_transaction_snapshot_equal(&current, before)) {
        NL_LOG_ERR("port %d transaction pre-state drift/read failure", port);
        return -1;
    }

    target = *before;
    target.admin_mode = effective_mode;
    if (before->xcvr_present) {
        if (!target.xcvr_tx_disable_valid ||
            target.xcvr_lane_mask == 0 ||
            (target.xcvr_lane_mask &
             (u8)~NETLAB_PORT_XCVR_TX_DISABLE_MASK) != 0)
            return -1;
        if (effective_mode == FM_PORT_MODE_UP)
            target.xcvr_tx_disable_byte &=
                (u8)~target.xcvr_lane_mask;
        else
            target.xcvr_tx_disable_byte |= target.xcvr_lane_mask;
    }

    if (hal_port_admin_transaction_snapshot_equal(&current, &target))
        return 0;
    if (hal_port_admin_transaction_write(
            sw, port, &current, &target) == 0) {
        NL_LOG_INFO("port %d: admin/XCVR transaction applied mode=%d",
                    port, effective_mode);
        return 0;
    }
    return -1;
}

int hal_port_set_admin_state(int sw, int port, int mode) {
    hal_port_admin_transaction_snapshot before =
        hal_port_admin_transaction_snapshot_get(sw, port);

    if (before.state != HAL_TRANSACTION_SNAPSHOT_PRESENT)
        return -1;
    return hal_port_admin_transaction_apply(
        sw, port, mode, &before);
}

static int hal_port_admin_transaction_quiesce(
    int sw, int port,
    const hal_port_admin_transaction_snapshot *before) {
    hal_port_admin_transaction_snapshot current;
    hal_port_admin_transaction_snapshot target;

    if (!before ||
        before->state != HAL_TRANSACTION_SNAPSHOT_PRESENT)
        return -1;
    current = hal_port_admin_transaction_snapshot_get(sw, port);
    if (!hal_port_admin_transaction_snapshot_equal(&current, before))
        return -1;
    if (current.admin_mode == FM_PORT_MODE_ADMIN_PWRDOWN ||
        current.admin_mode == FM_PORT_MODE_ADMIN_DOWN)
        return 0;

    /*
     * Runtime mode changes need a real MAC/PHY down state, but must not depend
     * on optional per-lane QSFP Tx_Disable writes. ADMIN_DOWN keeps the exact
     * XCVR byte unchanged while quiescing the SDK port; the later restore to
     * UP performs the actual retrain. User-facing disable still maps to
     * ADMIN_PWRDOWN through hal_port_admin_transaction_apply().
     */
    target = *before;
    target.admin_mode = FM_PORT_MODE_ADMIN_DOWN;
    if (hal_port_admin_transaction_write(
            sw, port, &current, &target) != 0)
        return -1;
    NL_LOG_INFO(
        "port %d: exact admin/XCVR transaction quiesced without Tx_Disable",
        port);
    return 0;
}

int hal_port_retrain(int sw, int port) {
    hal_port_admin_transaction_snapshot before =
        hal_port_admin_transaction_snapshot_get(sw, port);

    if (before.state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        before.admin_mode != FM_PORT_MODE_UP)
        return -1;
    if (hal_port_admin_transaction_quiesce(sw, port, &before) != 0)
        return -1;

    NETLAB_PORT_RETRAIN_DELAY(NETLAB_PORT_RETRAIN_DOWN_HOLD_US);
    if (hal_port_admin_transaction_restore(sw, port, &before) != 0) {
        NL_LOG_ERR("port %d: exact admin/XCVR retrain restore failed", port);
        return -1;
    }
    NL_LOG_NOTICE("port %d: exact admin/XCVR retrain completed", port);
    return 0;
}

int hal_port_get_state(int sw, int port, int *mode) {
    fm_int state;
    fm_int info[NETLAB_PORT_STATE_INFO_SLOTS] = {0};
    fm_status st = fmGetPortState((fm_int)sw, (fm_int)port,
                                  (fm_int *)mode, &state, info);
    return (st == FM_OK) ? 0 : -1;
}

const char *hal_port_ethernet_mode_name(int ethernet_mode) {
    switch ((fm_ethMode)ethernet_mode) {
        case FM_ETH_MODE_DISABLED:
            return "DISABLED";
        case FM_ETH_MODE_SGMII:
            return "SGMII";
        case FM_ETH_MODE_1000BASE_X:
            return "1000Base-X";
        case FM_ETH_MODE_1000BASE_KX:
            return "1000Base-KX";
        case FM_ETH_MODE_2500BASE_X:
            return "2500Base-X";
        case FM_ETH_MODE_6GBASE_KR:
            return "6GBase-KR";
        case FM_ETH_MODE_6GBASE_CR:
            return "6GBase-CR";
        case FM_ETH_MODE_10GBASE_KR:
            return "10GBase-KR";
        case FM_ETH_MODE_10GBASE_CR:
            return "10GBase-CR";
        case FM_ETH_MODE_10GBASE_SR:
            return "10GBase-SR";
        case FM_ETH_MODE_25GBASE_SR:
            return "25GBase-SR";
        case FM_ETH_MODE_25GBASE_KR:
            return "25GBase-KR";
        case FM_ETH_MODE_25GBASE_CR:
            return "25GBase-CR";
        case FM_ETH_MODE_AN_73:
            return "AN-73";
        case FM_ETH_MODE_XAUI:
            return "XAUI";
        case FM_ETH_MODE_10GBASE_KX4:
            return "10GBase-KX4";
        case FM_ETH_MODE_10GBASE_CX4:
            return "10GBase-CX4";
        case FM_ETH_MODE_24GBASE_KR4:
            return "24GBase-KR4";
        case FM_ETH_MODE_24GBASE_CR4:
            return "24GBase-CR4";
        case FM_ETH_MODE_40GBASE_KR4:
            return "40GBase-KR4";
        case FM_ETH_MODE_XLAUI:
            return "XLAUI";
        case FM_ETH_MODE_40GBASE_CR4:
            return "40GBase-CR4";
        case FM_ETH_MODE_40GBASE_SR4:
            return "40GBase-SR4";
        case FM_ETH_MODE_100GBASE_SR4:
            return "100GBase-SR4";
        case FM_ETH_MODE_100GBASE_CR4:
            return "100GBase-CR4";
        case FM_ETH_MODE_100GBASE_KR4:
            return "100GBase-KR4";
        default:
            return "unknown";
    }
}

static int ethernet_mode_for_speed(int speed) {
    if (speed == 10000)
        return FM_ETH_MODE_10GBASE_SR;
    if (speed == 25000)
        return FM_ETH_MODE_25GBASE_SR;
    return -1;
}

bool hal_port_ethernet_mode_restorable(int ethernet_mode) {
    /*
     * The pinned SDK may report negotiated KR/CR modes that its own public
     * setter documents as read-only.  A transaction must reject those
     * before mutation instead of accepting a before-image it cannot restore.
     * Every other enumerated mode below is writable through
     * FM_PORT_ETHERNET_INTERFACE_MODE.
     */
    switch ((fm_ethMode)ethernet_mode) {
    case FM_ETH_MODE_DISABLED:
    case FM_ETH_MODE_SGMII:
    case FM_ETH_MODE_1000BASE_X:
    case FM_ETH_MODE_1000BASE_KX:
    case FM_ETH_MODE_2500BASE_X:
    case FM_ETH_MODE_6GBASE_KR:
    case FM_ETH_MODE_6GBASE_CR:
    case FM_ETH_MODE_10GBASE_CR:
    case FM_ETH_MODE_10GBASE_SR:
    case FM_ETH_MODE_25GBASE_SR:
    case FM_ETH_MODE_AN_73:
    case FM_ETH_MODE_XAUI:
    case FM_ETH_MODE_10GBASE_KX4:
    case FM_ETH_MODE_10GBASE_CX4:
    case FM_ETH_MODE_24GBASE_KR4:
    case FM_ETH_MODE_24GBASE_CR4:
    case FM_ETH_MODE_XLAUI:
    case FM_ETH_MODE_40GBASE_SR4:
    case FM_ETH_MODE_100GBASE_SR4:
        return true;
    case FM_ETH_MODE_10GBASE_KR:
    case FM_ETH_MODE_25GBASE_KR:
    case FM_ETH_MODE_25GBASE_CR:
    case FM_ETH_MODE_40GBASE_KR4:
    case FM_ETH_MODE_40GBASE_CR4:
    case FM_ETH_MODE_100GBASE_CR4:
    case FM_ETH_MODE_100GBASE_KR4:
    default:
        return false;
    }
}

int hal_port_get_speed_mode(int sw, int port, int *speed,
                            int *ethernet_mode) {
    fm_uint32 sdk_speed = 0;
    fm_ethMode sdk_mode = FM_ETH_MODE_DISABLED;
    fm_status st;

    st = fmGetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_ETHERNET_INTERFACE_MODE, &sdk_mode);
    if (st != FM_OK) {
        NL_LOG_ERR("fmGetPortAttribute(ETHERNET_INTERFACE_MODE sw=%d port=%d): %s",
                   sw, port, fmErrorMsg(st));
        return -1;
    }
    st = fmGetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_SPEED, &sdk_speed);
    if (st != FM_OK) {
        NL_LOG_ERR("fmGetPortAttribute(SPEED sw=%d port=%d): %s",
                   sw, port, fmErrorMsg(st));
        return -1;
    }
    if (speed)
        *speed = (int)sdk_speed;
    if (ethernet_mode)
        *ethernet_mode = (int)sdk_mode;
    return 0;
}

int hal_port_set_ethernet_mode(int sw, int port, int ethernet_mode) {
    fm_ethMode sdk_mode = (fm_ethMode)ethernet_mode;
    int current_mode = -1;
    fm_status st;

    /* This board's PHY layout and FCI cache are owned by the EPL transaction. */
    if (fm10k_native_profile()) return -1;

    if (!hal_port_ethernet_mode_restorable(ethernet_mode))
        return -1;
    if (hal_port_get_speed_mode(sw, port, NULL, &current_mode) == 0 &&
        current_mode == ethernet_mode)
        return 0;

    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_ETHERNET_INTERFACE_MODE, &sdk_mode);
    if (st != FM_OK) {
        NL_LOG_ERR("fmSetPortAttribute(ETHERNET_INTERFACE_MODE sw=%d port=%d mode=%s): %s",
                   sw, port, hal_port_ethernet_mode_name(ethernet_mode),
                   fmErrorMsg(st));
        return -1;
    }
    NL_LOG_NOTICE("port %d: ethernet mode changed to %s without switch restart",
                  port, hal_port_ethernet_mode_name(ethernet_mode));
    return 0;
}

static int hal_port_speed_change_compensate(
    int sw, int port, int rollback_speed, int rollback_mode,
    const hal_port_admin_transaction_snapshot *admin_snapshot) {
    hal_port_admin_transaction_snapshot current;
    hal_port_admin_transaction_snapshot after;
    int speed = 0;
    int mode = 0;

    current = hal_port_admin_transaction_snapshot_get(sw, port);
    if (current.state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        !hal_port_admin_transaction_shape_equal(
            &current, admin_snapshot))
        return -1;
    if (current.admin_mode != FM_PORT_MODE_ADMIN_PWRDOWN &&
        hal_port_admin_transaction_quiesce(sw, port, &current) != 0)
        return -1;
    if (hal_port_set_ethernet_mode(sw, port, rollback_mode) != 0)
        return -1;
    if (hal_port_admin_transaction_restore(
            sw, port, admin_snapshot) != 0)
        return -1;

    after = hal_port_admin_transaction_snapshot_get(sw, port);
    if (!hal_port_admin_transaction_snapshot_equal(
            &after, admin_snapshot) ||
        hal_port_get_speed_mode(sw, port, &speed, &mode) != 0 ||
        speed != rollback_speed || mode != rollback_mode)
        return -1;
    return 0;
}

static int hal_port_speed_change_transaction(
    int sw, int port, int target_speed, int target_mode,
    int rollback_speed, int rollback_mode,
    const hal_port_admin_transaction_snapshot *admin_snapshot) {
    hal_port_admin_transaction_snapshot current;
    hal_port_admin_transaction_snapshot after;
    int speed = 0;
    int mode = 0;

    if (!admin_snapshot ||
        admin_snapshot->state != HAL_TRANSACTION_SNAPSHOT_PRESENT)
        return -1;
    current = hal_port_admin_transaction_snapshot_get(sw, port);
    if (!hal_port_admin_transaction_snapshot_equal(
            &current, admin_snapshot) ||
        hal_port_get_speed_mode(sw, port, &speed, &mode) != 0 ||
        speed != rollback_speed || mode != rollback_mode)
        return -1;
    if (speed == target_speed && mode == target_mode)
        return 0;

    if (current.admin_mode != FM_PORT_MODE_ADMIN_PWRDOWN &&
        hal_port_admin_transaction_quiesce(sw, port, &current) != 0)
        return -1;
    if (hal_port_set_ethernet_mode(sw, port, target_mode) != 0)
        goto compensate;
    if (hal_port_admin_transaction_restore(
            sw, port, admin_snapshot) != 0)
        goto compensate;

    after = hal_port_admin_transaction_snapshot_get(sw, port);
    if (hal_port_admin_transaction_snapshot_equal(
            &after, admin_snapshot) &&
        hal_port_get_speed_mode(sw, port, &speed, &mode) == 0 &&
        speed == target_speed && mode == target_mode) {
        NL_LOG_NOTICE(
            "port %d: transactional speed change completed at %d Mbps",
            port, target_speed);
        return 0;
    }

compensate:
    if (hal_port_speed_change_compensate(
            sw, port, rollback_speed, rollback_mode,
            admin_snapshot) != 0)
        NL_LOG_CRIT(
            "port %d: speed-change compensation failed; hardware OOS",
            port);
    return -1;
}

int hal_port_set_speed(int sw, int port, int speed) {
    int ethernet_mode = ethernet_mode_for_speed(speed);
    hal_port_admin_transaction_snapshot before;
    int before_speed = 0;
    int before_mode = 0;

    if (ethernet_mode < 0) {
        NL_LOG_ERR("port %d: unsupported runtime speed %d Mbps", port, speed);
        return -1;
    }
    before = hal_port_admin_transaction_snapshot_get(sw, port);
    if (before.state != HAL_TRANSACTION_SNAPSHOT_PRESENT ||
        hal_port_get_speed_mode(
            sw, port, &before_speed, &before_mode) != 0)
        return -1;
    return hal_port_speed_change_transaction(
        sw, port, speed, ethernet_mode,
        before_speed, before_mode, &before);
}

int hal_port_restore_speed(
    int sw, int port, int speed, int ethernet_mode,
    const hal_port_admin_transaction_snapshot *admin_snapshot) {
    int current_speed = 0;
    int current_mode = 0;

    if (!hal_port_ethernet_mode_restorable(ethernet_mode) ||
        hal_port_get_speed_mode(
            sw, port, &current_speed, &current_mode) != 0)
        return -1;
    return hal_port_speed_change_transaction(
        sw, port, speed, ethernet_mode,
        current_speed, current_mode, admin_snapshot);
}

int hal_port_mtu_to_max_frame(int mtu) {
    int max_frame = mtu + NETLAB_PORT_MTU_SDK_OVERHEAD;

    if (mtu <= 0)
        return 0;

    /*
     * FM10000 computes max-frame from destination MAC through FCS and rounds
     * to four-byte granularity. The CLI leaf is a Junos-style link MTU, so
     * keep the conversion in one place for apply and read-back verification.
     */
    return (max_frame + 3) & ~3;
}

int hal_port_max_frame_to_mtu(int max_frame) {
    if (max_frame <= NETLAB_PORT_MTU_SDK_OVERHEAD)
        return 0;
    return max_frame - NETLAB_PORT_MTU_SDK_OVERHEAD;
}

int hal_port_set_mtu(int sw, int port, int mtu) {
    fm_int max_frame = (fm_int)hal_port_mtu_to_max_frame(mtu);
    fm_status st;

    if (max_frame <= 0)
        return -1;

    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_MAX_FRAME_SIZE, &max_frame);
    if (st != FM_OK)
        NL_LOG_ERR("fmSetPortAttribute(MAX_FRAME_SIZE sw=%d port=%d mtu=%d max-frame=%d): %s",
                   sw, port, mtu, (int)max_frame, fmErrorMsg(st));
    return (st == FM_OK) ? 0 : -1;
}

int hal_port_get_mtu(int sw, int port, int *mtu, int *max_frame) {
    fm_int frame = 0;
    fm_status st = fmGetPortAttribute((fm_int)sw, (fm_int)port,
                                      FM_PORT_MAX_FRAME_SIZE, &frame);

    if (st != FM_OK)
        return -1;
    if (max_frame)
        *max_frame = (int)frame;
    if (mtu)
        *mtu = hal_port_max_frame_to_mtu((int)frame);
    return 0;
}

static fm_macaddr mac_bytes_to_fm(const u8 mac[6]) {
    return ((fm_macaddr)mac[0] << 40) |
           ((fm_macaddr)mac[1] << 32) |
           ((fm_macaddr)mac[2] << 24) |
           ((fm_macaddr)mac[3] << 16) |
           ((fm_macaddr)mac[4] << 8) |
           (fm_macaddr)mac[5];
}

static bool mac_address_type_is_static(fm_uint16 type) {
    return type == FM_ADDRESS_STATIC || type == FM_ADDRESS_SECURE_STATIC;
}

int hal_get_mac_table(int sw, struct sdk_result *result) {
    nl_mac_snapshot *snapshot;

    if (!result)
        return -1;
    snapshot = &result->data.mac_table;
    nl_mac_snapshot_reset(snapshot);

    for (int attempt = 0; attempt < 3; attempt++) {
        fm_macAddressEntry *sdk_entries = NULL;
        fm_int total = 0;
        fm_int received = 0;
        fm_status st;

        st = fmGetAddressTableExt((fm_int)sw, &total, NULL, 0);
        if (st != FM_OK)
            return (int)st;
        if (total < 0 || (u32)total > NL_MAC_SNAPSHOT_MAX_ENTRIES)
            return (int)FM_ERR_BUFFER_FULL;
        if (total == 0) {
            snapshot->complete = true;
            return 0;
        }
        sdk_entries = calloc((size_t)total, sizeof(*sdk_entries));
        if (!sdk_entries)
            return (int)FM_ERR_NO_MEM;
        st = fmGetAddressTableExt((fm_int)sw, &received, sdk_entries,
                                  total);
        if (st == FM_ERR_BUFFER_FULL || received > total) {
            free(sdk_entries);
            continue;
        }
        if (st != FM_OK || received < 0) {
            free(sdk_entries);
            return st != FM_OK ? (int)st : -1;
        }
        snapshot->entries = calloc((size_t)received,
                                   sizeof(*snapshot->entries));
        if (received > 0 && !snapshot->entries) {
            free(sdk_entries);
            return (int)FM_ERR_NO_MEM;
        }
        for (fm_int i = 0; i < received; i++) {
            nl_mac_snapshot_entry *entry = &snapshot->entries[i];
            fm_uint64 mac = (fm_uint64)sdk_entries[i].macAddress;
            fm_int lag_id = 0;

            if (sdk_entries[i].port <= 0 ||
                sdk_entries[i].port > UINT16_MAX) {
                free(sdk_entries);
                nl_mac_snapshot_reset(snapshot);
                return (int)FM_ERR_INVALID_PORT;
            }
            entry->vlan = (u16)sdk_entries[i].vlanID;
            entry->mac[0] = (u8)((mac >> 40) & 0xff);
            entry->mac[1] = (u8)((mac >> 32) & 0xff);
            entry->mac[2] = (u8)((mac >> 24) & 0xff);
            entry->mac[3] = (u8)((mac >> 16) & 0xff);
            entry->mac[4] = (u8)((mac >> 8) & 0xff);
            entry->mac[5] = (u8)(mac & 0xff);
            entry->port = (u16)sdk_entries[i].port;
            entry->ae_id = -1;
            if (fmLogicalPortToLAGNumber((fm_int)sw, sdk_entries[i].port,
                                         &lag_id) == FM_OK)
                entry->ae_id = hal_lag_ae_for_id((int)lag_id);
            entry->age = sdk_entries[i].age > 0 ?
                (u32)sdk_entries[i].age : 0;
            entry->is_static = mac_address_type_is_static(
                sdk_entries[i].type);
        }
        free(sdk_entries);
        snapshot->total_entries = (u32)received;
        snapshot->n_entries = (u32)received;
        snapshot->complete = true;
        return 0;
    }
    nl_mac_snapshot_reset(snapshot);
    return (int)FM_ERR_BUFFER_FULL;
}

int hal_mac_entry_get(int sw, u16 vid, const u8 mac[6],
                      int *port, bool *is_static) {
    bool present = false;
    int rc = hal_mac_entry_snapshot(
        sw, vid, mac, &present, port, is_static, NULL);

    return rc == 0 && present ? 0 : -1;
}

int hal_mac_entry_snapshot(int sw, u16 vid, const u8 mac[6],
                           bool *present, int *port, bool *is_static,
                           int *entry_type) {
    fm_macAddressEntry entry;
    fm_status st;

    if (!mac || !present || vid < 1 || vid > 4094)
        return -1;

    *present = false;
    if (port) *port = 0;
    if (is_static) *is_static = false;
    if (entry_type) *entry_type = -1;
    memset(&entry, 0, sizeof(entry));
    st = fmGetAddress((fm_int)sw, mac_bytes_to_fm(mac), (fm_int)vid, &entry);
    /* The pinned FM10000 lookup has one documented absence status. Other
     * failures cannot authorize deletion, compensation or a successful DEL. */
    if (st == FM_ERR_ADDR_NOT_FOUND)
        return 0;
    if (st == FM_ERR_INVALID_VLAN) {
        /* Replay after SDK restart may remove a static entry whose parent
         * VLAN is already absent. Prove that separately; INVALID_VLAN alone
         * is not an absence proof. This also preserves shared-FID semantics. */
        hal_presence_snapshot vlan = hal_vlan_presence_snapshot(sw, vid);
        if (vlan.state == HAL_PRESENCE_ABSENT) return 0;
    }
    if (st != FM_OK)
        return (int)st;
    if (entry.macAddress != mac_bytes_to_fm(mac) || entry.isTunnelEntry ||
        entry.port < 0 || entry.port > UINT16_MAX ||
        (entry.type != FM_ADDRESS_STATIC && entry.type != FM_ADDRESS_SECURE_STATIC &&
         entry.type != FM_ADDRESS_DYNAMIC && entry.type != FM_ADDRESS_SECURE_DYNAMIC))
        return FM_ERR_INVALID_STATE;

    *present = true;
    if (port)
        *port = (int)entry.port;
    if (is_static)
        *is_static = mac_address_type_is_static(entry.type);
    if (entry_type)
        *entry_type = (int)entry.type;
    return 0;
}

int hal_port_security_set(int sw, int port, bool enable, int action,
                          bool strict) {
    fm_uint32 sec_action = FM_PORT_SECURITY_ACTION_NONE;
    fm_macSecurityAction mac_action = FM_MAC_SECURITY_ACTION_DROP;
    fm_bool learning = enable ? FM_DISABLED : FM_ENABLED;
    fm_status st;

    if (port <= 0)
        return -1;

    if (enable) {
        sec_action = (fm_uint32)action;
        if (sec_action == FM_PORT_SECURITY_ACTION_DROP) {
            mac_action = FM_MAC_SECURITY_ACTION_DROP;
        } else if (sec_action == FM_PORT_SECURITY_ACTION_EVENT) {
            mac_action = FM_MAC_SECURITY_ACTION_EVENT;
        } else if (sec_action == FM_PORT_SECURITY_ACTION_TRAP) {
            mac_action = FM_MAC_SECURITY_ACTION_TRAP;
        } else {
            return -1;
        }
    }

    /*
     * FM10000 implements port security as security trigger programming
     * behind FM_PORT_SECURITY_ACTION.  The generic fmSetPortSecurity()
     * entrypoint exists in this SDK but returns unsupported for FM10000, so
     * the hardware-backed contract here is:
     *
     *   - set the unknown-SMAC action on the ingress port;
     *   - set the global secure-MAC move action;
     *   - freeze learning while enforcement is active so a new violator
     *     cannot become a normal dynamic entry after the first packet.
     */
    if (enable) {
        st = fmSetAddressTableAttribute((fm_int)sw,
                                        FM_MAC_TABLE_SECURITY_ACTION,
                                        &mac_action);
        if (st != FM_OK) {
            NL_LOG_ERR("MAC table security action=%u failed: %s",
                       (unsigned int)mac_action, fmErrorMsg(st));
            return (int)st;
        }
    }

    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_SECURITY_ACTION, &sec_action);
    if (st != FM_OK) {
        NL_LOG_ERR("port-security port=%d action=%u failed: %s",
                   port, sec_action, fmErrorMsg(st));
        return (int)st;
    }

    st = fmSetPortAttribute((fm_int)sw, (fm_int)port,
                            FM_PORT_LEARNING, &learning);
    if (st != FM_OK) {
        NL_LOG_ERR("port-security port=%d learning=%d failed: %s",
                   port, learning == FM_ENABLED ? 1 : 0, fmErrorMsg(st));
        return (int)st;
    }

    st = fmSetPortSecurity((fm_int)sw, (fm_int)port,
                           enable ? TRUE : FALSE,
                           strict ? TRUE : FALSE);
    if (st != FM_OK && st != FM_ERR_UNSUPPORTED) {
        NL_LOG_ERR("fmSetPortSecurity port=%d enable=%d strict=%d failed: %s",
                   port, enable ? 1 : 0, strict ? 1 : 0, fmErrorMsg(st));
        return (int)st;
    }
    if (st == FM_ERR_UNSUPPORTED) {
        NL_LOG_INFO("fmSetPortSecurity port=%d unsupported on this SDK/chip; using FM10000 trigger path",
                    port);
    }

    NL_LOG_INFO("port-security port=%d enable=%d strict=%d action=%u learning=%d",
                port, enable ? 1 : 0, strict ? 1 : 0, sec_action,
                learning == FM_ENABLED ? 1 : 0);
    return 0;
}

int hal_static_mac_add(int sw, u16 vid, const u8 mac[6], int port) {
    fm_macAddressEntry entry;
    fm_status st;

    if (!mac || vid < 1 || vid > 4094 || port <= 0)
        return -1;

    memset(&entry, 0, sizeof(entry));
    entry.macAddress = mac_bytes_to_fm(mac);
    entry.vlanID = (fm_uint16)vid;
    entry.type = FM_ADDRESS_STATIC;
    entry.destMask = FM_DESTMASK_UNUSED;
    entry.port = (fm_int)port;

    st = fmAddAddress((fm_int)sw, &entry);
    if (st != FM_OK) {
        NL_LOG_ERR("fmAddAddress(sw=%d, vid=%u, port=%d): %s",
                   sw, vid, port, fmErrorMsg(st));
        return -1;
    }

    NL_LOG_NOTICE("static MAC added vid=%u port=%d", vid, port);
    return 0;
}

int hal_static_mac_delete(int sw, u16 vid, const u8 mac[6]) {
    fm_macAddressEntry entry;
    fm_status st;
    bool present = false, is_static = false;
    int entry_type = -1;

    if (!mac || vid < 1 || vid > 4094)
        return -1;

    int read_status = hal_mac_entry_snapshot(sw, vid, mac, &present, NULL,
                                             &is_static, &entry_type);
    if (read_status != 0) return read_status;
    /* A learned replacement is not owned by the static configuration. */
    if (!present || !is_static) return 0;

    memset(&entry, 0, sizeof(entry));
    entry.macAddress = mac_bytes_to_fm(mac);
    entry.vlanID = (fm_uint16)vid;
    entry.type = (fm_uint16)entry_type;
    entry.destMask = FM_DESTMASK_UNUSED;

    st = fmDeleteAddress((fm_int)sw, &entry);
    read_status = hal_mac_entry_snapshot(sw, vid, mac, &present, NULL,
                                          &is_static, NULL);
    if (read_status != 0) {
        NL_LOG_ERR("static MAC delete read-back failed sw=%d vid=%u: %s",
                   sw, vid, fmErrorMsg(read_status));
        return read_status;
    }
    if (present && is_static) return st != FM_OK ? (int)st : FM_ERR_INVALID_STATE;

    NL_LOG_NOTICE("static MAC deleted vid=%u", vid);
    return 0;
}

int hal_clear_dynamic_mac_table(int sw, int port, int vid) {
    fm_flushParams params;
    fm_flushMode mode;
    fm_status st;

    memset(&params, 0, sizeof(params));
    params.statics = FALSE;

    if (port > 0 && vid > 0) {
        mode = FM_FLUSH_MODE_PORT_VLAN;
        params.port = (fm_uint)port;
        params.vid1 = (fm_uint16)vid;
    } else if (port > 0) {
        mode = FM_FLUSH_MODE_PORT;
        params.port = (fm_uint)port;
    } else if (vid > 0) {
        mode = FM_FLUSH_MODE_VLAN;
        params.vid1 = (fm_uint16)vid;
    } else {
        st = fmDeleteAllDynamicAddresses((fm_int)sw);
        if (st != FM_OK) {
            NL_LOG_ERR("fmDeleteAllDynamicAddresses(sw=%d): %s",
                       sw, fmErrorMsg(st));
            return -1;
        }

        NL_LOG_NOTICE("dynamic MAC address table cleared");
        return 0;
    }

    st = fmFlushAddresses((fm_int)sw, mode, params);
    if (st != FM_OK) {
        NL_LOG_ERR("fmFlushAddresses(sw=%d, port=%d, vid=%d): %s",
                   sw, port, vid, fmErrorMsg(st));
        return -1;
    }

    NL_LOG_NOTICE("dynamic MAC address table cleared port=%d vid=%d",
                  port, vid);
    return 0;
}

int hal_mac_aging_set(int sw, int seconds) {
    fm_int aging = (fm_int)seconds;
    fm_status st;

    if (seconds < 0 || seconds > 1000000)
        return -1;

    st = fmSetAddressTableAttribute((fm_int)sw,
                                    FM_MAC_TABLE_ADDRESS_AGING_TIME,
                                    &aging);
    if (st != FM_OK) {
        NL_LOG_ERR("fmSetAddressTableAttribute(MAC aging=%d): %s",
                   seconds, fmErrorMsg(st));
        return -1;
    }

    NL_LOG_NOTICE("dynamic MAC aging time set to %d seconds", seconds);
    return 0;
}

int hal_mac_aging_get(int sw, int *seconds) {
    fm_int aging = 0;
    fm_status st;

    if (!seconds)
        return -1;

    st = fmGetAddressTableAttribute((fm_int)sw,
                                    FM_MAC_TABLE_ADDRESS_AGING_TIME,
                                    &aging);
    if (st != FM_OK) {
        NL_LOG_ERR("fmGetAddressTableAttribute(MAC aging): %s",
                   fmErrorMsg(st));
        return -1;
    }

    *seconds = (int)aging;
    return 0;
}
