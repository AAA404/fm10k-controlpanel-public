/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_HAL_PORT_XCVR_SDK_ADAPTER_H
#define NETLAB_HAL_PORT_XCVR_SDK_ADAPTER_H

#include <stdbool.h>
#include <fm_sdk.h>
#include "fm10k_board.h"

/*
 * This adapter is intentionally pinned to the LibertyTrail SDK ABI.  It is
 * the port-specific switchd code allowed to couple a logical port transaction to the
 * SDK's private platform topology, loaded function table, I2C exclusion,
 * and fmRootPlatform transceiver cache.
 */
#define NETLAB_PORT_XCVR_QSFP_LANES 4
#define NETLAB_PORT_XCVR_TX_DISABLE_OFFSET 86
#define NETLAB_PORT_XCVR_TX_DISABLE_MASK 0x0fU

typedef struct {
    fm_uint64 topology_fingerprint;
    fm_uint32 module_hw_resource_id;
    fm_int module_owner_port;
    fm_byte lane_mask;
    fm_bool present;
    fm_bool tx_disable_valid;
    fm_byte tx_disable_byte;
} netlab_port_xcvr_sdk_snapshot;

typedef struct {
    fm_status status;
    fm_bool write_attempted;
    fm_bool readback_completed;
    fm_byte readback_byte;
} netlab_port_xcvr_sdk_cas_result;

/*
 * Read the authoritative module presence and, when present, the complete
 * QSFP lower-page byte 86.  A successful byte read also reconciles all four
 * lane disabled-cache projections without writing the module.
 * For sil001-hw4-b0, this is a normalized EPL disable nibble derived from
 * FCI's 12-bit enable mask. The fixed resource group identifies its MPO and
 * shift; SDK caches are updated under the same shared bus lease.
 */
fm_status netlab_port_xcvr_sdk_snapshot_get(
    fm_int sw, fm_int port, netlab_port_xcvr_sdk_snapshot *snapshot);

/*
 * Compare the complete byte 86 against expected->tx_disable_byte and replace
 * only the lane bits owned by expected->lane_mask.  desired_byte must already
 * preserve every unowned bit.  write_attempted becomes true immediately
 * before dispatching the non-idempotent I2C write and remains true regardless
 * of its return status, read-back status, or lock-release status.  The caller
 * must then authoritatively classify the live byte as before, attempted, or
 * unknown/third before deciding whether compensation is safe.
 * The FCI implementation compares this EPL's nibble, preserves the other
 * EPLs and reserved bits during 56/57 RMW, and performs bounded retries.
 */
fm_status netlab_port_xcvr_sdk_tx_disable_cas(
    fm_int sw, fm_int port,
    const netlab_port_xcvr_sdk_snapshot *expected,
    fm_byte desired_byte,
    netlab_port_xcvr_sdk_cas_result *result);

typedef struct {
    void *context;
    /* These hooks must acknowledge the target group's protocol lease.
     * The caller must not perform blocking daemon RPC on the SDK thread. */
    int (*quiesce)(void *, int epl, bool paused);
    void (*degraded)(void *, int epl);
} netlab_fm10k_group_control;

int netlab_fm10k_group_sdk_get(int sw, int epl, fm10k_group *out);
int netlab_fm10k_bootstrap_closed(int sw);
int netlab_fm10k_group_sdk_apply(int sw, const fm10k_group *target,
                                 const fm10k_group *expected,
                                 const netlab_fm10k_group_control *control);

#endif
