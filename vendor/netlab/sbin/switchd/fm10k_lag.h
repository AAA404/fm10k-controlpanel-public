#ifndef NETLAB_FM10K_LAG_H
#define NETLAB_FM10K_LAG_H

#include <stdbool.h>
#include <stdint.h>
#include "netlab/hal_fm10k.h"
#include "netlab/hal_qos.h"
#include "netlab/hal_transaction_snapshot.h"

/* Called only by the SDK owner. The native startup/replay gate is separate.
 * A member's detached image belongs to this SDK lifetime, not to lacpd. */
int hal_fm10k_lag_member_set(int sw, int lag_id, int port, bool attached);
int hal_fm10k_lag_members_status(int lag_id, const int *members, int count);
int hal_fm10k_lag_restore_port(int sw, int lag_id, int port, uint64_t tx_id);
int hal_fm10k_lag_del_port_transaction(int sw, int lag_id, int port, uint64_t tx_id);
int hal_fm10k_lag_transaction_check(uint64_t tx_id, bool committed);
void hal_fm10k_lag_transaction_retire(uint64_t tx_id);
int hal_fm10k_lag_attributes_capture(int sw, int lag_id, fm10k_lag_attributes *out);
int hal_fm10k_lag_attributes_restore(int sw, int lag_id, const fm10k_lag_attributes *before);
hal_qos_interface_transaction_snapshot hal_fm10k_lag_qos_snapshot(int sw, int lag_id);
int hal_fm10k_lag_qos_restore(int sw, int lag_id, const hal_qos_interface_transaction_snapshot *before);
int hal_fm10k_lag_qos_set(int sw, int lag_id, int trust, int priority);
int hal_fm10k_lag_qos_get(int sw, int lag_id, hal_qos_interface_entry *out);

#endif
