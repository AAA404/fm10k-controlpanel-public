#ifndef NETLAB_HAL_PFC_WATCHDOG_H
#define NETLAB_HAL_PFC_WATCHDOG_H

#include "netlab/pfc_watchdog.h"

/* All calls, including readback, run exclusively on the existing SDK owner. */
int hal_pfc_watchdog_configure(int sw, int port, const fm10k_pfc_wd_policy *policy);
void hal_pfc_watchdog_get(int sw, int port, hal_pfc_wd_status *status);
void hal_pfc_watchdog_poll(int sw, uint64_t now_ms);
bool hal_pfc_watchdog_enabled(void);
/* Restore every temporary mask before configuration captures its pre-state,
 * before port maintenance, and before the owner shuts down. */
int hal_pfc_watchdog_quiesce(int sw);
/* Read actual CM_PAUSE_CFG, not the SDK's rxClassPause cache. */
int hal_pfc_watchdog_rx_mask(int sw, int port, int *physical, int *mask);

#endif
