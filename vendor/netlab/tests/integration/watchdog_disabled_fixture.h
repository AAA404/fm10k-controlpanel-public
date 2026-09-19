#ifndef WATCHDOG_DISABLED_FIXTURE_H
#define WATCHDOG_DISABLED_FIXTURE_H
/* Unrelated HAL/queue fixtures have no enabled watchdog. The production
 * adapter and its failures are exercised in native_pfc_watchdog_sdk_test.c. */
#include "../../sbin/switchd/hal_pfc_watchdog.h"
#include <string.h>
static int watchdog_quiesce_error;
static unsigned watchdog_quiesce_calls;
int hal_pfc_watchdog_quiesce(int sw) {
    (void)sw; ++watchdog_quiesce_calls; return watchdog_quiesce_error;
}
bool hal_pfc_watchdog_enabled(void) { return false; }
void hal_pfc_watchdog_poll(int sw, uint64_t now_ms) { (void)sw; (void)now_ms; }
int hal_pfc_watchdog_configure(int sw, int port, const fm10k_pfc_wd_policy *policy) {
    (void)sw; (void)port; return policy && !policy->detect_ms ? 0 : -1;
}
void hal_pfc_watchdog_get(int sw, int port, hal_pfc_wd_status *out) {
    (void)sw; (void)port;
    memset(out, 0, sizeof(*out));
    out->policy = fm10k_pfc_wd_default_policy();
    out->saved_rx_mask = out->sample_status = -1;
}
#endif
