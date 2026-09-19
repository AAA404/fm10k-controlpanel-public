/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_CONFIGD_L3_CLIENT_H
#define NETLAB_CONFIGD_L3_CLIENT_H

#include "netlab/l3_plan.h"
#include "netlab/yang_config.h"
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    CONFIGD_L3_APPLY_FAILURE_UNKNOWN = 0,
    CONFIGD_L3_APPLY_FAILURE_NO_MUTATION,
    CONFIGD_L3_APPLY_FAILURE_RESTORED
} configd_l3_apply_failure_evidence;

int configd_l3_build_plan(nl_yang_session *active,
                          nl_yang_session *candidate,
                          char *plan, size_t plan_size,
                          int *plan_len, bool *has_l3,
                          char *err, size_t err_size);

int configd_l3_validate_plan(const char *plan, int plan_len, bool has_l3,
                             char *err, size_t err_size);
bool configd_l3_public_apply_enabled(void);
bool configd_l3_full_replay_required(bool has_l3);
const char *configd_l3_public_apply_gate_reason(void);
int configd_l3_apply_plan(const char *plan, int plan_len, bool has_l3,
                          unsigned long long tx_id, char *resp,
                          size_t resp_size, int *daemon_ec);
int configd_l3_verify_readback(const char *plan, int plan_len, bool has_l3,
                               char *resp, size_t resp_size,
                               int *daemon_ec);
int configd_l3_rollback(unsigned long long tx_id, char *resp,
                        size_t resp_size, int *daemon_ec);
configd_l3_apply_failure_evidence configd_l3_apply_failure_classify(
    unsigned long long tx_id, int rpc_result, int daemon_ec,
    const char *resp);
bool configd_l3_rollback_verified(unsigned long long tx_id,
                                  int rpc_result, int daemon_ec,
                                  const char *resp);

#endif
