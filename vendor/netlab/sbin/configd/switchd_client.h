#ifndef NETLAB_CONFIGD_SWITCHD_CLIENT_H
#define NETLAB_CONFIGD_SWITCHD_CLIENT_H

#include "netlab/error.h"
#include "netlab/types.h"
#include <stdbool.h>
#include <stddef.h>

bool configd_switchd_pfe_up(char *detail, size_t detail_size);
nl_error_code configd_switchd_commit_pfe_check(bool *switchd_available,
                                               char *detail,
                                               size_t detail_size);
int configd_switchd_apply_l2_plan(u64 tx_id, const char *plan, int plan_len,
                                  char *resp, size_t resp_size,
                                  s32 *error_code);
int configd_switchd_rollback_l2_plan(u64 tx_id, char *resp,
                                     size_t resp_size, s32 *error_code);
bool configd_switchd_l2_rollback_verified(u64 tx_id, int rpc_result,
                                          s32 error_code,
                                          const char *resp);
int configd_switchd_mark_success(u64 tx_id, char *resp, size_t resp_size,
                                 s32 *error_code);
int configd_switchd_mark_failed(u64 tx_id, char *resp, size_t resp_size,
                                s32 *error_code);

#endif
