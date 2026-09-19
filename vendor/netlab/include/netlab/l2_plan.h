/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_L2_PLAN_H
#define NETLAB_L2_PLAN_H

#include "netlab/types.h"
#include <stddef.h>

/* The HAL and packet-only daemons need the plan contract, not libyang's
 * headers or ABI. Configuration consumers include yang_config.h explicitly. */
struct nl_yang_session;

#define NL_L2_PLAN_MAX_BYTES (240 * 1024)
#define NL_L2_PLAN_ERROR_BYTES 512
#define NL_L2_PLAN_MAX_STEPS 8192
#define NL_PORT_SPEED_10G_MBPS 10000
#define NL_PORT_SPEED_25G_MBPS 25000

int nl_l2_build_plan(struct nl_yang_session *active,
                     struct nl_yang_session *candidate,
                     bool require_hw,
                     char *plan, size_t plan_size, int *plan_len,
                     bool *has_l2,
                     char *err, size_t err_size);

#endif
