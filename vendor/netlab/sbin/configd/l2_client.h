#ifndef NETLAB_CONFIGD_L2_CLIENT_H
#define NETLAB_CONFIGD_L2_CLIENT_H

#include "netlab/yang_config.h"
#include <stdbool.h>
#include <stddef.h>

int configd_l2_build_plan(nl_yang_session *active,
                          nl_yang_session *candidate,
                          bool require_hw,
                          char *plan, size_t plan_size,
                          int *plan_len, bool *has_l2,
                          char *err, size_t err_size);

int configd_l2_validate_plan(const char *plan, int plan_len, bool has_l2,
                             char *err, size_t err_size);
void configd_l2_refresh_cache(void);

#endif
