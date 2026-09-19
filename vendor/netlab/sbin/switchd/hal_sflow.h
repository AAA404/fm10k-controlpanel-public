#ifndef SWITCHD_HAL_SFLOW_H
#define SWITCHD_HAL_SFLOW_H

#include "netlab/sflow.h"
#include <stdbool.h>
#include <stddef.h>

int hal_sflow_state_get(int sw, nl_sflow_hw_state_v1 *state);
int hal_sflow_live_probe(int sw, int port, bool acknowledged, u64 tx_id,
                         char *response, size_t response_size);

#endif
