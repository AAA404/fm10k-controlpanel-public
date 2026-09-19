#ifndef SWITCHD_HAL_SDK_RUNTIME_H
#define SWITCHD_HAL_SDK_RUNTIME_H

#include "netlab/hal.h"
#include <stddef.h>

int hal_sdk_runtime_format(struct sdk_context *ctx,
                           char *resp, size_t resp_size);

#endif
