#ifndef CONFIGD_NATIVE_RUNTIME_H
#define CONFIGD_NATIVE_RUNTIME_H
#include "netlab/types.h"
#include <stdbool.h>
bool configd_native_control_mode(void);
int configd_native_status(const char *profile, u64 *generation, bool *bound);
int configd_native_bind(const char *profile, u64 generation, u64 commit);
#endif
