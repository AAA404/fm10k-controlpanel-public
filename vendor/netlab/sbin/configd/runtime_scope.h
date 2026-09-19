#ifndef NETLAB_CONFIGD_RUNTIME_SCOPE_H
#define NETLAB_CONFIGD_RUNTIME_SCOPE_H
#include "netlab/types.h"
#include <stddef.h>
int configd_scope_begin(u64 tx, const char *plan, size_t size, char *error, size_t error_size);
int configd_scope_finish(u64 tx, bool committed, char *error, size_t error_size);
bool configd_scope_was_not_dispatched(u64 tx);
bool configd_scope_engaged(void);
bool configd_scope_peers_available(void);
#endif
