/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_CONFIGD_RUNTIME_CLIENT_H
#define NETLAB_CONFIGD_RUNTIME_CLIENT_H

#include <stdbool.h>
void configd_runtime_notify_reload(void);
bool configd_runtime_reload_checked(void);

#endif
