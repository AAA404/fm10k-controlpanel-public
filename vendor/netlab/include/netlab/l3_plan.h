#ifndef NETLAB_L3_PLAN_H
#define NETLAB_L3_PLAN_H

#include "netlab/ipc.h"

/* Leave transport headroom inside the authenticated 256 KiB IPC envelope. */
#define NL_L3_PLAN_MAX_BYTES (240U * 1024U)
#define NL_L3_PLAN_ERROR_BYTES 512U

#if NL_L3_PLAN_MAX_BYTES > NETLAB_CONFIG_XML_MAX
#error "L3 plan capacity must fit inside the bounded IPC payload"
#endif

#endif
