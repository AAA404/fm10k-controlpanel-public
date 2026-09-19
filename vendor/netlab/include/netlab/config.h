#ifndef NETLAB_CONFIG_H
#define NETLAB_CONFIG_H

/*
 * Historical config-tree helpers were removed after configd moved to the
 * libyang-backed candidate/active model. Keep only shared config constants
 * here; new callers should use netlab/yang_config.h.
 */
#define NL_CONFIG_MAX_ROLLBACK 50

#endif
