#ifndef NETLAB_L3_CAPACITY_H
#define NETLAB_L3_CAPACITY_H

/*
 * Public IPv4 L3 V1 capacity contract.  Every producer, parser, owner and
 * test must use these values so a configuration accepted at the northbound
 * boundary cannot be silently rejected by a smaller downstream owner.
 */
#define NL_L3_PERSISTENT_MAX_RIFS 64
#define NL_L3_PERSISTENT_MAX_ARP 256
#define NL_L3_PERSISTENT_MAX_NEXTHOPS 256
#define NL_L3_PERSISTENT_MAX_ECMP 128
#define NL_L3_PERSISTENT_MAX_ECMP_MEMBERS 32
#define NL_L3_PERSISTENT_MAX_ROUTES 1024

#define NL_L3_DYNAMIC_MAX_ROUTES 4096
#define NL_L3_DYNAMIC_MAX_NEXTHOPS 16
/* Hardware-live dynamic routes may share at most this many unique NH owners. */
#define NL_L3_DYNAMIC_MAX_UNIQUE_NEXTHOPS \
    NL_L3_PERSISTENT_MAX_NEXTHOPS

#endif
