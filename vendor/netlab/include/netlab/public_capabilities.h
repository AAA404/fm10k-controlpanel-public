#ifndef NETLAB_PUBLIC_CAPABILITIES_H
#define NETLAB_PUBLIC_CAPABILITIES_H

/*
 * Immutable public configuration authority.
 *
 * These bits are deliberately compile-time and release-manifest owned.  The
 * CLI reads this same header, while configd compiles it into the commit and
 * replay boundary.  Promotion therefore changes one sealed authority instead
 * of independently opening presentation and backend paths.
 */
#define NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT 0
#define NETLAB_PUBLIC_MANAGEMENT_SERVICES 0

#if (NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT != 0 && \
     NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT != 1)
#error "NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT must be 0 or 1"
#endif

#if (NETLAB_PUBLIC_MANAGEMENT_SERVICES != 0 && \
     NETLAB_PUBLIC_MANAGEMENT_SERVICES != 1)
#error "NETLAB_PUBLIC_MANAGEMENT_SERVICES must be 0 or 1"
#endif

#endif
