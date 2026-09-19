#ifndef NETLAB_TYPES_H
#define NETLAB_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

typedef enum { NL_OK = 0, NL_ERR = -1, NL_ERR_HW_OUT_OF_SYNC = -2 } nl_status;

#define NL_INET6_ADDRSTRLEN 46
#define NL_MAC_ADDR_LEN      6
#define NL_MAX_IFNAME       64
#define NL_MAX_PORTS       256

#endif
