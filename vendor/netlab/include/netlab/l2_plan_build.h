#ifndef NETLAB_L2_PLAN_BUILD_H
#define NETLAB_L2_PLAN_BUILD_H

#include "types.h"

#include <stdbool.h>
#include <stddef.h>

#define NL_L2_PLAN_BUILD_MAGIC 0x4e4c5042U
#define NL_L2_PLAN_BUILD_VERSION 1U
#define NL_L2_PLAN_BUILD_TOKEN_BYTES 16U
#define NL_L2_PLAN_CONFIG_MAX_BYTES (8U * 1024U * 1024U)
#define NL_L2_PLAN_BUILD_PART_HEADER_BYTES 40U

typedef enum {
    NL_L2_PLAN_BUILD_ACTIVE = 1,
    NL_L2_PLAN_BUILD_CANDIDATE = 2,
} nl_l2_plan_build_stream;

typedef struct {
    u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES];
    u32 active_length;
    u32 candidate_length;
    bool require_hardware;
} nl_l2_plan_build_begin;

typedef struct {
    u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES];
    nl_l2_plan_build_stream stream;
    u32 offset;
    u32 total_length;
} nl_l2_plan_build_part;

int nl_l2_plan_build_begin_encode(const nl_l2_plan_build_begin *begin,
                                  void *buffer, size_t capacity);
int nl_l2_plan_build_begin_decode(const void *buffer, size_t length,
                                  nl_l2_plan_build_begin *begin);
int nl_l2_plan_build_part_encode(const nl_l2_plan_build_part *part,
                                 const void *data, size_t data_length,
                                 void *buffer, size_t capacity);
int nl_l2_plan_build_part_decode(const void *buffer, size_t length,
                                 nl_l2_plan_build_part *part,
                                 const u8 **data, size_t *data_length);
int nl_l2_plan_build_token_encode(
    const u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES],
    void *buffer, size_t capacity);
int nl_l2_plan_build_token_decode(
    const void *buffer, size_t length,
    u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES]);

#endif
