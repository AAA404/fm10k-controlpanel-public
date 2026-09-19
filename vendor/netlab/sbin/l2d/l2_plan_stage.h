#ifndef NETLAB_L2D_L2_PLAN_STAGE_H
#define NETLAB_L2D_L2_PLAN_STAGE_H

#include "netlab/l2_plan_build.h"

#include <pthread.h>

#define L2_PLAN_BUILD_STAGE_TTL_SECONDS 30U

typedef struct {
    pthread_mutex_t lock;
    bool initialized;
    bool active;
    u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES];
    char *active_xml;
    char *candidate_xml;
    u32 active_length;
    u32 candidate_length;
    u32 active_received;
    u32 candidate_received;
    bool require_hardware;
    u64 started_seconds;
} l2_plan_stage;

int l2_plan_stage_init(l2_plan_stage *stage);
void l2_plan_stage_destroy(l2_plan_stage *stage);
int l2_plan_stage_begin(l2_plan_stage *stage,
                        const nl_l2_plan_build_begin *begin,
                        u64 now_seconds);
int l2_plan_stage_append(l2_plan_stage *stage,
                         const nl_l2_plan_build_part *part,
                         const u8 *data, size_t data_length,
                         u64 now_seconds);
int l2_plan_stage_take(l2_plan_stage *stage,
                       const u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES],
                       u64 now_seconds, char **active_xml,
                       char **candidate_xml, bool *require_hardware);
int l2_plan_stage_abort(l2_plan_stage *stage,
                        const u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES],
                        u64 now_seconds);
bool l2_plan_stage_expire(l2_plan_stage *stage, u64 now_seconds);

#endif
