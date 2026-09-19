#include "l2_plan_stage.h"

#include "netlab/error.h"

#include <stdlib.h>
#include <string.h>

static void reset_locked(l2_plan_stage *stage) {
    free(stage->active_xml);
    free(stage->candidate_xml);
    stage->active_xml = NULL;
    stage->candidate_xml = NULL;
    stage->active = false;
    memset(stage->token, 0, sizeof(stage->token));
    stage->active_length = 0;
    stage->candidate_length = 0;
    stage->active_received = 0;
    stage->candidate_received = 0;
    stage->require_hardware = false;
    stage->started_seconds = 0;
}

static void expire_locked(l2_plan_stage *stage, u64 now_seconds) {
    if (stage->active && now_seconds > 0 &&
        stage->started_seconds > 0 &&
        now_seconds >= stage->started_seconds &&
        now_seconds - stage->started_seconds >=
            L2_PLAN_BUILD_STAGE_TTL_SECONDS)
        reset_locked(stage);
}

static bool token_equal(
    const u8 left[NL_L2_PLAN_BUILD_TOKEN_BYTES],
    const u8 right[NL_L2_PLAN_BUILD_TOKEN_BYTES]) {
    return left && right &&
        memcmp(left, right, NL_L2_PLAN_BUILD_TOKEN_BYTES) == 0;
}

static bool token_nonzero(
    const u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES]) {
    u8 accumulator = 0;

    if (!token)
        return false;
    for (size_t i = 0; i < NL_L2_PLAN_BUILD_TOKEN_BYTES; i++)
        accumulator |= token[i];
    return accumulator != 0;
}

int l2_plan_stage_init(l2_plan_stage *stage) {
    if (!stage)
        return NL_ERR_INVALID_VALUE;
    memset(stage, 0, sizeof(*stage));
    if (pthread_mutex_init(&stage->lock, NULL) != 0)
        return NL_ERR;
    stage->initialized = true;
    return NL_OK;
}

void l2_plan_stage_destroy(l2_plan_stage *stage) {
    if (!stage || !stage->initialized)
        return;
    pthread_mutex_lock(&stage->lock);
    reset_locked(stage);
    pthread_mutex_unlock(&stage->lock);
    pthread_mutex_destroy(&stage->lock);
    memset(stage, 0, sizeof(*stage));
}

int l2_plan_stage_begin(l2_plan_stage *stage,
                        const nl_l2_plan_build_begin *begin,
                        u64 now_seconds) {
    char *active_xml;
    char *candidate_xml;
    int status = NL_OK;

    if (!stage || !stage->initialized || !begin ||
        !token_nonzero(begin->token) ||
        begin->active_length == 0 || begin->candidate_length == 0 ||
        begin->active_length > NL_L2_PLAN_CONFIG_MAX_BYTES ||
        begin->candidate_length > NL_L2_PLAN_CONFIG_MAX_BYTES)
        return NL_ERR_INVALID_VALUE;
    active_xml = calloc((size_t)begin->active_length + 1U, 1);
    candidate_xml = calloc((size_t)begin->candidate_length + 1U, 1);
    if (!active_xml || !candidate_xml) {
        free(active_xml);
        free(candidate_xml);
        return NL_ERR;
    }
    pthread_mutex_lock(&stage->lock);
    expire_locked(stage, now_seconds);
    if (stage->active) {
        status = NL_ERR_RPC_BUSY;
    } else {
        stage->active = true;
        memcpy(stage->token, begin->token, sizeof(stage->token));
        stage->active_xml = active_xml;
        stage->candidate_xml = candidate_xml;
        stage->active_length = begin->active_length;
        stage->candidate_length = begin->candidate_length;
        stage->require_hardware = begin->require_hardware;
        stage->started_seconds = now_seconds;
        active_xml = NULL;
        candidate_xml = NULL;
    }
    pthread_mutex_unlock(&stage->lock);
    free(active_xml);
    free(candidate_xml);
    return status;
}

int l2_plan_stage_append(l2_plan_stage *stage,
                         const nl_l2_plan_build_part *part,
                         const u8 *data, size_t data_length,
                         u64 now_seconds) {
    char *target;
    u32 *received;
    u32 expected_length;
    int status = NL_OK;

    if (!stage || !stage->initialized || !part || !data ||
        data_length == 0 || data_length > UINT32_MAX ||
        memchr(data, '\0', data_length) != NULL)
        return NL_ERR_INVALID_VALUE;
    pthread_mutex_lock(&stage->lock);
    expire_locked(stage, now_seconds);
    if (!stage->active || !token_equal(stage->token, part->token)) {
        status = NL_ERR_INVALID_VALUE;
        goto out;
    }
    if (part->stream == NL_L2_PLAN_BUILD_ACTIVE) {
        target = stage->active_xml;
        received = &stage->active_received;
        expected_length = stage->active_length;
    } else if (part->stream == NL_L2_PLAN_BUILD_CANDIDATE) {
        target = stage->candidate_xml;
        received = &stage->candidate_received;
        expected_length = stage->candidate_length;
    } else {
        reset_locked(stage);
        status = NL_ERR_INVALID_VALUE;
        goto out;
    }
    if (!target || part->total_length != expected_length ||
        *received > expected_length || part->offset != *received ||
        data_length > expected_length - *received) {
        reset_locked(stage);
        status = NL_ERR_INVALID_VALUE;
        goto out;
    }
    memcpy(target + *received, data, data_length);
    *received += (u32)data_length;

out:
    pthread_mutex_unlock(&stage->lock);
    return status;
}

int l2_plan_stage_take(l2_plan_stage *stage,
                       const u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES],
                       u64 now_seconds, char **active_xml,
                       char **candidate_xml, bool *require_hardware) {
    int status = NL_OK;

    if (!stage || !stage->initialized || !token || !active_xml ||
        !candidate_xml || !require_hardware)
        return NL_ERR_INVALID_VALUE;
    *active_xml = NULL;
    *candidate_xml = NULL;
    *require_hardware = false;
    pthread_mutex_lock(&stage->lock);
    expire_locked(stage, now_seconds);
    if (!stage->active || !token_equal(stage->token, token)) {
        status = NL_ERR_INVALID_VALUE;
    } else if (stage->active_received != stage->active_length ||
               stage->candidate_received != stage->candidate_length) {
        reset_locked(stage);
        status = NL_ERR_INVALID_VALUE;
    } else {
        *active_xml = stage->active_xml;
        *candidate_xml = stage->candidate_xml;
        *require_hardware = stage->require_hardware;
        stage->active_xml = NULL;
        stage->candidate_xml = NULL;
        reset_locked(stage);
    }
    pthread_mutex_unlock(&stage->lock);
    return status;
}

int l2_plan_stage_abort(l2_plan_stage *stage,
                        const u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES],
                        u64 now_seconds) {
    int status = NL_OK;

    if (!stage || !stage->initialized || !token)
        return NL_ERR_INVALID_VALUE;
    pthread_mutex_lock(&stage->lock);
    expire_locked(stage, now_seconds);
    if (!stage->active || !token_equal(stage->token, token))
        status = NL_ERR_INVALID_VALUE;
    else
        reset_locked(stage);
    pthread_mutex_unlock(&stage->lock);
    return status;
}

bool l2_plan_stage_expire(l2_plan_stage *stage, u64 now_seconds) {
    bool expired;

    if (!stage || !stage->initialized || now_seconds == 0)
        return false;
    pthread_mutex_lock(&stage->lock);
    expired = stage->active && stage->started_seconds > 0 &&
        now_seconds >= stage->started_seconds &&
        now_seconds - stage->started_seconds >=
            L2_PLAN_BUILD_STAGE_TTL_SECONDS;
    if (expired)
        reset_locked(stage);
    pthread_mutex_unlock(&stage->lock);
    return expired;
}
