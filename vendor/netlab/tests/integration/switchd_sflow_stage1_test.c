#include <stdio.h>
#include <string.h>

#include "../../sbin/switchd/sflow_capture.h"

static fm_status g_free_result = FM_OK;
static unsigned int g_free_calls;
static int g_free_sw = -1;
static fm_buffer *g_free_chain;

fm_status fmFreeBufferChain(int sw, fm_buffer *buf_chain)
{
    g_free_calls++;
    g_free_sw = sw;
    g_free_chain = buf_chain;
    return g_free_result;
}

#include "../../sbin/switchd/sflow_capture.c"

static int expect_u64(const char *name, u64 actual, u64 expected)
{
    if (actual == expected)
        return 0;
    fprintf(stderr, "%s: got %llu, expected %llu\n", name,
            (unsigned long long)actual, (unsigned long long)expected);
    return 1;
}

static int check_frozen_abi(void)
{
    struct rate_case {
        u32 requested;
        u32 effective;
    };
    static const struct rate_case cases[] = {
        {0U, 0U},
        {NL_SFLOW_V1_MIN_SAMPLE_RATE, 1U},
        {2U, 2U},
        {NL_SFLOW_V1_RATE_MODULUS / 2U,
         NL_SFLOW_V1_RATE_MODULUS / 2U},
        {NL_SFLOW_V1_MAX_SAMPLE_RATE, NL_SFLOW_V1_RATE_MODULUS},
        {NL_SFLOW_V1_MAX_SAMPLE_RATE + 1U, 0U},
    };
    size_t i;

    if (NL_SFLOW_V1_VERSION != 1U ||
        NL_SFLOW_V1_HEADER_BYTES != 128U ||
        NL_SFLOW_V1_MAX_FRAME_BYTES != 9240U ||
        NL_SFLOW_V1_RING_CAPACITY != 4096U ||
        NL_SFLOW_V1_BATCH_MAX != 128U ||
        NL_SFLOW_V1_BATCH_INTERVAL_MS != 50U ||
        NL_SFLOW_V1_TOKEN_RATE != 2048U ||
        NL_SFLOW_V1_TOKEN_BURST != 4096U) {
        fprintf(stderr, "sFlow V1 constants changed\n");
        return 1;
    }
    if (sizeof(nl_sflow_config_snapshot_v1) != 32U ||
        sizeof(nl_sflow_reload_request_v1) != 16U ||
        sizeof(nl_sflow_hw_state_v1) != 144U ||
        sizeof(nl_sflow_capture_counters_v1) != 64U ||
        sizeof(nl_sflow_sample_v1) != 176U ||
        sizeof(nl_sflow_batch_request_v1) != 32U ||
        sizeof(nl_sflow_batch_response_v1) != 22656U) {
        fprintf(stderr, "sFlow V1 ABI size changed\n");
        return 1;
    }
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        u32 actual = nl_sflow_effective_rate(cases[i].requested);

        if (actual != cases[i].effective) {
            fprintf(stderr,
                    "effective rate mismatch: requested=%u got=%u expected=%u\n",
                    cases[i].requested, actual, cases[i].effective);
            return 1;
        }
    }
    return 0;
}

static int check_stage1_ownership(void)
{
    nl_sflow_capture_counters_v1 before;
    nl_sflow_capture_counters_v1 after;
    fm_buffer success_tail = {0};
    fm_buffer success_head = {0};
    fm_buffer failed_head = {0};
    fm_eventPktRecv empty_event = {0};
    fm_eventPktRecv success_event = {0};
    fm_eventPktRecv failed_event = {0};
    unsigned int calls_before;

    sflow_capture_init();
    memset(&before, 0, sizeof(before));
    sflow_capture_snapshot(&before);

    calls_before = g_free_calls;
    sflow_capture_handle_event(7, NULL);
    if (g_free_calls != calls_before) {
        fprintf(stderr, "NULL event attempted to free a chain\n");
        return 1;
    }

    sflow_capture_handle_event(7, &empty_event);
    if (g_free_calls != calls_before) {
        fprintf(stderr, "NULL chain attempted to call fmFreeBufferChain\n");
        return 1;
    }

    success_head.next = &success_tail;
    success_event.pkt = &success_head;
    g_free_result = FM_OK;
    sflow_capture_handle_event(19, &success_event);
    if (g_free_calls != calls_before + 1U ||
        g_free_sw != 19 || g_free_chain != &success_head ||
        success_event.pkt != NULL) {
        fprintf(stderr,
                "successful chain ownership transfer/free was not exact\n");
        return 1;
    }

    sflow_capture_handle_event(19, &success_event);
    if (g_free_calls != calls_before + 1U) {
        fprintf(stderr, "successfully freed chain was freed more than once\n");
        return 1;
    }

    failed_event.pkt = &failed_head;
    g_free_result = FM_FAIL;
    sflow_capture_handle_event(23, &failed_event);
    if (g_free_calls != calls_before + 2U ||
        g_free_sw != 23 || g_free_chain != &failed_head ||
        failed_event.pkt != NULL) {
        fprintf(stderr, "failed free did not consume ownership exactly once\n");
        return 1;
    }

    sflow_capture_handle_event(23, &failed_event);
    if (g_free_calls != calls_before + 2U) {
        fprintf(stderr, "failed chain free was retried\n");
        return 1;
    }

    memset(&after, 0, sizeof(after));
    sflow_capture_snapshot(&after);
    if (expect_u64("callback_events",
                   after.callback_events - before.callback_events, 6U) ||
        expect_u64("accepted", after.accepted - before.accepted, 0U) ||
        expect_u64("disabled_drops",
                   after.disabled_drops - before.disabled_drops, 2U) ||
        expect_u64("invalid_chain_drops",
                   after.invalid_chain_drops - before.invalid_chain_drops, 4U) ||
        expect_u64("lock_contention_drops",
                   after.lock_contention_drops -
                       before.lock_contention_drops,
                   0U) ||
        expect_u64("token_bucket_drops",
                   after.token_bucket_drops - before.token_bucket_drops, 0U) ||
        expect_u64("ring_overwrites",
                   after.ring_overwrites - before.ring_overwrites, 0U) ||
        expect_u64("buffer_free_failures",
                   after.buffer_free_failures -
                       before.buffer_free_failures,
                   1U))
        return 1;

    sflow_capture_shutdown();
    memset(&before, 0, sizeof(before));
    sflow_capture_snapshot(&before);
    if (memcmp(&before, &after, sizeof(before)) != 0) {
        fprintf(stderr, "shutdown erased Stage1 diagnostics\n");
        return 1;
    }
    return 0;
}

int main(void)
{
    if (check_frozen_abi() != 0)
        return 1;
    if (check_stage1_ownership() != 0)
        return 1;
    puts("PASS: switchd sFlow Stage1 ABI, counters, and ownership");
    return 0;
}
