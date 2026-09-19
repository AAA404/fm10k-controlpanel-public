#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

#include "../../sbin/switchd/sflow_capture.h"

#define FIXTURE_CHAIN_NODES 12U
#define FIXTURE_CONSUMERS 8U
#define FIXTURE_CONCURRENT_EVENTS 1024U
#define NS_PER_SECOND UINT64_C(1000000000)
#define DAY_NS (UINT64_C(86400) * NS_PER_SECOND)

typedef struct {
    fm_buffer nodes[FIXTURE_CHAIN_NODES];
    fm_uint32 storage[FIXTURE_CHAIN_NODES]
                     [NL_SFLOW_V1_CHUNK_BYTES / sizeof(fm_uint32)];
} fixture_chain;

static u64 g_fake_now_ns = UINT64_C(10000000000);
static int g_clock_status;
static fm_status g_free_status = FM_OK;
static u64 g_free_calls;
static u64 g_owned_events;
static fm_buffer *g_last_free_chain;
static int g_last_free_sw = -1;
static int g_allow_concurrent_free;
static int g_pause_after_entry_epoch;
static int g_after_entry_epoch_entered;
static int g_release_after_entry_epoch;
static int g_pause_before_free;
static int g_before_free_entered;
static int g_release_before_free;
static int g_force_ring_copy_miss;
static u64 g_forced_ring_cursor;

static void fixture_after_entry_epoch(void);
static void fixture_before_buffer_free(void);
static void fixture_before_ring_copy(u64 cursor);

static int fixture_monotonic_ns(u64 *out)
{
    if (!out || __atomic_load_n(&g_clock_status, __ATOMIC_RELAXED) != 0)
        return -1;
    *out = __atomic_load_n(&g_fake_now_ns, __ATOMIC_RELAXED);
    return 0;
}

#define SFLOW_CAPTURE_MONOTONIC_NS(out_ptr) \
    fixture_monotonic_ns((out_ptr))
#define SFLOW_CAPTURE_AFTER_ENTRY_EPOCH() \
    fixture_after_entry_epoch()
#define SFLOW_CAPTURE_BEFORE_BUFFER_FREE() \
    fixture_before_buffer_free()
#define SFLOW_CAPTURE_BEFORE_RING_COPY(cursor) \
    fixture_before_ring_copy((cursor))

fm_status fmFreeBufferChain(int sw, fm_buffer *buf_chain)
{
    (void)__atomic_fetch_add(&g_free_calls, UINT64_C(1), __ATOMIC_RELAXED);
    __atomic_store_n(&g_last_free_chain, buf_chain, __ATOMIC_RELAXED);
    __atomic_store_n(&g_last_free_sw, sw, __ATOMIC_RELAXED);
    return __atomic_load_n(&g_free_status, __ATOMIC_RELAXED);
}

#include "../../sbin/switchd/sflow_capture.c"

static void fixture_after_entry_epoch(void)
{
    if (__atomic_load_n(
            &g_pause_after_entry_epoch, __ATOMIC_ACQUIRE) == 0)
        return;
    __atomic_store_n(
        &g_after_entry_epoch_entered, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(
               &g_release_after_entry_epoch, __ATOMIC_ACQUIRE) == 0)
        sched_yield();
}

static void fixture_before_buffer_free(void)
{
    if (__atomic_load_n(&g_pause_before_free, __ATOMIC_ACQUIRE) == 0)
        return;
    __atomic_store_n(&g_before_free_entered, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(
               &g_release_before_free, __ATOMIC_ACQUIRE) == 0)
        sched_yield();
}

static void fixture_before_ring_copy(u64 cursor)
{
    sflow_capture_slot *slot;

    if (__atomic_exchange_n(
            &g_force_ring_copy_miss, 0, __ATOMIC_ACQ_REL) == 0)
        return;
    slot = &g_ring[
        (u32)((cursor - UINT64_C(1)) & SFLOW_RING_MASK)];
    g_forced_ring_cursor = cursor;
    __atomic_store_n(
        &slot->cursor, UINT64_C(0), __ATOMIC_SEQ_CST);
}

static int fail_text(const char *text)
{
    fprintf(stderr, "%s\n", text);
    return 1;
}

static int expect_u64(const char *name, u64 actual, u64 expected)
{
    if (actual == expected)
        return 0;
    fprintf(stderr, "%s: got %llu, expected %llu\n", name,
            (unsigned long long)actual, (unsigned long long)expected);
    return 1;
}

static int wait_for_flag(const int *flag, const char *failure)
{
    for (unsigned int attempt = 0; attempt < 1000000U; attempt++) {
        if (__atomic_load_n(flag, __ATOMIC_ACQUIRE) != 0)
            return 0;
        sched_yield();
    }
    return fail_text(failure);
}

static void fake_time_set(u64 now_ns)
{
    __atomic_store_n(&g_fake_now_ns, now_ns, __ATOMIC_RELAXED);
}

static void fake_time_advance(u64 delta_ns)
{
    (void)__atomic_fetch_add(
        &g_fake_now_ns, delta_ns, __ATOMIC_RELAXED);
}

static u8 fixture_byte(u8 seed, size_t offset)
{
    return (u8)((u32)seed + (u32)(offset * 37U) + 11U);
}

static size_t fixture_chain_build(fixture_chain *chain,
                                  const int *lengths,
                                  size_t node_count,
                                  u8 seed)
{
    size_t total = 0;
    size_t offset = 0;

    memset(chain, 0, sizeof(*chain));
    if (!lengths || node_count == 0 ||
        node_count > FIXTURE_CHAIN_NODES)
        return 0;

    for (size_t i = 0; i < node_count; i++) {
        size_t writable = 0;

        chain->nodes[i].data = chain->storage[i];
        chain->nodes[i].len = lengths[i];
        chain->nodes[i].next =
            i + 1U < node_count ? &chain->nodes[i + 1U] : NULL;
        if (lengths[i] > 0) {
            writable = (size_t)lengths[i];
            if (writable > NL_SFLOW_V1_CHUNK_BYTES)
                writable = NL_SFLOW_V1_CHUNK_BYTES;
            total += (size_t)lengths[i];
        }
        for (size_t j = 0; j < writable; j++)
            ((u8 *)chain->storage[i])[j] =
                fixture_byte(seed, offset + j);
        offset += writable;
    }

    if (total >= NL_SFLOW_V1_STRIPPED_BYTES &&
        total <= node_count * NL_SFLOW_V1_CHUNK_BYTES) {
        size_t fcs_start = total - NL_SFLOW_V1_STRIPPED_BYTES;
        size_t walked = 0;

        for (size_t i = 0; i < node_count; i++) {
            size_t length;

            if (lengths[i] <= 0)
                continue;
            length = (size_t)lengths[i];
            if (length > NL_SFLOW_V1_CHUNK_BYTES)
                length = NL_SFLOW_V1_CHUNK_BYTES;
            for (size_t j = 0; j < length; j++) {
                if (walked + j >= fcs_start)
                    ((u8 *)chain->storage[i])[j] = 0;
            }
            walked += length;
        }
    }
    return total;
}

static int emit_chain(int sw, fixture_chain *chain, int port, int vlan,
                      int priority)
{
    fm_eventPktRecv event;
    u64 free_before;

    memset(&event, 0, sizeof(event));
    event.pkt = &chain->nodes[0];
    event.srcPort = port;
    event.vlan = vlan;
    event.vlanPriority = priority;
    free_before = __atomic_load_n(&g_free_calls, __ATOMIC_RELAXED);
    (void)__atomic_fetch_add(
        &g_owned_events, UINT64_C(1), __ATOMIC_RELAXED);

    sflow_capture_handle_event(sw, &event);
    if (event.pkt != NULL)
        return fail_text("callback did not detach SDK chain ownership");
    if (__atomic_load_n(
            &g_allow_concurrent_free, __ATOMIC_ACQUIRE) == 0 &&
        __atomic_load_n(&g_free_calls, __ATOMIC_RELAXED) !=
            free_before + 1U)
        return fail_text("callback did not free the SDK chain exactly once");
    if (__atomic_load_n(
            &g_allow_concurrent_free, __ATOMIC_ACQUIRE) == 0 &&
        (__atomic_load_n(&g_last_free_chain, __ATOMIC_RELAXED) !=
             &chain->nodes[0] ||
         __atomic_load_n(&g_last_free_sw, __ATOMIC_RELAXED) != sw))
        return fail_text("callback freed the wrong SDK chain or switch");
    return 0;
}

static int emit_frame(u8 seed, int port)
{
    static const int lengths[] = {64};
    fixture_chain chain;

    (void)fixture_chain_build(
        &chain, lengths, sizeof(lengths) / sizeof(lengths[0]), seed);
    return emit_chain(0, &chain, port, 100 + port, port & 7);
}

static void request_init(nl_sflow_batch_request_v1 *request,
                         u32 flags, u32 max_samples,
                         u64 generation, u64 ack_sequence)
{
    memset(request, 0, sizeof(*request));
    request->version = NL_SFLOW_V1_VERSION;
    request->size = sizeof(*request);
    request->flags = flags;
    request->max_samples = max_samples;
    request->generation = generation;
    request->ack_sequence = ack_sequence;
}

static int drain_retry(const nl_sflow_batch_request_v1 *request,
                       nl_sflow_batch_response_v1 *response)
{
    int rc;

    for (unsigned int attempt = 0; attempt < 100000U; attempt++) {
        memset(response, 0xa5, sizeof(*response));
        rc = sflow_capture_drain(request, response);
        if (rc != SFLOW_CAPTURE_DRAIN_BUSY)
            return rc;
        sched_yield();
    }
    return SFLOW_CAPTURE_DRAIN_BUSY;
}

static int reset_to_tail(u64 generation, u64 *acked_sequence)
{
    nl_sflow_batch_request_v1 request;
    nl_sflow_batch_response_v1 response;
    nl_sflow_sample_v1 zero_sample;
    int rc;

    request_init(&request, NL_SFLOW_BATCH_F_RESET_TO_TAIL,
                 NL_SFLOW_V1_BATCH_MAX, generation, 0);
    rc = drain_retry(&request, &response);
    if (rc != SFLOW_CAPTURE_DRAIN_OK)
        return fail_text("RESET_TO_TAIL request failed");
    if (response.version != NL_SFLOW_V1_VERSION ||
        response.size != offsetof(
            nl_sflow_batch_response_v1, samples) ||
        response.generation != generation ||
        (response.flags & NL_SFLOW_BATCH_RESP_F_CURSOR_RESET) == 0 ||
        response.sample_count != 0U)
        return fail_text("RESET_TO_TAIL response is not canonical");
    memset(&zero_sample, 0, sizeof(zero_sample));
    for (u32 i = 0; i < NL_SFLOW_V1_BATCH_MAX; i++) {
        if (memcmp(&response.samples[i], &zero_sample,
                   sizeof(zero_sample)) != 0)
            return fail_text("unused batch samples were not zeroed");
    }
    if (acked_sequence)
        *acked_sequence = response.acked_sequence;
    return 0;
}

static int configure_generation(u64 generation, u32 effective_rate,
                                bool enabled, u64 now_ns,
                                u64 *acked_sequence)
{
    fake_time_set(now_ns);
    if (sflow_capture_configure(
            generation, effective_rate, enabled) != 0)
        return fail_text("capture configuration was rejected");
    if (!enabled) {
        if (acked_sequence)
            *acked_sequence = 0;
        return 0;
    }
    return reset_to_tail(generation, acked_sequence);
}

static int sample_header_valid(const nl_sflow_sample_v1 *sample, u8 seed)
{
    u32 expected_header;

    if (!sample)
        return 0;
    if (sample->frame_length < NL_SFLOW_V1_STRIPPED_BYTES)
        return 0;
    expected_header = sample->frame_length - NL_SFLOW_V1_STRIPPED_BYTES;
    if (expected_header > NL_SFLOW_V1_HEADER_BYTES)
        expected_header = NL_SFLOW_V1_HEADER_BYTES;
    if (sample->stripped != NL_SFLOW_V1_STRIPPED_BYTES ||
        sample->header_length != expected_header)
        return 0;
    for (u32 i = 0; i < sample->header_length; i++) {
        if (sample->header[i] != fixture_byte(seed, i))
            return 0;
    }
    for (u32 i = sample->header_length;
         i < NL_SFLOW_V1_HEADER_BYTES; i++) {
        if (sample->header[i] != 0U)
            return 0;
    }
    return 1;
}

static int drain_after(u64 generation, u64 ack_sequence, u32 max_samples,
                       nl_sflow_batch_response_v1 *response)
{
    nl_sflow_batch_request_v1 request;

    request_init(&request, 0, max_samples, generation, ack_sequence);
    return drain_retry(&request, response);
}

static int test_chain_fcs_metadata_and_ownership(void)
{
    static const int one_node_4[] = {4};
    static const int one_node_64[] = {64};
    static const int one_node_131[] = {131};
    static const int one_node_132[] = {132};
    static const int one_node_133[] = {133};
    static const int spanning_header_and_fcs[] = {64, 68};
    static const int split_fcs[] = {60, 2, 2};
    static const int ten_node_jumbo[] = {
        1024, 1024, 1024, 1024, 1024,
        1024, 1024, 1024, 1024, 24,
    };
    static const struct {
        const int *lengths;
        size_t count;
        u32 frame_length;
        u8 seed;
    } valid_cases[] = {
        {one_node_4, 1U, 4U, 1U},
        {one_node_64, 1U, 64U, 2U},
        {one_node_131, 1U, 131U, 3U},
        {one_node_132, 1U, 132U, 4U},
        {one_node_133, 1U, 133U, 5U},
        {spanning_header_and_fcs, 2U, 132U, 6U},
        {split_fcs, 3U, 64U, 7U},
        {ten_node_jumbo, 10U, 9240U, 8U},
    };
    static const int too_short[] = {3};
    static const int zero_length[] = {0};
    static const int oversized_chunk[] = {1025};
    static const int too_many_nodes[] = {
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 8,
    };
    static const int oversized_frame[] = {
        1024, 1024, 1024, 1024, 1024,
        1024, 1024, 1024, 1024, 25,
    };
    static const struct {
        const int *lengths;
        size_t count;
    } invalid_cases[] = {
        {too_short, 1U},
        {zero_length, 1U},
        {oversized_chunk, 1U},
        {too_many_nodes, 11U},
        {oversized_frame, 10U},
    };
    nl_sflow_capture_counters_v1 before_invalid;
    nl_sflow_capture_counters_v1 after_invalid;
    u64 invalid_sequence;
    u64 ack = 0;
    u32 invalid_pool;

    if (configure_generation(
            101U, 777U, true, UINT64_C(20000000000), &ack) != 0)
        return 1;

    for (size_t i = 0;
         i < sizeof(valid_cases) / sizeof(valid_cases[0]); i++) {
        fixture_chain chain;
        nl_sflow_batch_response_v1 response;
        size_t total = fixture_chain_build(
            &chain, valid_cases[i].lengths,
            valid_cases[i].count, valid_cases[i].seed);

        if (total != valid_cases[i].frame_length)
            return fail_text("fixture built an unexpected frame length");
        if (emit_chain(3, &chain, 9, 321, 5) != 0)
            return 1;
        if (drain_after(101U, ack, 1U, &response) !=
                SFLOW_CAPTURE_DRAIN_OK ||
            response.sample_count != 1U)
            return fail_text("valid frame was not returned by batch drain");
        if (response.samples[0].frame_length != valid_cases[i].frame_length ||
            response.samples[0].sampling_rate != 777U ||
            response.samples[0].input_port != 9U ||
            response.samples[0].source_vlan != 321U ||
            response.samples[0].source_priority != 5U ||
            response.samples[0].capture_monotonic_ns !=
                UINT64_C(20000000000) ||
            response.samples[0].config_generation != 101U ||
            response.samples[0].sequence != i + 1U ||
            response.samples[0].sample_pool !=
                (u32)((i + 1U) * 777U) ||
            !sample_header_valid(
                &response.samples[0], valid_cases[i].seed))
            return fail_text("captured sample metadata/header is incorrect");
        ack = response.next_sequence - 1U;
    }

    sflow_capture_snapshot(&before_invalid);
    invalid_sequence =
        __atomic_load_n(&g_flow_sequence[7], __ATOMIC_RELAXED);
    invalid_pool =
        __atomic_load_n(&g_sample_pool[7], __ATOMIC_RELAXED);
    for (size_t i = 0;
         i < sizeof(invalid_cases) / sizeof(invalid_cases[0]); i++) {
        fixture_chain chain;

        (void)fixture_chain_build(
            &chain, invalid_cases[i].lengths,
            invalid_cases[i].count, (u8)(30U + i));
        if (emit_chain(4, &chain, 7, 200, 3) != 0)
            return 1;
    }
    sflow_capture_snapshot(&after_invalid);
    if (expect_u64(
            "invalid_chain_drops",
            after_invalid.invalid_chain_drops -
                before_invalid.invalid_chain_drops,
            sizeof(invalid_cases) / sizeof(invalid_cases[0])) != 0)
        return 1;
    if (__atomic_load_n(
            &g_flow_sequence[7], __ATOMIC_RELAXED) !=
            invalid_sequence +
                sizeof(invalid_cases) / sizeof(invalid_cases[0]) ||
        __atomic_load_n(&g_sample_pool[7], __ATOMIC_RELAXED) !=
            invalid_pool +
                (u32)(sizeof(invalid_cases) /
                      sizeof(invalid_cases[0])) * 777U)
        return fail_text(
            "malformed sampled frames did not leave flow counter gaps");

    __atomic_store_n(&g_free_status, FM_FAIL, __ATOMIC_RELAXED);
    {
        fixture_chain chain;

        (void)fixture_chain_build(&chain, one_node_64, 1U, 44U);
        if (emit_chain(5, &chain, 8, 201, 4) != 0)
            return 1;
    }
    __atomic_store_n(&g_free_status, FM_OK, __ATOMIC_RELAXED);
    return 0;
}

static int emit_many(unsigned int count, u8 seed, int port)
{
    for (unsigned int i = 0; i < count; i++) {
        if (emit_frame((u8)(seed + i), port) != 0)
            return 1;
    }
    return 0;
}

static int validate_batch_cursor(
    const nl_sflow_batch_response_v1 *response, u64 ack_sequence);

static int test_token_bucket_boundaries(void)
{
    nl_sflow_capture_counters_v1 before;
    nl_sflow_capture_counters_v1 after_burst;
    nl_sflow_capture_counters_v1 after_remainder;
    nl_sflow_capture_counters_v1 before_long_jump;
    nl_sflow_capture_counters_v1 after_long_jump;
    nl_sflow_batch_response_v1 response;
    u64 burst_last_flow_sequence = 0;
    u32 burst_last_sample_pool = 0;
    u64 ack = 0;
    u64 base_time = UINT64_C(50000000000);

    if (configure_generation(
            201U, 1000U, true, base_time, &ack) != 0)
        return 1;
    sflow_capture_snapshot(&before);
    if (emit_many(NL_SFLOW_V1_TOKEN_BURST, 50U, 6) != 0 ||
        emit_frame(99U, 6) != 0)
        return 1;
    sflow_capture_snapshot(&after_burst);
    if (expect_u64(
            "initial burst accepts",
            after_burst.accepted - before.accepted,
            NL_SFLOW_V1_TOKEN_BURST) ||
        expect_u64(
            "first post-burst token drop",
            after_burst.token_bucket_drops -
                before.token_bucket_drops,
            1U))
        return 1;

    {
        u32 drained = 0;

        while (drained < NL_SFLOW_V1_TOKEN_BURST) {
            u32 expected = NL_SFLOW_V1_TOKEN_BURST - drained;

            if (expected > NL_SFLOW_V1_BATCH_MAX)
                expected = NL_SFLOW_V1_BATCH_MAX;
            if (drain_after(
                    201U, ack, NL_SFLOW_V1_BATCH_MAX, &response) !=
                    SFLOW_CAPTURE_DRAIN_OK ||
                response.sample_count != expected ||
                !validate_batch_cursor(&response, ack))
                return fail_text(
                    "could not drain the exact initial token burst");
            burst_last_flow_sequence =
                response.samples[response.sample_count - 1U].sequence;
            burst_last_sample_pool =
                response.samples[response.sample_count - 1U].sample_pool;
            ack = response.next_sequence - 1U;
            drained += response.sample_count;
        }
    }

    for (unsigned int i = 0; i < 5U; i++) {
        fake_time_advance(UINT64_C(100000));
        if (emit_frame((u8)(110U + i), 6) != 0)
            return 1;
    }
    sflow_capture_snapshot(&after_remainder);
    if (expect_u64(
            "sub-token remainder eventually accepts",
            after_remainder.accepted - after_burst.accepted, 1U) ||
        expect_u64(
            "sub-token attempts before refill",
            after_remainder.token_bucket_drops -
                after_burst.token_bucket_drops,
            4U))
        return 1;
    if (drain_after(
            201U, ack, NL_SFLOW_V1_BATCH_MAX, &response) !=
            SFLOW_CAPTURE_DRAIN_OK ||
        response.sample_count != 1U ||
        !validate_batch_cursor(&response, ack) ||
        response.samples[0].sequence !=
            burst_last_flow_sequence + 6U ||
        response.samples[0].sample_pool !=
            burst_last_sample_pool + 6000U)
        return fail_text(
            "token drops did not create only per-flow counter gaps");
    ack = response.next_sequence - 1U;
    if (drain_after(
            201U, ack, NL_SFLOW_V1_BATCH_MAX, &response) !=
            SFLOW_CAPTURE_DRAIN_OK ||
        response.sample_count != 0U ||
        !validate_batch_cursor(&response, ack))
        return fail_text("token-gap batch acknowledgement failed");

    fake_time_set(base_time);
    if (emit_frame(120U, 6) != 0)
        return 1;
    sflow_capture_snapshot(&before_long_jump);
    if (before_long_jump.accepted != after_remainder.accepted ||
        before_long_jump.token_bucket_drops !=
            after_remainder.token_bucket_drops + 1U)
        return fail_text("backward monotonic time minted a token");

    fake_time_set(base_time + UINT64_C(105) * DAY_NS);
    if (emit_many(NL_SFLOW_V1_TOKEN_BURST, 130U, 6) != 0 ||
        emit_frame(131U, 6) != 0)
        return 1;
    sflow_capture_snapshot(&after_long_jump);
    if (expect_u64(
            ">104-day refill is capped at burst",
            after_long_jump.accepted - before_long_jump.accepted,
            NL_SFLOW_V1_TOKEN_BURST) ||
        expect_u64(
            ">104-day post-burst drop",
            after_long_jump.token_bucket_drops -
                before_long_jump.token_bucket_drops,
            1U))
        return 1;
    return 0;
}

static int validate_batch_cursor(
    const nl_sflow_batch_response_v1 *response, u64 ack_sequence)
{
    if (!response ||
        response->sample_count > NL_SFLOW_V1_BATCH_MAX ||
        response->acked_sequence != ack_sequence ||
        response->next_sequence !=
            ack_sequence + response->sample_count + UINT64_C(1) ||
        response->size !=
            offsetof(nl_sflow_batch_response_v1, samples) +
            response->sample_count * sizeof(response->samples[0]))
        return 0;
    return 1;
}

static int test_ring_ack_and_batch_semantics(void)
{
    nl_sflow_batch_request_v1 request;
    nl_sflow_batch_response_v1 first;
    nl_sflow_batch_response_v1 retry;
    nl_sflow_batch_response_v1 partial;
    nl_sflow_capture_counters_v1 before_overwrite;
    nl_sflow_capture_counters_v1 at_capacity;
    nl_sflow_capture_counters_v1 after_overwrite;
    u64 ack = 0;

    if (configure_generation(
            301U, 2048U, true, UINT64_C(100000000000), &ack) != 0 ||
        emit_many(NL_SFLOW_V1_RING_CAPACITY - 1U, 1U, 5) != 0)
        return 1;
    if (drain_after(301U, ack, NL_SFLOW_V1_BATCH_MAX, &first) !=
            SFLOW_CAPTURE_DRAIN_OK ||
        first.sample_count != NL_SFLOW_V1_BATCH_MAX ||
        first.oldest_sequence == 0U ||
        first.latest_sequence < first.oldest_sequence ||
        first.oldest_sequence != ack + 1U ||
        !validate_batch_cursor(&first, ack))
        return fail_text("4095-entry ring batch metadata is invalid");
    request_init(&request, 0, NL_SFLOW_V1_BATCH_MAX, 301U, ack);
    if (drain_retry(&request, &retry) != SFLOW_CAPTURE_DRAIN_OK ||
        memcmp(&first, &retry, sizeof(first)) != 0)
        return fail_text("retry with unchanged ack was not idempotent");

    request.ack_sequence = first.oldest_sequence + 63U;
    if (drain_retry(&request, &partial) != SFLOW_CAPTURE_DRAIN_OK ||
        partial.sample_count == 0U ||
        memcmp(&partial.samples[0], &first.samples[64],
               sizeof(partial.samples[0])) != 0 ||
        !validate_batch_cursor(
            &partial, first.oldest_sequence + 63U))
        return fail_text("partial acknowledgement skipped or repeated data");

    sflow_capture_snapshot(&before_overwrite);
    if (emit_frame(2U, 5) != 0)
        return 1;
    sflow_capture_snapshot(&at_capacity);
    if (at_capacity.ring_overwrites !=
        before_overwrite.ring_overwrites)
        return fail_text("4096th sample incorrectly counted an overwrite");
    fake_time_advance(NS_PER_SECOND);
    if (emit_frame(3U, 5) != 0)
        return 1;
    sflow_capture_snapshot(&after_overwrite);
    if (after_overwrite.ring_overwrites !=
        at_capacity.ring_overwrites)
        return fail_text("reuse of an acknowledged ring slot counted loss");

    if (drain_after(
            301U, partial.acked_sequence, 1U, &retry) !=
        SFLOW_CAPTURE_DRAIN_OK)
        return fail_text("could not snapshot the latest batch cursor");
    request.ack_sequence = retry.latest_sequence + 1U;
    if (sflow_capture_drain(&request, &retry) !=
        SFLOW_CAPTURE_DRAIN_INVALID)
        return fail_text("future acknowledgement was accepted");
    request.ack_sequence = first.oldest_sequence + 63U;
    request.max_samples = NL_SFLOW_V1_BATCH_MAX + 1U;
    if (sflow_capture_drain(&request, &retry) !=
        SFLOW_CAPTURE_DRAIN_INVALID)
        return fail_text("batch larger than 128 samples was accepted");
    request.max_samples = 0;
    if (sflow_capture_drain(&request, &retry) !=
        SFLOW_CAPTURE_DRAIN_INVALID)
        return fail_text("zero-sized batch was accepted");

    if (configure_generation(
            302U, 2048U, true, UINT64_C(200000000000), &ack) != 0)
        return 1;
    sflow_capture_snapshot(&before_overwrite);
    if (emit_many(NL_SFLOW_V1_RING_CAPACITY, 10U, 4) != 0)
        return 1;
    sflow_capture_snapshot(&at_capacity);
    if (at_capacity.ring_overwrites !=
        before_overwrite.ring_overwrites)
        return fail_text(
            "full 4096-entry unacked ring incorrectly counted loss");
    fake_time_advance(NS_PER_SECOND);
    if (emit_frame(11U, 4) != 0)
        return 1;
    sflow_capture_snapshot(&after_overwrite);
    if (after_overwrite.ring_overwrites !=
            at_capacity.ring_overwrites + 1U)
        return fail_text("4097th unacked sample did not count one overwrite");
    if (drain_after(302U, ack, NL_SFLOW_V1_BATCH_MAX, &retry) !=
            SFLOW_CAPTURE_DRAIN_OK ||
        (retry.flags & NL_SFLOW_BATCH_RESP_F_CURSOR_RESET) == 0 ||
        retry.lost_before != 1U ||
        retry.oldest_sequence == 0U ||
        retry.acked_sequence != retry.oldest_sequence - 1U ||
        retry.next_sequence !=
            retry.oldest_sequence + retry.sample_count ||
        retry.size !=
            offsetof(nl_sflow_batch_response_v1, samples) +
            retry.sample_count * sizeof(retry.samples[0]))
        return fail_text("overwritten cursor did not reset at oldest sample");

    if (configure_generation(
            303U, 2048U, true, UINT64_C(250000000000), &ack) != 0 ||
        emit_many(NL_SFLOW_V1_RING_CAPACITY, 12U, 4) != 0)
        return 1;
    fake_time_advance(NS_PER_SECOND);
    if (emit_frame(13U, 4) != 0)
        return 1;
    g_forced_ring_cursor = 0;
    __atomic_store_n(
        &g_force_ring_copy_miss, 1, __ATOMIC_RELEASE);
    if (drain_after(303U, ack, NL_SFLOW_V1_BATCH_MAX, &retry) !=
            SFLOW_CAPTURE_DRAIN_OK ||
        retry.sample_count != 0U ||
        retry.lost_before != 1U ||
        (retry.flags & NL_SFLOW_BATCH_RESP_F_CURSOR_RESET) == 0 ||
        g_forced_ring_cursor != retry.oldest_sequence ||
        retry.acked_sequence != retry.oldest_sequence - 1U)
        return fail_text(
            "forced overwrite miss did not return a bounded reset");
    __atomic_store_n(
        &g_ring[(u32)((g_forced_ring_cursor - UINT64_C(1)) &
                      SFLOW_RING_MASK)].cursor,
        g_forced_ring_cursor, __ATOMIC_SEQ_CST);
    if (drain_after(
            303U, retry.acked_sequence,
            NL_SFLOW_V1_BATCH_MAX, &partial) !=
            SFLOW_CAPTURE_DRAIN_OK ||
        partial.sample_count == 0U)
        return fail_text(
            "forced overwrite reset acknowledgement became a dead end");
    return 0;
}

static int test_generation_and_reset_semantics(void)
{
    nl_sflow_batch_request_v1 request;
    nl_sflow_batch_response_v1 first;
    nl_sflow_batch_response_v1 second;
    u64 ack = 0;

    if (configure_generation(
            401U, 4096U, true, UINT64_C(300000000000), &ack) != 0 ||
        emit_many(3U, 70U, 3) != 0)
        return 1;

    request_init(&request, 0, 2U, 400U, 0U);
    if (drain_retry(&request, &first) != SFLOW_CAPTURE_DRAIN_OK ||
        first.generation != 401U ||
        (first.flags & NL_SFLOW_BATCH_RESP_F_CURSOR_RESET) == 0)
        return fail_text("generation mismatch did not reset the cursor");
    if (drain_retry(&request, &second) != SFLOW_CAPTURE_DRAIN_OK ||
        memcmp(&first, &second, sizeof(first)) != 0)
        return fail_text("generation-reset retry was not idempotent");

    request_init(&request, NL_SFLOW_BATCH_F_RESET_TO_TAIL,
                 NL_SFLOW_V1_BATCH_MAX, 401U, 1U);
    if (sflow_capture_drain(&request, &second) !=
        SFLOW_CAPTURE_DRAIN_INVALID)
        return fail_text("RESET_TO_TAIL accepted a nonzero acknowledgement");
    request.ack_sequence = 0;
    if (drain_retry(&request, &second) != SFLOW_CAPTURE_DRAIN_OK ||
        second.sample_count != 0U ||
        second.acked_sequence != second.latest_sequence ||
        (second.flags & NL_SFLOW_BATCH_RESP_F_CURSOR_RESET) == 0)
        return fail_text("RESET_TO_TAIL did not atomically discard backlog");

    /*
     * Model a process-local ring restart while the durable configuration
     * generation and the consumer's old acknowledgement survive.  A future
     * ACK must be rejected without silently discarding the new backlog.
     */
    __atomic_store_n(&g_acked_cursor, UINT64_C(0), __ATOMIC_RELEASE);
    __atomic_store_n(&g_delivered_cursor, UINT64_C(0), __ATOMIC_RELEASE);
    request_init(&request, 0, NL_SFLOW_V1_BATCH_MAX, 401U,
                 second.latest_sequence + UINT64_C(100));
    if (sflow_capture_drain(&request, &first) !=
            SFLOW_CAPTURE_DRAIN_INVALID ||
        __atomic_load_n(&g_acked_cursor, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&g_delivered_cursor, __ATOMIC_ACQUIRE) != 0)
        return fail_text(
            "stale restart acknowledgement silently discarded backlog");
    __atomic_store_n(
        &g_acked_cursor, second.latest_sequence, __ATOMIC_RELEASE);
    __atomic_store_n(
        &g_delivered_cursor, second.latest_sequence, __ATOMIC_RELEASE);
    return 0;
}

static int test_deterministic_gate_contention(void)
{
    static const int lengths[] = {64};
    fixture_chain chain;
    nl_sflow_capture_counters_v1 before;
    nl_sflow_capture_counters_v1 after;
    nl_sflow_batch_request_v1 request;
    nl_sflow_batch_response_v1 baseline;
    nl_sflow_batch_response_v1 after_busy;
    nl_sflow_batch_response_v1 busy_response;
    nl_sflow_batch_response_v1 busy_marker;
    u64 flow_sequence;
    u64 ack = 0;
    u32 sample_pool;
    int rc;

    if (configure_generation(
            451U, 1234U, true, UINT64_C(350000000000), &ack) != 0)
        return 1;
    flow_sequence =
        __atomic_load_n(&g_flow_sequence[24], __ATOMIC_RELAXED);
    sample_pool =
        __atomic_load_n(&g_sample_pool[24], __ATOMIC_RELAXED);
    sflow_capture_snapshot(&before);

    if (__atomic_exchange_n(
            &g_producer_gate, 1U, __ATOMIC_ACQ_REL) != 0U)
        return fail_text("producer gate was unexpectedly occupied");
    (void)fixture_chain_build(&chain, lengths, 1U, 201U);
    rc = emit_chain(7, &chain, 24, 4095, 7);
    __atomic_store_n(&g_producer_gate, 0U, __ATOMIC_RELEASE);
    if (rc != 0)
        return 1;

    sflow_capture_snapshot(&after);
    if (after.callback_events != before.callback_events + 1U ||
        after.lock_contention_drops !=
            before.lock_contention_drops + 1U ||
        after.accepted != before.accepted ||
        __atomic_load_n(
            &g_flow_sequence[24], __ATOMIC_RELAXED) !=
            flow_sequence + 1U ||
        __atomic_load_n(
            &g_sample_pool[24], __ATOMIC_RELAXED) !=
            sample_pool + 1234U)
        return fail_text(
            "producer contention terminal accounting is incorrect");

    if (drain_after(
            451U, ack, NL_SFLOW_V1_BATCH_MAX, &baseline) !=
            SFLOW_CAPTURE_DRAIN_OK ||
        baseline.sample_count != 0U ||
        !validate_batch_cursor(&baseline, ack))
        return fail_text("producer contention published a sample");

    request_init(
        &request, 0, NL_SFLOW_V1_BATCH_MAX, 451U, ack);
    memset(&busy_response, 0xa5, sizeof(busy_response));
    memset(&busy_marker, 0xa5, sizeof(busy_marker));
    if (__atomic_exchange_n(
            &g_consumer_gate, 1U, __ATOMIC_ACQ_REL) != 0U)
        return fail_text("consumer gate was unexpectedly occupied");
    rc = sflow_capture_drain(&request, &busy_response);
    __atomic_store_n(&g_consumer_gate, 0U, __ATOMIC_RELEASE);
    if (rc != SFLOW_CAPTURE_DRAIN_BUSY ||
        memcmp(&busy_response, &busy_marker, sizeof(busy_response)) != 0)
        return fail_text("BUSY drain mutated its response");

    if (drain_after(
            451U, ack, NL_SFLOW_V1_BATCH_MAX, &after_busy) !=
            SFLOW_CAPTURE_DRAIN_OK ||
        memcmp(&baseline, &after_busy, sizeof(baseline)) != 0)
        return fail_text("BUSY drain mutated the consumer cursor");
    return 0;
}

typedef struct {
    u64 generation;
    u32 rate;
    int started;
    int done;
    int rc;
} configure_job;

typedef struct {
    u8 seed;
    int port;
    int done;
    int rc;
} single_event_job;

typedef struct {
    int started;
    int done;
    int rc;
} shutdown_job;

static void *configure_once(void *arg)
{
    configure_job *job = arg;

    __atomic_store_n(&job->started, 1, __ATOMIC_RELEASE);
    job->rc = sflow_capture_configure(
        job->generation, job->rate, true);
    __atomic_store_n(&job->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void *emit_once(void *arg)
{
    single_event_job *job = arg;

    job->rc = emit_frame(job->seed, job->port);
    __atomic_store_n(&job->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void *shutdown_once(void *arg)
{
    shutdown_job *job = arg;

    __atomic_store_n(&job->started, 1, __ATOMIC_RELEASE);
    job->rc = sflow_capture_shutdown();
    __atomic_store_n(&job->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void *shutdown_wait_once(void *arg)
{
    shutdown_job *job = arg;

    __atomic_store_n(&job->started, 1, __ATOMIC_RELEASE);
    job->rc = sflow_capture_shutdown_wait();
    __atomic_store_n(&job->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static int test_generation_barrier_and_shutdown_drain(void)
{
    nl_sflow_capture_counters_v1 before;
    nl_sflow_capture_counters_v1 after;
    configure_job config;
    single_event_job event;
    single_event_job transition_event;
    shutdown_job shutdown;
    pthread_t config_thread;
    pthread_t event_thread;
    pthread_t shutdown_thread;
    u64 flow_sequence;
    u64 free_before;
    u64 transition_free_before;
    u64 ack = 0;
    u32 sample_pool;

    if (configure_generation(
            475U, 1111U, true, UINT64_C(375000000000), &ack) != 0)
        return 1;
    sflow_capture_snapshot(&before);
    flow_sequence =
        __atomic_load_n(&g_flow_sequence[10], __ATOMIC_RELAXED);
    sample_pool =
        __atomic_load_n(&g_sample_pool[10], __ATOMIC_RELAXED);
    memset(&config, 0, sizeof(config));
    memset(&event, 0, sizeof(event));
    memset(&transition_event, 0, sizeof(transition_event));
    config.generation = 476U;
    config.rate = 2222U;
    event.seed = 210U;
    event.port = 10;
    transition_event.seed = 209U;
    transition_event.port = 10;
    __atomic_store_n(&g_after_entry_epoch_entered, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_release_after_entry_epoch, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_pause_after_entry_epoch, 1, __ATOMIC_RELEASE);
    transition_free_before =
        __atomic_load_n(&g_free_calls, __ATOMIC_RELAXED);
    __atomic_store_n(
        &g_allow_concurrent_free, 1, __ATOMIC_RELEASE);
    if (pthread_create(&event_thread, NULL, emit_once, &event) != 0)
        return fail_text("could not start paused old-generation callback");
    if (wait_for_flag(
            &g_after_entry_epoch_entered,
            "old-generation callback did not reach transition hook") != 0)
        return 1;
    if (pthread_create(
            &config_thread, NULL, configure_once, &config) != 0)
        return fail_text("could not start concurrent reconfiguration");
    if (wait_for_flag(
            &config.started,
            "concurrent reconfiguration did not start") != 0)
        return 1;
    for (unsigned int attempt = 0; attempt < 1000000U; attempt++) {
        if ((__atomic_load_n(
                 &g_epoch_sequence, __ATOMIC_SEQ_CST) &
             UINT64_C(1)) != 0)
            break;
        if (attempt == 999999U)
            return fail_text(
                "reconfiguration did not publish its odd epoch");
        sched_yield();
    }
    for (unsigned int attempt = 0; attempt < 1000U; attempt++)
        sched_yield();
    if (__atomic_load_n(&config.done, __ATOMIC_ACQUIRE) != 0)
        return fail_text(
            "reconfiguration crossed an admitted old callback");
    __atomic_store_n(
        &g_pause_after_entry_epoch, 0, __ATOMIC_RELEASE);
    if (emit_frame(
            transition_event.seed, transition_event.port) != 0)
        return fail_text("odd-epoch callback fixture failed");
    __atomic_store_n(
        &g_release_after_entry_epoch, 1, __ATOMIC_RELEASE);
    (void)pthread_join(event_thread, NULL);
    (void)pthread_join(config_thread, NULL);
    __atomic_store_n(
        &g_allow_concurrent_free, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_pause_after_entry_epoch, 0, __ATOMIC_RELEASE);
    if (config.rc != 0 || event.rc != 0 ||
        __atomic_load_n(&g_free_calls, __ATOMIC_RELAXED) !=
            transition_free_before + 2U)
        return fail_text("generation-barrier worker failed");
    sflow_capture_snapshot(&after);
    if (after.accepted != before.accepted ||
        after.lock_contention_drops !=
            before.lock_contention_drops + 1U ||
        after.disabled_drops != before.disabled_drops + 1U ||
        __atomic_load_n(
            &g_flow_sequence[10], __ATOMIC_RELAXED) !=
            flow_sequence + 2U ||
        __atomic_load_n(
            &g_sample_pool[10], __ATOMIC_RELAXED) !=
            sample_pool + 2222U)
        return fail_text(
            "old callback crossed into the new generation/rate");
    if (reset_to_tail(476U, &ack) != 0)
        return 1;

    memset(&event, 0, sizeof(event));
    memset(&shutdown, 0, sizeof(shutdown));
    event.seed = 211U;
    event.port = 11;
    free_before = __atomic_load_n(&g_free_calls, __ATOMIC_RELAXED);
    __atomic_store_n(&g_before_free_entered, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_release_before_free, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_pause_before_free, 1, __ATOMIC_RELEASE);
    if (__atomic_exchange_n(
            &g_producer_gate, 1U, __ATOMIC_ACQ_REL) != 0U)
        return fail_text("producer gate occupied before shutdown fixture");
    if (pthread_create(&event_thread, NULL, emit_once, &event) != 0)
        return fail_text("could not start paused-free callback");
    if (wait_for_flag(
            &g_before_free_entered,
            "contended callback did not reach free hook") != 0)
        return 1;
    if (pthread_create(
            &shutdown_thread, NULL, shutdown_once, &shutdown) != 0)
        return fail_text("could not start capture shutdown");
    if (wait_for_flag(
            &shutdown.started, "capture shutdown did not start") != 0)
        return 1;
    __atomic_store_n(&g_producer_gate, 0U, __ATOMIC_RELEASE);
    for (unsigned int attempt = 0; attempt < 1000U; attempt++)
        sched_yield();
    if (__atomic_load_n(&shutdown.done, __ATOMIC_ACQUIRE) != 0)
        return fail_text(
            "capture shutdown crossed an outstanding SDK free");
    __atomic_store_n(&g_release_before_free, 1, __ATOMIC_RELEASE);
    (void)pthread_join(event_thread, NULL);
    (void)pthread_join(shutdown_thread, NULL);
    __atomic_store_n(&g_pause_before_free, 0, __ATOMIC_RELEASE);
    if (event.rc != 0 ||
        shutdown.rc != 0 ||
        __atomic_load_n(&shutdown.done, __ATOMIC_ACQUIRE) == 0 ||
        __atomic_load_n(
            &g_inflight_callbacks, __ATOMIC_ACQUIRE) != 0 ||
        __atomic_load_n(&g_free_calls, __ATOMIC_RELAXED) !=
            free_before + 1U)
        return fail_text(
            "shutdown did not drain the exact-free callback lifecycle");

    sflow_capture_init();
    if (configure_generation(
            477U, 3333U, true, UINT64_C(376000000000), &ack) != 0)
        return 1;
    memset(&event, 0, sizeof(event));
    memset(&shutdown, 0, sizeof(shutdown));
    event.seed = 212U;
    event.port = 12;
    free_before = __atomic_load_n(&g_free_calls, __ATOMIC_RELAXED);
    __atomic_store_n(&g_before_free_entered, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_release_before_free, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&g_pause_before_free, 1, __ATOMIC_RELEASE);
    sflow_capture_shutdown_begin();
    if (pthread_create(&event_thread, NULL, emit_once, &event) != 0)
        return fail_text("could not start post-close SDK callback");
    if (wait_for_flag(
            &g_before_free_entered,
            "post-close callback did not reach SDK free") != 0)
        return 1;
    if (pthread_create(
            &shutdown_thread, NULL, shutdown_wait_once, &shutdown) != 0)
        return fail_text("could not start post-barrier capture wait");
    if (wait_for_flag(
            &shutdown.started, "capture wait did not start") != 0)
        return 1;
    for (unsigned int attempt = 0; attempt < 1000U; attempt++)
        sched_yield();
    if (__atomic_load_n(&shutdown.done, __ATOMIC_ACQUIRE) != 0)
        return fail_text(
            "capture wait crossed a post-close SDK free");
    __atomic_store_n(&g_release_before_free, 1, __ATOMIC_RELEASE);
    (void)pthread_join(event_thread, NULL);
    (void)pthread_join(shutdown_thread, NULL);
    __atomic_store_n(&g_pause_before_free, 0, __ATOMIC_RELEASE);
    if (event.rc != 0 || shutdown.rc != 0 ||
        __atomic_load_n(&g_free_calls, __ATOMIC_RELAXED) !=
            free_before + 1U ||
        __atomic_load_n(&shutdown.done, __ATOMIC_ACQUIRE) == 0 ||
        __atomic_load_n(
            &g_inflight_callbacks, __ATOMIC_ACQUIRE) != 0)
        return fail_text(
            "post-close callback did not complete before capture finalization");

    sflow_capture_init();
    sflow_capture_shutdown_begin();
    sflow_capture_shutdown_cancel();
    if (sflow_capture_configure(478U, 4444U, true) == 0)
        return fail_text("cancelled shutdown reopened closed capture");
    sflow_capture_shutdown_begin();
    if (sflow_capture_shutdown_wait() != 0)
        return fail_text("cancelled shutdown could not be retried");
    sflow_capture_init();
    return 0;
}

typedef struct {
    nl_sflow_batch_request_v1 request;
    nl_sflow_batch_response_v1 response;
    int rc;
} consumer_job;

static void *consumer_once(void *arg)
{
    consumer_job *job = arg;

    job->rc = drain_retry(&job->request, &job->response);
    return NULL;
}

static int test_concurrent_consumers(void)
{
    pthread_t threads[FIXTURE_CONSUMERS];
    consumer_job jobs[FIXTURE_CONSUMERS];
    u64 ack = 0;

    if (configure_generation(
            501U, 4096U, true, UINT64_C(400000000000), &ack) != 0 ||
        emit_many(256U, 90U, 2) != 0)
        return 1;
    memset(jobs, 0, sizeof(jobs));
    for (unsigned int i = 0; i < FIXTURE_CONSUMERS; i++) {
        request_init(&jobs[i].request, 0, NL_SFLOW_V1_BATCH_MAX,
                     501U, ack);
        if (pthread_create(
                &threads[i], NULL, consumer_once, &jobs[i]) != 0)
            return fail_text("could not start concurrent batch consumer");
    }
    for (unsigned int i = 0; i < FIXTURE_CONSUMERS; i++)
        (void)pthread_join(threads[i], NULL);
    for (unsigned int i = 0; i < FIXTURE_CONSUMERS; i++) {
        if (jobs[i].rc != SFLOW_CAPTURE_DRAIN_OK ||
            jobs[i].response.sample_count != NL_SFLOW_V1_BATCH_MAX ||
            memcmp(&jobs[0].response, &jobs[i].response,
                   sizeof(jobs[i].response)) != 0)
            return fail_text(
                "concurrent consumers observed different/torn batches");
    }
    return 0;
}

typedef struct {
    unsigned int count;
    int failed;
    int done;
} producer_job;

static void *producer_many(void *arg)
{
    producer_job *job = arg;

    for (unsigned int i = 0; i < job->count; i++) {
        int port = 1 + (int)(i % 24U);
        u8 seed = (u8)port;

        if (emit_frame(seed, port) != 0) {
            job->failed = 1;
            break;
        }
    }
    __atomic_store_n(&job->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static int test_concurrent_publish_and_drain_no_torn_sample(void)
{
    nl_sflow_capture_counters_v1 before;
    nl_sflow_capture_counters_v1 after;
    nl_sflow_batch_response_v1 response;
    producer_job job;
    pthread_t producer;
    u64 ack = 0;
    u64 collected = 0;
    u64 last_flow_sequence[NL_SFLOW_V1_MAX_PORTS + 1U];
    u32 last_sample_pool[NL_SFLOW_V1_MAX_PORTS + 1U];
    bool flow_seen[NL_SFLOW_V1_MAX_PORTS + 1U];

    if (configure_generation(
            601U, 4096U, true, UINT64_C(500000000000), &ack) != 0)
        return 1;
    sflow_capture_snapshot(&before);
    memset(&job, 0, sizeof(job));
    memset(last_flow_sequence, 0, sizeof(last_flow_sequence));
    memset(last_sample_pool, 0, sizeof(last_sample_pool));
    memset(flow_seen, 0, sizeof(flow_seen));
    job.count = FIXTURE_CONCURRENT_EVENTS;
    if (pthread_create(&producer, NULL, producer_many, &job) != 0)
        return fail_text("could not start concurrent capture producer");

    for (;;) {
        int rc = drain_after(
            601U, ack, NL_SFLOW_V1_BATCH_MAX, &response);

        if (rc != SFLOW_CAPTURE_DRAIN_OK) {
            (void)pthread_join(producer, NULL);
            return fail_text("concurrent batch drain failed");
        }
        if (!validate_batch_cursor(&response, ack)) {
            (void)pthread_join(producer, NULL);
            return fail_text("concurrent batch cursor was torn/reordered");
        }
        for (u32 i = 0; i < response.sample_count; i++) {
            const nl_sflow_sample_v1 *sample = &response.samples[i];
            u8 seed = (u8)sample->input_port;

            if (sample->input_port < 1U || sample->input_port > 24U ||
                sample->sampling_rate != 4096U ||
                sample->config_generation != 601U ||
                sample->capture_monotonic_ns !=
                    UINT64_C(500000000000) ||
                sample->source_vlan !=
                    (u16)(100U + sample->input_port) ||
                sample->source_priority !=
                    (u8)(sample->input_port & 7U) ||
                !sample_header_valid(sample, seed)) {
                (void)pthread_join(producer, NULL);
                return fail_text("consumer observed a torn sample");
            }
            if (flow_seen[sample->input_port] &&
                (sample->sequence !=
                     last_flow_sequence[sample->input_port] + 1U ||
                 sample->sample_pool !=
                     last_sample_pool[sample->input_port] + 4096U)) {
                (void)pthread_join(producer, NULL);
                return fail_text(
                    "per-port sFlow counters were torn or reordered");
            }
            flow_seen[sample->input_port] = true;
            last_flow_sequence[sample->input_port] = sample->sequence;
            last_sample_pool[sample->input_port] = sample->sample_pool;
        }
        if (response.sample_count > 0U) {
            ack = response.next_sequence - 1U;
            collected += response.sample_count;
        }
        if (__atomic_load_n(&job.done, __ATOMIC_ACQUIRE) != 0 &&
            response.sample_count == 0U)
            break;
        sched_yield();
    }
    (void)pthread_join(producer, NULL);
    if (job.failed)
        return fail_text("concurrent capture producer failed");

    for (;;) {
        if (drain_after(
                601U, ack, NL_SFLOW_V1_BATCH_MAX, &response) !=
            SFLOW_CAPTURE_DRAIN_OK)
            return fail_text("final concurrent drain failed");
        if (response.sample_count == 0U)
            break;
        if (!validate_batch_cursor(&response, ack))
            return fail_text("final concurrent batch cursor was reordered");
        ack = response.next_sequence - 1U;
        collected += response.sample_count;
    }
    sflow_capture_snapshot(&after);
    if (collected != after.accepted - before.accepted)
        return fail_text("concurrent drain lost or duplicated accepted samples");
    return 0;
}

static int test_terminal_counter_equation_and_shutdown(void)
{
    static const int lengths[] = {64};
    fixture_chain chain;
    nl_sflow_capture_counters_v1 counters;
    nl_sflow_capture_counters_v1 after;
    u64 owned;

    sflow_capture_snapshot(&counters);
    if (counters.callback_events !=
        counters.accepted +
        counters.disabled_drops +
        counters.invalid_chain_drops +
        counters.lock_contention_drops +
        counters.token_bucket_drops)
        return fail_text("terminal callback counter equation is not exact");
    if (counters.buffer_free_failures > counters.callback_events)
        return fail_text("free failures exceed owned callback events");

    sflow_capture_shutdown();
    (void)fixture_chain_build(&chain, lengths, 1U, 200U);
    if (emit_chain(0, &chain, 1, 101, 1) != 0)
        return 1;
    sflow_capture_snapshot(&after);
    if (after.accepted != counters.accepted ||
        after.disabled_drops != counters.disabled_drops + 1U)
        return fail_text("post-shutdown callback published into the ring");

    owned = __atomic_load_n(&g_owned_events, __ATOMIC_RELAXED);
    if (__atomic_load_n(&g_free_calls, __ATOMIC_RELAXED) != owned)
        return fail_text("owned SDK chains were not freed exactly once");
    return 0;
}

int main(void)
{
    sflow_capture_init();
    if (test_chain_fcs_metadata_and_ownership() != 0)
        return 1;
    if (test_token_bucket_boundaries() != 0)
        return 1;
    if (test_ring_ack_and_batch_semantics() != 0)
        return 1;
    if (test_generation_and_reset_semantics() != 0)
        return 1;
    if (test_deterministic_gate_contention() != 0)
        return 1;
    if (test_concurrent_consumers() != 0)
        return 1;
    if (test_concurrent_publish_and_drain_no_torn_sample() != 0)
        return 1;
    if (test_generation_barrier_and_shutdown_drain() != 0)
        return 1;
    if (test_terminal_counter_equation_and_shutdown() != 0)
        return 1;
    puts("PASS: switchd sFlow Stage2 ring, token, batch, and concurrency");
    return 0;
}
