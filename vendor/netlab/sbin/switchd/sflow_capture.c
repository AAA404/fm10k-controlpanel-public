/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "sflow_capture.h"

#include <stddef.h>
#include <sched.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#define SFLOW_MODE_ENABLED (UINT64_C(1) << 63)
#define SFLOW_MODE_RATE_MASK UINT64_C(0xffffffff)
#define SFLOW_NSEC_PER_SEC UINT64_C(1000000000)
#define SFLOW_RING_MASK (NL_SFLOW_V1_RING_CAPACITY - 1U)
#define SFLOW_SAMPLE_WORDS \
    (sizeof(nl_sflow_sample_v1) / sizeof(u64))

#ifndef SFLOW_CAPTURE_AFTER_ENTRY_EPOCH
#define SFLOW_CAPTURE_AFTER_ENTRY_EPOCH() ((void)0)
#endif
#ifndef SFLOW_CAPTURE_BEFORE_BUFFER_FREE
#define SFLOW_CAPTURE_BEFORE_BUFFER_FREE() ((void)0)
#endif
#ifndef SFLOW_CAPTURE_BEFORE_RING_COPY
#define SFLOW_CAPTURE_BEFORE_RING_COPY(cursor) ((void)(cursor))
#endif
typedef struct {
    u64 cursor;
    u64 words[SFLOW_SAMPLE_WORDS];
} sflow_capture_slot;

_Static_assert(
    (NL_SFLOW_V1_RING_CAPACITY &
     (NL_SFLOW_V1_RING_CAPACITY - 1U)) == 0,
    "sFlow capture ring capacity must be a power of two");
_Static_assert(
    sizeof(nl_sflow_sample_v1) % sizeof(u64) == 0,
    "sFlow sample must be representable as atomic words");
_Static_assert(
    _Generic((u64)0,
        unsigned long: ATOMIC_LONG_LOCK_FREE,
        unsigned long long: ATOMIC_LLONG_LOCK_FREE,
        default: 0) == 2,
    "sFlow callback requires lock-free 64-bit atomics");
_Static_assert(
    _Generic((u32)0,
        unsigned int: ATOMIC_INT_LOCK_FREE,
        unsigned long: ATOMIC_LONG_LOCK_FREE,
        default: 0) == 2,
    "sFlow callback requires lock-free 32-bit atomics");

static sflow_capture_slot g_ring[NL_SFLOW_V1_RING_CAPACITY];
static nl_sflow_capture_counters_v1 g_counters;
static u64 g_flow_sequence[NL_SFLOW_V1_MAX_PORTS + 1U];
static u32 g_sample_pool[NL_SFLOW_V1_MAX_PORTS + 1U];

static u32 g_initialized;
static u32 g_control_gate;
static u32 g_producer_gate;
static u32 g_consumer_gate;
static u64 g_epoch_sequence;
static u64 g_inflight_callbacks;
static u64 g_mode;
static u64 g_transition_mode;
static u64 g_generation;
static u64 g_latest_cursor;
static u64 g_floor_cursor = UINT64_C(1);
static u64 g_acked_cursor;
static u64 g_delivered_cursor;

/* Accessed only while the producer gate is held. */
static u32 g_bucket_tokens = NL_SFLOW_V1_TOKEN_BURST;
static u64 g_bucket_last_ns;
static u64 g_bucket_remainder;
static bool g_bucket_started;

#ifndef SFLOW_CAPTURE_MONOTONIC_NS
static int sflow_capture_monotonic_ns(u64 *out)
{
    struct timespec now;

    if (!out || clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec < 0 || now.tv_nsec < 0 ||
        now.tv_nsec >= (long)SFLOW_NSEC_PER_SEC)
        return -1;
    if ((u64)now.tv_sec >
        (UINT64_MAX - (u64)now.tv_nsec) / SFLOW_NSEC_PER_SEC)
        return -1;
    *out = (u64)now.tv_sec * SFLOW_NSEC_PER_SEC + (u64)now.tv_nsec;
    return 0;
}
#define SFLOW_CAPTURE_MONOTONIC_NS(out) \
    sflow_capture_monotonic_ns((out))
#endif

static void counter_increment(u64 *counter)
{
    (void)__atomic_fetch_add(counter, UINT64_C(1), __ATOMIC_RELAXED);
}

static u64 counter_load(const u64 *counter)
{
    return __atomic_load_n(counter, __ATOMIC_RELAXED);
}

static u64 mode_make(bool enabled, u32 effective_rate)
{
    return (enabled ? SFLOW_MODE_ENABLED : UINT64_C(0)) |
        (u64)effective_rate;
}

static bool mode_enabled(u64 mode)
{
    return (mode & SFLOW_MODE_ENABLED) != 0;
}

static u32 mode_rate(u64 mode)
{
    return (u32)(mode & SFLOW_MODE_RATE_MASK);
}

static bool gate_try_enter(u32 *gate)
{
    u32 expected = 0;

    return __atomic_compare_exchange_n(
        gate, &expected, 1U, false, __ATOMIC_ACQUIRE,
        __ATOMIC_RELAXED);
}

static void gate_enter(u32 *gate)
{
    while (!gate_try_enter(gate))
        (void)sched_yield();
}

static void gate_leave(u32 *gate)
{
    __atomic_store_n(gate, 0U, __ATOMIC_RELEASE);
}

static u64 epoch_transition_begin(void)
{
    u64 sequence =
        __atomic_load_n(&g_epoch_sequence, __ATOMIC_SEQ_CST);

    if ((sequence & UINT64_C(1)) == 0)
        sequence++;
    __atomic_store_n(&g_epoch_sequence, sequence, __ATOMIC_SEQ_CST);
    return sequence;
}

static void epoch_transition_complete(u64 odd_sequence)
{
    __atomic_store_n(
        &g_epoch_sequence, odd_sequence + UINT64_C(1),
        __ATOMIC_SEQ_CST);
}

static void capture_counters_snapshot(nl_sflow_capture_counters_v1 *out)
{
    out->callback_events = counter_load(&g_counters.callback_events);
    out->accepted = counter_load(&g_counters.accepted);
    out->disabled_drops = counter_load(&g_counters.disabled_drops);
    out->invalid_chain_drops =
        counter_load(&g_counters.invalid_chain_drops);
    out->lock_contention_drops =
        counter_load(&g_counters.lock_contention_drops);
    out->token_bucket_drops =
        counter_load(&g_counters.token_bucket_drops);
    out->ring_overwrites = counter_load(&g_counters.ring_overwrites);
    out->buffer_free_failures =
        counter_load(&g_counters.buffer_free_failures);
}

static bool capture_sample_build(
    const fm_eventPktRecv *pkt, const fm_buffer *chain,
    nl_sflow_sample_v1 *sample)
{
    const fm_buffer *node;
    u32 copied = 0;
    u32 frame_length = 0;
    u32 nodes = 0;
    u32 header_length;

    if (!pkt || !chain || !sample ||
        pkt->srcPort < 1 ||
        pkt->srcPort > (fm_int)NL_SFLOW_V1_MAX_PORTS ||
        pkt->vlan < 0 || pkt->vlan > 4095 ||
        pkt->vlanPriority < 0 || pkt->vlanPriority > 7)
        return false;

    memset(sample, 0, sizeof(*sample));
    for (node = chain; node; node = node->next) {
        u32 chunk;
        u32 remaining;
        u32 take;

        nodes++;
        if (nodes > NL_SFLOW_V1_MAX_CHAIN_NODES ||
            !node->data || node->len <= 0 ||
            node->len > (int)NL_SFLOW_V1_CHUNK_BYTES)
            return false;
        chunk = (u32)node->len;
        if (chunk > NL_SFLOW_V1_MAX_FRAME_BYTES - frame_length)
            return false;
        remaining = NL_SFLOW_V1_HEADER_BYTES - copied;
        take = chunk < remaining ? chunk : remaining;
        if (take > 0) {
            memcpy(sample->header + copied, (const u8 *)node->data, take);
            copied += take;
        }
        frame_length += chunk;
    }
    if (frame_length < NL_SFLOW_V1_STRIPPED_BYTES)
        return false;

    header_length = frame_length - NL_SFLOW_V1_STRIPPED_BYTES;
    if (header_length > NL_SFLOW_V1_HEADER_BYTES)
        header_length = NL_SFLOW_V1_HEADER_BYTES;
    if (header_length < NL_SFLOW_V1_HEADER_BYTES) {
        memset(sample->header + header_length, 0,
               NL_SFLOW_V1_HEADER_BYTES - header_length);
    }
    sample->frame_length = frame_length;
    sample->input_port = (u32)pkt->srcPort;
    sample->stripped = NL_SFLOW_V1_STRIPPED_BYTES;
    sample->source_vlan = (u16)pkt->vlan;
    sample->source_priority = (u8)pkt->vlanPriority;
    sample->header_length = (u8)header_length;
    return true;
}

static void token_bucket_refill(u64 now_ns)
{
    u64 elapsed;
    u64 missing;
    u64 needed_units;
    u64 needed_ns;
    u64 units;
    u64 added;

    if (!g_bucket_started) {
        g_bucket_started = true;
        g_bucket_last_ns = now_ns;
        return;
    }
    if (now_ns <= g_bucket_last_ns)
        return;
    if (g_bucket_tokens >= NL_SFLOW_V1_TOKEN_BURST) {
        g_bucket_tokens = NL_SFLOW_V1_TOKEN_BURST;
        g_bucket_remainder = 0;
        g_bucket_last_ns = now_ns;
        return;
    }

    elapsed = now_ns - g_bucket_last_ns;
    missing = (u64)NL_SFLOW_V1_TOKEN_BURST - g_bucket_tokens;
    needed_units = missing * SFLOW_NSEC_PER_SEC;
    if (needed_units > g_bucket_remainder)
        needed_units -= g_bucket_remainder;
    else
        needed_units = 0;
    needed_ns = (needed_units +
                 (u64)NL_SFLOW_V1_TOKEN_RATE - 1U) /
        (u64)NL_SFLOW_V1_TOKEN_RATE;
    if (elapsed >= needed_ns) {
        g_bucket_tokens = NL_SFLOW_V1_TOKEN_BURST;
        g_bucket_remainder = 0;
        g_bucket_last_ns = now_ns;
        return;
    }

    /*
     * elapsed is smaller than the time needed to refill a 4096-token
     * bucket, so this multiplication is bounded to a few trillion.
     */
    units = elapsed * (u64)NL_SFLOW_V1_TOKEN_RATE +
        g_bucket_remainder;
    added = units / SFLOW_NSEC_PER_SEC;
    g_bucket_remainder = units % SFLOW_NSEC_PER_SEC;
    g_bucket_tokens += (u32)added;
    g_bucket_last_ns = now_ns;
}

static void flow_counters_advance(
    u32 input_port, u32 effective_rate, nl_sflow_sample_v1 *sample)
{
    u64 sequence;
    u32 pool;

    sequence = __atomic_add_fetch(
        &g_flow_sequence[input_port], UINT64_C(1), __ATOMIC_RELAXED);
    pool = __atomic_add_fetch(
        &g_sample_pool[input_port], effective_rate, __ATOMIC_RELAXED);
    if (sample) {
        sample->sequence = sequence;
        sample->sample_pool = pool;
        sample->sampling_rate = effective_rate;
    }
}

static void ring_publish(
    u64 cursor, const nl_sflow_sample_v1 *sample)
{
    sflow_capture_slot *slot =
        &g_ring[(u32)((cursor - UINT64_C(1)) & SFLOW_RING_MASK)];
    size_t i;

    /*
     * All slot operations are sequentially consistent.  A reader that sees
     * any word from this publication must therefore see either the
     * invalidating zero or the final cursor on its second cursor load.  This
     * is intentionally stronger than the surrounding ring atomics so the
     * snapshot proof also holds on weakly ordered targets.
     */
    __atomic_store_n(&slot->cursor, UINT64_C(0), __ATOMIC_SEQ_CST);
    for (i = 0; i < SFLOW_SAMPLE_WORDS; i++) {
        u64 word;

        memcpy(&word, (const u8 *)sample + i * sizeof(word), sizeof(word));
        __atomic_store_n(&slot->words[i], word, __ATOMIC_SEQ_CST);
    }
    __atomic_store_n(&slot->cursor, cursor, __ATOMIC_SEQ_CST);
}

static bool ring_copy(
    u64 cursor, nl_sflow_sample_v1 *sample)
{
    const sflow_capture_slot *slot =
        &g_ring[(u32)((cursor - UINT64_C(1)) & SFLOW_RING_MASK)];
    u64 observed;
    size_t i;

    observed = __atomic_load_n(&slot->cursor, __ATOMIC_SEQ_CST);
    if (observed != cursor)
        return false;
    for (i = 0; i < SFLOW_SAMPLE_WORDS; i++) {
        u64 word = __atomic_load_n(
            &slot->words[i], __ATOMIC_SEQ_CST);

        memcpy((u8 *)sample + i * sizeof(word), &word, sizeof(word));
    }
    return __atomic_load_n(
        &slot->cursor, __ATOMIC_SEQ_CST) == cursor;
}

static u64 retained_oldest(u64 latest, u64 floor)
{
    u64 physical;

    if (floor > latest)
        return latest + UINT64_C(1);
    physical = latest > (u64)NL_SFLOW_V1_RING_CAPACITY ?
        latest - (u64)NL_SFLOW_V1_RING_CAPACITY + UINT64_C(1) :
        UINT64_C(1);
    return floor > physical ? floor : physical;
}

void sflow_capture_init(void)
{
    u64 odd_sequence;
    u64 latest;

    gate_enter(&g_control_gate);
    __atomic_store_n(
        &g_transition_mode,
        __atomic_load_n(&g_mode, __ATOMIC_SEQ_CST),
        __ATOMIC_SEQ_CST);
    odd_sequence = epoch_transition_begin();
    gate_enter(&g_producer_gate);
    while (__atomic_load_n(
               &g_inflight_callbacks, __ATOMIC_SEQ_CST) != 0)
        (void)sched_yield();
    gate_enter(&g_consumer_gate);
    latest = __atomic_load_n(&g_latest_cursor, __ATOMIC_ACQUIRE);
    __atomic_store_n(
        &g_generation, UINT64_C(0), __ATOMIC_RELEASE);
    __atomic_store_n(
        &g_floor_cursor, latest + UINT64_C(1), __ATOMIC_RELEASE);
    __atomic_store_n(&g_acked_cursor, latest, __ATOMIC_RELEASE);
    __atomic_store_n(&g_delivered_cursor, latest, __ATOMIC_RELEASE);
    g_bucket_tokens = NL_SFLOW_V1_TOKEN_BURST;
    g_bucket_last_ns = 0;
    g_bucket_remainder = 0;
    g_bucket_started = false;
    __atomic_store_n(&g_mode, UINT64_C(0), __ATOMIC_RELEASE);
    gate_leave(&g_consumer_gate);
    __atomic_store_n(&g_initialized, 1U, __ATOMIC_RELEASE);
    epoch_transition_complete(odd_sequence);
    gate_leave(&g_producer_gate);
    gate_leave(&g_control_gate);
}

void sflow_capture_shutdown_begin(void)
{
    gate_enter(&g_control_gate);
    __atomic_store_n(
        &g_transition_mode,
        __atomic_load_n(&g_mode, __ATOMIC_SEQ_CST),
        __ATOMIC_SEQ_CST);
    (void)epoch_transition_begin();
    __atomic_store_n(&g_initialized, 0U, __ATOMIC_RELEASE);
}

void sflow_capture_shutdown_cancel(void)
{
    /*
     * Capture remains closed and the epoch remains odd.  The SDK owner must
     * keep the SDK alive, then may retry begin -> event barrier -> wait.
     */
    gate_leave(&g_control_gate);
}

int sflow_capture_shutdown_wait(void)
{
    /*
     * The caller has already crossed the SDK event barrier, so no new sFlow
     * callback can be admitted.  The producer gate plus the SC admission
     * counter now form an exact final ownership barrier.
     */
    gate_enter(&g_producer_gate);
    while (__atomic_load_n(
               &g_inflight_callbacks, __ATOMIC_SEQ_CST) != 0)
        (void)sched_yield();
    __atomic_store_n(&g_mode, UINT64_C(0), __ATOMIC_RELEASE);
    gate_leave(&g_producer_gate);
    gate_leave(&g_control_gate);
    return 0;
}

int sflow_capture_shutdown(void)
{
    sflow_capture_shutdown_begin();
    return sflow_capture_shutdown_wait();
}

int sflow_capture_configure(
    u64 generation, u32 effective_rate, bool enabled)
{
    u64 odd_sequence;
    u64 old_mode;
    u64 latest;
    bool changed;

    if (enabled &&
        (generation == 0 || effective_rate == 0 ||
         effective_rate > NL_SFLOW_V1_RATE_MODULUS))
        return -1;
    if (!enabled && effective_rate > NL_SFLOW_V1_RATE_MODULUS)
        return -1;
    gate_enter(&g_control_gate);
    if (enabled &&
        __atomic_load_n(&g_initialized, __ATOMIC_ACQUIRE) == 0) {
        gate_leave(&g_control_gate);
        return -1;
    }
    gate_enter(&g_producer_gate);
    old_mode = __atomic_load_n(&g_mode, __ATOMIC_ACQUIRE);
    changed =
        __atomic_load_n(&g_generation, __ATOMIC_ACQUIRE) != generation ||
        mode_rate(old_mode) != effective_rate ||
        mode_enabled(old_mode) != enabled;
    if (!changed) {
        gate_leave(&g_producer_gate);
        gate_leave(&g_control_gate);
        return 0;
    }

    __atomic_store_n(
        &g_transition_mode, old_mode, __ATOMIC_SEQ_CST);
    odd_sequence = epoch_transition_begin();
    while (__atomic_load_n(
               &g_inflight_callbacks, __ATOMIC_SEQ_CST) != 0)
        (void)sched_yield();
    gate_enter(&g_consumer_gate);
    latest = __atomic_load_n(&g_latest_cursor, __ATOMIC_ACQUIRE);
    __atomic_store_n(&g_generation, generation, __ATOMIC_RELEASE);
    __atomic_store_n(
        &g_floor_cursor, latest + UINT64_C(1), __ATOMIC_RELEASE);
    __atomic_store_n(&g_acked_cursor, latest, __ATOMIC_RELEASE);
    __atomic_store_n(&g_delivered_cursor, latest, __ATOMIC_RELEASE);
    g_bucket_tokens = NL_SFLOW_V1_TOKEN_BURST;
    g_bucket_last_ns = 0;
    g_bucket_remainder = 0;
    g_bucket_started = false;
    gate_leave(&g_consumer_gate);
    __atomic_store_n(
        &g_mode, mode_make(enabled, effective_rate), __ATOMIC_RELEASE);
    epoch_transition_complete(odd_sequence);
    gate_leave(&g_producer_gate);
    gate_leave(&g_control_gate);
    return 0;
}

void sflow_capture_handle_event(int sw, fm_eventPktRecv *pkt)
{
    nl_sflow_sample_v1 sample;
    fm_buffer *chain;
    fm_status free_status;
    u64 entry_epoch;
    u64 entry_generation;
    u64 entry_mode;
    u64 current_epoch;
    u64 current_generation;
    u64 current_mode;
    u64 gap_mode;
    u64 now_ns;
    u64 cursor;
    u64 acked;
    u32 effective_rate;
    u32 input_port = 0;
    bool producer_owned = false;

    (void)__atomic_fetch_add(
        &g_inflight_callbacks, UINT64_C(1), __ATOMIC_SEQ_CST);
    counter_increment(&g_counters.callback_events);
    if (!pkt || !pkt->pkt) {
        counter_increment(&g_counters.invalid_chain_drops);
        goto release_inflight;
    }

    /*
     * Transfer ownership before any fallible work.  Every path below reaches
     * the single SDK release and the event can never be retried.
     */
    chain = (fm_buffer *)pkt->pkt;
    pkt->pkt = NULL;
    entry_epoch =
        __atomic_load_n(&g_epoch_sequence, __ATOMIC_SEQ_CST);
    SFLOW_CAPTURE_AFTER_ENTRY_EPOCH();
    entry_mode = __atomic_load_n(&g_mode, __ATOMIC_ACQUIRE);
    entry_generation =
        __atomic_load_n(&g_generation, __ATOMIC_ACQUIRE);
    if (pkt->srcPort >= 1 &&
        pkt->srcPort <= (fm_int)NL_SFLOW_V1_MAX_PORTS)
        input_port = (u32)pkt->srcPort;
    if (__atomic_load_n(&g_initialized, __ATOMIC_ACQUIRE) == 0 ||
        (entry_epoch & UINT64_C(1)) != 0 ||
        !mode_enabled(entry_mode)) {
        gap_mode = (entry_epoch & UINT64_C(1)) != 0 ||
            __atomic_load_n(&g_initialized, __ATOMIC_ACQUIRE) == 0 ?
            __atomic_load_n(
                &g_transition_mode, __ATOMIC_SEQ_CST) :
            entry_mode;
        if (input_port != 0 && mode_enabled(gap_mode))
            flow_counters_advance(
                input_port, mode_rate(gap_mode), NULL);
        counter_increment(&g_counters.disabled_drops);
        goto release_chain;
    }

    if (!gate_try_enter(&g_producer_gate)) {
        if (input_port != 0)
            flow_counters_advance(
                input_port, mode_rate(entry_mode), NULL);
        counter_increment(&g_counters.lock_contention_drops);
        goto release_chain;
    }
    producer_owned = true;
    current_epoch =
        __atomic_load_n(&g_epoch_sequence, __ATOMIC_SEQ_CST);
    current_mode = __atomic_load_n(&g_mode, __ATOMIC_ACQUIRE);
    current_generation =
        __atomic_load_n(&g_generation, __ATOMIC_ACQUIRE);
    if (__atomic_load_n(&g_initialized, __ATOMIC_ACQUIRE) == 0 ||
        (current_epoch & UINT64_C(1)) != 0 ||
        current_epoch != entry_epoch ||
        current_mode != entry_mode ||
        current_generation != entry_generation) {
        if (input_port != 0)
            flow_counters_advance(
                input_port, mode_rate(entry_mode), NULL);
        counter_increment(&g_counters.disabled_drops);
        goto release_producer;
    }
    if (!capture_sample_build(pkt, chain, &sample)) {
        if (input_port != 0)
            flow_counters_advance(
                input_port, mode_rate(entry_mode), NULL);
        counter_increment(&g_counters.invalid_chain_drops);
        goto release_producer;
    }

    effective_rate = mode_rate(entry_mode);
    flow_counters_advance(
        sample.input_port, effective_rate, &sample);
    sample.config_generation = entry_generation;
    if (SFLOW_CAPTURE_MONOTONIC_NS(&now_ns) != 0) {
        counter_increment(&g_counters.token_bucket_drops);
        goto release_producer;
    }
    token_bucket_refill(now_ns);
    if (g_bucket_tokens == 0) {
        counter_increment(&g_counters.token_bucket_drops);
        goto release_producer;
    }
    g_bucket_tokens--;
    sample.capture_monotonic_ns = now_ns;

    cursor = __atomic_load_n(
        &g_latest_cursor, __ATOMIC_RELAXED) + UINT64_C(1);
    acked = __atomic_load_n(&g_acked_cursor, __ATOMIC_ACQUIRE);
    if (cursor > acked &&
        cursor - acked > (u64)NL_SFLOW_V1_RING_CAPACITY)
        counter_increment(&g_counters.ring_overwrites);
    ring_publish(cursor, &sample);
    __atomic_store_n(&g_latest_cursor, cursor, __ATOMIC_RELEASE);
    counter_increment(&g_counters.accepted);

release_producer:
release_chain:
    SFLOW_CAPTURE_BEFORE_BUFFER_FREE();
    free_status = fmFreeBufferChain(sw, chain);
    if (free_status != FM_OK)
        counter_increment(&g_counters.buffer_free_failures);
    if (producer_owned)
        gate_leave(&g_producer_gate);
release_inflight:
    (void)__atomic_fetch_sub(
        &g_inflight_callbacks, UINT64_C(1), __ATOMIC_SEQ_CST);
}

void sflow_capture_snapshot(nl_sflow_capture_counters_v1 *out)
{
    if (out)
        capture_counters_snapshot(out);
}

int sflow_capture_drain(
    const nl_sflow_batch_request_v1 *request,
    nl_sflow_batch_response_v1 *response)
{
    const size_t response_base =
        offsetof(nl_sflow_batch_response_v1, samples);
    u64 generation;
    u64 latest;
    u64 floor;
    u64 oldest;
    u64 acked;
    u64 delivered;
    u64 cursor;
    u64 last_delivered = 0;

    if (!request || !response ||
        request->version != NL_SFLOW_V1_VERSION ||
        request->size != sizeof(*request) ||
        (request->flags & ~NL_SFLOW_BATCH_F_ALL) != 0 ||
        request->max_samples == 0 ||
        request->max_samples > NL_SFLOW_V1_BATCH_MAX ||
        ((request->flags & NL_SFLOW_BATCH_F_RESET_TO_TAIL) != 0 &&
         request->ack_sequence != 0))
        return SFLOW_CAPTURE_DRAIN_INVALID;
    if (!gate_try_enter(&g_consumer_gate))
        return SFLOW_CAPTURE_DRAIN_BUSY;

    memset(response, 0, sizeof(*response));
    generation = __atomic_load_n(&g_generation, __ATOMIC_ACQUIRE);
    latest = __atomic_load_n(&g_latest_cursor, __ATOMIC_ACQUIRE);
    floor = __atomic_load_n(&g_floor_cursor, __ATOMIC_ACQUIRE);
    oldest = retained_oldest(latest, floor);
    acked = __atomic_load_n(&g_acked_cursor, __ATOMIC_ACQUIRE);
    delivered = __atomic_load_n(
        &g_delivered_cursor, __ATOMIC_ACQUIRE);

    response->version = NL_SFLOW_V1_VERSION;
    response->generation = generation;
    response->oldest_sequence = oldest;
    response->latest_sequence = latest;

    if (request->generation != generation) {
        response->flags |= NL_SFLOW_BATCH_RESP_F_CURSOR_RESET;
        response->acked_sequence = latest;
        response->next_sequence = latest + UINT64_C(1);
        if (delivered < latest) {
            __atomic_store_n(
                &g_delivered_cursor, latest, __ATOMIC_RELEASE);
        }
        goto complete;
    }

    if ((request->flags & NL_SFLOW_BATCH_F_RESET_TO_TAIL) != 0) {
        acked = latest;
        delivered = latest;
        __atomic_store_n(&g_acked_cursor, acked, __ATOMIC_RELEASE);
        __atomic_store_n(
            &g_delivered_cursor, delivered, __ATOMIC_RELEASE);
        response->flags |= NL_SFLOW_BATCH_RESP_F_CURSOR_RESET;
        response->acked_sequence = acked;
        response->next_sequence = latest + UINT64_C(1);
        goto complete;
    }

    if (request->ack_sequence > delivered) {
        gate_leave(&g_consumer_gate);
        return SFLOW_CAPTURE_DRAIN_INVALID;
    }
    if (request->ack_sequence > acked) {
        acked = request->ack_sequence;
        __atomic_store_n(&g_acked_cursor, acked, __ATOMIC_RELEASE);
    }
    if (acked + UINT64_C(1) < oldest) {
        response->lost_before =
            oldest - (acked + UINT64_C(1));
        acked = oldest - UINT64_C(1);
        __atomic_store_n(&g_acked_cursor, acked, __ATOMIC_RELEASE);
        if (delivered < acked) {
            delivered = acked;
            __atomic_store_n(
                &g_delivered_cursor, delivered, __ATOMIC_RELEASE);
        }
        response->flags |= NL_SFLOW_BATCH_RESP_F_CURSOR_RESET;
    }
    response->acked_sequence = acked;
    cursor = acked + UINT64_C(1);
    if (cursor < oldest)
        cursor = oldest;
    response->next_sequence = cursor;

    while (cursor <= latest &&
           response->sample_count < request->max_samples) {
        nl_sflow_sample_v1 *sample =
            &response->samples[response->sample_count];

        SFLOW_CAPTURE_BEFORE_RING_COPY(cursor);
        if (!ring_copy(cursor, sample))
            break;
        response->sample_count++;
        last_delivered = cursor;
        cursor++;
    }
    response->next_sequence = cursor;
    if (last_delivered > delivered) {
        __atomic_store_n(
            &g_delivered_cursor, last_delivered, __ATOMIC_RELEASE);
    }

complete:
    capture_counters_snapshot(&response->counters);
    response->size = (u32)(
        response_base +
        (size_t)response->sample_count * sizeof(response->samples[0]));
    gate_leave(&g_consumer_gate);
    return SFLOW_CAPTURE_DRAIN_OK;
}
