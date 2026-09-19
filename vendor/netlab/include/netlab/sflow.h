#ifndef NETLAB_SFLOW_H
#define NETLAB_SFLOW_H

#include "types.h"
#include <stddef.h>

#define NL_SFLOW_V1_VERSION             1U
#define NL_SFLOW_V1_SAMPLER_ID          0U
#define NL_SFLOW_V1_MIRROR_GROUP        31U
#define NL_SFLOW_V1_MAX_PORTS           24U
#define NL_SFLOW_V1_MIN_SAMPLE_RATE     1U
#define NL_SFLOW_V1_MAX_SAMPLE_RATE     UINT32_C(0x00ffffff)
#define NL_SFLOW_V1_RATE_MODULUS        UINT32_C(0x01000000)
#define NL_SFLOW_V1_HEADER_BYTES        128U
#define NL_SFLOW_V1_MAX_FRAME_BYTES     9240U
#define NL_SFLOW_V1_MAX_CHAIN_NODES     10U
#define NL_SFLOW_V1_CHUNK_BYTES         1024U
#define NL_SFLOW_V1_STRIPPED_BYTES      4U
#define NL_SFLOW_V1_RING_CAPACITY       4096U
#define NL_SFLOW_V1_BATCH_MAX           128U
#define NL_SFLOW_V1_BATCH_INTERVAL_MS   50U
#define NL_SFLOW_V1_TOKEN_RATE          2048U
#define NL_SFLOW_V1_TOKEN_BURST         4096U
#define NL_SFLOW_V1_UDP_MAX_BYTES       1400U
#define NL_SFLOW_V1_DATAGRAM_MAX_SAMPLES 6U
#define NL_SFLOW_V1_DEFAULT_COLLECTOR_PORT 6343U
#define NL_SFLOW_V1_PROBE_REQUEST_MAX     256U
#define NL_SFLOW_V1_PROBE_RESPONSE_MAX    8192U

#define NL_SFLOW_V1_PROBE_ACK \
    "NETLAB_ENABLE_SFLOW_SDK_LIVE_PROBE"

#define NL_SFLOW_BATCH_F_RESET_TO_TAIL UINT32_C(0x00000001)
#define NL_SFLOW_BATCH_F_ALL           NL_SFLOW_BATCH_F_RESET_TO_TAIL

#define NL_SFLOW_BATCH_RESP_F_CURSOR_RESET UINT32_C(0x00000001)
#define NL_SFLOW_BATCH_RESP_F_ALL \
    NL_SFLOW_BATCH_RESP_F_CURSOR_RESET

typedef struct {
    u32 version;
    u32 size;
    u64 generation;
    u32 requested_rate;
    u16 collector_port;
    u8 enabled;
    u8 reserved;
    u8 collector_ipv4[4];
    u8 agent_ipv4[4];
} nl_sflow_config_snapshot_v1;

typedef struct {
    u32 version;
    u32 size;
    u64 target_generation;
} nl_sflow_reload_request_v1;

typedef struct {
    u32 version;
    u32 size;
    u64 sample_count;
    u32 sampler_id;
    u32 mirror_group;
    u32 requested_rate;
    u32 effective_rate;
    s32 trap_code;
    s32 mirror_trap_code;
    u32 port_count;
    u8 exists;
    u8 type;
    u16 vlan;
    u32 ports[NL_SFLOW_V1_MAX_PORTS];
} nl_sflow_hw_state_v1;

typedef struct {
    u64 callback_events;
    u64 accepted;
    u64 disabled_drops;
    u64 invalid_chain_drops;
    u64 lock_contention_drops;
    u64 token_bucket_drops;
    u64 ring_overwrites;
    u64 buffer_free_failures;
} nl_sflow_capture_counters_v1;

/*
 * sequence and sample_pool are sFlow data-source counters scoped to
 * input_port.  They are not the batch-ring cursor: dropped software samples
 * can therefore create sequence gaps while the batch cursor remains
 * contiguous.  sample_pool advances by the effective hardware sampling rate.
 */
typedef struct {
    u64 sequence;
    u64 capture_monotonic_ns;
    u64 config_generation;
    u32 frame_length;
    u32 sampling_rate;
    u32 input_port;
    u32 stripped;
    u16 source_vlan;
    u8 source_priority;
    u8 header_length;
    u8 header[NL_SFLOW_V1_HEADER_BYTES];
    u32 sample_pool;
} nl_sflow_sample_v1;

/*
 * generation and ack_sequence form the two-phase consumer cursor.  A request
 * acknowledges only a previously delivered contiguous batch; returning a
 * response does not remove samples.  oldest/latest/next_sequence in the
 * response are internal publish cursors and are independent of
 * nl_sflow_sample_v1.sequence.  A future acknowledgement is invalid, including
 * after a process restart; the consumer must retry from zero or explicitly
 * request RESET_TO_TAIL instead of assuming cursor continuity.
 */
typedef struct {
    u32 version;
    u32 size;
    u32 flags;
    u32 max_samples;
    u64 generation;
    u64 ack_sequence;
} nl_sflow_batch_request_v1;

typedef struct {
    u32 version;
    u32 size;
    u32 flags;
    u32 sample_count;
    u64 generation;
    u64 acked_sequence;
    u64 oldest_sequence;
    u64 latest_sequence;
    u64 next_sequence;
    u64 lost_before;
    nl_sflow_capture_counters_v1 counters;
    nl_sflow_sample_v1 samples[NL_SFLOW_V1_BATCH_MAX];
} nl_sflow_batch_response_v1;

static inline u32 nl_sflow_effective_rate(u32 requested_rate) {
    u32 quotient;

    if (requested_rate < NL_SFLOW_V1_MIN_SAMPLE_RATE ||
        requested_rate > NL_SFLOW_V1_MAX_SAMPLE_RATE)
        return 0;
    quotient = NL_SFLOW_V1_RATE_MODULUS / requested_rate;
    if (quotient == 0)
        return 0;
    return (NL_SFLOW_V1_RATE_MODULUS + quotient / 2U) / quotient;
}

_Static_assert(sizeof(nl_sflow_config_snapshot_v1) == 32,
               "sFlow config snapshot v1 ABI size changed");
_Static_assert(sizeof(nl_sflow_reload_request_v1) == 16,
               "sFlow reload request v1 ABI size changed");
_Static_assert(sizeof(nl_sflow_hw_state_v1) == 144,
               "sFlow hardware state v1 ABI size changed");
_Static_assert(sizeof(nl_sflow_capture_counters_v1) == 64,
               "sFlow capture counters v1 ABI size changed");
_Static_assert(sizeof(nl_sflow_sample_v1) == 176,
               "sFlow sample v1 ABI size changed");
_Static_assert(sizeof(nl_sflow_batch_request_v1) == 32,
               "sFlow batch request v1 ABI size changed");
_Static_assert(offsetof(nl_sflow_batch_response_v1, samples) == 128,
               "sFlow batch response v1 header size changed");
_Static_assert(sizeof(nl_sflow_batch_response_v1) == 22656,
               "sFlow batch response v1 ABI size changed");

#endif
