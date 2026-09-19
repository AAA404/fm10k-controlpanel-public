#include "netlab/l2_plan_build.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

typedef struct __attribute__((packed)) {
    u32 magic;
    u16 version;
    u16 size;
    u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES];
    u32 active_length;
    u32 candidate_length;
    u8 require_hardware;
    u8 reserved[7];
} begin_wire;

typedef struct __attribute__((packed)) {
    u32 magic;
    u16 version;
    u16 header_size;
    u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES];
    u8 stream;
    u8 reserved[3];
    u32 offset;
    u32 total_length;
    u32 data_length;
} part_wire;

typedef struct __attribute__((packed)) {
    u32 magic;
    u16 version;
    u16 size;
    u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES];
} token_wire;

_Static_assert(sizeof(begin_wire) == 40, "L2 plan begin wire changed");
_Static_assert(sizeof(part_wire) == NL_L2_PLAN_BUILD_PART_HEADER_BYTES,
               "L2 plan part wire changed");
_Static_assert(sizeof(token_wire) == 24, "L2 plan token wire changed");

static bool token_valid(const u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES]) {
    u8 value = 0;

    if (!token)
        return false;
    for (size_t i = 0; i < NL_L2_PLAN_BUILD_TOKEN_BYTES; i++)
        value |= token[i];
    return value != 0;
}

int nl_l2_plan_build_begin_encode(const nl_l2_plan_build_begin *begin,
                                  void *buffer, size_t capacity) {
    begin_wire wire;

    if (!begin || !buffer || capacity < sizeof(wire) ||
        !token_valid(begin->token) || begin->active_length == 0 ||
        begin->candidate_length == 0 ||
        begin->active_length > NL_L2_PLAN_CONFIG_MAX_BYTES ||
        begin->candidate_length > NL_L2_PLAN_CONFIG_MAX_BYTES)
        return -1;
    memset(&wire, 0, sizeof(wire));
    wire.magic = htonl(NL_L2_PLAN_BUILD_MAGIC);
    wire.version = htons(NL_L2_PLAN_BUILD_VERSION);
    wire.size = htons((u16)sizeof(wire));
    memcpy(wire.token, begin->token, sizeof(wire.token));
    wire.active_length = htonl(begin->active_length);
    wire.candidate_length = htonl(begin->candidate_length);
    wire.require_hardware = begin->require_hardware ? 1U : 0U;
    memcpy(buffer, &wire, sizeof(wire));
    return (int)sizeof(wire);
}

int nl_l2_plan_build_begin_decode(const void *buffer, size_t length,
                                  nl_l2_plan_build_begin *begin) {
    begin_wire wire;
    nl_l2_plan_build_begin decoded;

    if (!buffer || !begin || length != sizeof(wire))
        return -1;
    memcpy(&wire, buffer, sizeof(wire));
    if (ntohl(wire.magic) != NL_L2_PLAN_BUILD_MAGIC ||
        ntohs(wire.version) != NL_L2_PLAN_BUILD_VERSION ||
        ntohs(wire.size) != sizeof(wire) || wire.require_hardware > 1U)
        return -1;
    for (size_t i = 0; i < sizeof(wire.reserved); i++)
        if (wire.reserved[i] != 0)
            return -1;
    memset(&decoded, 0, sizeof(decoded));
    memcpy(decoded.token, wire.token, sizeof(decoded.token));
    decoded.active_length = ntohl(wire.active_length);
    decoded.candidate_length = ntohl(wire.candidate_length);
    decoded.require_hardware = wire.require_hardware != 0;
    if (!token_valid(decoded.token) || decoded.active_length == 0 ||
        decoded.candidate_length == 0 ||
        decoded.active_length > NL_L2_PLAN_CONFIG_MAX_BYTES ||
        decoded.candidate_length > NL_L2_PLAN_CONFIG_MAX_BYTES)
        return -1;
    *begin = decoded;
    return 0;
}

int nl_l2_plan_build_part_encode(const nl_l2_plan_build_part *part,
                                 const void *data, size_t data_length,
                                 void *buffer, size_t capacity) {
    part_wire wire;

    if (!part || !data || data_length == 0 || !buffer ||
        !token_valid(part->token) ||
        (part->stream != NL_L2_PLAN_BUILD_ACTIVE &&
         part->stream != NL_L2_PLAN_BUILD_CANDIDATE) ||
        part->total_length == 0 ||
        part->total_length > NL_L2_PLAN_CONFIG_MAX_BYTES ||
        data_length > UINT32_MAX ||
        part->offset > part->total_length ||
        data_length > part->total_length - part->offset ||
        sizeof(wire) + data_length > capacity)
        return -1;
    memset(&wire, 0, sizeof(wire));
    wire.magic = htonl(NL_L2_PLAN_BUILD_MAGIC);
    wire.version = htons(NL_L2_PLAN_BUILD_VERSION);
    wire.header_size = htons((u16)sizeof(wire));
    memcpy(wire.token, part->token, sizeof(wire.token));
    wire.stream = (u8)part->stream;
    wire.offset = htonl(part->offset);
    wire.total_length = htonl(part->total_length);
    wire.data_length = htonl((u32)data_length);
    memcpy(buffer, &wire, sizeof(wire));
    memcpy((u8 *)buffer + sizeof(wire), data, data_length);
    return (int)(sizeof(wire) + data_length);
}

int nl_l2_plan_build_part_decode(const void *buffer, size_t length,
                                 nl_l2_plan_build_part *part,
                                 const u8 **data, size_t *data_length) {
    part_wire wire;
    nl_l2_plan_build_part decoded;
    u32 chunk_length;

    if (!buffer || !part || !data || !data_length ||
        length <= sizeof(wire))
        return -1;
    memcpy(&wire, buffer, sizeof(wire));
    if (ntohl(wire.magic) != NL_L2_PLAN_BUILD_MAGIC ||
        ntohs(wire.version) != NL_L2_PLAN_BUILD_VERSION ||
        ntohs(wire.header_size) != sizeof(wire) ||
        wire.reserved[0] != 0 || wire.reserved[1] != 0 ||
        wire.reserved[2] != 0)
        return -1;
    memset(&decoded, 0, sizeof(decoded));
    memcpy(decoded.token, wire.token, sizeof(decoded.token));
    decoded.stream = (nl_l2_plan_build_stream)wire.stream;
    decoded.offset = ntohl(wire.offset);
    decoded.total_length = ntohl(wire.total_length);
    chunk_length = ntohl(wire.data_length);
    if (!token_valid(decoded.token) ||
        (decoded.stream != NL_L2_PLAN_BUILD_ACTIVE &&
         decoded.stream != NL_L2_PLAN_BUILD_CANDIDATE) ||
        decoded.total_length == 0 ||
        decoded.total_length > NL_L2_PLAN_CONFIG_MAX_BYTES ||
        chunk_length == 0 || sizeof(wire) + (size_t)chunk_length != length ||
        decoded.offset > decoded.total_length ||
        chunk_length > decoded.total_length - decoded.offset)
        return -1;
    *part = decoded;
    *data = (const u8 *)buffer + sizeof(wire);
    *data_length = chunk_length;
    return 0;
}

int nl_l2_plan_build_token_encode(
    const u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES],
    void *buffer, size_t capacity) {
    token_wire wire;

    if (!token_valid(token) || !buffer || capacity < sizeof(wire))
        return -1;
    memset(&wire, 0, sizeof(wire));
    wire.magic = htonl(NL_L2_PLAN_BUILD_MAGIC);
    wire.version = htons(NL_L2_PLAN_BUILD_VERSION);
    wire.size = htons((u16)sizeof(wire));
    memcpy(wire.token, token, sizeof(wire.token));
    memcpy(buffer, &wire, sizeof(wire));
    return (int)sizeof(wire);
}

int nl_l2_plan_build_token_decode(
    const void *buffer, size_t length,
    u8 token[NL_L2_PLAN_BUILD_TOKEN_BYTES]) {
    token_wire wire;

    if (!buffer || !token || length != sizeof(wire))
        return -1;
    memcpy(&wire, buffer, sizeof(wire));
    if (ntohl(wire.magic) != NL_L2_PLAN_BUILD_MAGIC ||
        ntohs(wire.version) != NL_L2_PLAN_BUILD_VERSION ||
        ntohs(wire.size) != sizeof(wire) || !token_valid(wire.token))
        return -1;
    memcpy(token, wire.token, sizeof(wire.token));
    return 0;
}
