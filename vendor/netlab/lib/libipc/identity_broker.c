#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "netlab/identity_broker.h"
#include "netlab/daemon_identity.h"
#include "netlab/error.h"
#include "netlab/process_identity.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

_Static_assert(sizeof(nl_identity_capture_request) == 16,
               "identity capture request wire size changed");
_Static_assert(sizeof(nl_identity_capture_response) == 48,
               "identity capture response wire size changed");
_Static_assert(sizeof(nl_identity_verify_request) == 40,
               "identity verify request wire size changed");
_Static_assert(sizeof(nl_identity_verify_response) == 8,
               "identity verify response wire size changed");
_Static_assert(sizeof(nl_identity_release_request) == 40,
               "identity release request wire size changed");
_Static_assert(sizeof(nl_identity_release_response) == 8,
               "identity release response wire size changed");

typedef struct {
    u32 state[8];
    u64 bit_count;
    size_t buffered;
    u8 block[64];
} identity_sha256;

typedef enum {
    IDENTITY_LEASE_EMPTY = 0,
    IDENTITY_LEASE_CAPTURED,
    IDENTITY_LEASE_PREQUEUED,
} identity_lease_state;

typedef struct {
    identity_lease_state state;
    u64 expires_at_ms;
    u8 token_digest[32];
    nl_process_identity_handle requester;
    nl_process_identity_handle target;
} identity_lease_entry;

struct nl_identity_broker {
    pthread_mutex_t lock;
    identity_lease_entry entries[NL_IDENTITY_BROKER_MAX_LEASES];
};

static const u32 g_sha256_round_constants[64] = {
    UINT32_C(0x428a2f98), UINT32_C(0x71374491),
    UINT32_C(0xb5c0fbcf), UINT32_C(0xe9b5dba5),
    UINT32_C(0x3956c25b), UINT32_C(0x59f111f1),
    UINT32_C(0x923f82a4), UINT32_C(0xab1c5ed5),
    UINT32_C(0xd807aa98), UINT32_C(0x12835b01),
    UINT32_C(0x243185be), UINT32_C(0x550c7dc3),
    UINT32_C(0x72be5d74), UINT32_C(0x80deb1fe),
    UINT32_C(0x9bdc06a7), UINT32_C(0xc19bf174),
    UINT32_C(0xe49b69c1), UINT32_C(0xefbe4786),
    UINT32_C(0x0fc19dc6), UINT32_C(0x240ca1cc),
    UINT32_C(0x2de92c6f), UINT32_C(0x4a7484aa),
    UINT32_C(0x5cb0a9dc), UINT32_C(0x76f988da),
    UINT32_C(0x983e5152), UINT32_C(0xa831c66d),
    UINT32_C(0xb00327c8), UINT32_C(0xbf597fc7),
    UINT32_C(0xc6e00bf3), UINT32_C(0xd5a79147),
    UINT32_C(0x06ca6351), UINT32_C(0x14292967),
    UINT32_C(0x27b70a85), UINT32_C(0x2e1b2138),
    UINT32_C(0x4d2c6dfc), UINT32_C(0x53380d13),
    UINT32_C(0x650a7354), UINT32_C(0x766a0abb),
    UINT32_C(0x81c2c92e), UINT32_C(0x92722c85),
    UINT32_C(0xa2bfe8a1), UINT32_C(0xa81a664b),
    UINT32_C(0xc24b8b70), UINT32_C(0xc76c51a3),
    UINT32_C(0xd192e819), UINT32_C(0xd6990624),
    UINT32_C(0xf40e3585), UINT32_C(0x106aa070),
    UINT32_C(0x19a4c116), UINT32_C(0x1e376c08),
    UINT32_C(0x2748774c), UINT32_C(0x34b0bcb5),
    UINT32_C(0x391c0cb3), UINT32_C(0x4ed8aa4a),
    UINT32_C(0x5b9cca4f), UINT32_C(0x682e6ff3),
    UINT32_C(0x748f82ee), UINT32_C(0x78a5636f),
    UINT32_C(0x84c87814), UINT32_C(0x8cc70208),
    UINT32_C(0x90befffa), UINT32_C(0xa4506ceb),
    UINT32_C(0xbef9a3f7), UINT32_C(0xc67178f2),
};

static void secure_zero(void *buffer, size_t length) {
    volatile u8 *bytes = buffer;

    while (length-- > 0)
        *bytes++ = 0;
}

static u32 rotate_right(u32 value, unsigned int count) {
    return (value >> count) | (value << (32U - count));
}

static void sha256_transform(identity_sha256 *ctx, const u8 block[64]) {
    u32 words[64];
    u32 a;
    u32 b;
    u32 c;
    u32 d;
    u32 e;
    u32 f;
    u32 g;
    u32 h;

    for (size_t i = 0; i < 16; i++) {
        words[i] = ((u32)block[i * 4] << 24) |
                   ((u32)block[i * 4 + 1] << 16) |
                   ((u32)block[i * 4 + 2] << 8) |
                   (u32)block[i * 4 + 3];
    }
    for (size_t i = 16; i < 64; i++) {
        u32 s0 = rotate_right(words[i - 15], 7) ^
                 rotate_right(words[i - 15], 18) ^
                 (words[i - 15] >> 3);
        u32 s1 = rotate_right(words[i - 2], 17) ^
                 rotate_right(words[i - 2], 19) ^
                 (words[i - 2] >> 10);

        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    for (size_t i = 0; i < 64; i++) {
        u32 choice = (e & f) ^ ((~e) & g);
        u32 majority = (a & b) ^ (a & c) ^ (b & c);
        u32 sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^
                   rotate_right(a, 22);
        u32 sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^
                   rotate_right(e, 25);
        u32 temp1 = h + sum1 + choice + g_sha256_round_constants[i] +
                    words[i];
        u32 temp2 = sum0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
    secure_zero(words, sizeof(words));
}

static void sha256_init(identity_sha256 *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->state[0] = UINT32_C(0x6a09e667);
    ctx->state[1] = UINT32_C(0xbb67ae85);
    ctx->state[2] = UINT32_C(0x3c6ef372);
    ctx->state[3] = UINT32_C(0xa54ff53a);
    ctx->state[4] = UINT32_C(0x510e527f);
    ctx->state[5] = UINT32_C(0x9b05688c);
    ctx->state[6] = UINT32_C(0x1f83d9ab);
    ctx->state[7] = UINT32_C(0x5be0cd19);
}

static void sha256_update(identity_sha256 *ctx, const u8 *data,
                          size_t length) {
    for (size_t i = 0; i < length; i++) {
        ctx->block[ctx->buffered++] = data[i];
        if (ctx->buffered == sizeof(ctx->block)) {
            sha256_transform(ctx, ctx->block);
            ctx->bit_count += UINT64_C(512);
            ctx->buffered = 0;
        }
    }
}

static void sha256_finish(identity_sha256 *ctx, u8 digest[32]) {
    size_t index = ctx->buffered;
    u64 total_bits = ctx->bit_count + (u64)ctx->buffered * UINT64_C(8);

    ctx->block[index++] = 0x80;
    if (index > 56) {
        memset(ctx->block + index, 0, sizeof(ctx->block) - index);
        sha256_transform(ctx, ctx->block);
        index = 0;
    }
    memset(ctx->block + index, 0, 56 - index);
    for (size_t i = 0; i < 8; i++)
        ctx->block[63 - i] = (u8)(total_bits >> (i * 8));
    sha256_transform(ctx, ctx->block);
    for (size_t i = 0; i < 8; i++) {
        digest[i * 4] = (u8)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (u8)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (u8)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (u8)ctx->state[i];
    }
    secure_zero(ctx, sizeof(*ctx));
}

static void token_digest(const u8 token[NL_IDENTITY_TOKEN_SIZE],
                         u8 digest[32]) {
    identity_sha256 ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, token, NL_IDENTITY_TOKEN_SIZE);
    sha256_finish(&ctx, digest);
}

static bool constant_time_equal(const u8 *left, const u8 *right,
                                size_t length) {
    u8 difference = 0;

    for (size_t i = 0; i < length; i++)
        difference |= left[i] ^ right[i];
    return difference == 0;
}

static bool fill_random(void *buffer, size_t length) {
    u8 *bytes = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = getrandom(bytes + offset, length - offset, 0);

        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return false;
        offset += (size_t)count;
    }
    return true;
}

static u64 monotonic_ms(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0)
        return 0;
    return (u64)now.tv_sec * UINT64_C(1000) +
           (u64)now.tv_nsec / UINT64_C(1000000);
}

static void lease_entry_init(identity_lease_entry *entry) {
    memset(entry, 0, sizeof(*entry));
    nl_process_identity_init(&entry->requester);
    nl_process_identity_init(&entry->target);
}

static void lease_entry_clear(identity_lease_entry *entry) {
    if (!entry)
        return;
    nl_process_identity_close(&entry->requester);
    nl_process_identity_close(&entry->target);
    secure_zero(entry, sizeof(*entry));
    nl_process_identity_init(&entry->requester);
    nl_process_identity_init(&entry->target);
}

static bool daemon_process_open_verified(
    nl_daemon_id service, pid_t pid, uid_t uid, gid_t gid,
    nl_process_identity_handle *handle) {
    const nl_daemon_identity *identity;
    nl_daemon_credentials credentials;
    nl_process_identity_expectation expectation;
    nl_process_identity_result result;
    char executable[NL_DAEMON_EXECUTABLE_PATH_MAX];

    if (pid <= 0 || !handle)
        return false;
    identity = nl_daemon_identity_lookup(service);
    if (!nl_daemon_identity_is_peer_process(identity) ||
        !nl_daemon_identity_resolve_credentials(identity, &credentials) ||
        credentials.uid != uid || credentials.primary_gid != gid ||
        !nl_daemon_identity_expected_executable(
            identity, executable, sizeof(executable)))
        return false;
    nl_process_identity_init(handle);
    result = nl_process_identity_open(pid, handle);
    if (result != NL_PROCESS_IDENTITY_OK)
        return false;
    if (handle->baseline.pid != pid ||
        handle->baseline.euid != uid ||
        handle->baseline.egid != gid) {
        nl_process_identity_close(handle);
        return false;
    }
    memset(&expectation, 0, sizeof(expectation));
    expectation.check_euid = true;
    expectation.euid = uid;
    expectation.check_egid = true;
    expectation.egid = gid;
    expectation.executable = executable;
    result = nl_process_identity_verify(handle, &expectation, NULL);
    if (result != NL_PROCESS_IDENTITY_OK) {
        nl_process_identity_close(handle);
        return false;
    }
    return true;
}

static bool daemon_process_still_verified(
    nl_daemon_id service, const nl_process_identity_handle *handle) {
    const nl_daemon_identity *identity;
    nl_daemon_credentials credentials;
    nl_process_identity_expectation expectation;
    char executable[NL_DAEMON_EXECUTABLE_PATH_MAX];

    if (!handle || handle->fd < 0)
        return false;
    identity = nl_daemon_identity_lookup(service);
    if (!nl_daemon_identity_is_peer_process(identity) ||
        !nl_daemon_identity_resolve_credentials(identity, &credentials) ||
        handle->baseline.euid != credentials.uid ||
        handle->baseline.egid != credentials.primary_gid ||
        !nl_daemon_identity_expected_executable(
            identity, executable, sizeof(executable)))
        return false;
    memset(&expectation, 0, sizeof(expectation));
    expectation.check_euid = true;
    expectation.euid = credentials.uid;
    expectation.check_egid = true;
    expectation.egid = credentials.primary_gid;
    expectation.executable = executable;
    return nl_process_identity_verify(handle, &expectation, NULL) ==
           NL_PROCESS_IDENTITY_OK;
}

static void broker_reap_locked(nl_identity_broker *broker, u64 now) {
    if (!broker || now == 0)
        return;
    for (size_t i = 0; i < NL_IDENTITY_BROKER_MAX_LEASES; i++) {
        identity_lease_entry *entry = &broker->entries[i];

        if (entry->state != IDENTITY_LEASE_EMPTY &&
            now >= entry->expires_at_ms)
            lease_entry_clear(entry);
    }
}

static int broker_find_digest_locked(
    nl_identity_broker *broker, const u8 digest[32]) {
    if (!broker || !digest)
        return -1;
    for (size_t i = 0; i < NL_IDENTITY_BROKER_MAX_LEASES; i++) {
        if (broker->entries[i].state != IDENTITY_LEASE_EMPTY &&
            constant_time_equal(
                broker->entries[i].token_digest, digest, 32))
            return (int)i;
    }
    return -1;
}

static int broker_find_empty_locked(nl_identity_broker *broker) {
    for (size_t i = 0; i < NL_IDENTITY_BROKER_MAX_LEASES; i++) {
        if (broker->entries[i].state == IDENTITY_LEASE_EMPTY)
            return (int)i;
    }
    return -1;
}

static size_t broker_requester_count_locked(
    nl_identity_broker *broker,
    const nl_process_identity_handle *requester) {
    size_t count = 0;

    for (size_t i = 0; i < NL_IDENTITY_BROKER_MAX_LEASES; i++) {
        const identity_lease_entry *entry = &broker->entries[i];

        if (entry->state != IDENTITY_LEASE_EMPTY &&
            entry->requester.baseline.pid == requester->baseline.pid &&
            entry->requester.baseline.euid == requester->baseline.euid &&
            entry->requester.baseline.egid == requester->baseline.egid &&
            entry->requester.baseline.starttime ==
                requester->baseline.starttime)
            count++;
    }
    return count;
}

static bool requester_matches_connection(
    const identity_lease_entry *entry, const nl_conn *conn) {
    return entry && conn &&
        entry->requester.baseline.pid == conn->peer_pid &&
        entry->requester.baseline.euid == conn->peer_uid &&
        entry->requester.baseline.egid == conn->peer_gid;
}

static s32 broker_capture(
    nl_identity_broker *broker, const nl_conn *conn,
    const nl_msg_hdr *msg, const nl_identity_capture_request *request,
    nl_identity_capture_response *response) {
    nl_process_identity_handle requester =
        NL_PROCESS_IDENTITY_HANDLE_INITIALIZER;
    nl_process_identity_handle target =
        NL_PROCESS_IDENTITY_HANDLE_INITIALIZER;
    u8 digest[32];
    u64 now;
    int slot = -1;
    s32 result = NL_ERR_PERMISSION_DENIED;

    memset(response, 0, sizeof(*response));
    if (!broker || !conn || !msg || !request ||
        !conn->peer_authenticated ||
        !conn->peer_credentials_enabled ||
        msg->daemon_id != NL_DAEMON_CHASSISD ||
        request->version != NL_IDENTITY_BROKER_PROTOCOL_VERSION ||
        request->target_pid == 0 ||
        request->target_pid > (u32)INT_MAX ||
        (u32)(uid_t)request->target_uid != request->target_uid ||
        (u32)(gid_t)request->target_gid != request->target_gid ||
        (pid_t)request->target_pid == conn->peer_pid)
        goto out;
    if (!daemon_process_open_verified(
            NL_DAEMON_CHASSISD, conn->peer_pid,
            conn->peer_uid, conn->peer_gid, &requester) ||
        !daemon_process_open_verified(
            NL_DAEMON_MGMTD, (pid_t)request->target_pid,
            (uid_t)request->target_uid, (gid_t)request->target_gid,
            &target))
        goto out;
    if ((u32)target.baseline.euid != request->target_uid ||
        (u32)target.baseline.egid != request->target_gid)
        goto out;
    now = monotonic_ms();
    if (now == 0 ||
        now > UINT64_MAX - NL_IDENTITY_BROKER_TTL_MS ||
        !fill_random(response->token, sizeof(response->token)))
        goto out;
    token_digest(response->token, digest);

    pthread_mutex_lock(&broker->lock);
    broker_reap_locked(broker, now);
    slot = broker_find_empty_locked(broker);
    if (slot >= 0 &&
        broker_requester_count_locked(broker, &requester) <
            NL_IDENTITY_BROKER_MAX_PER_REQUESTER &&
        broker_find_digest_locked(broker, digest) < 0) {
        identity_lease_entry *entry = &broker->entries[slot];

        entry->state = IDENTITY_LEASE_CAPTURED;
        entry->expires_at_ms = now + NL_IDENTITY_BROKER_TTL_MS;
        memcpy(entry->token_digest, digest, sizeof(entry->token_digest));
        if (nl_process_identity_move(&entry->requester, &requester) &&
            nl_process_identity_move(&entry->target, &target)) {
            response->version = NL_IDENTITY_BROKER_PROTOCOL_VERSION;
            response->expires_at_monotonic_ms = entry->expires_at_ms;
            result = NL_ERR_OK;
        } else {
            lease_entry_clear(entry);
        }
    }
    pthread_mutex_unlock(&broker->lock);

out:
    nl_process_identity_close(&requester);
    nl_process_identity_close(&target);
    secure_zero(digest, sizeof(digest));
    if (result != NL_ERR_OK)
        secure_zero(response, sizeof(*response));
    return result;
}

static s32 broker_verify(
    nl_identity_broker *broker, const nl_conn *conn,
    const nl_identity_verify_request *request) {
    identity_lease_entry *entry;
    u8 digest[32];
    u64 now;
    int index;
    bool valid;
    s32 result = NL_ERR_PERMISSION_DENIED;

    token_digest(request->token, digest);
    now = monotonic_ms();
    pthread_mutex_lock(&broker->lock);
    broker_reap_locked(broker, now);
    index = broker_find_digest_locked(broker, digest);
    if (index < 0)
        goto out;
    entry = &broker->entries[index];
    valid = now != 0 &&
        requester_matches_connection(entry, conn) &&
        daemon_process_still_verified(
            NL_DAEMON_CHASSISD, &entry->requester) &&
        daemon_process_still_verified(
            NL_DAEMON_MGMTD, &entry->target);
    if (request->phase == NL_IDENTITY_VERIFY_PREQUEUE) {
        valid = valid && entry->state == IDENTITY_LEASE_CAPTURED;
        if (valid) {
            entry->state = IDENTITY_LEASE_PREQUEUED;
            result = NL_ERR_OK;
        } else {
            lease_entry_clear(entry);
        }
    } else {
        valid = valid && entry->state == IDENTITY_LEASE_PREQUEUED;
        lease_entry_clear(entry);
        if (valid)
            result = NL_ERR_OK;
    }
out:
    pthread_mutex_unlock(&broker->lock);
    secure_zero(digest, sizeof(digest));
    return result;
}

static s32 broker_release(
    nl_identity_broker *broker, const nl_conn *conn,
    const nl_identity_release_request *request) {
    identity_lease_entry *entry;
    u8 digest[32];
    u64 now;
    int index;
    bool valid;
    s32 result = NL_ERR_PERMISSION_DENIED;

    token_digest(request->token, digest);
    now = monotonic_ms();
    pthread_mutex_lock(&broker->lock);
    broker_reap_locked(broker, now);
    index = broker_find_digest_locked(broker, digest);
    if (index >= 0) {
        entry = &broker->entries[index];
        valid = now != 0 &&
            requester_matches_connection(entry, conn) &&
            daemon_process_still_verified(
                NL_DAEMON_CHASSISD, &entry->requester) &&
            daemon_process_still_verified(
                NL_DAEMON_MGMTD, &entry->target);
        lease_entry_clear(entry);
        if (valid)
            result = NL_ERR_OK;
    }
    pthread_mutex_unlock(&broker->lock);
    secure_zero(digest, sizeof(digest));
    return result;
}

static nl_status send_wire_response(
    nl_conn *conn, u64 request_id, const void *payload, u32 payload_len) {
    nl_msg_hdr *response;
    nl_status status;

    response = nl_msg_alloc(payload_len);
    if (!response)
        return NL_ERR;
    response->type = NL_MSG_RESPONSE;
    response->request_id = request_id;
    response->error_code = NL_ERR_OK;
    response->payload_len = payload_len;
    memcpy(response->payload, payload, payload_len);
    status = nl_send(conn, response);
    secure_zero(response->payload, payload_len);
    nl_msg_free(response);
    return status;
}

static void broker_forget_token(
    nl_identity_broker *broker,
    const u8 token[NL_IDENTITY_TOKEN_SIZE]) {
    u8 digest[32];
    int index;

    token_digest(token, digest);
    pthread_mutex_lock(&broker->lock);
    index = broker_find_digest_locked(broker, digest);
    if (index >= 0)
        lease_entry_clear(&broker->entries[index]);
    pthread_mutex_unlock(&broker->lock);
    secure_zero(digest, sizeof(digest));
}

nl_identity_broker *nl_identity_broker_create(void) {
    nl_identity_broker *broker = calloc(1, sizeof(*broker));

    if (!broker)
        return NULL;
    if (pthread_mutex_init(&broker->lock, NULL) != 0) {
        free(broker);
        return NULL;
    }
    for (size_t i = 0; i < NL_IDENTITY_BROKER_MAX_LEASES; i++)
        lease_entry_init(&broker->entries[i]);
    return broker;
}

void nl_identity_broker_destroy(nl_identity_broker *broker) {
    if (!broker)
        return;
    pthread_mutex_lock(&broker->lock);
    for (size_t i = 0; i < NL_IDENTITY_BROKER_MAX_LEASES; i++)
        lease_entry_clear(&broker->entries[i]);
    pthread_mutex_unlock(&broker->lock);
    pthread_mutex_destroy(&broker->lock);
    secure_zero(broker, sizeof(*broker));
    free(broker);
}

void nl_identity_broker_reap(nl_identity_broker *broker) {
    u64 now;

    if (!broker)
        return;
    now = monotonic_ms();
    pthread_mutex_lock(&broker->lock);
    broker_reap_locked(broker, now);
    pthread_mutex_unlock(&broker->lock);
}

int nl_identity_broker_dispatch(nl_identity_broker *broker, nl_conn *conn,
                                nl_msg_hdr *msg) {
    s32 result = NL_ERR_PERMISSION_DENIED;

    if (!broker || !conn || !msg)
        return NL_ERR;
    if (msg->type != NL_MSG_REQUEST ||
        msg->daemon_id != NL_DAEMON_CHASSISD ||
        !conn->peer_authenticated ||
        !conn->peer_credentials_enabled) {
        result = NL_ERR_PERMISSION_DENIED;
        goto denied;
    }
    switch (msg->method) {
    case NL_IDENTITYD_CAPTURE:
        if (msg->payload_len == sizeof(nl_identity_capture_request)) {
            nl_identity_capture_request request;
            nl_identity_capture_response response;

            memcpy(&request, msg->payload, sizeof(request));
            if (request.version != NL_IDENTITY_BROKER_PROTOCOL_VERSION)
                break;
            result = broker_capture(
                broker, conn, msg, &request, &response);
            if (result == NL_ERR_OK) {
                if (send_wire_response(
                        conn, msg->request_id, &response,
                        sizeof(response)) != NL_OK) {
                    broker_forget_token(broker, response.token);
                }
                secure_zero(&response, sizeof(response));
                return NL_OK;
            }
        }
        break;
    case NL_IDENTITYD_VERIFY:
        if (msg->payload_len == sizeof(nl_identity_verify_request)) {
            nl_identity_verify_request request;
            nl_identity_verify_response response;
            u32 phase;

            memcpy(&request, msg->payload, sizeof(request));
            secure_zero(msg->payload, msg->payload_len);
            if (request.version != NL_IDENTITY_BROKER_PROTOCOL_VERSION ||
                (request.phase != NL_IDENTITY_VERIFY_PREQUEUE &&
                 request.phase != NL_IDENTITY_VERIFY_PREDISPATCH)) {
                secure_zero(&request, sizeof(request));
                break;
            }
            phase = request.phase;
            result = broker_verify(broker, conn, &request);
            secure_zero(&request, sizeof(request));
            if (result == NL_ERR_OK) {
                memset(&response, 0, sizeof(response));
                response.version = NL_IDENTITY_BROKER_PROTOCOL_VERSION;
                response.phase = phase;
                (void)send_wire_response(
                    conn, msg->request_id, &response, sizeof(response));
                return NL_OK;
            }
        } else {
            secure_zero(msg->payload, msg->payload_len);
        }
        break;
    case NL_IDENTITYD_RELEASE:
        if (msg->payload_len == sizeof(nl_identity_release_request)) {
            nl_identity_release_request request;
            nl_identity_release_response response;

            memcpy(&request, msg->payload, sizeof(request));
            secure_zero(msg->payload, msg->payload_len);
            if (request.version != NL_IDENTITY_BROKER_PROTOCOL_VERSION ||
                request.reserved != 0) {
                secure_zero(&request, sizeof(request));
                break;
            }
            result = broker_release(broker, conn, &request);
            secure_zero(&request, sizeof(request));
            if (result == NL_ERR_OK) {
                memset(&response, 0, sizeof(response));
                response.version = NL_IDENTITY_BROKER_PROTOCOL_VERSION;
                (void)send_wire_response(
                    conn, msg->request_id, &response, sizeof(response));
                return NL_OK;
            }
        } else {
            secure_zero(msg->payload, msg->payload_len);
        }
        break;
    default:
        break;
    }

denied:
    (void)nl_send_response(conn, msg->request_id, result);
    return NL_OK;
}

static void client_lease_clear(nl_identity_lease *lease) {
    if (!lease)
        return;
    secure_zero(lease, sizeof(*lease));
}

static s32 client_call(
    const char *socket_path, nl_daemon_id requester_service,
    nl_rpc_method method, const void *request, size_t request_size,
    void *response_buffer, size_t response_size) {
    nl_rpc_response response;
    int length;
    s32 result = NL_ERR_PERMISSION_DENIED;

    if (!socket_path || requester_service != NL_DAEMON_CHASSISD ||
        !request || !response_buffer ||
        request_size > INT_MAX || response_size > UINT32_MAX)
        return NL_ERR_PERMISSION_DENIED;
    length = nl_rpc_call_alloc_ex(
        socket_path, requester_service, NL_DAEMON_IDENTITYD, method, 0,
        request, (int)request_size, NL_IDENTITY_BROKER_DEFAULT_TIMEOUT_MS,
        &response);
    if (length == (int)response_size &&
        response.error_code == NL_ERR_OK) {
        memcpy(response_buffer, response.payload, response_size);
        result = NL_ERR_OK;
    }
    secure_zero(response.payload, response.payload_len);
    nl_rpc_response_free(&response);
    return result;
}

s32 nl_identity_broker_capture(const char *socket_path,
                               nl_daemon_id requester_service,
                               pid_t target_pid, uid_t target_uid,
                               gid_t target_gid,
                               nl_identity_lease *lease) {
    nl_identity_capture_request request;
    nl_identity_capture_response response;
    s32 result;

    if (!lease || lease->active || target_pid <= 0 ||
        (u64)target_pid > UINT32_MAX)
        return NL_ERR_PERMISSION_DENIED;
    client_lease_clear(lease);
    memset(&request, 0, sizeof(request));
    request.version = NL_IDENTITY_BROKER_PROTOCOL_VERSION;
    request.target_pid = (u32)target_pid;
    request.target_uid = (u32)target_uid;
    request.target_gid = (u32)target_gid;
    memset(&response, 0, sizeof(response));
    result = client_call(
        socket_path, requester_service, NL_IDENTITYD_CAPTURE,
        &request, sizeof(request), &response, sizeof(response));
    if (result != NL_ERR_OK ||
        response.version != NL_IDENTITY_BROKER_PROTOCOL_VERSION ||
        response.reserved != 0 ||
        response.expires_at_monotonic_ms == 0) {
        secure_zero(&response, sizeof(response));
        return NL_ERR_PERMISSION_DENIED;
    }
    memcpy(lease->token, response.token, sizeof(lease->token));
    lease->expires_at_monotonic_ms = response.expires_at_monotonic_ms;
    lease->active = true;
    secure_zero(&response, sizeof(response));
    return NL_ERR_OK;
}

s32 nl_identity_broker_verify(const char *socket_path,
                              nl_daemon_id requester_service,
                              nl_identity_lease *lease,
                              nl_identity_verify_phase phase) {
    nl_identity_verify_request request;
    nl_identity_verify_response response;
    s32 result;

    if (!lease || !lease->active ||
        (phase != NL_IDENTITY_VERIFY_PREQUEUE &&
         phase != NL_IDENTITY_VERIFY_PREDISPATCH))
        return NL_ERR_PERMISSION_DENIED;
    memset(&request, 0, sizeof(request));
    request.version = NL_IDENTITY_BROKER_PROTOCOL_VERSION;
    request.phase = (u32)phase;
    memcpy(request.token, lease->token, sizeof(request.token));
    memset(&response, 0, sizeof(response));
    result = client_call(
        socket_path, requester_service, NL_IDENTITYD_VERIFY,
        &request, sizeof(request), &response, sizeof(response));
    secure_zero(&request, sizeof(request));
    if (phase == NL_IDENTITY_VERIFY_PREDISPATCH ||
        result != NL_ERR_OK)
        client_lease_clear(lease);
    if (result != NL_ERR_OK ||
        response.version != NL_IDENTITY_BROKER_PROTOCOL_VERSION ||
        response.phase != (u32)phase) {
        secure_zero(&response, sizeof(response));
        if (phase == NL_IDENTITY_VERIFY_PREQUEUE)
            client_lease_clear(lease);
        return NL_ERR_PERMISSION_DENIED;
    }
    secure_zero(&response, sizeof(response));
    return NL_ERR_OK;
}

s32 nl_identity_broker_release(const char *socket_path,
                               nl_daemon_id requester_service,
                               nl_identity_lease *lease) {
    nl_identity_release_request request;
    nl_identity_release_response response;
    s32 result;

    if (!lease || !lease->active)
        return NL_ERR_PERMISSION_DENIED;
    memset(&request, 0, sizeof(request));
    request.version = NL_IDENTITY_BROKER_PROTOCOL_VERSION;
    memcpy(request.token, lease->token, sizeof(request.token));
    memset(&response, 0, sizeof(response));
    result = client_call(
        socket_path, requester_service, NL_IDENTITYD_RELEASE,
        &request, sizeof(request), &response, sizeof(response));
    secure_zero(&request, sizeof(request));
    client_lease_clear(lease);
    if (result != NL_ERR_OK ||
        response.version != NL_IDENTITY_BROKER_PROTOCOL_VERSION ||
        response.reserved != 0) {
        secure_zero(&response, sizeof(response));
        return NL_ERR_PERMISSION_DENIED;
    }
    secure_zero(&response, sizeof(response));
    return NL_ERR_OK;
}
