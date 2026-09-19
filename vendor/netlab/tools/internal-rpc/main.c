#include "netlab/ipc.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define INTERNAL_RPC_ENVELOPE_MAGIC UINT32_C(0x4e4c4952)
#define INTERNAL_RPC_ENVELOPE_VERSION UINT16_C(1)
#define INTERNAL_RPC_ENVELOPE_SIZE 14U

enum helper_exit_code {
    HELPER_EXIT_OK = 0,
    HELPER_EXIT_USAGE = 2,
    HELPER_EXIT_PRIVILEGE = 3,
    HELPER_EXIT_INPUT = 4,
    HELPER_EXIT_POLICY = 5,
    HELPER_EXIT_TRANSPORT = 6,
    HELPER_EXIT_OUTPUT = 7,
};

typedef struct {
    nl_daemon_id service;
    nl_rpc_method method;
    u64 tx_id;
    int timeout_ms;
    const char *socket_path;
    bool have_service;
    bool have_method;
    bool have_tx_id;
    bool have_timeout;
    bool have_socket;
} helper_options;

static void usage(const char *program) {
    fprintf(stderr,
            "usage: %s --service SERVICE --method METHOD --tx-id TX_ID "
            "--timeout TIMEOUT_MS --socket ABSOLUTE_SOCKET\n",
            program);
}

static bool parse_u64(const char *text, u64 maximum, u64 *value) {
    char *end = NULL;
    const char *cursor;
    unsigned long long parsed;

    if (!text || !text[0] || !value)
        return false;
    for (cursor = text; *cursor; cursor++) {
        if (*cursor < '0' || *cursor > '9')
            return false;
    }
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed > maximum)
        return false;
    *value = (u64)parsed;
    return true;
}

static bool parse_service(const char *text, nl_daemon_id *service) {
    u64 value;

    if (!text || !service)
        return false;
    if (strcmp(text, "switchd") == 0)
        *service = NL_DAEMON_SWITCHD;
    else if (strcmp(text, "configd") == 0)
        *service = NL_DAEMON_CONFIGD;
    else if (strcmp(text, "l2d") == 0)
        *service = NL_DAEMON_L2D;
    else if (strcmp(text, "rpd") == 0)
        *service = NL_DAEMON_RPD;
    else {
        if (!parse_u64(text, UINT16_MAX, &value))
            return false;
        *service = (nl_daemon_id)value;
    }
    return *service == NL_DAEMON_SWITCHD ||
        *service == NL_DAEMON_CONFIGD ||
        *service == NL_DAEMON_L2D ||
        *service == NL_DAEMON_RPD;
}

static bool parse_options(int argc, char **argv, helper_options *options) {
    int index;

    if (!options)
        return false;
    memset(options, 0, sizeof(*options));
    for (index = 1; index < argc; index++) {
        const char *name = argv[index];
        const char *value;
        u64 parsed;

        if (index + 1 >= argc)
            return false;
        value = argv[++index];
        if (strcmp(name, "--service") == 0 && !options->have_service) {
            if (!parse_service(value, &options->service))
                return false;
            options->have_service = true;
        } else if (strcmp(name, "--method") == 0 &&
                   !options->have_method) {
            if (!parse_u64(value, UINT16_MAX, &parsed))
                return false;
            options->method = (nl_rpc_method)parsed;
            options->have_method = true;
        } else if (strcmp(name, "--tx-id") == 0 &&
                   !options->have_tx_id) {
            if (!parse_u64(value, UINT64_MAX, &options->tx_id))
                return false;
            options->have_tx_id = true;
        } else if (strcmp(name, "--timeout") == 0 &&
                   !options->have_timeout) {
            if (!parse_u64(value, INT_MAX, &parsed) || parsed == 0)
                return false;
            options->timeout_ms = (int)parsed;
            options->have_timeout = true;
        } else if (strcmp(name, "--socket") == 0 &&
                   !options->have_socket) {
            if (value[0] != '/' || !nl_ipc_socket_path_safe(value))
                return false;
            options->socket_path = value;
            options->have_socket = true;
        } else {
            return false;
        }
    }
    return options->have_service && options->have_method &&
        options->have_tx_id && options->have_timeout &&
        options->have_socket;
}

static int read_payload(u8 **payload, u32 *payload_len) {
    u8 *buffer;
    size_t used = 0;

    if (!payload || !payload_len)
        return -1;
    *payload = NULL;
    *payload_len = 0;
    buffer = malloc(NETLAB_MAX_MSG);
    if (!buffer) {
        fprintf(stderr, "error: cannot allocate request payload buffer\n");
        return -1;
    }
    while (used < NETLAB_MAX_MSG) {
        size_t received = fread(
            buffer + used, 1, (size_t)NETLAB_MAX_MSG - used, stdin);

        used += received;
        if (received == 0)
            break;
    }
    if (ferror(stdin)) {
        fprintf(stderr, "error: cannot read request payload from stdin\n");
        free(buffer);
        return -1;
    }
    if (used == NETLAB_MAX_MSG) {
        int extra = fgetc(stdin);

        if (extra != EOF) {
            fprintf(stderr,
                    "error: request payload exceeds NETLAB_MAX_MSG\n");
            free(buffer);
            return -1;
        }
        if (ferror(stdin)) {
            fprintf(stderr,
                    "error: cannot finish reading request payload\n");
            free(buffer);
            return -1;
        }
    }
    if (used == 0) {
        free(buffer);
        buffer = NULL;
    }
    *payload = buffer;
    *payload_len = (u32)used;
    return 0;
}

static bool request_allowed(const helper_options *options, const u8 *payload,
                            u32 payload_len, const char **reason) {
    const nl_rpc_contract *contract;

    if (reason)
        *reason = "method is not registered";
    if (!options)
        return false;
    contract = nl_rpc_contract_lookup(options->service, options->method);
    if (!contract)
        return false;
    if (!contract->internal_authority_allowed) {
        if (reason)
            *reason = "method is not authorized for sealed INTERNAL RPC";
        return false;
    }
    if (!nl_rpc_contract_payload_valid(
            contract->request_format, payload, payload_len,
            contract->max_request_len)) {
        if (reason)
            *reason = "payload violates the typed RPC contract";
        return false;
    }
    if ((contract->flags & NL_RPC_CONTRACT_TX_ID_REQUIRED) &&
        options->tx_id == 0) {
        if (reason)
            *reason = "typed RPC contract requires a nonzero transaction ID";
        return false;
    }
    if (reason)
        *reason = "ok";
    return true;
}

static void store_u16_be(u8 *out, u16 value) {
    out[0] = (u8)(value >> 8);
    out[1] = (u8)value;
}

static void store_u32_be(u8 *out, u32 value) {
    out[0] = (u8)(value >> 24);
    out[1] = (u8)(value >> 16);
    out[2] = (u8)(value >> 8);
    out[3] = (u8)value;
}

static bool write_all(int fd, const u8 *data, size_t data_len) {
    size_t written = 0;

    while (written < data_len) {
        ssize_t result = write(fd, data + written, data_len - written);

        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0)
            return false;
        written += (size_t)result;
    }
    return true;
}

static bool write_envelope(s32 error_code, const u8 *payload,
                           u32 payload_len) {
    u8 header[INTERNAL_RPC_ENVELOPE_SIZE];

    store_u32_be(header, INTERNAL_RPC_ENVELOPE_MAGIC);
    store_u16_be(header + 4, INTERNAL_RPC_ENVELOPE_VERSION);
    store_u32_be(header + 6, (u32)error_code);
    store_u32_be(header + 10, payload_len);
    return write_all(STDOUT_FILENO, header, sizeof(header)) &&
        (payload_len == 0 ||
         write_all(STDOUT_FILENO, payload, payload_len));
}

int main(int argc, char **argv) {
    helper_options options;
    const nl_rpc_contract *contract;
    const char *reason = NULL;
    nl_rpc_response response = {0};
    u8 *payload = NULL;
    u32 payload_len = 0;
    int response_len;
    int result = HELPER_EXIT_OK;

    if (geteuid() != 0 || getegid() != 0) {
        fprintf(stderr,
                "error: netlab-internal-rpc requires effective UID/GID 0\n");
        return HELPER_EXIT_PRIVILEGE;
    }
    if (!parse_options(argc, argv, &options)) {
        usage(argv[0]);
        return HELPER_EXIT_USAGE;
    }
    if (read_payload(&payload, &payload_len) != 0)
        return HELPER_EXIT_INPUT;
    if (!request_allowed(&options, payload, payload_len, &reason)) {
        fprintf(stderr, "error: INTERNAL RPC denied locally: %s\n", reason);
        result = HELPER_EXIT_POLICY;
        goto out;
    }

    /*
     * Re-check the registry result immediately before the client call.  This
     * keeps the typed contract as the sole method allowlist authority.
     */
    contract = nl_rpc_contract_lookup(options.service, options.method);
    if (!contract || !contract->internal_authority_allowed) {
        fprintf(stderr,
                "error: INTERNAL RPC contract changed before dispatch\n");
        result = HELPER_EXIT_POLICY;
        goto out;
    }
    response_len = nl_rpc_call_alloc_ex(
        options.socket_path, NL_DAEMON_INTERNAL, options.service,
        options.method, options.tx_id, payload, (int)payload_len,
        options.timeout_ms, &response);
    if (response_len < 0) {
        fprintf(stderr,
                "error: INTERNAL RPC transport or protocol failure "
                "service=%u method=%u socket=%s\n",
                (unsigned)options.service, (unsigned)options.method,
                options.socket_path);
        result = HELPER_EXIT_TRANSPORT;
        goto out;
    }
    if (!write_envelope(
            response.error_code, response.payload, response.payload_len)) {
        fprintf(stderr, "error: cannot write INTERNAL RPC response envelope\n");
        result = HELPER_EXIT_OUTPUT;
    }

out:
    nl_rpc_response_free(&response);
    free(payload);
    return result;
}
