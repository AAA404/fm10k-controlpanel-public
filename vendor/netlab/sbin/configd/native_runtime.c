#include "native_runtime.h"
#include "netlab/ipc.h"
#include "netlab/error.h"
#include "netlab/fm10k_board_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool configd_native_control_mode(void) {
    const char *native = getenv("NETLAB_FM10K_NATIVE");
    const char *mode = getenv("NETLAB_FM10K_STARTUP_MODE");
    return native && !strcmp(native, "1") && mode && !strcmp(mode, "control");
}

static const char *socket_path(void) {
    return nl_ipc_socket_path_from_env("NETLAB_SWITCHD_SOCKET", "/var/run/netlab/switchd.sock");
}

static bool native_hex_field(const char *text, const char *key, u64 *out) {
    const char *value = strstr(text, key);
    if (!value) return false;
    value += strlen(key);
    if (strspn(value, "0123456789abcdef") != 16 || value[16] != '"') return false;
    unsigned long long parsed = 0;
    if (sscanf(value, "%16llx", &parsed) != 1) return false;
    *out = (u64)parsed; return true;
}

static int native_status(const char *profile, u64 *generation, bool *bound, u64 *commit) {
    char response[8192] = {0}, expected[96];
    s32 error = 0;
    if (!generation || !bound || !nl_fm10k_profile_known(profile)) return NL_ERR_INVALID_VALUE;
    *generation = 0; *bound = false;
    int n = nl_rpc_call_ex(socket_path(), NL_DAEMON_CONFIGD, NL_DAEMON_SWITCHD,
        NL_SWITCHD_FM10K_BOARD_GET, 0, (const u8 *)"contract", 8,
        (u8 *)response, sizeof(response) - 1, 3000, &error);
    if (n <= 0 || n >= (int)sizeof(response) || error) return NL_ERR_PFE_DOWN;
    response[n] = 0;
    snprintf(expected, sizeof(expected), "\"profile\":\"%s\"", profile);
    if (!strstr(response, expected) || !strstr(response, "\"native_ready\":true"))
        return NL_ERR_PFE_DOWN;
    if (!native_hex_field(response, "\"native_generation\":\"", generation) || !*generation ||
        (commit && !native_hex_field(response, "\"native_commit\":\"", commit)))
        return NL_ERR_MALFORMED_REQUEST;
    *bound = strstr(response, "\"board_hal\":\"bound\"") != NULL;
    return 0;
}
int configd_native_status(const char *profile, u64 *generation, bool *bound) {
    return native_status(profile, generation, bound, NULL);
}

int configd_native_bind(const char *profile, u64 generation, u64 commit) {
    struct { u32 schema, reserved; u64 generation; } request = {1, 0, generation};
    s32 error = 0;
    if (!generation || !commit) return NL_ERR_INVALID_VALUE;
    int n = nl_rpc_call_ex(socket_path(), NL_DAEMON_CONFIGD, NL_DAEMON_SWITCHD,
        NL_SWITCHD_FM10K_BIND, commit, (const u8 *)&request, sizeof(request), NULL, 0, 3000, &error);
    if (n >= 0 && error) return error;
    u64 actual = 0, verified_commit = 0;
    bool bound = false;
    /* A lost acknowledgement is resolved from the same SDK lifetime; the
     * caller has already verified the durable active image through replay. */
    int read = native_status(profile, &actual, &bound, &verified_commit);
    if (!read && actual == generation && bound && verified_commit == commit) return 0;
    return error ? error : n < 0 ? NL_ERR_DAEMON_UNREACHABLE : NL_ERR_HW_STATE_OUT_OF_SYNC;
}
