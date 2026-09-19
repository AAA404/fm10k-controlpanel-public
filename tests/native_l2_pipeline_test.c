#include "netlab/l2_plan.h"
#include "netlab/hal.h"
#include "netlab/yang_config.h"
#include "netlab/log.h"
#include "netlab/ipc.h"
#include "netlab/interface_id.h"
#include <stdarg.h>
#include "l2_plan_text.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)file; (void)line;
    if (level <= NL_LOG_WARNING) { va_list ap; va_start(ap, format); vfprintf(stderr, format, ap); va_end(ap); fputc('\n', stderr); }
}
const char *nl_ipc_socket_path_from_env(const char *name, const char *fallback) {
    const char *value = getenv(name); return value && *value ? value : fallback;
}
int nl_rpc_call_ex(const char *socket_path, nl_daemon_id caller, nl_daemon_id service,
                    nl_rpc_method method, u64 tx, const u8 *payload, int payload_len,
                    u8 *out, int capacity, int timeout, s32 *error) {
    (void)socket_path; (void)caller; (void)service; (void)method; (void)tx;
    (void)payload; (void)payload_len; (void)out; (void)capacity; (void)timeout;
    if (method == NL_SWITCHD_LAG_GET_ALL && getenv("NETLAB_TEST_EMPTY_LAGS")) {
        const char *empty = "<lags>\n</lags>\n";
        assert(capacity > (int)strlen(empty));
        strcpy((char *)out, empty); *error = 0; return (int)strlen(empty);
    }
    *error = NL_ERR_DAEMON_UNREACHABLE;
    return -1; /* Offline planner uses actual intent; no invented hardware. */
}
int nl_rpc_call_alloc_ex(const char *path, nl_daemon_id caller, nl_daemon_id service,
                         nl_rpc_method method, u64 tx, const u8 *payload, int length,
                         int timeout, nl_rpc_response *response) {
    (void)path; (void)caller; (void)service; (void)method; (void)tx;
    (void)payload; (void)length; (void)timeout;
    memset(response, 0, sizeof(*response)); return -1;
}
void nl_rpc_response_free(nl_rpc_response *response) { (void)response; }
static nl_yang_session *read_config(const char *path) {
    FILE *file = fopen(path, "r"); assert(file);
    char *xml = calloc(250001, 1); assert(xml);
    size_t length = fread(xml, 1, 250000, file); assert(length && !ferror(file));
    fclose(file);
    nl_yang_session *s = nl_yang_session_create(NULL); assert(s);
    struct lyd_node *tree = nl_yang_from_xml(s, xml); assert(tree);
    free(xml); nl_yang_data_set(s, tree); return s;
}
int main(int argc, char **argv) {
    assert(argc == 3);
    assert(nl_ifid_resolver_init(NULL) == NL_OK);
    const char *invalid_filters[] = {
        "port-ingress-filter-set port=1 enabled=2\n",
        "port-ingress-filter-set port=1 enabled=-1\n",
        "port-ingress-filter-set port=1\n",
        "port-ingress-filter-set enabled=1\n",
        "storm-control-set port=1 kind=ingress rate=22000 burst=65536\n",
        "storm-control-set port=1 kind=invalid rate=22000 burst=65536\n",
        "storm-control-set port=1 kind=broadcast rate=100 burst=65536\n",
        "storm-control-del port=1 kind=invalid\n",
        "qos-interface-set ae=-1 trust=0 default-priority=0\n",
        "qos-interface-set ae=0 trust=3 default-priority=0\n",
        "qos-interface-set ae=0 trust=0 default-priority=8\n",
        "qos-interface-del ae=9999\n",
        "qos-dscp-set dscp=64 priority=3\n",
        "qos-dscp-set dscp=26 priority=16\n",
        "qos-dscp-set dscp=26\n",
        "qos-pfc-set port=13 rx-class-mask=8 tx-class-mask=8 lossless-smp-mask=2 shared-pause-mask=2 watchdog-detect-ms=999\n",
        "qos-pfc-set port=13 rx-class-mask=8 tx-class-mask=8 lossless-smp-mask=2 shared-pause-mask=2 watchdog-detect-ms=20000 watchdog-cooldown-ms=10000\n",
        "qos-pfc-set port=13 rx-class-mask=255 tx-class-mask=8 lossless-smp-mask=2 shared-pause-mask=2 watchdog-detect-ms=1000\n",
        "qos-pfc-set port=13 rx-class-mask=8 tx-class-mask=8 lossless-smp-mask=2 shared-pause-mask=2 watchdog-recovery-ms=-1\n",
    };
    for (size_t i = 0; i < sizeof(invalid_filters) / sizeof(invalid_filters[0]); ++i) {
        l2_apply_plan bad; l2_apply_plan_init(&bad);
        assert(l2_plan_parse(invalid_filters[i], &bad) < 0);
        l2_apply_plan_reset(&bad);
    }
    nl_yang_session *a = read_config(argv[1]), *b = read_config(argv[2]);
    char *text = calloc(NL_L2_PLAN_MAX_BYTES, 1); assert(text);
    char error[512] = {0};
    int length, count;
    bool has;
    int rc = nl_l2_build_plan(a, b, false, text, NL_L2_PLAN_MAX_BYTES, &length, &has, error, sizeof(error));
    if (rc) { fprintf(stderr, "L2 plan: %s\n", error); return 1; }
    if (length) {
        if (l2_plan_text_validate(text, &count, error, sizeof(error))) {
            fprintf(stderr, "text validation: %s\n%s", error, text); return 2;
        }
        l2_apply_plan parsed; l2_apply_plan_init(&parsed);
        assert(l2_plan_parse(text, &parsed) == count);
        assert(parsed.fm10k_scope_present);
        l2_apply_plan copy; l2_apply_plan_init(&copy);
        assert(!l2_apply_plan_clone(&copy, &parsed));
        assert(copy.fm10k_scope_present && copy.fm10k_scope_mask == parsed.fm10k_scope_mask);
        l2_apply_plan_reset(&copy);
        l2_apply_plan_reset(&parsed);
    }
    fputs(text, stdout);
    nl_yang_session_destroy(a); nl_yang_session_destroy(b); free(text);
    return 0;
}
