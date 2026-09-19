#include "frr_telemetry_json.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check(const char *name, int ok, int scale) {
    printf("%s: %s scale=%d\n", ok ? "PASS" : "FAIL", name, scale);
    return ok ? 0 : 1;
}

static int appendf(char *buf, size_t size, size_t *off,
                   const char *format, ...) {
    va_list ap;
    int n;

    if (*off >= size)
        return -1;
    va_start(ap, format);
    n = vsnprintf(buf + *off, size - *off, format, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= size - *off)
        return -1;
    *off += (size_t)n;
    return 0;
}

static int build_ospf_json(char *buf, size_t size, int count) {
    size_t off = 0;

    if (appendf(buf, size, &off, "{\"neighbors\":{") != 0)
        return -1;
    for (int i = 0; i < count; i++) {
        if (appendf(
                buf, size, &off,
                "%s\"192.0.2.%d\":[{\"priority\":1,"
                "\"state\":\"Full/DR\",\"deadTimeMsecs\":31000,"
                "\"address\":\"192.0.2.%d\","
                "\"ifaceName\":\"irb.%d\"}]",
                i ? "," : "", i + 1, i + 1, i + 1) != 0)
            return -1;
    }
    return appendf(buf, size, &off, "}}") == 0 ? (int)off : -1;
}

static int build_bgp_json(char *buf, size_t size, int count) {
    size_t off = 0;

    if (appendf(buf, size, &off,
                "{\"ipv4Unicast\":{\"peers\":{") != 0)
        return -1;
    for (int i = 0; i < count; i++) {
        if (appendf(
                buf, size, &off,
                "%s\"198.51.100.%d\":{\"remoteAs\":%d,"
                "\"peerUptime\":\"00:00:05\","
                "\"state\":\"Established\",\"pfxRcd\":%d}",
                i ? "," : "", i + 1, 65000 + i, i) != 0)
            return -1;
    }
    return appendf(buf, size, &off, "}}}") == 0 ? (int)off : -1;
}

int main(void) {
    static const int scales[] = {8, 9, 64, 65};
    char *json = malloc(131072);
    int failed = 0;

    if (!json)
        return 1;
    for (size_t i = 0; i < sizeof(scales) / sizeof(scales[0]); i++) {
        rpd_frr_runtime rt = {0};
        char err[192] = {0};
        int count = scales[i];
        int total = -1;
        int full = -1;
        int stored = count < 64 ? count : 64;
        int rc;

        if (build_ospf_json(json, 131072, count) < 0)
            return 1;
        rc = rpd_frr_parse_ospf_neighbors_json(
            json, &rt, &total, &full, err, sizeof(err));
        failed += check(
            "OSPF telemetry carries total/complete/truncated",
            rc == 0 && total == count && full == count &&
            rt.ospf_neighbor_entries == stored &&
            rt.ospf_neighbor_complete == (count <= 64) &&
            rt.ospf_neighbor_truncated == (count > 64),
            count);

        memset(&rt, 0, sizeof(rt));
        memset(err, 0, sizeof(err));
        total = -1;
        full = -1;
        if (build_bgp_json(json, 131072, count) < 0)
            return 1;
        rc = rpd_frr_parse_bgp_summary_json(
            json, &rt, &total, &full, err, sizeof(err));
        failed += check(
            "BGP telemetry carries total/complete/truncated",
            rc == 0 && total == count && full == count &&
            rt.bgp_peer_entries == stored &&
            rt.bgp_peer_complete == (count <= 64) &&
            rt.bgp_peer_truncated == (count > 64),
            count);
    }
    free(json);
    return failed ? 1 : 0;
}
