/* Exercise configd's actual candidate boundary with Web-generated XML and
 * libyang, without a hardware or daemon transport. */
#define main configd_daemon_entry
#include "../vendor/netlab/sbin/configd/main.c"
#undef main
#include <assert.h>

void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)format;
}
static char *read_xml(const char *path, u32 *length) {
    FILE *file = fopen(path, "rb"); assert(file);
    char *xml = calloc(NETLAB_CONFIG_XML_MAX + 1, 1); assert(xml);
    *length = (u32)fread(xml, 1, NETLAB_CONFIG_XML_MAX, file);
    assert(*length && !ferror(file) && feof(file)); fclose(file);
    return xml;
}
static void unchanged(const char *before) {
    char *actual = nl_yang_to_xml(g_ctx.candidate);
    assert(actual && !strcmp(actual, before)); free(actual);
}
int main(int argc, char **argv) {
    assert(argc >= 4);
    g_ctx.active = nl_yang_session_create(NULL);
    g_ctx.candidate = nl_yang_session_create(NULL);
    assert(g_ctx.active && g_ctx.candidate);
    u32 length;
    char *xml = read_xml(argv[1], &length);
    nl_yang_data_set(g_ctx.active, nl_yang_from_xml(g_ctx.active, xml));
    nl_yang_data_set(g_ctx.candidate, nl_yang_from_xml(g_ctx.candidate, xml));
    free(xml);
    char *before = nl_yang_to_xml(g_ctx.candidate); assert(before);
    char detail[512];
    const char *job = "00000000000000000000000000000000";
    xml = read_xml(argv[2], &length);
    /* Semantic input must not weaken the separate hash-authoritative API. */
    assert(replace_candidate_xml_payload((const u8 *)xml, length, detail, sizeof(detail)) == NL_ERR_INVALID_VALUE);
    assert(strstr(detail, "canonical bytes")); unchanged(before);
    struct lyd_node *previous = NULL;
    assert(panel_prepare_candidate((const u8 *)xml, length, job, &previous, detail, sizeof(detail)) == NL_ERR_OK);
    assert(previous && nl_yang_exists(g_ctx.candidate, "/netlab:netlab-config/vlans/vlan[name='V4033']"));
    assert(!nl_yang_exists(g_ctx.active, "/netlab:netlab-config/vlans/vlan[name='V4033']"));
    char *canonical = nl_yang_to_xml(g_ctx.candidate); assert(canonical);
    size_t n = strlen(canonical);
    char *persisted = malloc(n + 2); assert(persisted);
    memcpy(persisted, canonical, n); persisted[n] = '\n'; persisted[n + 1] = 0;
    assert(validate_candidate_xml_payload((const u8 *)persisted, (u32)n + 1, false, detail, sizeof(detail)) == NL_ERR_OK);
    assert(validate_candidate_xml_payload((const u8 *)canonical, (u32)n, false, detail, sizeof(detail)) == NL_ERR_INVALID_VALUE);
    free(persisted); free(canonical); free(xml);
    /* A preview restores the in-memory image, without canonical-byte parsing. */
    nl_yang_data_set(g_ctx.candidate, previous); unchanged(before);
    for (int i = 3; i < argc; ++i) {
        xml = read_xml(argv[i], &length); previous = NULL;
        assert(panel_prepare_candidate((const u8 *)xml, length, job, &previous, detail, sizeof(detail)) != NL_ERR_OK);
        assert(!previous && detail[0]); unchanged(before); free(xml);
    }
    free(before); nl_yang_session_destroy(g_ctx.active); nl_yang_session_destroy(g_ctx.candidate);
    puts("panel semantic XML, exact checkpoint bytes, rejected namespaces and candidate restoration passed");
    return 0;
}
