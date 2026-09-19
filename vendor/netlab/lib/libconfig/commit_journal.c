/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/journal.h"
#include "netlab/log.h"
#include "netlab/monotonic.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <dirent.h>
#include <inttypes.h>
#include <errno.h>
#include <limits.h>

#define JOURNAL_INDEX_NAME "unresolved-v2.json"
#define JOURNAL_MIGRATION_NAME "migration-v2.json"
#define JOURNAL_RESERVATION_PREFIX ".reserve-"

typedef struct {
    u64 *ids;
    size_t count;
    size_t capacity;
} journal_id_list;

typedef struct {
    u64 tx_id;
    s64 updated_at;
    bool pinned;
} journal_terminal_entry;

static size_t journal_active_retention;

static bool dir_path_safe(const char *path) {
    size_t len;

    if (!path || path[0] != '/')
        return false;
    len = strlen(path);
    if (len == 0 || len >= 384)
        return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)path[i];

        if (!(isalnum(c) || c == '/' || c == '.' || c == '_' ||
              c == '-' || c == ':'))
            return false;
    }
    return true;
}

const char *nl_config_dir(void) {
    const char *path = getenv("NETLAB_CONFIG_DIR");

    if (dir_path_safe(path))
        return path;
    return NL_CONFIG_DIR;
}

const char *nl_journal_dir(void) {
    static char derived[512];
    const char *path = getenv("NETLAB_JOURNAL_DIR");

    if (dir_path_safe(path))
        return path;
    snprintf(derived, sizeof(derived), "%s/journal", nl_config_dir());
    return derived;
}

void nl_config_file_path(char *buf, size_t size, const char *name) {
    if (!buf || size == 0)
        return;
    snprintf(buf, size, "%s/%s", nl_config_dir(), name ? name : "");
}

void nl_journal_file_path(char *buf, size_t size, const char *name) {
    if (!buf || size == 0)
        return;
    snprintf(buf, size, "%s/%s", nl_journal_dir(), name ? name : "");
}

static const char *journal_state_str(nl_journal_state state) {
    static const char *state_str[] = {
        "PREPARED", "APPLYING", "VERIFYING", "VERIFY_OK",
        "HW_MARKED_COMMITTED", "COMMITTED", "FAILED_ROLLED_BACK",
        "HW_OUT_OF_SYNC", "RECONCILED_TO_ACTIVE"
    };
    if (state < NL_JOURNAL_PREPARED ||
        state > NL_JOURNAL_RECONCILED_TO_ACTIVE)
        return NULL;
    return state_str[state];
}

static bool journal_state_from_str(const char *name,
                                   nl_journal_state *state) {
    if (!name || !state)
        return false;
    for (int i = NL_JOURNAL_PREPARED;
         i <= NL_JOURNAL_RECONCILED_TO_ACTIVE; i++) {
        const char *candidate = journal_state_str((nl_journal_state)i);

        if (candidate && strcmp(name, candidate) == 0) {
            *state = (nl_journal_state)i;
            return true;
        }
    }
    return false;
}

static void journal_path_buf(char *buf, size_t size, u64 tx_id) {
    char name[64];

    snprintf(name, sizeof(name), "%016lx.json", tx_id);
    nl_journal_file_path(buf, size, name);
}

static void rollback_path_buf(char *buf, size_t size, u64 tx_id) {
    snprintf(buf, size, "%s/rollback/%016lx.conf", nl_config_dir(), tx_id);
}

static void candidate_snapshot_path_buf(
    char *buf, size_t size, u64 tx_id) {
    snprintf(buf, size, "%s/candidates/%016lx.conf",
             nl_journal_dir(), tx_id);
}

static bool parse_journal_tx_filename(const char *name, u64 *tx_id) {
    u64 value = 0;

    if (!name || strlen(name) != 21 || strcmp(name + 16, ".json") != 0)
        return false;
    for (int i = 0; i < 16; i++) {
        unsigned char c = (unsigned char)name[i];
        u64 digit;

        if (c >= '0' && c <= '9') {
            digit = (u64)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = (u64)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            digit = (u64)(c - 'A' + 10);
        } else {
            return false;
        }
        value = (value << 4) | digit;
    }
    if (tx_id)
        *tx_id = value;
    return true;
}

static nl_status fsync_parent_dir(const char *path) {
    char parent[512];
    char *slash;
    int fd;
    nl_status st = NL_OK;

    if (!path || strlen(path) >= sizeof(parent))
        return NL_ERR;
    snprintf(parent, sizeof(parent), "%s", path);
    slash = strrchr(parent, '/');
    if (!slash || slash == parent)
        return NL_ERR;
    *slash = '\0';
    fd = open(parent, O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return NL_ERR;
    if (fsync(fd) != 0)
        st = NL_ERR;
    if (close(fd) != 0)
        st = NL_ERR;
    return st;
}

static nl_status ensure_durable_directory(const char *path) {
    struct stat st;

    if (!dir_path_safe(path))
        return NL_ERR;
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return NL_ERR;
    if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode))
        return NL_ERR;
    return fsync_parent_dir(path);
}

static nl_status ensure_journal_directories(void) {
    if (ensure_durable_directory(nl_config_dir()) != NL_OK)
        return NL_ERR;
    return ensure_durable_directory(nl_journal_dir());
}

static nl_status unlink_file_durable(const char *path) {
    if (unlink(path) != 0) {
        if (errno == ENOENT)
            return NL_OK;
        return NL_ERR;
    }
    return fsync_parent_dir(path);
}

static int write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static nl_status persist_text_atomic(const char *path, const char *content,
                                     size_t len, mode_t mode) {
    char tmp[640];
    int fd;
    nl_status st = NL_ERR;

    if (!path || !content)
        return NL_ERR;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path) >= (int)sizeof(tmp))
        return NL_ERR;
    fd = mkstemp(tmp);
    if (fd < 0)
        return NL_ERR;
    if (fchmod(fd, mode) != 0)
        goto out;
    if (write_all(fd, content, len) != 0)
        goto out;
    if (fsync(fd) != 0)
        goto out;
    if (close(fd) != 0) {
        fd = -1;
        goto out_unlink;
    }
    fd = -1;
    if (rename(tmp, path) != 0)
        goto out_unlink;
    if (fsync_parent_dir(path) != NL_OK)
        return NL_ERR;
    st = NL_OK;
    return st;

out:
    if (fd >= 0)
        close(fd);
out_unlink:
    unlink(tmp);
    return st;
}

static char *read_text_file(const char *path, size_t *out_len) {
    FILE *f;
    long flen;
    char *content;
    size_t rlen;

    if (out_len)
        *out_len = 0;
    f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    flen = ftell(f);
    if (flen < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    content = malloc((size_t)flen + 1);
    if (!content) {
        fclose(f);
        return NULL;
    }
    rlen = fread(content, 1, (size_t)flen, f);
    if (ferror(f)) {
        free(content);
        fclose(f);
        return NULL;
    }
    fclose(f);
    content[rlen] = '\0';
    if (out_len)
        *out_len = rlen;
    return content;
}

static char *json_escape_string(const char *value) {
    const unsigned char *src = (const unsigned char *)(value ? value : "");
    size_t len = 0;
    char *out;
    char *dst;

    for (const unsigned char *p = src; *p; p++) {
        if (*p == '"' || *p == '\\' || *p == '\b' || *p == '\f' ||
            *p == '\n' || *p == '\r' || *p == '\t') {
            len += 2;
        } else if (*p < 0x20) {
            len += 6;
        } else {
            len++;
        }
        if (len > 4096)
            return NULL;
    }
    out = malloc(len + 1);
    if (!out)
        return NULL;
    dst = out;
    for (const unsigned char *p = src; *p; p++) {
        switch (*p) {
        case '"': *dst++ = '\\'; *dst++ = '"'; break;
        case '\\': *dst++ = '\\'; *dst++ = '\\'; break;
        case '\b': *dst++ = '\\'; *dst++ = 'b'; break;
        case '\f': *dst++ = '\\'; *dst++ = 'f'; break;
        case '\n': *dst++ = '\\'; *dst++ = 'n'; break;
        case '\r': *dst++ = '\\'; *dst++ = 'r'; break;
        case '\t': *dst++ = '\\'; *dst++ = 't'; break;
        default:
            if (*p < 0x20) {
                snprintf(dst, 7, "\\u%04x", *p);
                dst += 6;
            } else {
                *dst++ = (char)*p;
            }
            break;
        }
    }
    *dst = '\0';
    return out;
}

static const char *json_skip_ws(const char *p) {
    while (p && isspace((unsigned char)*p))
        p++;
    return p;
}

static bool json_parse_value(const char **pp, int depth);

static bool json_parse_hex4(const char **pp) {
    const char *p = *pp;

    for (int i = 0; i < 4; i++) {
        if (!isxdigit((unsigned char)p[i]))
            return false;
    }
    *pp = p + 4;
    return true;
}

static bool json_parse_string(const char **pp) {
    const char *p = *pp;

    if (*p != '"')
        return false;
    p++;
    while (*p) {
        unsigned char c = (unsigned char)*p++;

        if (c == '"') {
            *pp = p;
            return true;
        }
        if (c < 0x20)
            return false;
        if (c == '\\') {
            c = (unsigned char)*p++;
            if (c == '"' || c == '\\' || c == '/' || c == 'b' ||
                c == 'f' || c == 'n' || c == 'r' || c == 't') {
                continue;
            }
            if (c == 'u') {
                if (!json_parse_hex4(&p))
                    return false;
                continue;
            }
            return false;
        }
    }
    return false;
}

static bool json_parse_literal(const char **pp, const char *lit) {
    size_t len = strlen(lit);

    if (strncmp(*pp, lit, len) != 0)
        return false;
    *pp += len;
    return true;
}

static bool json_parse_number(const char **pp) {
    const char *p = *pp;

    if (*p == '-')
        p++;
    if (*p == '0') {
        p++;
    } else if (*p >= '1' && *p <= '9') {
        while (isdigit((unsigned char)*p))
            p++;
    } else {
        return false;
    }
    if (*p == '.') {
        p++;
        if (!isdigit((unsigned char)*p))
            return false;
        while (isdigit((unsigned char)*p))
            p++;
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-')
            p++;
        if (!isdigit((unsigned char)*p))
            return false;
        while (isdigit((unsigned char)*p))
            p++;
    }
    *pp = p;
    return true;
}

static bool json_parse_array(const char **pp, int depth) {
    const char *p = *pp + 1;

    p = json_skip_ws(p);
    if (*p == ']') {
        *pp = p + 1;
        return true;
    }
    while (*p) {
        if (!json_parse_value(&p, depth + 1))
            return false;
        p = json_skip_ws(p);
        if (*p == ']') {
            *pp = p + 1;
            return true;
        }
        if (*p != ',')
            return false;
        p = json_skip_ws(p + 1);
    }
    return false;
}

static bool json_parse_object(const char **pp, int depth) {
    const char *p = *pp + 1;

    p = json_skip_ws(p);
    if (*p == '}') {
        *pp = p + 1;
        return true;
    }
    while (*p) {
        if (!json_parse_string(&p))
            return false;
        p = json_skip_ws(p);
        if (*p != ':')
            return false;
        p = json_skip_ws(p + 1);
        if (!json_parse_value(&p, depth + 1))
            return false;
        p = json_skip_ws(p);
        if (*p == '}') {
            *pp = p + 1;
            return true;
        }
        if (*p != ',')
            return false;
        p = json_skip_ws(p + 1);
    }
    return false;
}

static bool json_parse_value(const char **pp, int depth) {
    const char *p;

    if (!pp || !*pp || depth > 64)
        return false;
    p = json_skip_ws(*pp);
    if (*p == '{') {
        *pp = p;
        return json_parse_object(pp, depth);
    }
    if (*p == '[') {
        *pp = p;
        return json_parse_array(pp, depth);
    }
    if (*p == '"') {
        *pp = p;
        return json_parse_string(pp);
    }
    if (*p == '-' || isdigit((unsigned char)*p)) {
        *pp = p;
        return json_parse_number(pp);
    }
    if (*p == 't') {
        if (!json_parse_literal(&p, "true"))
            return false;
        *pp = p;
        return true;
    }
    if (*p == 'f') {
        if (!json_parse_literal(&p, "false"))
            return false;
        *pp = p;
        return true;
    }
    if (*p == 'n') {
        if (!json_parse_literal(&p, "null"))
            return false;
        *pp = p;
        return true;
    }
    return false;
}

static bool json_step_structurally_valid(const char *json) {
    const char *p;

    if (!json)
        return false;
    p = json_skip_ws(json);
    if (*p != '{' && *p != '[')
        return false;
    if (!json_parse_value(&p, 0))
        return false;
    p = json_skip_ws(p);
    return *p == '\0';
}

static bool json_document_structurally_valid(const char *json) {
    const char *p;

    if (!json)
        return false;
    p = json_skip_ws(json);
    if (*p != '{' || !json_parse_value(&p, 0))
        return false;
    return *json_skip_ws(p) == '\0';
}

static nl_status journal_persist_record(const nl_commit_journal *j);
static nl_status journal_index_reserve_create(u64 tx_id);
static nl_status journal_index_finish_create(u64 tx_id);
static nl_status journal_index_cancel_create(u64 tx_id);
static nl_status journal_index_ensure(u64 tx_id);
static nl_status journal_index_remove(u64 tx_id);
static nl_status journal_compact_terminal(size_t retention_limit,
                                          u64 *removed_out,
                                          u64 *retained_out);
static size_t journal_retention_limit(void);

nl_status nl_journal_create(u64 tx_id, u64 base_commit_id,
                            const char *candidate_hash) {
    nl_commit_journal j;
    s64 now = (s64)time(NULL);
    char path[512];

    if (ensure_journal_directories() != NL_OK)
        return NL_ERR;
    if (journal_index_reserve_create(tx_id) != NL_OK)
        return NL_ERR;
    memset(&j, 0, sizeof(j));
    j.schema_version = NL_JOURNAL_SCHEMA_VERSION;
    j.tx_id = tx_id;
    j.base_commit_id = base_commit_id;
    j.state = NL_JOURNAL_PREPARED;
    j.started_at = now;
    j.updated_at = now;
    snprintf(j.candidate_hash, sizeof(j.candidate_hash), "%s",
             candidate_hash ? candidate_hash : "");
    snprintf(j.plan, sizeof(j.plan), "[]");
    snprintf(j.applied_steps, sizeof(j.applied_steps), "[]");
    snprintf(j.rollback_steps, sizeof(j.rollback_steps), "[]");
    if (journal_persist_record(&j) != NL_OK) {
        journal_path_buf(path, sizeof(path), tx_id);
        if (unlink_file_durable(path) != NL_OK)
            return NL_ERR;
        if (journal_index_cancel_create(tx_id) != NL_OK)
            return NL_ERR;
        return NL_ERR;
    }
    if (journal_index_finish_create(tx_id) != NL_OK)
        return NL_ERR;
    journal_path_buf(path, sizeof(path), tx_id);
    NL_LOG_INFO("journal v2 created %s state=PREPARED", path);
    return NL_OK;
}

nl_status nl_journal_update_state(u64 tx_id, nl_journal_state state) {
    nl_commit_journal j;
    nl_status index_st;

    if (!journal_state_str(state) || nl_journal_get(tx_id, &j) != NL_OK)
        return NL_ERR;
    j.schema_version = NL_JOURNAL_SCHEMA_VERSION;
    j.state = state;
    j.updated_at = (s64)time(NULL);
    j.legacy_malformed_state = false;
    if (journal_persist_record(&j) != NL_OK)
        return NL_ERR;
    if (state == NL_JOURNAL_COMMITTED ||
        state == NL_JOURNAL_FAILED_ROLLED_BACK ||
        state == NL_JOURNAL_RECONCILED_TO_ACTIVE) {
        index_st = journal_index_remove(tx_id);
        if (index_st == NL_OK)
            index_st = journal_compact_terminal(
                journal_retention_limit(), NULL, NULL);
    } else {
        index_st = journal_index_ensure(tx_id);
    }
    if (index_st != NL_OK)
        return NL_ERR;
    NL_LOG_INFO("journal tx=0x%016lx state=%s", tx_id,
                journal_state_str(state));
    return NL_OK;
}

static bool parse_journal_state_line(const char *line,
                                     nl_journal_state *state,
                                     bool *legacy_malformed) {
    const char *key;
    const char *best = NULL;
    nl_journal_state best_state = NL_JOURNAL_PREPARED;

    if (!line || !state || !legacy_malformed)
        return false;
    key = strstr(line, "\"state\"");
    if (!key)
        return false;

    *legacy_malformed = strstr(line, "\"state\":") == NULL;
    for (int i = NL_JOURNAL_PREPARED;
         i <= NL_JOURNAL_RECONCILED_TO_ACTIVE; i++) {
        const char *name = journal_state_str((nl_journal_state)i);
        const char *p = name ? strstr(key, name) : NULL;
        if (p && (!best || p < best)) {
            best = p;
            best_state = (nl_journal_state)i;
        }
    }
    if (!best)
        return false;

    *state = best_state;
    return true;
}

static bool json_member_value(const char *content, const char *key,
                              const char **start, const char **end) {
    char needle[128];
    const char *p;
    const char *value;

    if (!content || !key || !start || !end ||
        snprintf(needle, sizeof(needle), "\"%s\"", key) >=
        (int)sizeof(needle))
        return false;
    p = strstr(content, needle);
    if (!p)
        return false;
    p = json_skip_ws(p + strlen(needle));
    if (*p != ':')
        return false;
    value = json_skip_ws(p + 1);
    p = value;
    if (!json_parse_value(&p, 0))
        return false;
    *start = value;
    *end = p;
    return true;
}

static bool json_copy_member(const char *content, const char *key,
                             char *out, size_t out_size, char required_start) {
    const char *start;
    const char *end;
    size_t len;

    if (!out || out_size == 0 ||
        !json_member_value(content, key, &start, &end) ||
        (required_start && *start != required_start))
        return false;
    len = (size_t)(end - start);
    if (len >= out_size)
        return false;
    memcpy(out, start, len);
    out[len] = '\0';
    return true;
}

static bool json_decode_string_member(const char *content, const char *key,
                                      char *out, size_t out_size) {
    const char *start;
    const char *end;
    const char *p;
    size_t off = 0;

    if (!out || out_size == 0 ||
        !json_member_value(content, key, &start, &end) || *start != '"')
        return false;
    p = start + 1;
    while (p < end && *p != '"') {
        unsigned char c = (unsigned char)*p++;

        if (c == '\\') {
            if (p >= end)
                return false;
            c = (unsigned char)*p++;
            switch (c) {
            case '"': case '\\': case '/': break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u':
                if (p + 4 > end)
                    return false;
                c = '?';
                p += 4;
                break;
            default:
                return false;
            }
        }
        if (off + 1 >= out_size)
            return false;
        out[off++] = (char)c;
    }
    if (p >= end || *p != '"')
        return false;
    out[off] = '\0';
    return true;
}

static bool json_parse_u64_member(const char *content, const char *key,
                                  u64 *value) {
    const char *start;
    const char *end;
    char number[64];
    size_t len;
    char *parse_end;
    unsigned long long parsed;

    if (!value || !json_member_value(content, key, &start, &end))
        return false;
    if (*start == '"') {
        start++;
        end--;
    }
    len = (size_t)(end - start);
    if (len == 0 || len >= sizeof(number))
        return false;
    memcpy(number, start, len);
    number[len] = '\0';
    errno = 0;
    parsed = strtoull(number, &parse_end, 0);
    if (errno != 0 || *parse_end != '\0')
        return false;
    *value = (u64)parsed;
    return true;
}

static bool json_parse_s64_member(const char *content, const char *key,
                                  s64 *value) {
    const char *start;
    const char *end;
    char number[64];
    size_t len;
    char *parse_end;
    long long parsed;

    if (!value || !json_member_value(content, key, &start, &end))
        return false;
    len = (size_t)(end - start);
    if (len == 0 || len >= sizeof(number))
        return false;
    memcpy(number, start, len);
    number[len] = '\0';
    errno = 0;
    parsed = strtoll(number, &parse_end, 10);
    if (errno != 0 || *parse_end != '\0')
        return false;
    *value = (s64)parsed;
    return true;
}

static bool confirm_boot_id_valid(const char *id) {
    if (!id || strnlen(id, 37) != 36) return false;
    for (int i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (id[i] != '-') return false;
        } else if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) return false;
    }
    return true;
}

static bool confirm_read_boot_id(char id[37]) {
    char value[38] = {0};
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    ssize_t n;
    do { n = read(fd, value, sizeof(value) - 1); } while (n < 0 && errno == EINTR);
    close(fd);
    if (n != 36 && !(n == 37 && value[36] == '\n')) return false;
    value[36] = '\0';
    if (!confirm_boot_id_valid(value)) return false;
    memcpy(id, value, 37);
    return true;
}

static bool confirm_clock_parse(const char *content, s64 *deadline, char boot_id[37]) {
    *deadline = 0; boot_id[0] = '\0';
    if (!strstr(content, "\"confirm_monotonic_deadline\"") && !strstr(content, "\"confirm_boot_id\"")) return true;
    return json_parse_s64_member(content, "confirm_monotonic_deadline", deadline) && *deadline > 0 &&
           json_decode_string_member(content, "confirm_boot_id", boot_id, 37) && confirm_boot_id_valid(boot_id);
}

static bool confirm_clock_format(char *out, size_t size, s64 deadline, const char boot_id[37]) {
    out[0] = '\0';
    if (!deadline && !boot_id[0]) return true;
    if (deadline <= 0 || !confirm_boot_id_valid(boot_id)) return false;
    int n = snprintf(out, size, "  \"confirm_monotonic_deadline\": %lld,\n  \"confirm_boot_id\": \"%s\",\n",
                     (long long)deadline, boot_id);
    return n > 0 && (size_t)n < size;
}

static nl_status journal_persist_record(const nl_commit_journal *j) {
    char path[512];
    char clock_fields[160];
    char *escaped_hash;
    char *content;
    const char *state;
    int n;
    nl_status st;

    if (!j || !(state = journal_state_str(j->state)) ||
        !confirm_clock_format(clock_fields, sizeof(clock_fields), j->confirm_monotonic_deadline, j->confirm_boot_id) ||
        !json_step_structurally_valid(j->plan) || j->plan[0] != '[' ||
        !json_step_structurally_valid(j->applied_steps) ||
        j->applied_steps[0] != '[' ||
        !json_step_structurally_valid(j->rollback_steps) ||
        j->rollback_steps[0] != '[')
        return NL_ERR;
    escaped_hash = json_escape_string(j->candidate_hash);
    if (!escaped_hash)
        return NL_ERR;
    n = snprintf(NULL, 0,
                 "{\n"
                 "  \"schema_version\": %u,\n"
                 "  \"tx_id\": \"0x%016lx\",\n"
                 "  \"base_commit_id\": \"0x%016lx\",\n"
                 "  \"candidate_hash\": \"%s\",\n"
                 "  \"state\": \"%s\",\n"
                 "  \"plan\": %s,\n"
                 "  \"applied_steps\": %s,\n"
                 "  \"rollback_steps\": %s,\n"
                 "  \"resulting_commit_id\": \"0x%016lx\",\n"
                 "  \"commit_confirmed\": %u,\n"
                 "  \"confirm_deadline\": %ld,\n"
                 "%s"
                 "  \"confirm_previous_commit_id\": \"0x%016lx\",\n"
                 "  \"started_at\": %ld,\n"
                 "  \"updated_at\": %ld\n"
                 "}\n",
                 j->schema_version, j->tx_id, j->base_commit_id,
                 escaped_hash, state, j->plan, j->applied_steps,
                 j->rollback_steps, j->resulting_commit_id,
                 j->commit_confirmed ? 1U : 0U,
                 (long)j->confirm_deadline, clock_fields,
                 j->confirm_previous_commit_id,
                 (long)j->started_at, (long)j->updated_at);
    if (n <= 0) {
        free(escaped_hash);
        return NL_ERR;
    }
    content = malloc((size_t)n + 1);
    if (!content) {
        free(escaped_hash);
        return NL_ERR;
    }
    snprintf(content, (size_t)n + 1,
             "{\n"
             "  \"schema_version\": %u,\n"
             "  \"tx_id\": \"0x%016lx\",\n"
             "  \"base_commit_id\": \"0x%016lx\",\n"
             "  \"candidate_hash\": \"%s\",\n"
             "  \"state\": \"%s\",\n"
             "  \"plan\": %s,\n"
             "  \"applied_steps\": %s,\n"
             "  \"rollback_steps\": %s,\n"
             "  \"resulting_commit_id\": \"0x%016lx\",\n"
             "  \"commit_confirmed\": %u,\n"
             "  \"confirm_deadline\": %ld,\n"
             "%s"
             "  \"confirm_previous_commit_id\": \"0x%016lx\",\n"
             "  \"started_at\": %ld,\n"
             "  \"updated_at\": %ld\n"
             "}\n",
             j->schema_version, j->tx_id, j->base_commit_id,
             escaped_hash, state, j->plan, j->applied_steps,
             j->rollback_steps, j->resulting_commit_id,
             j->commit_confirmed ? 1U : 0U,
             (long)j->confirm_deadline, clock_fields,
             j->confirm_previous_commit_id,
             (long)j->started_at, (long)j->updated_at);
    free(escaped_hash);
    journal_path_buf(path, sizeof(path), j->tx_id);
    st = persist_text_atomic(path, content, (size_t)n, 0600);
    free(content);
    return st;
}

static bool journal_has_committed_snapshot(u64 tx_id) {
    char path[512];
    struct stat st;
    u64 current_tx = 0;

    /*
     * A snapshot exists for every immutable transaction attempt.  Only exact
     * equality with the active pointer proves that this particular attempt
     * committed; a later active ID must not retroactively bless an older
     * failed attempt.
     */
    if (nl_tx_id_load(&current_tx) != NL_OK || current_tx != tx_id)
        return false;
    rollback_path_buf(path, sizeof(path), tx_id);
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static nl_status journal_append_to_array(u64 tx_id, const char *key,
                                          const char *step_json) {
    nl_commit_journal j;
    char *array;
    size_t array_size;
    size_t len;
    size_t step_len;

    if (!key || !step_json || !json_step_structurally_valid(step_json) ||
        nl_journal_get(tx_id, &j) != NL_OK)
        return NL_ERR;
    if (strcmp(key, "applied_steps") == 0) {
        array = j.applied_steps;
        array_size = sizeof(j.applied_steps);
    } else if (strcmp(key, "rollback_steps") == 0) {
        array = j.rollback_steps;
        array_size = sizeof(j.rollback_steps);
    } else {
        return NL_ERR;
    }
    len = strlen(array);
    step_len = strlen(step_json);
    if (len < 2 || array[0] != '[' || array[len - 1] != ']' ||
        len + step_len + 3 >= array_size)
        return NL_ERR;
    if (len == 2) {
        snprintf(array, array_size, "[%s]", step_json);
    } else {
        array[len - 1] = '\0';
        snprintf(array + len - 1, array_size - len + 1, ",%s]", step_json);
    }
    j.schema_version = NL_JOURNAL_SCHEMA_VERSION;
    j.updated_at = (s64)time(NULL);
    return journal_persist_record(&j);
}

nl_status nl_journal_set_plan(u64 tx_id, const char *plan_json) {
    nl_commit_journal j;

    if (!plan_json || plan_json[0] != '[' ||
        !json_step_structurally_valid(plan_json) ||
        strlen(plan_json) >= sizeof(j.plan) ||
        nl_journal_get(tx_id, &j) != NL_OK)
        return NL_ERR;
    snprintf(j.plan, sizeof(j.plan), "%s", plan_json);
    j.schema_version = NL_JOURNAL_SCHEMA_VERSION;
    j.updated_at = (s64)time(NULL);
    return journal_persist_record(&j);
}

nl_status nl_journal_append_applied(u64 tx_id, const char *step_json) {
    nl_status st = journal_append_to_array(tx_id, "applied_steps", step_json);
    if (st == NL_OK)
        NL_LOG_INFO("journal tx=0x%lx: appended applied step", tx_id);
    return st;
}

nl_status nl_journal_append_rollback(u64 tx_id, const char *step_json) {
    nl_status st = journal_append_to_array(tx_id, "rollback_steps", step_json);
    if (st == NL_OK)
        NL_LOG_INFO("journal tx=0x%lx: appended rollback step", tx_id);
    return st;
}

nl_status nl_journal_set_resulting_commit(u64 tx_id, u64 commit_id) {
    nl_commit_journal j;

    if (nl_journal_get(tx_id, &j) != NL_OK)
        return NL_ERR;
    j.schema_version = NL_JOURNAL_SCHEMA_VERSION;
    j.resulting_commit_id = commit_id;
    j.updated_at = (s64)time(NULL);
    return journal_persist_record(&j);
}

static nl_status journal_set_confirmed_intent(
    u64 tx_id, u64 previous_commit_id, s64 deadline, s64 seconds) {
    nl_commit_journal j;

    if (deadline <= 0 || nl_journal_get(tx_id, &j) != NL_OK)
        return NL_ERR;
    j.schema_version = NL_JOURNAL_SCHEMA_VERSION;
    j.commit_confirmed = true;
    j.confirm_deadline = deadline;
    j.confirm_monotonic_deadline = 0;
    j.confirm_boot_id[0] = '\0';
    if (seconds) {
        s64 now = (s64)nl_monotonic_seconds();
        if (seconds < 1 || seconds > 3600 || now <= 0 || now > LLONG_MAX - seconds ||
            !confirm_read_boot_id(j.confirm_boot_id)) return NL_ERR;
        j.confirm_monotonic_deadline = now + seconds;
    }
    j.confirm_previous_commit_id = previous_commit_id;
    j.updated_at = (s64)time(NULL);
    return journal_persist_record(&j);
}

nl_status nl_journal_set_confirmed_intent(u64 tx_id, u64 previous_commit_id, s64 deadline) {
    return journal_set_confirmed_intent(tx_id, previous_commit_id, deadline, 0);
}

nl_status nl_journal_set_confirmed_intent_monotonic(u64 tx_id, u64 previous_commit_id, s64 deadline, s64 seconds) {
    if (seconds < 1) return NL_ERR;
    return journal_set_confirmed_intent(tx_id, previous_commit_id, deadline, seconds);
}

nl_status nl_journal_get(u64 tx_id, nl_commit_journal *j) {
    char path[512];
    char *content;
    char *line;
    bool state_seen = false;
    bool malformed_state = false;
    u64 parsed_tx = tx_id;
    u64 schema = 1;
    bool schema_seen;

    if (!j)
        return NL_ERR;
    journal_path_buf(path, sizeof(path), tx_id);
    content = read_text_file(path, NULL);
    if (!content)
        return NL_ERR;
    memset(j, 0, sizeof(*j));
    j->schema_version = 1;
    j->tx_id = tx_id;
    snprintf(j->plan, sizeof(j->plan), "[]");
    snprintf(j->applied_steps, sizeof(j->applied_steps), "[]");
    snprintf(j->rollback_steps, sizeof(j->rollback_steps), "[]");

    line = content;
    while (line && *line) {
        char *next = strchr(line, '\n');

        if (strstr(line, "\"state\"") &&
            parse_journal_state_line(line, &j->state, &malformed_state)) {
            state_seen = true;
            j->legacy_malformed_state = malformed_state;
            break;
        }
        line = next ? next + 1 : NULL;
    }
    schema_seen = json_parse_u64_member(content, "schema_version", &schema);
    if ((strstr(content, "\"schema_version\"") && !schema_seen) ||
        (schema_seen && schema != 1 &&
         schema != NL_JOURNAL_SCHEMA_VERSION)) {
        free(content);
        return NL_ERR;
    }
    j->schema_version = (u32)schema;
    if (schema == NL_JOURNAL_SCHEMA_VERSION) {
        char state_name[64];
        u64 commit_confirmed = 0;
        bool confirmed_seen =
            strstr(content, "\"commit_confirmed\"") != NULL;

        if (!json_document_structurally_valid(content) ||
            !json_parse_u64_member(content, "tx_id", &parsed_tx) ||
            parsed_tx != tx_id ||
            !json_parse_u64_member(content, "base_commit_id",
                                   &j->base_commit_id) ||
            !json_decode_string_member(content, "candidate_hash",
                                       j->candidate_hash,
                                       sizeof(j->candidate_hash)) ||
            !json_decode_string_member(content, "state", state_name,
                                       sizeof(state_name)) ||
            !journal_state_from_str(state_name, &j->state) ||
            !json_parse_u64_member(content, "resulting_commit_id",
                                   &j->resulting_commit_id) ||
            !json_parse_s64_member(content, "started_at", &j->started_at) ||
            !json_parse_s64_member(content, "updated_at", &j->updated_at) ||
            !json_copy_member(content, "plan", j->plan, sizeof(j->plan),
                              '[') ||
            !json_copy_member(content, "applied_steps", j->applied_steps,
                              sizeof(j->applied_steps), '[') ||
            !json_copy_member(content, "rollback_steps", j->rollback_steps,
                              sizeof(j->rollback_steps), '[')) {
            free(content);
            return NL_ERR;
        }
        if (confirmed_seen) {
            if (!json_parse_u64_member(
                    content, "commit_confirmed", &commit_confirmed) ||
                commit_confirmed > 1 ||
                !json_parse_s64_member(
                    content, "confirm_deadline",
                    &j->confirm_deadline) ||
                !json_parse_u64_member(
                    content, "confirm_previous_commit_id",
                    &j->confirm_previous_commit_id) ||
                (commit_confirmed != 0 &&
                 j->confirm_deadline <= 0)) {
                free(content);
                return NL_ERR;
            }
            j->commit_confirmed = commit_confirmed != 0;
        }
        if (!confirm_clock_parse(content, &j->confirm_monotonic_deadline, j->confirm_boot_id) ||
            (j->confirm_monotonic_deadline && !j->commit_confirmed)) {
            free(content); return NL_ERR;
        }
        j->legacy_malformed_state = false;
        free(content);
        return NL_OK;
    }
    if (json_parse_u64_member(content, "tx_id", &parsed_tx) &&
        parsed_tx != tx_id) {
        free(content);
        return NL_ERR;
    }
    (void)json_parse_u64_member(content, "base_commit_id",
                                &j->base_commit_id);
    (void)json_decode_string_member(content, "candidate_hash",
                                    j->candidate_hash,
                                    sizeof(j->candidate_hash));
    (void)json_parse_u64_member(content, "resulting_commit_id",
                                &j->resulting_commit_id);
    (void)json_parse_s64_member(content, "started_at", &j->started_at);
    (void)json_parse_s64_member(content, "updated_at", &j->updated_at);
    if (!json_copy_member(content, "plan", j->plan, sizeof(j->plan), '[') ||
        !json_copy_member(content, "applied_steps", j->applied_steps,
                          sizeof(j->applied_steps), '[') ||
        !json_copy_member(content, "rollback_steps", j->rollback_steps,
                          sizeof(j->rollback_steps), '[')) {
        free(content);
        return NL_ERR;
    }
    free(content);
    if (!state_seen) {
        NL_LOG_ERR("journal tx=0x%lx has no parseable state", tx_id);
        j->state = NL_JOURNAL_HW_OUT_OF_SYNC;
        j->legacy_malformed_state = true;
    }
    return NL_OK;
}

nl_status nl_tx_id_save(u64 tx_id) {
    char path[512];
    char content[64];
    int n;

    nl_journal_file_path(path, sizeof(path), "tx_counter");
    if (ensure_journal_directories() != NL_OK)
        return NL_ERR;
    n = snprintf(content, sizeof(content), "%lu\n", tx_id);
    if (n <= 0 || (size_t)n >= sizeof(content))
        return NL_ERR;
    if (persist_text_atomic(path, content, (size_t)n, 0600) != NL_OK)
        return NL_ERR;
    return NL_OK;
}

nl_status nl_tx_id_load(u64 *tx_id) {
    char path[512];
    nl_journal_file_path(path, sizeof(path), "tx_counter");
    FILE *f = fopen(path, "r");
    if (!f) { *tx_id = 0; return NL_ERR; }
    if (fscanf(f, "%lu", tx_id) != 1) {
        fclose(f);
        *tx_id = 0;
        return NL_ERR;
    }
    fclose(f);
    return NL_OK;
}

nl_status nl_tx_sequence_next(u64 minimum, u64 *tx_id) {
    char path[512];
    char content[64];
    unsigned long long current = 0;
    FILE *f;
    bool sequence_exists = false;
    int n;

    if (!tx_id || minimum == UINT64_MAX)
        return NL_ERR;
    *tx_id = 0;
    nl_journal_file_path(path, sizeof(path), "tx_sequence");
    if (ensure_journal_directories() != NL_OK)
        return NL_ERR;

    f = fopen(path, "r");
    if (f) {
        sequence_exists = true;
        if (fscanf(f, "%llu", &current) != 1) {
            fclose(f);
            return NL_ERR;
        }
        if (fclose(f) != 0)
            return NL_ERR;
    } else if (errno != ENOENT) {
        return NL_ERR;
    }

    /*
     * tx_sequence was introduced after Journal V2 was already deployed.
     * On first use, seed it above every retained historical attempt so the
     * upgrade cannot reuse a failed transaction ID newer than tx_counter.
     * Once the sequence exists it is the reservation authority and no
     * directory scan is needed on the commit path.
     */
    if (!sequence_exists) {
        DIR *dir = opendir(nl_journal_dir());

        if (dir) {
            struct dirent *entry;

            while ((entry = readdir(dir)) != NULL) {
                u64 historical = 0;

                if (parse_journal_tx_filename(
                        entry->d_name, &historical) &&
                    historical > (u64)current)
                    current = historical;
            }
            if (closedir(dir) != 0)
                return NL_ERR;
        } else if (errno != ENOENT) {
            return NL_ERR;
        }
    }

    if ((u64)current < minimum)
        current = minimum;
    if (current == UINT64_MAX)
        return NL_ERR;
    current++;
    n = snprintf(content, sizeof(content), "%llu\n", current);
    if (n <= 0 || (size_t)n >= sizeof(content))
        return NL_ERR;
    if (persist_text_atomic(path, content, (size_t)n, 0600) != NL_OK)
        return NL_ERR;
    *tx_id = (u64)current;
    return NL_OK;
}

static void journal_id_list_free(journal_id_list *list) {
    if (!list)
        return;
    free(list->ids);
    memset(list, 0, sizeof(*list));
}

static bool journal_id_list_contains(const journal_id_list *list, u64 tx_id) {
    if (!list)
        return false;
    for (size_t i = 0; i < list->count; i++) {
        if (list->ids[i] == tx_id)
            return true;
    }
    return false;
}

static nl_status journal_id_list_add(journal_id_list *list, u64 tx_id) {
    u64 *grown;
    size_t capacity;

    if (!list)
        return NL_ERR;
    if (journal_id_list_contains(list, tx_id))
        return NL_OK;
    if (list->count == list->capacity) {
        capacity = list->capacity ? list->capacity * 2 : 16;
        if (capacity > 65536)
            return NL_ERR;
        grown = realloc(list->ids, capacity * sizeof(*grown));
        if (!grown)
            return NL_ERR;
        list->ids = grown;
        list->capacity = capacity;
    }
    list->ids[list->count++] = tx_id;
    return NL_OK;
}

static void journal_id_list_remove(journal_id_list *list, u64 tx_id) {
    if (!list)
        return;
    for (size_t i = 0; i < list->count; i++) {
        if (list->ids[i] != tx_id)
            continue;
        memmove(&list->ids[i], &list->ids[i + 1],
                (list->count - i - 1) * sizeof(list->ids[0]));
        list->count--;
        return;
    }
}

static int journal_u64_compare(const void *left, const void *right) {
    u64 a = *(const u64 *)left;
    u64 b = *(const u64 *)right;

    return a < b ? -1 : a > b ? 1 : 0;
}

static void journal_index_path(char *path, size_t size) {
    nl_journal_file_path(path, size, JOURNAL_INDEX_NAME);
}

static void journal_migration_path(char *path, size_t size) {
    nl_journal_file_path(path, size, JOURNAL_MIGRATION_NAME);
}

static void journal_reservation_path(char *path, size_t size, u64 tx_id) {
    char name[96];

    snprintf(name, sizeof(name), "%s%016lx", JOURNAL_RESERVATION_PREFIX,
             tx_id);
    nl_journal_file_path(path, size, name);
}

static bool parse_index_tx_id(const char *p, u64 *tx_id) {
    char number[19];
    char *end;
    unsigned long long value;

    if (!p || !tx_id || p[0] != '0' || p[1] != 'x')
        return false;
    for (int i = 0; i < 16; i++) {
        if (!isxdigit((unsigned char)p[i + 2]))
            return false;
    }
    memcpy(number, p, 18);
    number[18] = '\0';
    errno = 0;
    value = strtoull(number, &end, 0);
    if (errno != 0 || *end != '\0')
        return false;
    *tx_id = (u64)value;
    return true;
}

static nl_status journal_index_load(journal_id_list *list) {
    char path[512];
    char *content;
    const char *start;
    const char *end;
    const char *p;
    u64 schema = 0;

    if (!list)
        return NL_ERR;
    memset(list, 0, sizeof(*list));
    journal_index_path(path, sizeof(path));
    content = read_text_file(path, NULL);
    if (!content)
        return NL_ERR;
    if (!json_parse_u64_member(content, "schema_version", &schema) ||
        schema != NL_JOURNAL_SCHEMA_VERSION ||
        !json_member_value(content, "tx_ids", &start, &end) ||
        *start != '[') {
        free(content);
        return NL_ERR;
    }
    p = start + 1;
    while (p < end) {
        u64 tx_id;

        while (p < end && (isspace((unsigned char)*p) || *p == ','))
            p++;
        if (p >= end || *p == ']')
            break;
        if (*p != '"' || p + 20 > end || p[19] != '"' ||
            !parse_index_tx_id(p + 1, &tx_id) ||
            journal_id_list_add(list, tx_id) != NL_OK) {
            journal_id_list_free(list);
            free(content);
            return NL_ERR;
        }
        p += 20;
    }
    free(content);
    qsort(list->ids, list->count, sizeof(list->ids[0]),
          journal_u64_compare);
    return NL_OK;
}

static nl_status journal_index_persist(journal_id_list *list) {
    char path[512];
    char *content;
    size_t capacity;
    size_t off;
    int n;

    if (!list)
        return NL_ERR;
    qsort(list->ids, list->count, sizeof(list->ids[0]),
          journal_u64_compare);
    capacity = 128 + list->count * 32;
    content = malloc(capacity);
    if (!content)
        return NL_ERR;
    n = snprintf(content, capacity,
                 "{\n  \"schema_version\": %d,\n"
                 "  \"updated_at\": %ld,\n  \"tx_ids\": [",
                 NL_JOURNAL_SCHEMA_VERSION, (long)time(NULL));
    if (n <= 0 || (size_t)n >= capacity) {
        free(content);
        return NL_ERR;
    }
    off = (size_t)n;
    for (size_t i = 0; i < list->count; i++) {
        n = snprintf(content + off, capacity - off,
                     "%s\"0x%016lx\"", i ? ", " : "", list->ids[i]);
        if (n <= 0 || (size_t)n >= capacity - off) {
            free(content);
            return NL_ERR;
        }
        off += (size_t)n;
    }
    n = snprintf(content + off, capacity - off, "]\n}\n");
    if (n <= 0 || (size_t)n >= capacity - off) {
        free(content);
        return NL_ERR;
    }
    off += (size_t)n;
    journal_index_path(path, sizeof(path));
    nl_status st = persist_text_atomic(path, content, off, 0600);
    free(content);
    return st;
}

static nl_status journal_rebuild_index(journal_id_list *list,
                                       u64 *scanned_out) {
    DIR *dir;
    struct dirent *entry;
    u64 scanned = 0;

    if (!list)
        return NL_ERR;
    memset(list, 0, sizeof(*list));
    dir = opendir(nl_journal_dir());
    if (!dir)
        return errno == ENOENT ? NL_OK : NL_ERR;
    while ((entry = readdir(dir)) != NULL) {
        nl_commit_journal journal;
        u64 tx_id;

        if (!parse_journal_tx_filename(entry->d_name, &tx_id))
            continue;
        scanned++;
        if (nl_journal_get(tx_id, &journal) != NL_OK) {
            closedir(dir);
            journal_id_list_free(list);
            return NL_ERR_HW_OUT_OF_SYNC;
        }
        if (journal.state != NL_JOURNAL_COMMITTED &&
            journal.state != NL_JOURNAL_FAILED_ROLLED_BACK &&
            journal.state != NL_JOURNAL_RECONCILED_TO_ACTIVE &&
            journal_id_list_add(list, tx_id) != NL_OK) {
            closedir(dir);
            journal_id_list_free(list);
            return NL_ERR;
        }
    }
    closedir(dir);
    if (scanned_out)
        *scanned_out = scanned;
    return NL_OK;
}

static bool journal_id_lists_same_set(const journal_id_list *left,
                                      const journal_id_list *right) {
    if (!left || !right || left->count != right->count)
        return false;
    for (size_t i = 0; i < left->count; i++) {
        if (!journal_id_list_contains(right, left->ids[i]))
            return false;
    }
    return true;
}

/*
 * unresolved-v2.json is an acceleration index, not transaction authority.
 * Even with a valid migration marker, startup must derive the unresolved set
 * from every journal filename in the durable directory and reconcile the
 * loaded index against that set.
 *
 * An indexed-but-missing journal can be removed only when the matching create
 * reservation proves that journal creation never completed.  Without that
 * reservation the missing record is lost transaction authority and startup
 * must fail closed.
 */
static nl_status journal_index_crosscheck_directory(
        journal_id_list *loaded, u64 *scanned_out) {
    journal_id_list directory = {0};
    journal_id_list reservations = {0};
    nl_status st;
    bool changed;

    if (!loaded)
        return NL_ERR;
    st = journal_rebuild_index(&directory, scanned_out);
    if (st != NL_OK)
        return st;

    for (size_t i = 0; i < loaded->count; i++) {
        nl_commit_journal journal;
        char reservation[512];
        struct stat reservation_stat;
        u64 tx_id = loaded->ids[i];

        if (journal_id_list_contains(&directory, tx_id))
            continue;

        /*
         * Directory rebuild parsed terminal journals but deliberately omitted
         * them.  They are stale index entries and can be removed without
         * deleting the retained terminal record.
         */
        if (nl_journal_get(tx_id, &journal) == NL_OK) {
            if (journal.state != NL_JOURNAL_COMMITTED &&
                journal.state != NL_JOURNAL_FAILED_ROLLED_BACK &&
                journal.state != NL_JOURNAL_RECONCILED_TO_ACTIVE) {
                st = NL_ERR_HW_OUT_OF_SYNC;
                goto out;
            }
            continue;
        }

        journal_reservation_path(
            reservation, sizeof(reservation), tx_id);
        if (lstat(reservation, &reservation_stat) != 0 ||
            !S_ISREG(reservation_stat.st_mode)) {
            NL_LOG_CRIT(
                "journal index cross-check: tx=0x%lx is indexed but "
                "its journal and create reservation are missing",
                tx_id);
            st = NL_ERR_HW_OUT_OF_SYNC;
            goto out;
        }
        if (journal_id_list_add(&reservations, tx_id) != NL_OK) {
            st = NL_ERR;
            goto out;
        }
    }

    changed = !journal_id_lists_same_set(loaded, &directory);
    if (changed && journal_index_persist(&directory) != NL_OK) {
        st = NL_ERR;
        goto out;
    }

    /*
     * Persist removal before deleting a create reservation.  A crash between
     * these operations leaves a harmless orphan reservation; reversing the
     * order could leave an indexed missing journal with no proof that create
     * was incomplete.
     */
    for (size_t i = 0; i < reservations.count; i++) {
        char reservation[512];

        journal_reservation_path(
            reservation, sizeof(reservation), reservations.ids[i]);
        if (unlink_file_durable(reservation) != NL_OK) {
            st = NL_ERR_HW_OUT_OF_SYNC;
            goto out;
        }
    }

    journal_id_list_free(loaded);
    *loaded = directory;
    memset(&directory, 0, sizeof(directory));
    st = NL_OK;

out:
    journal_id_list_free(&directory);
    journal_id_list_free(&reservations);
    return st;
}

static nl_status journal_index_load_or_rebuild(journal_id_list *list) {
    nl_status st = journal_index_load(list);

    if (st == NL_OK)
        return NL_OK;
    st = journal_rebuild_index(list, NULL);
    if (st != NL_OK)
        return st;
    return journal_index_persist(list);
}

static nl_status journal_index_reserve_create(u64 tx_id) {
    char reservation[512];
    journal_id_list list;
    nl_status st;
    const char content[] = "journal-v2-create-reservation\n";

    journal_reservation_path(reservation, sizeof(reservation), tx_id);
    if (persist_text_atomic(reservation, content, sizeof(content) - 1,
                            0600) != NL_OK)
        return NL_ERR;
    st = journal_index_load_or_rebuild(&list);
    if (st == NL_OK)
        st = journal_id_list_add(&list, tx_id);
    if (st == NL_OK)
        st = journal_index_persist(&list);
    journal_id_list_free(&list);
    if (st != NL_OK)
        unlink(reservation);
    return st;
}

static nl_status journal_index_finish_create(u64 tx_id) {
    char reservation[512];

    journal_reservation_path(reservation, sizeof(reservation), tx_id);
    if (unlink(reservation) != 0 && errno != ENOENT)
        return NL_ERR;
    return fsync_parent_dir(reservation);
}

static nl_status journal_index_cancel_create(u64 tx_id) {
    char reservation[512];
    journal_id_list list;
    nl_status st = journal_index_load_or_rebuild(&list);

    if (st == NL_OK) {
        journal_id_list_remove(&list, tx_id);
        st = journal_index_persist(&list);
    }
    journal_id_list_free(&list);
    journal_reservation_path(reservation, sizeof(reservation), tx_id);
    if (unlink_file_durable(reservation) != NL_OK)
        st = NL_ERR;
    return st;
}

static nl_status journal_index_ensure(u64 tx_id) {
    journal_id_list list;
    nl_status st = journal_index_load_or_rebuild(&list);

    if (st == NL_OK)
        st = journal_id_list_add(&list, tx_id);
    if (st == NL_OK)
        st = journal_index_persist(&list);
    journal_id_list_free(&list);
    return st;
}

static nl_status journal_index_remove(u64 tx_id) {
    journal_id_list list;
    nl_status st = journal_index_load_or_rebuild(&list);

    if (st == NL_OK) {
        journal_id_list_remove(&list, tx_id);
        st = journal_index_persist(&list);
    }
    journal_id_list_free(&list);
    return st;
}

static nl_status confirmed_parse(const char *content, nl_commit_confirmed *c);

nl_status nl_confirmed_migrate_legacy_terminal_sentinel(bool *migrated) {
    static const char legacy_sentinel[] =
        "{\n"
        "  \"tx_id\": \"0x0000000000000000\",\n"
        "  \"confirm_deadline\": 0,\n"
        "  \"previous_commit_id\": \"0x0000000000000000\",\n"
        "  \"state\": \"TIMED_OUT\"\n"
        "}\n";
    char path[512];
    char *content = NULL;
    struct stat path_stat;
    struct stat fd_stat;
    size_t offset = 0, length = 0;
    int fd;
    nl_status st = NL_ERR;

    if (migrated)
        *migrated = false;
    nl_journal_file_path(path, sizeof(path), "confirmed.json");
    if (lstat(path, &path_stat) != 0)
        return errno == ENOENT ? NL_OK : NL_ERR;
    if (!S_ISREG(path_stat.st_mode) ||
        path_stat.st_size <= 0 || path_stat.st_size > 8192)
        return NL_ERR;
    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return NL_ERR;
    if (fstat(fd, &fd_stat) != 0 ||
        !S_ISREG(fd_stat.st_mode) ||
        fd_stat.st_dev != path_stat.st_dev ||
        fd_stat.st_ino != path_stat.st_ino ||
        fd_stat.st_size != path_stat.st_size)
        goto out;
    length = (size_t)fd_stat.st_size;
    content = calloc(length + 1, 1);
    if (!content)
        goto out;
    while (offset < length) {
        ssize_t n = read(fd, content + offset, length - offset);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto out;
        }
        if (n == 0)
            goto out;
        offset += (size_t)n;
    }
    if (memchr(content, '\0', length))
        goto out;
    if (length != sizeof(legacy_sentinel) - 1 ||
        memcmp(content, legacy_sentinel, length) != 0) {
        nl_commit_confirmed current;

        /* Current records are authoritative, not migration failures. Validate
         * without advancing deadlines or deleting a confirmed/pending record. */
        st = confirmed_parse(content, &current);
        goto out;
    }
    free(content);
    content = NULL;
    if (close(fd) != 0)
        return NL_ERR;
    fd = -1;

    /*
     * Recheck the directory entry before deleting it.  A replaced record is
     * new authority and must never be removed based on bytes read from the
     * old inode.
     */
    if (lstat(path, &path_stat) != 0 ||
        path_stat.st_dev != fd_stat.st_dev ||
        path_stat.st_ino != fd_stat.st_ino ||
        path_stat.st_size != fd_stat.st_size)
        return NL_ERR;
    if (unlink_file_durable(path) != NL_OK)
        return NL_ERR;
    if (migrated)
        *migrated = true;
    return NL_OK;

out:
    free(content);
    if (fd >= 0)
        close(fd);
    return st;
}

/*
 * Read confirmed.json without advancing an expired AWAITING_CONFIRM record.
 * Terminal compaction is a retention operation and must never perform the
 * configd timeout state transition as a side effect.
 */
static nl_status confirmed_parse(const char *content, nl_commit_confirmed *c) {
    char state[64];
    u64 tx_id = 0;
    u64 previous_commit_id = 0;
    s64 confirm_deadline = 0;

    if (!content || !c)
        return NL_ERR;
    memset(c, 0, sizeof(*c));
    if (!json_document_structurally_valid(content) ||
        !json_parse_u64_member(content, "tx_id", &tx_id) ||
        tx_id == 0 ||
        !json_parse_u64_member(
            content, "previous_commit_id", &previous_commit_id) ||
        !json_parse_s64_member(
            content, "confirm_deadline", &confirm_deadline) ||
        confirm_deadline <= 0 ||
        !confirm_clock_parse(content, &c->confirm_monotonic_deadline, c->confirm_boot_id) ||
        !json_decode_string_member(
            content, "state", state, sizeof(state))) {
        return NL_ERR;
    }

    c->tx_id = tx_id;
    c->previous_commit_id = previous_commit_id;
    c->confirm_deadline = confirm_deadline;
    if (strcmp(state, "AWAITING_CONFIRM") == 0)
        c->state = NL_CONFIRM_AWAITING;
    else if (strcmp(state, "CONFIRMED") == 0)
        c->state = NL_CONFIRMED;
    else if (strcmp(state, "TIMED_OUT") == 0)
        c->state = NL_TIMED_OUT;
    else {
        memset(c, 0, sizeof(*c));
        return NL_ERR;
    }
    return NL_OK;
}

nl_status nl_confirmed_load_readonly(nl_commit_confirmed *c) {
    char path[512];
    char *content;
    size_t length = 0;
    nl_status st;

    if (!c)
        return NL_ERR;
    memset(c, 0, sizeof(*c));
    nl_journal_file_path(path, sizeof(path), "confirmed.json");
    content = read_text_file(path, &length);
    if (!content)
        return NL_ERR;
    st = memchr(content, '\0', length) ? NL_ERR : confirmed_parse(content, c);
    free(content);
    return st;
}

typedef struct {
    bool pending;
    bool conflict;
    u64 active_tx_id;
    nl_commit_confirmed confirmed;
} journal_confirmed_pin;

static void journal_confirmed_pin_load(journal_confirmed_pin *pin) {
    char path[512];
    struct stat st;
    u64 observed_tx_id = 0;

    if (!pin)
        return;
    memset(pin, 0, sizeof(*pin));
    if (nl_confirmed_load_readonly(&pin->confirmed) != NL_OK) {
        nl_journal_file_path(path, sizeof(path), "confirmed.json");
        errno = 0;
        if (lstat(path, &st) == 0 || errno != ENOENT)
            pin->conflict = true;
        return;
    }
    if (pin->confirmed.state != NL_CONFIRM_AWAITING &&
        pin->confirmed.state != NL_TIMED_OUT)
        return;
    if (nl_tx_id_load(&pin->active_tx_id) != NL_OK) {
        pin->conflict = true;
        return;
    }
    if (pin->active_tx_id > pin->confirmed.tx_id)
        return;
    if (pin->active_tx_id < pin->confirmed.tx_id) {
        pin->conflict = true;
        return;
    }
    /*
     * Narrow the read-only snapshot window: a pointer transition concurrent
     * with the confirmed-record read must not produce a mixed-generation pin.
     */
    if (nl_tx_id_load(&observed_tx_id) != NL_OK) {
        pin->conflict = true;
        return;
    }
    if (observed_tx_id > pin->active_tx_id)
        return;
    if (observed_tx_id != pin->active_tx_id) {
        pin->conflict = true;
        return;
    }
    pin->pending = true;
}

static bool journal_confirmed_pin_matches(
    const journal_confirmed_pin *pin,
    const nl_commit_journal *journal) {
    return pin && pin->pending && journal &&
           journal->tx_id == pin->active_tx_id &&
           journal->state == NL_JOURNAL_COMMITTED &&
           journal->resulting_commit_id == journal->tx_id &&
           journal->commit_confirmed &&
           journal->base_commit_id ==
               journal->confirm_previous_commit_id &&
           journal->confirm_deadline ==
               pin->confirmed.confirm_deadline &&
           journal->confirm_monotonic_deadline == pin->confirmed.confirm_monotonic_deadline &&
           !strcmp(journal->confirm_boot_id, pin->confirmed.confirm_boot_id) &&
           journal->confirm_previous_commit_id ==
               pin->confirmed.previous_commit_id;
}

static size_t journal_retention_limit(void) {
    const char *env = getenv("NETLAB_JOURNAL_RETENTION");
    char *end;
    unsigned long value;

    if (journal_active_retention != 0)
        return journal_active_retention;
    if (!env || !*env)
        return NL_JOURNAL_RETENTION_DEFAULT;
    errno = 0;
    value = strtoul(env, &end, 10);
    if (errno != 0 || *end != '\0' || value == 0 || value > 65536)
        return NL_JOURNAL_RETENTION_DEFAULT;
    return (size_t)value;
}

static int journal_terminal_newest_first(const void *left,
                                         const void *right) {
    const journal_terminal_entry *a = left;
    const journal_terminal_entry *b = right;

    if (a->updated_at != b->updated_at)
        return a->updated_at > b->updated_at ? -1 : 1;
    return a->tx_id > b->tx_id ? -1 : a->tx_id < b->tx_id ? 1 : 0;
}

static nl_status journal_compact_terminal(size_t retention_limit,
                                          u64 *removed_out,
                                          u64 *retained_out) {
    DIR *dir;
    struct dirent *entry;
    journal_terminal_entry *terminal = NULL;
    size_t count = 0;
    size_t capacity = 0;
    size_t ordinary_retained = 0;
    u64 removed = 0;
    nl_status st = NL_OK;
    journal_confirmed_pin confirmed_pin;
    bool confirmed_journal_seen = false;

    if (retention_limit == 0)
        retention_limit = NL_JOURNAL_RETENTION_DEFAULT;
    journal_confirmed_pin_load(&confirmed_pin);
    if (confirmed_pin.conflict)
        return NL_ERR_HW_OUT_OF_SYNC;
    dir = opendir(nl_journal_dir());
    if (!dir)
        return errno == ENOENT ? NL_OK : NL_ERR;
    while ((entry = readdir(dir)) != NULL) {
        nl_commit_journal journal;
        u64 tx_id;

        if (!parse_journal_tx_filename(entry->d_name, &tx_id))
            continue;
        if (nl_journal_get(tx_id, &journal) != NL_OK) {
            st = NL_ERR_HW_OUT_OF_SYNC;
            break;
        }
        if (confirmed_pin.pending &&
            journal.tx_id == confirmed_pin.active_tx_id) {
            confirmed_journal_seen = true;
            if (journal.state == NL_JOURNAL_COMMITTED &&
                !journal_confirmed_pin_matches(
                    &confirmed_pin, &journal)) {
                st = NL_ERR_HW_OUT_OF_SYNC;
                break;
            }
            if (journal.state == NL_JOURNAL_FAILED_ROLLED_BACK ||
                journal.state == NL_JOURNAL_RECONCILED_TO_ACTIVE) {
                st = NL_ERR_HW_OUT_OF_SYNC;
                break;
            }
        }
        if (journal.state != NL_JOURNAL_COMMITTED &&
            journal.state != NL_JOURNAL_FAILED_ROLLED_BACK &&
            journal.state != NL_JOURNAL_RECONCILED_TO_ACTIVE)
            continue;
        if (count == capacity) {
            size_t next = capacity ? capacity * 2 : 256;
            journal_terminal_entry *grown = realloc(
                terminal, next * sizeof(*grown));
            if (!grown) {
                st = NL_ERR;
                break;
            }
            terminal = grown;
            capacity = next;
        }
        terminal[count++] = (journal_terminal_entry){
            .tx_id = tx_id,
            .updated_at = journal.updated_at,
            .pinned = journal_confirmed_pin_matches(
                &confirmed_pin, &journal),
        };
    }
    closedir(dir);
    if (st == NL_OK && confirmed_pin.pending &&
        !confirmed_journal_seen)
        st = NL_ERR_HW_OUT_OF_SYNC;
    if (st != NL_OK) {
        free(terminal);
        return st;
    }
    qsort(terminal, count, sizeof(terminal[0]),
          journal_terminal_newest_first);
    for (size_t i = 0; i < count; i++) {
        char path[512];
        char candidate_path[512];

        /*
         * A still-pending commit-confirmed journal is rollback authority and
         * does not consume the ordinary terminal retention budget.
         */
        if (terminal[i].pinned)
            continue;
        if (ordinary_retained < retention_limit) {
            ordinary_retained++;
            continue;
        }
        journal_path_buf(path, sizeof(path), terminal[i].tx_id);
        candidate_snapshot_path_buf(
            candidate_path, sizeof(candidate_path), terminal[i].tx_id);
        /*
         * Delete the dependent candidate first.  If journal deletion then
         * fails, the retained terminal journal makes the cleanup retryable;
         * deleting the journal first could leave an undiscoverable candidate
         * orphan.
         */
        if (unlink_file_durable(candidate_path) != NL_OK ||
            unlink_file_durable(path) != NL_OK) {
            st = NL_ERR;
            break;
        }
        removed++;
    }
    if (removed_out)
        *removed_out = removed;
    if (retained_out)
        *retained_out = count - removed;
    free(terminal);
    return st;
}

static nl_status journal_write_migration_marker(
        size_t retention_limit, const nl_journal_migration_stats *stats) {
    char path[512];
    char content[512];
    int n;

    n = snprintf(content, sizeof(content),
                 "{\n"
                 "  \"schema_version\": %d,\n"
                 "  \"completed_at\": %ld,\n"
                 "  \"retention_limit\": %zu,\n"
                 "  \"scanned\": %lu,\n"
                 "  \"unresolved\": %lu,\n"
                 "  \"retained_terminal\": %lu,\n"
                 "  \"removed_terminal\": %lu\n"
                 "}\n",
                 NL_JOURNAL_SCHEMA_VERSION, (long)time(NULL),
                 retention_limit, stats ? stats->scanned : 0,
                 stats ? stats->unresolved : 0,
                 stats ? stats->retained_terminal : 0,
                 stats ? stats->removed_terminal : 0);
    if (n <= 0 || (size_t)n >= sizeof(content))
        return NL_ERR;
    journal_migration_path(path, sizeof(path));
    return persist_text_atomic(path, content, (size_t)n, 0600);
}

static bool journal_migration_marker_valid(const char *path,
                                           size_t retention_limit) {
    char *content;
    u64 schema = 0;
    u64 marker_retention = 0;
    bool valid;

    content = read_text_file(path, NULL);
    if (!content)
        return false;
    valid = json_parse_u64_member(content, "schema_version", &schema) &&
            schema == NL_JOURNAL_SCHEMA_VERSION &&
            json_parse_u64_member(content, "retention_limit",
                                  &marker_retention) &&
            marker_retention == retention_limit;
    free(content);
    return valid;
}

nl_status nl_journal_initialize_v2(size_t retention_limit,
                                   nl_journal_migration_stats *stats) {
    char marker_path[512];
    struct stat marker_stat;
    journal_id_list list;
    nl_journal_migration_stats local = {0};
    nl_status st;
    bool marker_valid;

    if (retention_limit == 0)
        retention_limit = journal_retention_limit();
    if (retention_limit > 65536)
        return NL_ERR;
    journal_active_retention = retention_limit;
    if (ensure_journal_directories() != NL_OK)
        return NL_ERR;
    journal_migration_path(marker_path, sizeof(marker_path));
    marker_valid =
        stat(marker_path, &marker_stat) == 0 &&
        S_ISREG(marker_stat.st_mode) &&
        journal_migration_marker_valid(marker_path, retention_limit);
    st = journal_index_load(&list);
    if (st == NL_OK) {
        st = journal_index_crosscheck_directory(
            &list, &local.scanned);
        if (st != NL_OK) {
            journal_id_list_free(&list);
            return st;
        }
        local.unresolved = list.count;
        if (marker_valid) {
            journal_id_list_free(&list);
            if (stats)
                *stats = local;
            return NL_OK;
        }
    } else {
        st = journal_rebuild_index(&list, &local.scanned);
        if (st != NL_OK)
            return st;
        local.unresolved = list.count;
    }

    st = journal_index_persist(&list);
    journal_id_list_free(&list);
    if (st != NL_OK)
        return st;
    st = journal_compact_terminal(
        retention_limit, &local.removed_terminal,
        &local.retained_terminal);
    if (st != NL_OK)
        return st;
    local.migrated = true;
    st = journal_write_migration_marker(retention_limit, &local);
    if (st == NL_OK && stats)
        *stats = local;
    return st;
}

nl_status nl_journal_scan_unresolved(nl_commit_journal *journals,
                                     int *count, int max) {
    journal_id_list list;
    nl_status st;
    int n = 0;
    bool index_changed = false;

    if (!count || max < 0 || (max > 0 && !journals))
        return NL_ERR;
    *count = 0;
    st = journal_index_load(&list);
    if (st != NL_OK)
        return NL_ERR_HW_OUT_OF_SYNC;
    size_t i = 0;
    while (i < list.count) {
        nl_commit_journal journal;
        char reservation[512];
        struct stat reservation_stat;
        u64 tx_id = list.ids[i];

        if (nl_journal_get(tx_id, &journal) != NL_OK) {
            journal_reservation_path(reservation, sizeof(reservation),
                                     tx_id);
            if (stat(reservation, &reservation_stat) == 0 &&
                S_ISREG(reservation_stat.st_mode)) {
                journal_id_list_remove(&list, tx_id);
                if (journal_index_persist(&list) != NL_OK ||
                    unlink_file_durable(reservation) != NL_OK) {
                    journal_id_list_free(&list);
                    return NL_ERR_HW_OUT_OF_SYNC;
                }
                index_changed = false;
                continue;
            }
            journal_id_list_free(&list);
            return NL_ERR_HW_OUT_OF_SYNC;
        }
        if (journal.state == NL_JOURNAL_COMMITTED ||
            journal.state == NL_JOURNAL_FAILED_ROLLED_BACK ||
            journal.state == NL_JOURNAL_RECONCILED_TO_ACTIVE) {
            journal_id_list_remove(&list, tx_id);
            index_changed = true;
            continue;
        }
        if (n >= max) {
            journal_id_list_free(&list);
            return NL_ERR_HW_OUT_OF_SYNC;
        }
        journals[n++] = journal;
        i++;
    }
    if (index_changed)
        st = journal_index_persist(&list);
    journal_id_list_free(&list);
    *count = n;
    return st;
}

nl_status nl_journal_scan(nl_commit_journal *journals, int *count, int max) {
    DIR *d = opendir(nl_journal_dir());
    if (!d) { *count = 0; return NL_OK; }

    int n = 0;
    int total = 0;
    bool truncated = false;
    bool corrupt = false;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_type != DT_REG && entry->d_type != DT_UNKNOWN)
            continue;
        u64 tx_id = 0;

        if (!parse_journal_tx_filename(entry->d_name, &tx_id))
            continue;

        total++;
        if (n >= max) {
            truncated = true;
            continue;
        }

        if (nl_journal_get(tx_id, &journals[n]) == NL_OK) {
            n++;
        } else {
            corrupt = true;
        }
    }
    closedir(d);
    *count = n;
    if (truncated || corrupt) {
        NL_LOG_CRIT("journal scan incomplete: parsed=%d total=%d "
                    "truncated=%s corrupt=%s", n, total,
                    truncated ? "true" : "false",
                    corrupt ? "true" : "false");
        return NL_ERR_HW_OUT_OF_SYNC;
    }
    return NL_OK;
}

nl_status nl_journal_persist_state(u64 tx_id, nl_journal_state state) {
    // Persist state change in the journal file by updating the "state" field
    return nl_journal_update_state(tx_id, state);
}

nl_status nl_journal_recover(nl_commit_journal *j) {
    if (!j) return NL_ERR;

    if (j->legacy_malformed_state) {
        if (journal_has_committed_snapshot(j->tx_id)) {
            NL_LOG_WARN("recovery: repairing legacy malformed COMMITTED journal tx=0x%lx",
                        j->tx_id);
            j->state = NL_JOURNAL_COMMITTED;
            if (nl_journal_persist_state(
                    j->tx_id, NL_JOURNAL_COMMITTED) != NL_OK)
                return NL_ERR;
        } else {
            NL_LOG_CRIT("recovery: malformed journal tx=0x%lx has no committed snapshot",
                        j->tx_id);
            j->state = NL_JOURNAL_HW_OUT_OF_SYNC;
            if (nl_journal_persist_state(
                    j->tx_id, NL_JOURNAL_HW_OUT_OF_SYNC) != NL_OK)
                return NL_ERR;
        }
    }

    switch (j->state) {
        case NL_JOURNAL_PREPARED:
            NL_LOG_WARN("recovery: stale PREPARED tx=0x%lx (no HW applied) — terminalizing",
                        j->tx_id);
            j->state = NL_JOURNAL_FAILED_ROLLED_BACK;
            if (nl_journal_persist_state(
                    j->tx_id, NL_JOURNAL_FAILED_ROLLED_BACK) != NL_OK)
                return NL_ERR;
            break;

        case NL_JOURNAL_APPLYING:
        case NL_JOURNAL_VERIFYING:
        case NL_JOURNAL_VERIFY_OK:
        case NL_JOURNAL_HW_MARKED_COMMITTED:
            // Partial commit detected — must rollback or reconcile
            NL_LOG_CRIT("recovery: found %s journal tx=0x%lx — entering HW_OUT_OF_SYNC",
                        j->state == NL_JOURNAL_APPLYING ? "APPLYING" :
                        j->state == NL_JOURNAL_VERIFYING ? "VERIFYING" :
                        j->state == NL_JOURNAL_VERIFY_OK ? "VERIFY_OK" : "HW_MARKED_COMMITTED",
                        j->tx_id);
            // Persist HW_OUT_OF_SYNC to journal file
            j->state = NL_JOURNAL_HW_OUT_OF_SYNC;
            if (nl_journal_persist_state(
                    j->tx_id, NL_JOURNAL_HW_OUT_OF_SYNC) != NL_OK)
                return NL_ERR;
            break;

        case NL_JOURNAL_COMMITTED:
            NL_LOG_DBG("recovery: COMMITTED journal tx=0x%lx (OK)", j->tx_id);
            if (journal_index_remove(j->tx_id) != NL_OK)
                return NL_ERR;
            break;

        case NL_JOURNAL_FAILED_ROLLED_BACK:
            NL_LOG_INFO("recovery: already rolled back tx=0x%lx", j->tx_id);
            if (journal_index_remove(j->tx_id) != NL_OK)
                return NL_ERR;
            break;

        case NL_JOURNAL_RECONCILED_TO_ACTIVE:
            NL_LOG_INFO(
                "recovery: tx=0x%lx already reconciled to durable active authority",
                j->tx_id);
            if (journal_index_remove(j->tx_id) != NL_OK)
                return NL_ERR;
            break;

        case NL_JOURNAL_HW_OUT_OF_SYNC:
            NL_LOG_CRIT("recovery: HW_OUT_OF_SYNC from tx=0x%lx — blocking commit",
                        j->tx_id);
            if (journal_index_ensure(j->tx_id) != NL_OK)
                return NL_ERR;
            break;
    }
    return NL_OK;
}

nl_status nl_confirmed_save(nl_commit_confirmed *c) {
    char path[512];
    char content[512];
    char clock_fields[160];
    int n;

    if (!c || c->tx_id == 0 || c->confirm_deadline <= 0 ||
        !confirm_clock_format(clock_fields, sizeof(clock_fields), c->confirm_monotonic_deadline, c->confirm_boot_id) ||
        (c->state != NL_CONFIRM_AWAITING &&
         c->state != NL_CONFIRMED &&
         c->state != NL_TIMED_OUT))
        return NL_ERR;
    nl_journal_file_path(path, sizeof(path), "confirmed.json");
    if (ensure_journal_directories() != NL_OK)
        return NL_ERR;
    n = snprintf(content, sizeof(content),
                 "{\n"
                 "  \"tx_id\": \"0x%016lx\",\n"
                 "  \"confirm_deadline\": %ld,\n"
                 "%s"
                 "  \"previous_commit_id\": \"0x%016lx\",\n"
                 "  \"state\": \"%s\"\n"
                 "}\n",
                 c->tx_id, (long)c->confirm_deadline, clock_fields,
                 c->previous_commit_id,
                 c->state == NL_CONFIRM_AWAITING ? "AWAITING_CONFIRM"
                 : c->state == NL_CONFIRMED ? "CONFIRMED" : "TIMED_OUT");
    if (n <= 0 || (size_t)n >= sizeof(content))
        return NL_ERR;
    if (persist_text_atomic(path, content, (size_t)n, 0600) != NL_OK)
        return NL_ERR;
    return NL_OK;
}

s64 nl_confirmed_remaining_seconds(const nl_commit_confirmed *c) {
    if (!c || c->confirm_deadline <= 0) return -1;
    s64 now, deadline;
    if (c->confirm_monotonic_deadline || c->confirm_boot_id[0]) {
        char boot_id[37];
        if (c->confirm_monotonic_deadline <= 0 || !confirm_boot_id_valid(c->confirm_boot_id) ||
            !confirm_read_boot_id(boot_id)) return -1;
        if (strcmp(c->confirm_boot_id, boot_id)) return 0;
        now = (s64)nl_monotonic_seconds();
        deadline = c->confirm_monotonic_deadline;
    } else {
        now = (s64)time(NULL);
        deadline = c->confirm_deadline;
    }
    if (now <= 0) return -1;
    return deadline > now ? deadline - now : 0;
}

s64 nl_confirmed_display_deadline(const nl_commit_confirmed *c) {
    s64 remaining = nl_confirmed_remaining_seconds(c), now = (s64)time(NULL);
    if (remaining < 0 || now <= 0 || remaining > LLONG_MAX - now) return -1;
    return now + remaining;
}

nl_status nl_confirmed_load(nl_commit_confirmed *c) {
    if (nl_confirmed_load_readonly(c) != NL_OK)
        return NL_ERR;
    if (c->state == NL_CONFIRM_AWAITING) {
        s64 remaining = nl_confirmed_remaining_seconds(c);
        if (remaining < 0) return NL_ERR;
        if (!remaining) {
            NL_LOG_WARN("confirmed: deadline passed, marking TIMED_OUT");
            c->state = NL_TIMED_OUT;
            if (nl_confirmed_save(c) != NL_OK) {
                NL_LOG_ERR("confirmed: failed to persist TIMED_OUT state");
                return NL_ERR;
            }
        }
    }
    return NL_OK;
}
