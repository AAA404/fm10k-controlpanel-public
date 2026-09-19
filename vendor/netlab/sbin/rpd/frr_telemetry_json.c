#include "frr_telemetry_json.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRR_JSON_MAX_TOKENS 2048
#define FRR_JSON_MAX_DEPTH 32

typedef enum {
    FRR_JSON_OBJECT,
    FRR_JSON_ARRAY,
    FRR_JSON_STRING,
    FRR_JSON_PRIMITIVE,
} frr_json_type;

typedef struct {
    frr_json_type type;
    int start;
    int end;
    int parent;
    int size;
} frr_json_token;

typedef struct {
    const char *text;
    size_t length;
    size_t pos;
    frr_json_token *tokens;
    int token_count;
    int token_capacity;
    char *err;
    size_t err_size;
} frr_json_parser;

typedef struct {
    const char *text;
    frr_json_token *tokens;
    int token_count;
    int root;
} frr_json_doc;

static void set_error(char *err, size_t err_size, const char *message) {
    if (err && err_size > 0)
        snprintf(err, err_size, "%s", message ? message : "JSON error");
}

static int parser_fail(frr_json_parser *parser, const char *message) {
    if (parser && parser->err && parser->err_size > 0 && !parser->err[0])
        snprintf(parser->err, parser->err_size, "%s at byte %zu",
                 message ? message : "invalid JSON", parser->pos);
    return -1;
}

static void skip_space(frr_json_parser *parser) {
    while (parser->pos < parser->length &&
           isspace((unsigned char)parser->text[parser->pos]))
        parser->pos++;
}

static int add_token(frr_json_parser *parser, frr_json_type type,
                     int start, int parent) {
    frr_json_token *token;

    if (parser->token_count >= parser->token_capacity)
        return parser_fail(parser, "JSON token limit exceeded");
    token = &parser->tokens[parser->token_count];
    memset(token, 0, sizeof(*token));
    token->type = type;
    token->start = start;
    token->end = -1;
    token->parent = parent;
    return parser->token_count++;
}

static int hex_value(unsigned char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int parse_string(frr_json_parser *parser, int parent) {
    int token_index;

    if (parser->pos >= parser->length || parser->text[parser->pos] != '"')
        return parser_fail(parser, "expected JSON string");
    parser->pos++;
    token_index = add_token(parser, FRR_JSON_STRING, (int)parser->pos,
                            parent);
    if (token_index < 0)
        return -1;
    while (parser->pos < parser->length) {
        unsigned char c = (unsigned char)parser->text[parser->pos++];

        if (c == '"') {
            parser->tokens[token_index].end = (int)parser->pos - 1;
            return token_index;
        }
        if (c < 0x20)
            return parser_fail(parser, "unescaped control in JSON string");
        if (c != '\\')
            continue;
        if (parser->pos >= parser->length)
            return parser_fail(parser, "truncated JSON escape");
        c = (unsigned char)parser->text[parser->pos++];
        if (strchr("\"\\/bfnrt", c))
            continue;
        if (c != 'u')
            return parser_fail(parser, "invalid JSON escape");
        if (parser->length - parser->pos < 4)
            return parser_fail(parser, "truncated JSON unicode escape");
        for (int i = 0; i < 4; i++) {
            if (hex_value((unsigned char)parser->text[parser->pos + i]) < 0)
                return parser_fail(parser, "invalid JSON unicode escape");
        }
        parser->pos += 4;
    }
    return parser_fail(parser, "unterminated JSON string");
}

static bool number_delimiter(unsigned char c) {
    return c == ',' || c == ']' || c == '}' || isspace(c);
}

static int parse_number(frr_json_parser *parser, int parent) {
    size_t start = parser->pos;
    int token_index;

    if (parser->text[parser->pos] == '-')
        parser->pos++;
    if (parser->pos >= parser->length)
        return parser_fail(parser, "truncated JSON number");
    if (parser->text[parser->pos] == '0') {
        parser->pos++;
    } else if (parser->text[parser->pos] >= '1' &&
               parser->text[parser->pos] <= '9') {
        while (parser->pos < parser->length &&
               isdigit((unsigned char)parser->text[parser->pos]))
            parser->pos++;
    } else {
        return parser_fail(parser, "invalid JSON number");
    }
    if (parser->pos < parser->length && parser->text[parser->pos] == '.') {
        parser->pos++;
        if (parser->pos >= parser->length ||
            !isdigit((unsigned char)parser->text[parser->pos]))
            return parser_fail(parser, "invalid JSON fraction");
        while (parser->pos < parser->length &&
               isdigit((unsigned char)parser->text[parser->pos]))
            parser->pos++;
    }
    if (parser->pos < parser->length &&
        (parser->text[parser->pos] == 'e' ||
         parser->text[parser->pos] == 'E')) {
        parser->pos++;
        if (parser->pos < parser->length &&
            (parser->text[parser->pos] == '+' ||
             parser->text[parser->pos] == '-'))
            parser->pos++;
        if (parser->pos >= parser->length ||
            !isdigit((unsigned char)parser->text[parser->pos]))
            return parser_fail(parser, "invalid JSON exponent");
        while (parser->pos < parser->length &&
               isdigit((unsigned char)parser->text[parser->pos]))
            parser->pos++;
    }
    if (parser->pos < parser->length &&
        !number_delimiter((unsigned char)parser->text[parser->pos]))
        return parser_fail(parser, "invalid JSON number suffix");
    token_index = add_token(parser, FRR_JSON_PRIMITIVE, (int)start, parent);
    if (token_index >= 0)
        parser->tokens[token_index].end = (int)parser->pos;
    return token_index;
}

static int parse_literal(frr_json_parser *parser, int parent,
                         const char *literal) {
    size_t length = strlen(literal);
    int token_index;

    if (parser->length - parser->pos < length ||
        memcmp(parser->text + parser->pos, literal, length) != 0)
        return parser_fail(parser, "invalid JSON literal");
    token_index = add_token(parser, FRR_JSON_PRIMITIVE,
                            (int)parser->pos, parent);
    if (token_index < 0)
        return -1;
    parser->pos += length;
    if (parser->pos < parser->length &&
        !number_delimiter((unsigned char)parser->text[parser->pos]))
        return parser_fail(parser, "invalid JSON literal suffix");
    parser->tokens[token_index].end = (int)parser->pos;
    return token_index;
}

static int parse_value(frr_json_parser *parser, int parent, int depth);

static int parse_object(frr_json_parser *parser, int parent, int depth) {
    int object_index = add_token(parser, FRR_JSON_OBJECT,
                                 (int)parser->pos, parent);

    if (object_index < 0)
        return -1;
    parser->pos++;
    skip_space(parser);
    if (parser->pos < parser->length && parser->text[parser->pos] == '}') {
        parser->pos++;
        parser->tokens[object_index].end = (int)parser->pos;
        return object_index;
    }
    while (parser->pos < parser->length) {
        int key_index;

        key_index = parse_string(parser, object_index);
        if (key_index < 0)
            return -1;
        skip_space(parser);
        if (parser->pos >= parser->length ||
            parser->text[parser->pos] != ':')
            return parser_fail(parser, "expected JSON object colon");
        parser->pos++;
        skip_space(parser);
        if (parse_value(parser, key_index, depth + 1) < 0)
            return -1;
        parser->tokens[key_index].size = 1;
        parser->tokens[object_index].size++;
        skip_space(parser);
        if (parser->pos >= parser->length)
            return parser_fail(parser, "unterminated JSON object");
        if (parser->text[parser->pos] == '}') {
            parser->pos++;
            parser->tokens[object_index].end = (int)parser->pos;
            return object_index;
        }
        if (parser->text[parser->pos] != ',')
            return parser_fail(parser, "expected JSON object comma");
        parser->pos++;
        skip_space(parser);
    }
    return parser_fail(parser, "unterminated JSON object");
}

static int parse_array(frr_json_parser *parser, int parent, int depth) {
    int array_index = add_token(parser, FRR_JSON_ARRAY,
                                (int)parser->pos, parent);

    if (array_index < 0)
        return -1;
    parser->pos++;
    skip_space(parser);
    if (parser->pos < parser->length && parser->text[parser->pos] == ']') {
        parser->pos++;
        parser->tokens[array_index].end = (int)parser->pos;
        return array_index;
    }
    while (parser->pos < parser->length) {
        if (parse_value(parser, array_index, depth + 1) < 0)
            return -1;
        parser->tokens[array_index].size++;
        skip_space(parser);
        if (parser->pos >= parser->length)
            return parser_fail(parser, "unterminated JSON array");
        if (parser->text[parser->pos] == ']') {
            parser->pos++;
            parser->tokens[array_index].end = (int)parser->pos;
            return array_index;
        }
        if (parser->text[parser->pos] != ',')
            return parser_fail(parser, "expected JSON array comma");
        parser->pos++;
        skip_space(parser);
    }
    return parser_fail(parser, "unterminated JSON array");
}

static int parse_value(frr_json_parser *parser, int parent, int depth) {
    if (depth > FRR_JSON_MAX_DEPTH)
        return parser_fail(parser, "JSON nesting limit exceeded");
    skip_space(parser);
    if (parser->pos >= parser->length)
        return parser_fail(parser, "missing JSON value");
    switch (parser->text[parser->pos]) {
    case '{':
        return parse_object(parser, parent, depth);
    case '[':
        return parse_array(parser, parent, depth);
    case '"':
        return parse_string(parser, parent);
    case 't':
        return parse_literal(parser, parent, "true");
    case 'f':
        return parse_literal(parser, parent, "false");
    case 'n':
        return parse_literal(parser, parent, "null");
    default:
        if (parser->text[parser->pos] == '-' ||
            isdigit((unsigned char)parser->text[parser->pos]))
            return parse_number(parser, parent);
        return parser_fail(parser, "unexpected JSON value");
    }
}

static int parse_document(const char *text, frr_json_doc *doc,
                          char *err, size_t err_size) {
    frr_json_parser parser;
    frr_json_token *tokens;
    int root;

    if (!text || !doc) {
        set_error(err, err_size, "missing JSON document");
        return -1;
    }
    if (err && err_size > 0)
        err[0] = '\0';
    tokens = calloc(FRR_JSON_MAX_TOKENS, sizeof(*tokens));
    if (!tokens) {
        set_error(err, err_size, "JSON token allocation failed");
        return -1;
    }
    memset(&parser, 0, sizeof(parser));
    parser.text = text;
    parser.length = strlen(text);
    parser.tokens = tokens;
    parser.token_capacity = FRR_JSON_MAX_TOKENS;
    parser.err = err;
    parser.err_size = err_size;
    skip_space(&parser);
    root = parse_value(&parser, -1, 0);
    skip_space(&parser);
    if (root < 0 || parser.pos != parser.length) {
        if (root >= 0)
            parser_fail(&parser, "trailing data after JSON document");
        free(tokens);
        return -1;
    }
    doc->text = text;
    doc->tokens = tokens;
    doc->token_count = parser.token_count;
    doc->root = root;
    return 0;
}

static void free_document(frr_json_doc *doc) {
    if (!doc)
        return;
    free(doc->tokens);
    memset(doc, 0, sizeof(*doc));
    doc->root = -1;
}

static bool token_equals(const frr_json_doc *doc, int token_index,
                         const char *expected) {
    const frr_json_token *token;
    size_t expected_len;

    if (!doc || !expected || token_index < 0 ||
        token_index >= doc->token_count)
        return false;
    token = &doc->tokens[token_index];
    if (token->type != FRR_JSON_STRING || token->end < token->start)
        return false;
    expected_len = strlen(expected);
    return (size_t)(token->end - token->start) == expected_len &&
           memcmp(doc->text + token->start, expected, expected_len) == 0;
}

static int object_member(const frr_json_doc *doc, int object_index,
                         const char *name, int *value_index) {
    int found = -1;

    if (!doc || object_index < 0 || object_index >= doc->token_count ||
        doc->tokens[object_index].type != FRR_JSON_OBJECT)
        return -1;
    for (int i = 0; i < doc->token_count; i++) {
        if (doc->tokens[i].parent != object_index)
            continue;
        if (doc->tokens[i].type != FRR_JSON_STRING ||
            i + 1 >= doc->token_count || doc->tokens[i + 1].parent != i)
            return -1;
        if (!token_equals(doc, i, name))
            continue;
        if (found >= 0)
            return -1;
        found = i + 1;
    }
    if (found >= 0 && value_index)
        *value_index = found;
    return found >= 0 ? 1 : 0;
}

static int decode_string(const frr_json_doc *doc, int token_index,
                         char *out, size_t out_size) {
    const frr_json_token *token;
    size_t off = 0;

    if (!doc || !out || out_size == 0 || token_index < 0 ||
        token_index >= doc->token_count)
        return -1;
    token = &doc->tokens[token_index];
    if (token->type != FRR_JSON_STRING || token->end < token->start)
        return -1;
    for (int i = token->start; i < token->end; i++) {
        unsigned char c = (unsigned char)doc->text[i];

        if (c == '\\') {
            int codepoint = 0;

            if (++i >= token->end)
                return -1;
            c = (unsigned char)doc->text[i];
            switch (c) {
            case '"': case '\\': case '/':
                break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u':
                if (token->end - i <= 4)
                    return -1;
                for (int j = 0; j < 4; j++) {
                    int value = hex_value(
                        (unsigned char)doc->text[++i]);
                    if (value < 0)
                        return -1;
                    codepoint = codepoint * 16 + value;
                }
                c = codepoint >= 0x20 && codepoint <= 0x7e ?
                    (unsigned char)codepoint : '?';
                break;
            default:
                return -1;
            }
        }
        if (off + 1 >= out_size)
            return -1;
        out[off++] = (char)c;
    }
    out[off] = '\0';
    return 0;
}

static bool telemetry_text_safe(const char *text) {
    if (!text || !text[0])
        return false;
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-' ||
              *p == ':' || *p == '/' || *p == ' ' || *p == '(' ||
              *p == ')'))
            return false;
    }
    return true;
}

static int copy_string_field(const frr_json_doc *doc, int token_index,
                             char *out, size_t out_size) {
    char decoded[256];
    size_t length;

    if (decode_string(doc, token_index, decoded, sizeof(decoded)) != 0 ||
        !telemetry_text_safe(decoded))
        return -1;
    length = strlen(decoded);
    if (length >= out_size)
        return -1;
    memcpy(out, decoded, length + 1);
    return 0;
}

static int token_i64(const frr_json_doc *doc, int token_index,
                     int64_t *value) {
    const frr_json_token *token;
    char number[64];
    char *end = NULL;
    size_t length;
    long long parsed;

    if (!doc || !value || token_index < 0 ||
        token_index >= doc->token_count)
        return -1;
    token = &doc->tokens[token_index];
    if (token->type != FRR_JSON_PRIMITIVE || token->end <= token->start)
        return -1;
    length = (size_t)(token->end - token->start);
    if (length >= sizeof(number))
        return -1;
    memcpy(number, doc->text + token->start, length);
    number[length] = '\0';
    for (size_t i = number[0] == '-' ? 1U : 0U; i < length; i++) {
        if (!isdigit((unsigned char)number[i]))
            return -1;
    }
    errno = 0;
    parsed = strtoll(number, &end, 10);
    if (errno != 0 || !end || *end != '\0')
        return -1;
    *value = (int64_t)parsed;
    return 0;
}

static int required_member(const frr_json_doc *doc, int object_index,
                           const char *name, frr_json_type type,
                           int *value_index, char *err, size_t err_size) {
    int result = object_member(doc, object_index, name, value_index);

    if (result != 1) {
        char message[128];

        snprintf(message, sizeof(message),
                 result < 0 ? "duplicate or malformed JSON member: %s" :
                 "missing JSON member: %s", name);
        set_error(err, err_size, message);
        return -1;
    }
    if (doc->tokens[*value_index].type != type) {
        char message[128];

        snprintf(message, sizeof(message), "wrong JSON type for member: %s",
                 name);
        set_error(err, err_size, message);
        return -1;
    }
    return 0;
}

static int format_dead_time(int64_t milliseconds,
                            char *out, size_t out_size) {
    int64_t seconds;
    int64_t hours;
    int64_t minutes;
    int64_t remainder;
    int n;

    if (milliseconds < 0)
        milliseconds = 0;
    seconds = milliseconds / 1000;
    hours = seconds / 3600;
    remainder = seconds % 3600;
    minutes = remainder / 60;
    remainder %= 60;
    n = snprintf(out, out_size, "%02lld:%02lld:%02lld",
                 (long long)hours, (long long)minutes,
                 (long long)remainder);
    return n > 0 && (size_t)n < out_size ? 0 : -1;
}

int rpd_frr_parse_ospf_neighbors_json(const char *json,
                                      rpd_frr_runtime *rt,
                                      int *neighbors, int *full,
                                      char *err, size_t err_size) {
    frr_json_doc doc = {0};
    rpd_frr_ospf_neighbor entries[RPD_FRR_VTYSH_MAX_NEIGHBORS];
    int entry_count = 0;
    int total = 0;
    int full_count = 0;
    int neighbors_object = -1;
    int result = -1;

    if (!rt || !neighbors || !full) {
        set_error(err, err_size, "invalid OSPF JSON parse request");
        return -1;
    }
    memset(entries, 0, sizeof(entries));
    if (parse_document(json, &doc, err, err_size) != 0)
        return -1;
    if (doc.tokens[doc.root].type != FRR_JSON_OBJECT) {
        set_error(err, err_size, "OSPF JSON root is not an object");
        goto done;
    }
    if (doc.tokens[doc.root].size == 0) {
        result = 0;
        goto commit;
    }
    if (required_member(&doc, doc.root, "neighbors", FRR_JSON_OBJECT,
                        &neighbors_object, err, err_size) != 0)
        goto done;
    for (int i = 0; i < doc.token_count; i++) {
        int array_index;

        if (doc.tokens[i].parent != neighbors_object)
            continue;
        if (doc.tokens[i].type != FRR_JSON_STRING ||
            i + 1 >= doc.token_count || doc.tokens[i + 1].parent != i ||
            doc.tokens[i + 1].type != FRR_JSON_ARRAY) {
            set_error(err, err_size, "malformed OSPF neighbor map");
            goto done;
        }
        array_index = i + 1;
        for (int j = 0; j < doc.token_count; j++) {
            rpd_frr_ospf_neighbor entry = {0};
            int priority_index;
            int state_index;
            int dead_index;
            int address_index;
            int interface_index;
            int64_t priority;
            int64_t dead_msecs;

            if (doc.tokens[j].parent != array_index)
                continue;
            if (doc.tokens[j].type != FRR_JSON_OBJECT) {
                set_error(err, err_size,
                          "OSPF neighbor array entry is not an object");
                goto done;
            }
            if (required_member(&doc, j, "priority", FRR_JSON_PRIMITIVE,
                                &priority_index, err, err_size) != 0 ||
                required_member(&doc, j, "state", FRR_JSON_STRING,
                                &state_index, err, err_size) != 0 ||
                required_member(&doc, j, "deadTimeMsecs",
                                FRR_JSON_PRIMITIVE, &dead_index,
                                err, err_size) != 0 ||
                required_member(&doc, j, "address", FRR_JSON_STRING,
                                &address_index, err, err_size) != 0 ||
                required_member(&doc, j, "ifaceName", FRR_JSON_STRING,
                                &interface_index, err, err_size) != 0)
                goto done;
            if (token_i64(&doc, priority_index, &priority) != 0 ||
                priority < 0 || priority > 255 ||
                token_i64(&doc, dead_index, &dead_msecs) != 0 ||
                copy_string_field(&doc, i, entry.neighbor_id,
                                  sizeof(entry.neighbor_id)) != 0 ||
                copy_string_field(&doc, state_index, entry.state,
                                  sizeof(entry.state)) != 0 ||
                copy_string_field(&doc, address_index, entry.address,
                                  sizeof(entry.address)) != 0 ||
                copy_string_field(&doc, interface_index, entry.interface,
                                  sizeof(entry.interface)) != 0 ||
                format_dead_time(dead_msecs, entry.dead_time,
                                 sizeof(entry.dead_time)) != 0) {
                set_error(err, err_size,
                          "invalid OSPF neighbor JSON field value");
                goto done;
            }
            entry.priority = (int)priority;
            entry.full = strncmp(entry.state, "Full", 4) == 0;
            if (total == INT_MAX) {
                set_error(err, err_size, "OSPF neighbor count overflow");
                goto done;
            }
            total++;
            if (entry.full)
                full_count++;
            if (entry_count < RPD_FRR_VTYSH_MAX_NEIGHBORS)
                entries[entry_count++] = entry;
        }
    }
    result = 0;

commit:
    rt->ospf_neighbor_entries = entry_count;
    rt->ospf_neighbor_truncated = entry_count != total;
    rt->ospf_neighbor_complete = !rt->ospf_neighbor_truncated;
    memcpy(rt->ospf_neighbor, entries, sizeof(entries));
    *neighbors = total;
    *full = full_count;
done:
    free_document(&doc);
    return result;
}

int rpd_frr_parse_bgp_summary_json(const char *json,
                                   rpd_frr_runtime *rt,
                                   int *peers, int *established,
                                   char *err, size_t err_size) {
    frr_json_doc doc = {0};
    rpd_frr_bgp_peer entries[RPD_FRR_VTYSH_MAX_PEERS];
    int entry_count = 0;
    int total = 0;
    int established_count = 0;
    int family_object = -1;
    int peers_object = -1;
    int result = -1;

    if (!rt || !peers || !established) {
        set_error(err, err_size, "invalid BGP JSON parse request");
        return -1;
    }
    memset(entries, 0, sizeof(entries));
    if (parse_document(json, &doc, err, err_size) != 0)
        return -1;
    if (doc.tokens[doc.root].type != FRR_JSON_OBJECT) {
        set_error(err, err_size, "BGP JSON root is not an object");
        goto done;
    }
    if (doc.tokens[doc.root].size == 0) {
        result = 0;
        goto commit;
    }
    if (required_member(&doc, doc.root, "ipv4Unicast", FRR_JSON_OBJECT,
                        &family_object, err, err_size) != 0 ||
        required_member(&doc, family_object, "peers", FRR_JSON_OBJECT,
                        &peers_object, err, err_size) != 0)
        goto done;
    for (int i = 0; i < doc.token_count; i++) {
        rpd_frr_bgp_peer entry = {0};
        int peer_object;
        int remote_as_index;
        int uptime_index;
        int state_index;
        int prefixes_index;
        int64_t remote_as;
        int64_t prefixes;

        if (doc.tokens[i].parent != peers_object)
            continue;
        if (doc.tokens[i].type != FRR_JSON_STRING ||
            i + 1 >= doc.token_count || doc.tokens[i + 1].parent != i ||
            doc.tokens[i + 1].type != FRR_JSON_OBJECT) {
            set_error(err, err_size, "malformed BGP peer map");
            goto done;
        }
        peer_object = i + 1;
        if (required_member(&doc, peer_object, "remoteAs",
                            FRR_JSON_PRIMITIVE, &remote_as_index,
                            err, err_size) != 0 ||
            required_member(&doc, peer_object, "peerUptime",
                            FRR_JSON_STRING, &uptime_index,
                            err, err_size) != 0 ||
            required_member(&doc, peer_object, "state", FRR_JSON_STRING,
                            &state_index, err, err_size) != 0 ||
            required_member(&doc, peer_object, "pfxRcd",
                            FRR_JSON_PRIMITIVE, &prefixes_index,
                            err, err_size) != 0)
            goto done;
        if (token_i64(&doc, remote_as_index, &remote_as) != 0 ||
            remote_as < 0 || remote_as > UINT32_MAX ||
            token_i64(&doc, prefixes_index, &prefixes) != 0 ||
            prefixes < 0 ||
            copy_string_field(&doc, i, entry.neighbor,
                              sizeof(entry.neighbor)) != 0 ||
            copy_string_field(&doc, uptime_index, entry.uptime,
                              sizeof(entry.uptime)) != 0 ||
            copy_string_field(&doc, state_index, entry.state,
                              sizeof(entry.state)) != 0) {
            set_error(err, err_size, "invalid BGP peer JSON field value");
            goto done;
        }
        snprintf(entry.remote_as, sizeof(entry.remote_as), "%llu",
                 (unsigned long long)remote_as);
        snprintf(entry.prefixes, sizeof(entry.prefixes), "%llu",
                 (unsigned long long)prefixes);
        entry.established = strcmp(entry.state, "Established") == 0;
        if (total == INT_MAX) {
            set_error(err, err_size, "BGP peer count overflow");
            goto done;
        }
        total++;
        if (entry.established)
            established_count++;
        if (entry_count < RPD_FRR_VTYSH_MAX_PEERS)
            entries[entry_count++] = entry;
    }
    result = 0;

commit:
    rt->bgp_peer_entries = entry_count;
    rt->bgp_peer_truncated = entry_count != total;
    rt->bgp_peer_complete = !rt->bgp_peer_truncated;
    memcpy(rt->bgp_peer, entries, sizeof(entries));
    *peers = total;
    *established = established_count;
done:
    free_document(&doc);
    return result;
}
