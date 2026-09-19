/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/yang_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <libyang/context.h>
#include <libyang/tree_data.h>
#include <libyang/tree_schema.h>
#include <libyang/parser_schema.h>
#include <libyang/printer_data.h>
#include <libyang/set.h>

struct nl_yang_session {
    struct ly_ctx *ctx;
    struct lyd_node *data;
    char *xml_cache;
};

static void nl_yang_invalidate_serialization(nl_yang_session *s) {
    if (!s)
        return;
    free(s->xml_cache);
    s->xml_cache = NULL;
}

nl_yang_session *nl_yang_session_create(const char *search_dir) {
    nl_yang_session *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    LY_ERR err = ly_ctx_new(search_dir, 0, &s->ctx);
    if (err != LY_SUCCESS) {
        free(s);
        return NULL;
    }

    // Set search dir so yanglint can find netlab.yang
    if (search_dir) {
        ly_ctx_set_searchdir(s->ctx, search_dir);
    }

    char root_yang[512] = {0};
    const char *root = getenv("NETLAB_ROOT");
    if (root && root[0]) {
        snprintf(root_yang, sizeof(root_yang),
                 "%s/include/netlab/netlab.yang", root);
    }

    const char *try_paths[] = {
        root_yang,
        "include/netlab/netlab.yang",
        "/etc/netlab/netlab.yang",
        "netlab.yang",
        NULL
    };

    err = LY_ENOTFOUND;
    for (int i = 0; try_paths[i]; i++) {
        /*
         * The parsed module output is optional and the session is not
         * returned unless loading succeeds.  Passing NULL also keeps this
         * call compatible with libyang builds that differ only in whether
         * the output pointer is const-qualified.
         */
        err = lys_parse_path(s->ctx, try_paths[i], LYS_IN_YANG, NULL);
        if (err == LY_SUCCESS) break;
    }
    if (err != LY_SUCCESS) {
        ly_ctx_destroy(s->ctx);
        free(s);
        return NULL;
    }

    s->data = NULL;
    return s;
}

void nl_yang_session_destroy(nl_yang_session *s) {
    if (!s) return;
    nl_yang_invalidate_serialization(s);
    if (s->data) {
        lyd_free_all(s->data);
        s->data = NULL;
    }
    ly_ctx_destroy(s->ctx);
    free(s);
}

struct ly_ctx *nl_yang_session_ctx(nl_yang_session *s) {
    return s ? s->ctx : NULL;
}

struct lyd_node *nl_yang_data_clone(nl_yang_session *s) {
    if (!s || !s->data) return NULL;
    char *xml = nl_yang_to_xml(s);
    if (!xml) return NULL;
    struct lyd_node *clone = nl_yang_from_xml(s, xml);
    free(xml);
    return clone;
}

struct lyd_node *nl_yang_data_clone_into(nl_yang_session *dst,
                                         nl_yang_session *src) {
    if (!dst || !src || !src->data) return NULL;
    char *xml = nl_yang_to_xml(src);
    if (!xml) return NULL;
    struct lyd_node *clone = nl_yang_from_xml(dst, xml);
    free(xml);
    return clone;
}

void nl_yang_data_set(nl_yang_session *s, struct lyd_node *tree) {
    if (!s) return;
    nl_yang_invalidate_serialization(s);
    if (s->data) lyd_free_all(s->data);
    s->data = tree;
}

// --- CRUD ---

nl_error_code nl_yang_set(nl_yang_session *s, const char *path, const char *value) {
    if (!s || !path) return NL_ERR_INVALID_PATH;

    struct lyd_node *node = NULL;
    LY_ERR err;

    if (s->data) {
        err = lyd_new_path(s->data, NULL, path, value,
                           LYD_NEW_PATH_UPDATE, &node);
    } else {
        err = lyd_new_path(NULL, s->ctx, path, value,
                           LYD_NEW_PATH_UPDATE, &node);
    }
    if (err == LY_SUCCESS) {
        if (!s->data) {
            if (!node)
                return (nl_error_code)NL_OK;
            while (lyd_parent(node))
                node = lyd_parent(node);
            s->data = node;
        } else {
            s->data = lyd_first_sibling(s->data);
        }
        nl_yang_invalidate_serialization(s);
        return (nl_error_code)NL_OK;
    }

    if (err == LY_ENOTFOUND)
        return NL_ERR_INVALID_PATH;
    if (err == LY_EVALID)
        return NL_ERR_INVALID_VALUE;

    return NL_ERR_INVALID_VALUE;
}

nl_error_code nl_yang_delete(nl_yang_session *s, const char *path) {
    if (!s || !path || !s->data) return NL_ERR_INVALID_PATH;

    struct ly_set *set = NULL;
    lyd_find_xpath(s->data, path, &set);
    if (!set || set->count == 0) {
        if (set) ly_set_free(set, NULL);
        return NL_ERR_INVALID_PATH;
    }

    // Unlink each node from its parent before freeing to avoid double-free
    for (uint32_t i = 0; i < set->count; i++) {
        struct lyd_node *n = set->dnodes[i];
        if (n == s->data) s->data = NULL;
        struct lyd_node *p = lyd_parent(n);
        if (p) {
            // Detach from parent's child list
            if (lyd_child(p) == n) {
                // This is the first child — unlinking requires struct access
                // Use lyd_free_tree which handles this internally
            }
        }
        lyd_free_tree(n);
    }
    ly_set_free(set, NULL);
    nl_yang_invalidate_serialization(s);
    return (nl_error_code)NL_OK;
}

const char *nl_yang_get(nl_yang_session *s, const char *path) {
    if (!s || !path || !s->data) return NULL;

    struct ly_set *set = NULL;
    LY_ERR err = lyd_find_xpath(s->data, path, &set);
    if (err != LY_SUCCESS || !set || set->count == 0) {
        if (set) ly_set_free(set, NULL);
        return NULL;
    }

    const char *val = lyd_get_value(set->dnodes[0]);
    ly_set_free(set, NULL);
    return val;
}

bool nl_yang_exists(nl_yang_session *s, const char *path) {
    if (!s || !path) return false;

    struct ly_set *set = NULL;
    LY_ERR err = lyd_find_xpath(s->data, path, &set);
    bool exists = (err == LY_SUCCESS && set && set->count > 0);
    if (set) ly_set_free(set, NULL);
    return exists;
}

static bool subtree_has_explicit(const struct lyd_node *node) {
    if (!node || !node->schema)
        return false;
    if (!(node->flags & LYD_DEFAULT) &&
        (node->schema->nodetype != LYS_CONTAINER ||
         (node->schema->flags & LYS_PRESENCE)))
        return true;
    const struct lyd_node *child;
    LY_LIST_FOR(lyd_child(node), child) {
        if (subtree_has_explicit(child))
            return true;
    }
    return false;
}

bool nl_yang_has_explicit(nl_yang_session *s, const char *path) {
    if (!s || !path)
        return true;
    if (!s->data)
        return false;
    struct ly_set *set = NULL;
    LY_ERR err = lyd_find_xpath(s->data, path, &set);
    bool explicit = err != LY_SUCCESS;
    for (uint32_t i = 0; !explicit && set && i < set->count; ++i)
        explicit = subtree_has_explicit(set->dnodes[i]);
    if (set)
        ly_set_free(set, NULL);
    return explicit;
}

int nl_yang_count(nl_yang_session *s, const char *path) {
    struct ly_set *set = NULL;
    LY_ERR err;
    int count;

    if (!s || !path)
        return -1;
    if (!s->data)
        return 0;

    err = lyd_find_xpath(s->data, path, &set);
    if (err != LY_SUCCESS || !set) {
        if (set)
            ly_set_free(set, NULL);
        return -1;
    }
    count = set->count > INT_MAX ? -1 : (int)set->count;
    ly_set_free(set, NULL);
    return count;
}

// --- Serialization ---

char *nl_yang_to_xml(nl_yang_session *s) {
    static const char empty_xml[] =
        "<netlab-config xmlns=\"urn:netlab:config\"/>";

    if (!s || !s->data) {
        return strdup(empty_xml);
    }

    if (s->xml_cache)
        return strdup(s->xml_cache);

    char *result = NULL;
    LY_ERR err = lyd_print_mem(&result, s->data, LYD_XML,
                                LYD_PRINT_WITHSIBLINGS);
    if (err != LY_SUCCESS)
        return NULL;
    /*
     * libyang emits no buffer for a valid tree containing only an empty
     * non-presence container.  Keep the public serialization contract
     * stable and never cache a NULL value for that successful result.
     */
    if (!result)
        result = strdup(empty_xml);
    if (!result)
        return NULL;
    s->xml_cache = result;
    return strdup(s->xml_cache);
}

char *nl_yang_to_json(nl_yang_session *s) {
    if (!s || !s->data) {
        return strdup("{}");
    }

    char *result = NULL;
    LY_ERR err = lyd_print_mem(&result, s->data, LYD_JSON,
                                LYD_PRINT_WITHSIBLINGS);
    if (err != LY_SUCCESS) return NULL;
    return result;
}

struct lyd_node *nl_yang_from_xml(nl_yang_session *s, const char *xml) {
    if (!s || !xml || !xml[0]) return NULL;

    struct lyd_node *node = NULL;
    /* A live session always has the NetLab module loaded. */
    uint32_t parse_opts = LYD_PARSE_ONLY | LYD_PARSE_STRICT;
    LY_ERR err = lyd_parse_data_mem(s->ctx, xml, LYD_XML,
                                     parse_opts, 0, &node);
    if (err != LY_SUCCESS) return NULL;
    return node;
}

// --- Diff ---

struct lyd_node *nl_yang_diff(nl_yang_session *s,
                              const struct lyd_node *old_tree,
                              const struct lyd_node *new_tree) {
    (void)s;
    struct lyd_node *diff = NULL;
    LY_ERR err = lyd_diff_tree(old_tree, new_tree, 0, &diff);
    if (err != LY_SUCCESS) return NULL;
    return diff;
}

nl_error_code nl_yang_merge(nl_yang_session *s,
                            struct lyd_node **target,
                            const struct lyd_node *source) {
    (void)s;
    LY_ERR err = lyd_merge_tree(target, source, 0);
    if (err == LY_SUCCESS)
        nl_yang_invalidate_serialization(s);
    return (err == LY_SUCCESS) ? (nl_error_code)NL_OK : NL_ERR_INVALID_VALUE;
}

// --- Display helpers ---

static int emit_set_line(char *buf, int buf_size, int off,
                         const char *path, const char *value) {
    int remain = buf_size - off;
    if (remain <= 2) return off;
    if (value && value[0]) {
        return off + snprintf(buf + off, remain, "set %s %s\n", path, value);
    }
    return off + snprintf(buf + off, remain, "set %s\n", path);
}

// Recursively walk data tree and emit set commands
static int walk_tree_set_format(struct lyd_node *root, char *buf, int buf_size,
                                int off, char *path_buf, int path_off) {
    if (!root || off >= buf_size) return off;

    struct lyd_node *child = NULL;
    LY_LIST_FOR(lyd_child(root), child) {
        if (!child->schema) continue;

        const char *name = child->schema->name;
        uint16_t nt = child->schema->nodetype;

        // Build path for this child
        int saved = path_off;
        if (path_off > 0) path_buf[path_off++] = ' ';
        int n = snprintf(path_buf + path_off, 1024 - path_off, "%s", name);
        if (n > 0 && path_off + n < 1024) path_off += n;
        path_buf[path_off] = '\0';

        switch (nt) {
        case LYS_CONTAINER:
        case LYS_LIST:
            off = walk_tree_set_format(child, buf, buf_size, off,
                                       path_buf, path_off);
            break;
        case LYS_LEAF:
        case LYS_LEAFLIST: {
            const char *val = lyd_get_value(child);
            if (val) {
                off = emit_set_line(buf, buf_size, off, path_buf, val);
            }
            break;
        }
        default:
            break;
        }

        path_off = saved;
        if (off >= buf_size) break;
    }

    return off;
}

int nl_yang_to_set_format(nl_yang_session *s, char *buf, int buf_size) {
    if (!s || !s->data || !buf || buf_size <= 0) return -1;

    char path_buf[1024] = {0};
    return walk_tree_set_format(s->data, buf, buf_size, 0, path_buf, 0);
}

static int appendf(char *buf, int buf_size, int off, const char *fmt, ...) {
    if (!buf || buf_size <= 0 || off >= buf_size) return off;

    int remain = buf_size - off;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + off, (size_t)remain, fmt, ap);
    va_end(ap);

    if (n < 0) return off;
    if (n >= remain) return buf_size - 1;
    return off + n;
}

static int append_path_token(char *path, int path_size, int off,
                             const char *token) {
    if (!path || path_size <= 0 || !token || !token[0]) return off;
    if (off >= path_size) return path_size - 1;

    if (off > 0) {
        if (off >= path_size - 1) return path_size - 1;
        path[off++] = ' ';
        path[off] = '\0';
    }

    int remain = path_size - off;
    int n = snprintf(path + off, (size_t)remain, "%s", token);
    if (n < 0) return off;
    if (n >= remain) return path_size - 1;
    return off + n;
}

static const char *direct_child_value(const struct lyd_node *node,
                                      const char *child_name) {
    if (!node || !child_name) return NULL;

    struct lyd_node *child = NULL;
    LY_LIST_FOR(lyd_child((struct lyd_node *)node), child) {
        if (!child->schema || !child->schema->name) continue;
        if (strcmp(child->schema->name, child_name) == 0) {
            return lyd_get_value(child);
        }
    }
    return NULL;
}

static char diff_node_op(const struct lyd_node *node, char inherited) {
    char op_char = inherited ? inherited : '+';
    if (!node || !node->meta) return op_char;

    struct lyd_meta *m = node->meta;
    while (m) {
        if (m->name && strcmp(m->name, "operation") == 0) {
            const char *op = lyd_get_meta_value(m);
            if (op && (strcmp(op, "delete") == 0 ||
                       strcmp(op, "remove") == 0)) {
                return '-';
            }
            if (op && (strcmp(op, "create") == 0 ||
                       strcmp(op, "replace") == 0)) {
                return '+';
            }
        }
        m = m->next;
    }

    return op_char;
}

static bool is_key_leaf(const struct lyd_node *node) {
    if (!node || !node->schema || !node->schema->name) return false;

    struct lyd_node *parent = lyd_parent((struct lyd_node *)node);
    if (!parent || !parent->schema || !parent->schema->name) return false;

    const char *pname = parent->schema->name;
    const char *name = node->schema->name;
    return ((strcmp(pname, "vlan") == 0 && strcmp(name, "name") == 0) ||
            (strcmp(pname, "interface") == 0 && strcmp(name, "name") == 0) ||
            (strcmp(pname, "logical-unit") == 0 && strcmp(name, "unit-id") == 0));
}

static int append_data_node_path(const struct lyd_node *node, char *path,
                                 int path_size, int path_off) {
    if (!node || !node->schema || !node->schema->name) return path_off;

    const char *name = node->schema->name;
    uint16_t nt = node->schema->nodetype;

    if (strcmp(name, "netlab-config") == 0) {
        return path_off;
    }

    if (nt == LYS_CONTAINER) {
        return append_path_token(path, path_size, path_off, name);
    }

    if (nt != LYS_LIST) {
        return path_off;
    }

    if (strcmp(name, "vlan") == 0) {
        const char *key = direct_child_value(node, "name");
        return append_path_token(path, path_size, path_off, key ? key : name);
    }
    if (strcmp(name, "interface") == 0) {
        const char *key = direct_child_value(node, "name");
        struct lyd_node *parent = lyd_parent((struct lyd_node *)node);
        if (parent && parent->schema && parent->schema->name &&
            strcmp(parent->schema->name, "interfaces") != 0) {
            path_off = append_path_token(path, path_size, path_off,
                                         "interface");
        }
        return append_path_token(path, path_size, path_off,
                                 key ? key : name);
    }
    if (strcmp(name, "logical-unit") == 0) {
        const char *key = direct_child_value(node, "unit-id");
        return append_path_token(path, path_size, path_off, key ? key : name);
    }

    return append_path_token(path, path_size, path_off, name);
}

static bool value_needs_quotes(const char *value) {
    if (!value) return false;
    for (const char *p = value; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '"' || *p == '\\') {
            return true;
        }
    }
    return false;
}

static int append_cli_value(char *buf, int buf_size, int off,
                            const char *value) {
    if (!value || !value[0]) return off;
    if (!value_needs_quotes(value)) {
        return appendf(buf, buf_size, off, " %s", value);
    }

    off = appendf(buf, buf_size, off, " \"");
    for (const char *p = value; *p; p++) {
        if (*p == '"' || *p == '\\') {
            off = appendf(buf, buf_size, off, "\\%c", *p);
        } else {
            off = appendf(buf, buf_size, off, "%c", *p);
        }
    }
    return appendf(buf, buf_size, off, "\"");
}

static bool is_lacp_mode_leaf(const struct lyd_node *node) {
    if (!node || !node->schema || !node->schema->name ||
        strcmp(node->schema->name, "mode") != 0) {
        return false;
    }

    struct lyd_node *parent = lyd_parent((struct lyd_node *)node);
    return parent && parent->schema && parent->schema->name &&
        strcmp(parent->schema->name, "lacp") == 0;
}

static bool is_boolean_keyword_leaf(const struct lyd_node *node,
                                    const char *value) {
    if (!node || !node->schema || !node->schema->name ||
        !value || strcmp(value, "true") != 0) {
        return false;
    }

    const char *name = node->schema->name;
    return strcmp(name, "disable") == 0 ||
        strcmp(name, "edge") == 0 ||
        strcmp(name, "bpdu-block-on-edge") == 0 ||
        strcmp(name, "root-protection") == 0 ||
        strcmp(name, "loop-protection") == 0;
}

static int append_junos_compare_statement(char *buf, int buf_size, int off,
                                          char op, const char *section_path,
                                          const char *statement,
                                          char *last_section,
                                          int last_section_size) {
    if (!statement || !statement[0]) return off;

    const char *section = section_path ? section_path : "";
    if (!last_section || strcmp(last_section, section) != 0) {
        if (section[0]) {
            off = appendf(buf, buf_size, off, "[edit %s]\n", section);
        } else {
            off = appendf(buf, buf_size, off, "[edit]\n");
        }
        if (last_section && last_section_size > 0) {
            snprintf(last_section, (size_t)last_section_size, "%s", section);
        }
    }

    return appendf(buf, buf_size, off, "%c   %s;\n",
                   op == '-' ? '-' : '+', statement);
}

static int build_compare_leaf_statement(const struct lyd_node *node,
                                        char *section_path,
                                        int section_size,
                                        int section_off,
                                        char *statement,
                                        int statement_size) {
    if (!node || !node->schema || !node->schema->name ||
        !statement || statement_size <= 0) {
        return -1;
    }

    const char *name = node->schema->name;
    const char *value = lyd_get_value(node);
    const char *display = name;
    bool include_value = true;

    if (strcmp(name, "vlan-members") == 0) {
        section_off = append_path_token(section_path, section_size,
                                        section_off, "vlan");
        if (section_off >= 0 && section_off < section_size)
            section_path[section_off] = '\0';
        display = "members";
    } else if (strcmp(name, "ieee8023ad") == 0) {
        display = "802.3ad";
    } else if (is_lacp_mode_leaf(node)) {
        display = value;
        include_value = false;
    } else if (is_boolean_keyword_leaf(node, value)) {
        include_value = false;
    }

    if (!display || !display[0]) return -1;

    int off = snprintf(statement, (size_t)statement_size, "%s", display);
    if (off < 0) return -1;
    if (off >= statement_size) {
        statement[statement_size - 1] = '\0';
        return 0;
    }
    if (include_value && value && value[0]) {
        off = append_cli_value(statement, statement_size, off, value);
    }
    return 0;
}

static int walk_diff_compare(const struct lyd_node *node, char *buf,
                             int buf_size, int off, char *path,
                             int path_size, int path_off, char inherited_op,
                             int *emitted, char *last_section,
                             int last_section_size) {
    if (!node || !node->schema || off >= buf_size) return off;

    char op = diff_node_op(node, inherited_op);
    uint16_t nt = node->schema->nodetype;
    int saved = path_off;
    int before = emitted ? *emitted : 0;

    if (nt == LYS_CONTAINER || nt == LYS_LIST) {
        path_off = append_data_node_path(node, path, path_size, path_off);

        struct lyd_node *child = NULL;
        LY_LIST_FOR(lyd_child((struct lyd_node *)node), child) {
            off = walk_diff_compare(child, buf, buf_size, off, path,
                                    path_size, path_off, op, emitted,
                                    last_section, last_section_size);
            if (off >= buf_size - 1) break;
        }

        if ((op == '-' || op == '+') && nt == LYS_LIST &&
            emitted && *emitted == before && path_off > 0) {
            path[path_off] = '\0';
            off = append_junos_compare_statement(buf, buf_size, off, op, "",
                                                 path, last_section,
                                                 last_section_size);
            (*emitted)++;
        }
    } else if ((nt == LYS_LEAF || nt == LYS_LEAFLIST) && !is_key_leaf(node)) {
        path[path_off] = '\0';
        char section[1024];
        char statement[512];
        snprintf(section, sizeof(section), "%s", path);
        if (build_compare_leaf_statement(node, section, (int)sizeof(section),
                                         path_off, statement,
                                         (int)sizeof(statement)) == 0) {
            off = append_junos_compare_statement(buf, buf_size, off, op,
                                                 section, statement,
                                                 last_section,
                                                 last_section_size);
            if (emitted) (*emitted)++;
        }
    }

    path[saved] = '\0';
    return off;
}

int nl_yang_diff_to_compare(nl_yang_session *s,
                            const struct lyd_node *diff_tree,
                            char *buf, int buf_size) {
    (void)s;
    if (!diff_tree || !buf || buf_size <= 0) return -1;

    int off = 0;
    struct lyd_node *iter = NULL;
    char path[1024] = {0};
    char last_section[1024] = {0};
    int emitted = 0;

    LY_LIST_FOR((struct lyd_node *)diff_tree, iter) {
        off = walk_diff_compare(iter, buf, buf_size, off, path,
                                (int)sizeof(path), 0, '+', &emitted,
                                last_section, (int)sizeof(last_section));
        if (off >= buf_size - 1) break;
    }

    return off;
}

int nl_yang_walk_children(nl_yang_session *s, const char *xpath,
                          nl_yang_child_cb cb, void *user) {
    if (!s || !xpath || !cb) return -1;
    char *xml = nl_yang_to_xml(s);
    if (!xml) return -1;
    struct lyd_node *root = nl_yang_from_xml(s, xml);
    free(xml);
    if (!root) return -1;
    struct ly_set *set = NULL;
    lyd_find_xpath(root, xpath, &set);
    int count = 0;
    if (set) {
        for (uint32_t i = 0; i < set->count; i++) {
            struct lyd_node *node = set->dnodes[i];
            const char *name = node->schema ? node->schema->name : "";
            const char *val = lyd_get_value(node);
            cb(name, val, 0, user);
            count++;
        }
        ly_set_free(set, NULL);
    }
    lyd_free_tree(root);
    return count;
}
