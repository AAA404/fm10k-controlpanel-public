/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#ifndef NETLAB_YANG_CONFIG_H
#define NETLAB_YANG_CONFIG_H

#include "types.h"
#include "error.h"

#include <libyang/libyang.h>
#include <libyang/tree_data.h>

// Opaque handle for a libyang-backed config session
typedef struct nl_yang_session nl_yang_session;

// Initialize a new session with the netlab YANG module loaded.
// search_dir: path to search for YANG modules (can be NULL for default).
// Returns NULL on failure.
nl_yang_session *nl_yang_session_create(const char *search_dir);

// Destroy a session and free all resources.
void nl_yang_session_destroy(nl_yang_session *s);

// Get the underlying ly_ctx (for advanced operations).
struct ly_ctx *nl_yang_session_ctx(nl_yang_session *s);

// Clone the internal data tree. Caller must lyd_free_tree().
struct lyd_node *nl_yang_data_clone(nl_yang_session *s);

// Clone src data into dst's libyang context. Caller must lyd_free_tree().
struct lyd_node *nl_yang_data_clone_into(nl_yang_session *dst,
                                         nl_yang_session *src);

// Set data tree from external source (takes ownership).
void nl_yang_data_set(nl_yang_session *s, struct lyd_node *tree);

// --- CRUD operations on the data tree ---

// Set a value at a simple XPath. Creates intermediate nodes as needed.
// path: e.g. "/netlab:vlans/vlan[name='V100']/vlan-id"
// value: string value (NULL for container nodes), "" to delete a leaf
// Returns NL_OK on success, or error code.
nl_error_code nl_yang_set(nl_yang_session *s, const char *path, const char *value);

// Delete a node and its subtree at the given path.
// Returns NL_OK on success, NL_ERR_INVALID_PATH if not found.
nl_error_code nl_yang_delete(nl_yang_session *s, const char *path);

// Get the value of a node at path. Returns NULL if not found.
// Returned string is valid until next session mutation; caller must strdup if needed.
const char *nl_yang_get(nl_yang_session *s, const char *path);

// Check if a node exists at path.
bool nl_yang_exists(nl_yang_session *s, const char *path);

// True when a subtree has explicit leaves, lists or presence containers.
// Implicit libyang defaults do not count as operator configuration.
// Invalid XPath/session conservatively returns true for write-policy checks.
bool nl_yang_has_explicit(nl_yang_session *s, const char *path);

// Count all data nodes matching an XPath without serializing the tree.
// Returns the number of matches, or -1 when the XPath cannot be evaluated.
int nl_yang_count(nl_yang_session *s, const char *path);

// --- Serialization ---

// Serialize tree to XML string. Caller must free().
char *nl_yang_to_xml(nl_yang_session *s);

// Serialize tree to JSON string. Caller must free().
char *nl_yang_to_json(nl_yang_session *s);

// Parse XML into a lyd_node tree (for loading config files).
struct lyd_node *nl_yang_from_xml(nl_yang_session *s, const char *xml);

// --- Diff ---

// Diff two trees. Returns an annotated diff tree (or NULL if identical).
// Caller must lyd_free_tree() the result.
struct lyd_node *nl_yang_diff(nl_yang_session *s,
                              const struct lyd_node *old_tree,
                              const struct lyd_node *new_tree);

// Merge source tree into target tree (target takes ownership).
nl_error_code nl_yang_merge(nl_yang_session *s,
                            struct lyd_node **target,
                            const struct lyd_node *source);

// --- Display helpers ---

// Render a data tree as "set" CLI commands in a buffer.
// Returns number of bytes written (excluding null terminator), or -1 on error.
int nl_yang_to_set_format(nl_yang_session *s, char *buf, int buf_size);

// Render a diff tree as "show | compare" output.
int nl_yang_diff_to_compare(nl_yang_session *s,
                            const struct lyd_node *diff_tree,
                            char *buf, int buf_size);

// Walk direct children of a path and call callback for each.
// callback receives: child_name, child_value (or NULL for containers), user_data.
// Returns number of children processed, or -1 on error.
typedef void (*nl_yang_child_cb)(const char *name, const char *value,
                                 int depth, void *user);
int nl_yang_walk_children(nl_yang_session *s, const char *xpath,
                          nl_yang_child_cb cb, void *user);

#endif
