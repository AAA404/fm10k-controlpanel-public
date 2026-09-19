#!/usr/bin/env python3.11
"""The immutable YANG tree view is serialized once per mutation epoch."""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from build_support import libyang_flags, runtime_environment


ROOT = Path(__file__).resolve().parents[2]

SOURCE = r'''
#include "netlab/yang_config.h"

#include <libyang/printer_data.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int print_calls;

LY_ERR __real_lyd_print_mem(char **strp, const struct lyd_node *root,
                            LYD_FORMAT format, uint32_t options);

LY_ERR __wrap_lyd_print_mem(char **strp, const struct lyd_node *root,
                            LYD_FORMAT format, uint32_t options) {
    print_calls++;
    return __real_lyd_print_mem(strp, root, format, options);
}

static int expect_xml(nl_yang_session *session, const char *needle,
                      int expected_calls) {
    char *xml = nl_yang_to_xml(session);
    int ok = xml && strstr(xml, needle) && print_calls == expected_calls;
    free(xml);
    return ok ? 0 : -1;
}

int main(void) {
    nl_yang_session *session = nl_yang_session_create("include/netlab");
    nl_yang_session *empty_session;
    struct lyd_node *replacement;
    struct lyd_node *empty_tree;
    const char *path = "/netlab:netlab-config/system/host-name";

    if (!session || (int)nl_yang_set(session, path, "cache-one") != 0)
        return 10;
    for (int i = 0; i < 50; i++)
        if (expect_xml(session, "cache-one", 1) != 0)
            return 11;
    if ((int)nl_yang_set(session, path, "cache-two") != 0 ||
        expect_xml(session, "cache-two", 2) != 0)
        return 12;
    if ((int)nl_yang_delete(session, path) != 0)
        return 13;
    {
        char *xml = nl_yang_to_xml(session);
        int ok = xml && !strstr(xml, "cache-two") && print_calls == 3;
        free(xml);
        if (!ok)
            return 14;
    }
    replacement = nl_yang_from_xml(
        session,
        "<netlab-config xmlns=\"urn:netlab:config\">"
        "<system><host-name>cache-three</host-name></system>"
        "</netlab-config>");
    if (!replacement)
        return 15;
    nl_yang_data_set(session, replacement);
    if (expect_xml(session, "cache-three", 4) != 0)
        return 16;
    nl_yang_session_destroy(session);

    empty_session = nl_yang_session_create("include/netlab");
    if (!empty_session)
        return 17;
    empty_tree = nl_yang_from_xml(
        empty_session,
        "<netlab-config xmlns=\"urn:netlab:config\"/>");
    if (!empty_tree)
        return 18;
    nl_yang_data_set(empty_session, empty_tree);
    for (int i = 0; i < 2; i++)
        if (expect_xml(empty_session,
                       "<netlab-config xmlns=\"urn:netlab:config\"/>",
                       5) != 0)
            return 19;
    {
        char *json = nl_yang_to_json(empty_session);
        int ok = json && strchr(json, '{') && strchr(json, '}') &&
            print_calls == 6;
        free(json);
        if (!ok)
            return 20;
    }
    nl_yang_session_destroy(empty_session);
    return 0;
}
'''


def main() -> int:
    libyang_cflags, libyang_libs, library_dir = libyang_flags()
    with tempfile.TemporaryDirectory(prefix="netlab-yang-cache-") as td:
        source = Path(td) / "yang_cache.c"
        binary = Path(td) / "yang_cache"
        source.write_text(SOURCE, encoding="ascii")
        compile_result = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-D_GNU_SOURCE", f"-I{ROOT / 'include'}",
                *libyang_cflags,
                str(source), str(ROOT / "lib/libconfig/yang_config.c"),
                *libyang_libs,
                "-Wl,--wrap=lyd_print_mem", "-o", str(binary),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        assert compile_result.returncode == 0, compile_result.stdout
        run = subprocess.run(
            [str(binary)], cwd=ROOT,
            env={**runtime_environment(library_dir),
                 "NETLAB_ROOT": str(ROOT)},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, check=False,
        )
        assert run.returncode == 0, run.stdout
    print("OK: repeated YANG XML reads serialize once per mutation epoch")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
