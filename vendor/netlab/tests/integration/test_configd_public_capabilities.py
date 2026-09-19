#!/usr/bin/env python3.11
"""Offline configd public capability authority fixture."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from build_support import libyang_flags, runtime_environment


ROOT = Path(__file__).resolve().parents[2]


C_SOURCE = r'''
#include "netlab/yang_config.h"
#include "public_capabilities.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define ROOT_PATH "/netlab:netlab-config"

static int check(const char *name, bool condition) {
    printf("%s: %s\n", condition ? "PASS" : "FAIL", name);
    return condition ? 0 : 1;
}

static int setv(nl_yang_session *session, const char *path,
                const char *value) {
    int status = (int)nl_yang_set(session, path, value);

    if (status != 0)
        fprintf(stderr, "set failed status=%d path=%s\n", status, path);
    return status;
}

int main(void) {
    nl_yang_session *session = nl_yang_session_create(NULL);
    nl_yang_session *active = nl_yang_session_create(NULL);
    nl_yang_session *cleanup = nl_yang_session_create(NULL);
    nl_yang_session *divergent = nl_yang_session_create(NULL);
    nl_yang_session *closed_only = nl_yang_session_create(NULL);
    nl_yang_session *empty_cleanup = nl_yang_session_create(NULL);
    struct lyd_node *tree = NULL;
    configd_public_capability_status status;
    char detail[512] = {0};
    int failed = 0;

    if (!session || !active || !cleanup || !divergent || !closed_only ||
        !empty_cleanup) {
        fprintf(stderr, "failed to create YANG session\n");
        return 1;
    }

    failed += check(
        "ordinary public path remains allowed",
        configd_public_capability_path_allowed(
            ROOT_PATH "/system/host-name", detail, sizeof(detail)));
    failed += check(
        "General ACL set path is closed",
        !configd_public_capability_path_allowed(
            ROOT_PATH "/ethernet-switching-options/acl-independent/group",
            detail, sizeof(detail)) &&
        strstr(detail, "General ACL") != NULL);
    failed += check(
        "management service set path is closed",
        !configd_public_capability_path_allowed(
            ROOT_PATH "/system/services/gnmi/grpc",
            detail, sizeof(detail)) &&
        strstr(detail, "runtime owner") != NULL);
    failed += check(
        "SNMP set path is closed without prefix overmatch",
        !configd_public_capability_path_allowed(
            ROOT_PATH "/snmp/community", detail, sizeof(detail)) &&
        configd_public_capability_path_allowed(
            ROOT_PATH "/snmpish", detail, sizeof(detail)));

    failed += check(
        "empty candidate passes public capability validation",
        configd_public_capabilities_validate(
            session, detail, sizeof(detail)));
    failed += check(
        "unrelated system intent does not materialize a service false positive",
        setv(session, ROOT_PATH "/system/host-name", "leaf-1") == 0 &&
        configd_public_capabilities_validate(
            session, detail, sizeof(detail)));
    tree = nl_yang_data_clone(session);
    failed += check(
        "parsed-tree guard accepts unrelated system intent",
        tree && configd_public_capabilities_validate_tree(
            tree, detail, sizeof(detail)));
    lyd_free_all(tree);
    tree = NULL;

    failed += check(
        "management service candidate is rejected",
        setv(session, ROOT_PATH "/system/services/gnmi/grpc", "true") == 0 &&
        !configd_public_capabilities_validate(
            session, detail, sizeof(detail)) &&
        strstr(detail, "runtime owner") != NULL);
    tree = nl_yang_data_clone(session);
    failed += check(
        "parsed-tree guard rejects management service replay",
        tree && !configd_public_capabilities_validate_tree(
            tree, detail, sizeof(detail)));
    lyd_free_all(tree);
    tree = NULL;
    failed += check(
        "management service subtree can be deleted for cleanup",
        nl_yang_delete(session, ROOT_PATH "/system/services") == 0 &&
        configd_public_capabilities_validate(
            session, detail, sizeof(detail)));

    failed += check(
        "SNMP candidate is rejected",
        setv(session, ROOT_PATH "/snmp/contact", "NOC") == 0 &&
        !configd_public_capabilities_validate(
            session, detail, sizeof(detail)));
    failed += check(
        "SNMP subtree can be deleted for cleanup",
        nl_yang_delete(session, ROOT_PATH "/snmp") == 0 &&
        configd_public_capabilities_validate(
            session, detail, sizeof(detail)));

    failed += check(
        "independent General ACL candidate is rejected",
        setv(
            session,
            ROOT_PATH "/ethernet-switching-options/acl-independent/"
            "group[name='dc']/term[name='web'][family='inet']/"
            "destination-port",
            "443") == 0 &&
        !configd_public_capabilities_validate(
            session, detail, sizeof(detail)) &&
        strstr(detail, "not promoted") != NULL);
    failed += check(
        "General ACL subtree can be deleted for cleanup",
        nl_yang_delete(
            session,
            ROOT_PATH "/ethernet-switching-options/acl-independent") == 0 &&
        configd_public_capabilities_validate(
            session, detail, sizeof(detail)));

    failed += check(
        "legacy active tree is classified as cleanup-required",
        setv(active, ROOT_PATH "/system/host-name", "leaf-1") == 0 &&
        setv(active, ROOT_PATH "/system/services/gnmi/grpc", "true") == 0 &&
        setv(active,
             ROOT_PATH "/ethernet-switching-options/acl-independent/"
             "group[name='dc']/term[name='web'][family='inet']/"
             "destination-port", "443") == 0 &&
        configd_public_capabilities_cleanup_required(
            active, detail, sizeof(detail)));
    failed += check(
        "closed capability roots have typed cleanup instructions",
        configd_public_capabilities_status(
            active, &status, detail, sizeof(detail)) &&
        status.inspection_complete && status.closed_root_count == 2 &&
        strcmp(status.closed_roots[0].capability_id,
               "general-acl-independent") == 0 &&
        strcmp(status.closed_roots[0].cleanup_delete_command,
               "delete ethernet-switching-options acl independent-group") == 0 &&
        strcmp(status.closed_roots[1].capability_id,
               "management-services") == 0 &&
        strcmp(status.closed_roots[1].cleanup_delete_command,
               "delete system services") == 0);
    failed += check(
        "exact closed-intent deletion is an authorized cleanup commit",
        setv(cleanup, ROOT_PATH "/system/host-name", "leaf-1") == 0 &&
        configd_public_capabilities_cleanup_candidate(
            active, cleanup, detail, sizeof(detail)));
    failed += check(
        "cleanup mode rejects unrelated candidate changes",
        setv(divergent, ROOT_PATH "/system/host-name", "leaf-2") == 0 &&
        !configd_public_capabilities_cleanup_candidate(
            active, divergent, detail, sizeof(detail)) &&
        strstr(detail, "only exact removal") != NULL);
    failed += check(
        "removing the only closed intent may produce an empty candidate",
        setv(closed_only,
             ROOT_PATH "/system/services/ssh/enable", "true") == 0 &&
        configd_public_capabilities_cleanup_candidate(
            closed_only, empty_cleanup, detail, sizeof(detail)));
    failed += check(
        "clean active tree reports no closed capability roots",
        configd_public_capabilities_status(
            cleanup, &status, detail, sizeof(detail)) &&
        status.inspection_complete && status.closed_root_count == 0);

    nl_yang_session_destroy(session);
    nl_yang_session_destroy(active);
    nl_yang_session_destroy(cleanup);
    nl_yang_session_destroy(divergent);
    nl_yang_session_destroy(closed_only);
    nl_yang_session_destroy(empty_cleanup);
    return failed ? 1 : 0;
}
'''


def test_cli_visibility() -> int:
    sys.path.insert(0, str(ROOT / "bin" / "cli"))
    from cli import NetLabCLI
    from config_paths import cli_to_delete_path
    from session import DAEMON_CONFIGD, DAEMON_MGMTD

    mgmtd_xml = b'''<mgmtd total-sessions="0" active-sessions="0"
        total-requests="0" routed-requests="0" denied-requests="0"
        malformed-requests="0" backend-errors="0"
        max-concurrent-handlers="16" audit-log="/tmp/audit">
        <backends/></mgmtd>'''
    capability_xml = b'''<configd-public-capability-status schema="1"
        cleanup-required="true" inspection-complete="true"
        active-commit-id="0000000000000042">
        <active-replay admission="deferred" deferred="true"
            reason-code="closed-public-capability-intent"/>
        <closed-roots count="2">
          <closed-root capability-id="general-acl-independent"
            xpath="/netlab:netlab-config/ethernet-switching-options/acl-independent"
            cleanup-delete-command="delete ethernet-switching-options acl independent-group"/>
          <closed-root capability-id="management-services"
            xpath="/netlab:netlab-config/system/services"
            cleanup-delete-command="delete system services"/>
        </closed-roots><inspection-detail/>
        </configd-public-capability-status>'''

    class FixtureCLI(NetLabCLI):
        def __init__(self):
            super().__init__()
            self.calls = []

        def _public_runtime_rpc(self, daemon, method, payload=b""):
            self.calls.append((daemon, method, payload))
            if (daemon, method) == (DAEMON_MGMTD, 1):
                return mgmtd_xml
            if (daemon, method) == (DAEMON_CONFIGD, 18):
                return capability_xml
            return b"error: unexpected fixture request"

    cli = FixtureCLI()
    output = cli.dispatch("show system management") or ""
    checks = (
        ("management CLI requests typed configd capability status",
         (DAEMON_CONFIGD, 18, b"") in cli.calls),
        ("management CLI renders cleanup-required and replay deferral",
         "Cleanup required : true" in output and
         "Active replay    : deferred" in output and
         "closed-public-capability-intent" in output),
        ("management CLI renders exact cleanup delete command",
         "delete ethernet-switching-options acl independent-group" in output and
         "delete system services" in output),
        ("General ACL cleanup command deletes the closed root",
         cli_to_delete_path([
             "ethernet-switching-options", "acl", "independent-group"
         ]) == ("/netlab:netlab-config/ethernet-switching-options/"
                 "acl-independent")),
    )
    failed = 0
    for name, condition in checks:
        print(("PASS" if condition else "FAIL") + ": " + name)
        failed += 0 if condition else 1
    return failed


def main() -> int:
    try:
        libyang_cflags, libyang_libs, library_dir = libyang_flags()
    except RuntimeError as error:
        print(f"FAIL: {error}")
        return 1
    required = (
        ROOT / "include/netlab/netlab.yang",
        ROOT / "lib/libconfig/yang_config.c",
        ROOT / "sbin/configd/public_capabilities.c",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        print("FAIL: configd public capability fixture inputs missing: " +
              ", ".join(missing))
        return 1

    with tempfile.TemporaryDirectory(
            prefix="netlab-configd-public-capabilities.") as temporary:
        source = Path(temporary) / "public_capabilities_test.c"
        binary = Path(temporary) / "public_capabilities_test"
        source.write_text(C_SOURCE, encoding="utf-8")
        command = [
            "cc",
            "-std=c11",
            "-D_GNU_SOURCE",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-I", str(ROOT / "include"),
            "-I", str(ROOT / "sbin/configd"),
            *libyang_cflags,
            str(source),
            str(ROOT / "lib/libconfig/yang_config.c"),
            str(ROOT / "sbin/configd/public_capabilities.c"),
            *libyang_libs,
            "-o", str(binary),
        ]
        built = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if built.returncode != 0:
            print("FAIL: configd public capability fixture builds")
            print(built.stdout, end="")
            return 1
        print("PASS: configd public capability fixture builds")
        run = subprocess.run(
            [str(binary)],
            cwd=ROOT,
            env={**runtime_environment(library_dir),
                 "NETLAB_ROOT": str(ROOT)},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        print(run.stdout, end="")
        if run.returncode != 0:
            return run.returncode
        return 1 if test_cli_visibility() else 0


if __name__ == "__main__":
    raise SystemExit(main())
