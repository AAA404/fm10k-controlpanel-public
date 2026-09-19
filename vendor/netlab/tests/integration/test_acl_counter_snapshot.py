#!/usr/bin/env python3.11
"""Typed ACL counter snapshot boundaries and one-RPC failure atomicity."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="netlab-acl-counter-snapshot-") as tmp:
        binary = pathlib.Path(tmp) / "acl-counter-snapshot-test"
        command = [
            "gcc",
            "-std=c11",
            "-Wall",
            "-Werror",
            "-Wextra",
            "-pedantic",
            "-D_GNU_SOURCE",
            "-ffunction-sections",
            "-fdata-sections",
            f"-I{ROOT}",
            f"-I{ROOT / 'include'}",
            str(ROOT / "tests/integration/acl_counter_snapshot_test.c"),
            str(ROOT / "lib/libipc/acl_counter_snapshot.c"),
            str(ROOT / "sbin/l2d/l2d_switchd.c"),
            "-Wl,--gc-sections",
            "-o",
            str(binary),
        ]
        subprocess.run(command, cwd=ROOT, check=True)
        subprocess.run([str(binary)], cwd=ROOT, check=True)

    show_source = (ROOT / "sbin/l2d/l2d_show.c").read_text(encoding="utf-8")
    show_body = show_source.split("int l2d_show_mac_security", 1)[1]
    assert show_body.count("l2d_switchd_get_acl_counter_snapshot(") == 1
    for legacy_call in (
        "l2d_switchd_get_user_filter_counters(",
        "l2d_switchd_get_ingress_ipv4_acl_counters(",
        "l2d_switchd_get_egress_acl_counters(",
        "l2d_switchd_get_acl_policer_counters(",
        "l2d_switchd_get_acl_independent_counters(",
    ):
        assert legacy_call not in show_body

    rpc_source = (ROOT / "sbin/switchd/rpc_server.c").read_text(encoding="utf-8")
    rpc_case = rpc_source.split(
        "case NL_SWITCHD_ACL_COUNTER_SNAPSHOT_GET:", 1
    )[1].split("case ", 1)[0]
    assert rpc_case.count("sdk_exec_with_prio(") == 1
    assert "SDK_OP_GET_ACL_COUNTER_SNAPSHOT" in rpc_case

    user_hal = (ROOT / "sbin/switchd/hal_l2_security.c").read_text(
        encoding="utf-8"
    ).split("int hal_l2_security_user_filter_counter_snapshot", 1)[1]
    user_hal = user_hal.split("\n}", 1)[0]
    assert user_hal.count("fmGetFlowRuleFirst(") == 1
    ingress_hal = (ROOT / "sbin/switchd/hal_ingress_ipv4_acl.c").read_text(
        encoding="utf-8"
    ).split("int hal_ingress_ipv4_acl_counter_snapshot", 1)[1]
    assert ingress_hal.count("fmGetFlowRuleFirst(") == 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
