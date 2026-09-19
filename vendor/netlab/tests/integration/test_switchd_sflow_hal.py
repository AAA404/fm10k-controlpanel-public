#!/usr/bin/env python3.11
"""Build and run the switchd sFlow HAL state-machine fixture."""

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VENDOR_ROOT = Path(os.environ.get("NETLAB_VENDOR_ROOT", "/opt/netlab-vendor"))
SDK_TREE = os.environ.get(
    "NETLAB_SDK_TREE",
    "IES_SDK-4.3.2-20160607_6ports_15032017_14i_LINK_OPT_EEE_VRM",
)
IES_SDK = Path(os.environ.get("IES_SDK", VENDOR_ROOT / SDK_TREE / "ies"))
SOURCE = ROOT / "tests" / "integration" / "switchd_sflow_hal_test.c"
BINARY = ROOT / "build" / "switchd_sflow_hal_test"
HAL_SFLOW = ROOT / "sbin" / "switchd" / "hal_sflow.c"


def check_source_invariants() -> bool:
    source = HAL_SFLOW.read_text(encoding="utf-8")

    forbidden_span_writes = (
        "fmCreateMirror(",
        "fmDeleteMirror(",
        "fmSetMirrorDestination(",
        "fmAddMirrorPort(",
        "fmAddMirrorPortExt(",
        "fmDeleteMirrorPort(",
    )
    if any(token in source for token in forbidden_span_writes):
        print("FAIL: sFlow HAL never mutates SPAN/mirror APIs directly")
        return False

    live_probe = source.find("int hal_sflow_live_probe(")
    writes_started = source.find("writes_started = true;", live_probe)
    if live_probe < 0 or writes_started < 0:
        print("FAIL: locate sFlow live-probe write boundary")
        return False
    prewrite = source[live_probe:writes_started]
    required_prewrite = (
        "FM_PORT_STATE_UP",
        "FM_PORT_STATE_PARTIALLY_UP",
        "rx_projection_equal(&rx_before, &rx_stable)",
        "group31-foreign-owner",
        "hal_mirror_state_get",
        "sflow_state_restorable",
    )
    if any(token not in prewrite for token in required_prewrite):
        print("FAIL: all sFlow ingress/ownership guards precede writes")
        return False

    create_exact = source.find("static int sflow_create_exact(")
    restore = source.find("static int sflow_restore(", create_exact)
    if create_exact < 0 or restore < 0:
        print("FAIL: locate exact sFlow apply/restore helpers")
        return False
    apply_body = source[create_exact:restore]
    create = apply_body.find("fmCreateSFlow(")
    rate = apply_body.find("fmSetSFlowAttribute(")
    add = apply_body.find("fmAddSFlowPort(")
    readback = apply_body.find("hal_sflow_state_get(")
    if not (0 <= create < rate < add < readback):
        print("FAIL: sFlow apply is create -> rate -> ports -> readback")
        return False

    cleanup = source.find("cleanup:", writes_started)
    out = source.find("\nout:", cleanup)
    if cleanup < 0 or out < 0:
        print("FAIL: locate sFlow probe cleanup block")
        return False
    cleanup_body = source[cleanup:out]
    required_cleanup = (
        "sflow_restore(sw, &prior)",
        "sflow_config_equal(&final_state, &prior)",
        "hal_mirror_state_equal(&span_before, &span_after)",
        "SFLOW_PROBE_SETTLE()",
        "cleanup_status",
    )
    if any(token not in cleanup_body for token in required_cleanup):
        print("FAIL: cleanup restores and verifies sFlow plus SPAN state")
        return False

    print("PASS: sFlow HAL source preserves write and cleanup boundaries")
    return True


def main() -> int:
    include_dirs = [
        ROOT / "include",
        IES_SDK / "include",
        IES_SDK / "include" / "platforms",
        IES_SDK / "include" / "alos",
        IES_SDK / "include" / "alos" / "linux",
        IES_SDK / "include" / "common",
        IES_SDK / "include" / "api",
        IES_SDK / "include" / "std" / "intel",
        IES_SDK / "include" / "platforms" / "libertyTrail",
        IES_SDK / "include" / "platforms" / "common",
        IES_SDK / "include" / "platforms" / "util" / "boardManager",
    ]
    if not IES_SDK.is_dir():
        print(f"FAIL: SDK include tree is missing: {IES_SDK}")
        return 1
    if not HAL_SFLOW.is_file():
        print(f"FAIL: sFlow HAL source is missing: {HAL_SFLOW}")
        return 1
    if not check_source_invariants():
        return 1

    BINARY.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "cc",
        "-std=c99",
        "-D_GNU_SOURCE",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-ffunction-sections",
        "-Wl,--gc-sections",
    ]
    for include_dir in include_dirs:
        command.extend(("-I", str(include_dir)))
    command.extend(("-o", str(BINARY), str(SOURCE)))

    build = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if build.returncode != 0:
        print("FAIL: switchd sFlow HAL fixture builds")
        print(build.stdout)
        return 1
    print("PASS: switchd sFlow HAL fixture builds")

    run = subprocess.run(
        [str(BINARY)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    print(run.stdout, end="")
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
