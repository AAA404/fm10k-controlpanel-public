#!/usr/bin/env python3.11
"""Build and run the deterministic switchd sFlow Stage2 fixture."""

import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VENDOR_ROOT = Path(os.environ.get("NETLAB_VENDOR_ROOT", "/opt/netlab-vendor"))
SDK_TREE = os.environ.get(
    "NETLAB_SDK_TREE",
    "IES_SDK-4.3.2-20160607_6ports_15032017_14i_LINK_OPT_EEE_VRM",
)
IES_SDK = Path(os.environ.get("IES_SDK", VENDOR_ROOT / SDK_TREE / "ies"))
SOURCE = ROOT / "tests" / "integration" / "switchd_sflow_stage2_test.c"
BINARY = ROOT / "build" / "switchd_sflow_stage2_test"
CAPTURE = ROOT / "sbin" / "switchd" / "sflow_capture.c"
CAPTURE_HEADER = ROOT / "sbin" / "switchd" / "sflow_capture.h"


def check_source_boundary() -> bool:
    source = CAPTURE.read_text(encoding="utf-8")
    header = CAPTURE_HEADER.read_text(encoding="utf-8")
    callback_start = source.find("void sflow_capture_handle_event(")
    snapshot_start = source.find(
        "void sflow_capture_snapshot(", callback_start
    )
    if callback_start < 0 or snapshot_start < 0:
        print("FAIL: locate sFlow capture callback boundary")
        return False
    callback = source[callback_start:snapshot_start]
    forbidden = (
        "pthread_mutex_lock(",
        "pthread_mutex_trylock(",
        "pthread_spin",
        "nanosleep(",
        "usleep(",
        "malloc(",
        "calloc(",
        "realloc(",
        "NL_LOG_",
    )
    found = [token for token in forbidden if token in callback]
    if found:
        print(
            "FAIL: sFlow callback contains blocking/allocation/logging paths: "
            + ", ".join(found)
        )
        return False
    required_api = (
        "SFLOW_CAPTURE_DRAIN_OK",
        "SFLOW_CAPTURE_DRAIN_INVALID",
        "SFLOW_CAPTURE_DRAIN_BUSY",
        "sflow_capture_configure",
        "sflow_capture_drain",
    )
    missing = [token for token in required_api if token not in header]
    if missing:
        print("FAIL: Stage2 capture API is incomplete: " + ", ".join(missing))
        return False
    if "SFLOW_CAPTURE_MONOTONIC_NS" not in source:
        print("FAIL: Stage2 capture has no deterministic monotonic clock hook")
        return False
    ring_start = source.find("static void ring_publish(")
    ring_end = source.find("static u64 retained_oldest(", ring_start)
    ring = (
        source[ring_start:ring_end]
        if ring_start >= 0 and ring_end > ring_start
        else ""
    )
    if (
        ring.count("__ATOMIC_SEQ_CST") < 5
        or "__ATOMIC_RELAXED" in ring
    ):
        print(
            "FAIL: ring snapshots lack portable full-order publication"
        )
        return False
    admission_patterns = (
        r"__atomic_fetch_add\(\s*&g_inflight_callbacks,\s*"
        r"UINT64_C\(1\),\s*"
        r"__ATOMIC_SEQ_CST",
        r"__atomic_fetch_sub\(\s*&g_inflight_callbacks,\s*"
        r"UINT64_C\(1\),\s*__ATOMIC_SEQ_CST",
        r"&g_epoch_sequence,\s*__ATOMIC_SEQ_CST",
    )
    configure_start = source.find("int sflow_capture_configure(")
    configure_end = source.find(
        "void sflow_capture_handle_event(", configure_start
    )
    configure = (
        source[configure_start:configure_end]
        if configure_start >= 0 and configure_end > configure_start
        else ""
    )
    if (
        not all(re.search(pattern, source) for pattern in admission_patterns)
        or configure.find("&g_transition_mode, old_mode") < 0
        or configure.find("&g_transition_mode, old_mode") >
        configure.find("odd_sequence = epoch_transition_begin()")
    ):
        print(
            "FAIL: epoch admission lacks a sequentially consistent old-tuple "
            "barrier"
        )
        return False
    print("PASS: sFlow callback remains bounded and nonblocking")
    print("PASS: sFlow ring publication is fully ordered")
    print("PASS: sFlow epoch admission preserves the old tuple")
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
    if not CAPTURE.is_file() or not CAPTURE_HEADER.is_file():
        print("FAIL: switchd sFlow capture sources are missing")
        return 1
    if not check_source_boundary():
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
        "-pthread",
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
        print("FAIL: switchd sFlow Stage2 fixture builds")
        print(build.stdout)
        return 1
    print("PASS: switchd sFlow Stage2 fixture builds")

    run = subprocess.run(
        [str(BINARY)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=90,
        check=False,
    )
    print(run.stdout, end="")
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
