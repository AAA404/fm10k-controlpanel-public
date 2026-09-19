#!/usr/bin/env python3.11
"""Build and run the switchd event-publisher lifecycle fixture."""

from __future__ import annotations

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
SOURCE = (
    ROOT / "tests" / "integration" /
    "switchd_event_publisher_lifecycle_test.c"
)
BINARY = ROOT / "build" / "switchd_event_publisher_lifecycle_test"


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
    switchd_main = (
        ROOT / "sbin" / "switchd" / "main.c"
    ).read_text(encoding="utf-8")
    failure_path = switchd_main.split(
        "if (sdk_event_publisher_start(state->ctx) != 0)", 1
    )[1].split("state->event_started = true;", 1)[0]
    if not all(marker in failure_path for marker in (
            "if (sdk_shutdown(state->ctx) == 0)",
            "state->ctx = NULL;",
            "retained SDK context after cleanup failure",
            "return -1;")):
        print(
            "FAIL: switchd init failure must clean SDK without on_shutdown")
        return 1
    print("PASS: switchd init failure cleans SDK without on_shutdown")

    BINARY.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "cc",
        "-std=c99",
        "-D_GNU_SOURCE",
        "-Wall",
        "-Werror",
        "-Wextra",
        "-pedantic",
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
        print("FAIL: switchd event-publisher lifecycle fixture builds")
        print(build.stdout)
        return 1
    print("PASS: switchd event-publisher lifecycle fixture builds")

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
