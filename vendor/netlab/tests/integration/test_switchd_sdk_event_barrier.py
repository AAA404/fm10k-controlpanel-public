#!/usr/bin/env python3.11
"""Build and run the FM10840 SDK event-barrier regression fixture."""

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
SOURCE = ROOT / "tests" / "integration" / "switchd_sdk_event_barrier_test.c"
BINARY = ROOT / "build" / "switchd_sdk_event_barrier_test"


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
    BINARY.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "cc",
        "-std=c99",
        "-D_GNU_SOURCE",
        "-Wall",
        "-Wextra",
        "-Werror",
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
        print("FAIL: SDK event-barrier fixture builds")
        print(build.stdout)
        return 1
    print("PASS: SDK event-barrier fixture builds")
    run = subprocess.run(
        [str(BINARY)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    print(run.stdout, end="")
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
