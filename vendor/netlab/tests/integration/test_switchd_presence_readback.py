#!/usr/bin/env python3.11
# Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json.
"""Build and run VLAN/LAG presence and read-back fault injection."""

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
SOURCE = ROOT / "tests/integration/switchd_presence_readback_test.c"
BINARY = ROOT / "build/switchd_presence_readback_test"


def main() -> int:
    include_dirs = [
        ROOT / "include",
        IES_SDK / "include",
        IES_SDK / "include/platforms",
        IES_SDK / "include/alos",
        IES_SDK / "include/alos/linux",
        IES_SDK / "include/common",
        IES_SDK / "include/api",
        IES_SDK / "include/std/intel",
        IES_SDK / "include/platforms/libertyTrail",
        IES_SDK / "include/platforms/common",
        IES_SDK / "include/platforms/util/boardManager",
    ]
    command = [
        "cc",
        "-std=c99",
        "-D_GNU_SOURCE",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-ffunction-sections",
        "-fdata-sections",
        "-fvisibility=hidden",
        "-Wl,--gc-sections",
    ]
    for include_dir in include_dirs:
        command.extend(("-I", str(include_dir)))
    command.extend(("-o", str(BINARY), str(SOURCE)))
    BINARY.parent.mkdir(parents=True, exist_ok=True)

    built = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if built.returncode != 0:
        print("FAIL: VLAN/LAG presence fixture builds")
        print(built.stdout, end="")
        return 1
    print("PASS: VLAN/LAG presence fixture builds")

    try:
        run = subprocess.run(
            [str(BINARY)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        print("FAIL: presence readback did not return within the iterator deadline")
        return 1
    print(run.stdout, end="")
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
