#!/usr/bin/env python3.11
# Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json.
"""Build and run the sliced optics mux executor fairness fixture."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
VENDOR_ROOT = Path(os.environ.get("NETLAB_VENDOR_ROOT", "/opt/netlab-vendor"))
SDK_TREE = os.environ.get(
    "NETLAB_SDK_TREE",
    "IES_SDK-4.3.2-20160607_6ports_15032017_14i_LINK_OPT_EEE_VRM",
)
IES_SDK = Path(os.environ.get("IES_SDK", VENDOR_ROOT / SDK_TREE / "ies"))
SOURCE = ROOT / "tests/integration/switchd_optics_executor_fairness_test.c"
BINARY = ROOT / "build/switchd_optics_executor_fairness_test"
RPC_SERVER = ROOT / "sbin/switchd/rpc_server.c"


def main() -> int:
    include_dirs = [
        ROOT / "include", ROOT.parents[1] / "hardware/native", IES_SDK / "include",
        IES_SDK / "include/platforms", IES_SDK / "include/alos",
        IES_SDK / "include/alos/linux", IES_SDK / "include/common",
        IES_SDK / "include/api", IES_SDK / "include/std/intel",
        IES_SDK / "include/platforms/libertyTrail",
        IES_SDK / "include/platforms/common",
        IES_SDK / "include/platforms/util/boardManager",
    ]
    command = [
        "cc", "-std=c99", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
        "-pedantic", "-ffunction-sections", "-fdata-sections",
        "-fvisibility=hidden", "-Wl,--gc-sections", "-pthread",
    ]
    for include_dir in include_dirs:
        command.extend(("-I", str(include_dir)))
    command.extend(("-o", str(BINARY), str(SOURCE), str(ROOT / "lib/libipc/port_scope.c")))
    BINARY.parent.mkdir(parents=True, exist_ok=True)
    built = subprocess.run(command, cwd=ROOT, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if built.returncode != 0:
        print("FAIL: optics executor fairness fixture builds")
        print(built.stdout, end="")
        return 1
    print("PASS: optics executor fairness fixture builds")
    run = subprocess.run([str(BINARY)], cwd=ROOT, text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         timeout=40)
    print(run.stdout, end="")
    if run.returncode != 0:
        return run.returncode
    rpc_source = RPC_SERVER.read_text(encoding="utf-8")
    exact_rpc = all(token in rpc_source for token in (
        "!result.data.optics_mux_probe.complete",
        "NL_ERR_SDK_CALL_FAILED",
        'complete=\\"true\\"',
        'generation=\\"%llu\\"',
        'sampled-monotonic-ms=\\"%llu\\"',
    ))
    print(("PASS" if exact_rpc else "FAIL") +
          ": optics RPC rejects partial results and publishes freshness")
    return 0 if exact_rpc else 1


if __name__ == "__main__":
    raise SystemExit(main())
