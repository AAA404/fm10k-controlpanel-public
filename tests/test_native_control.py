import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux" or os.environ.get("FM10K_CHECK_NATIVE") != "1",
                    reason="requires Debian and the pinned SDK headers; no device is opened")
def test_native_replay_readiness_and_private_binding(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sdk = root / "hardware/sdk/ies/include"
    includes = [sdk / p for p in ("", "api", "common", "alos", "alos/linux", "std/intel",
                                  "platforms", "platforms/libertyTrail", "platforms/common",
                                  "platforms/util/boardManager")]
    flags = [v for p in includes for v in ("-I", str(p))]
    common = ["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
              "-Wall", "-Wextra", "-Werror", "-pedantic", *flags,
              "-I", str(root / "hardware/native"), "-I", str(root / "vendor/netlab/include")]
    cases = {
        "lifecycle": ["tests/native_lifecycle_test.c", "hardware/native/fm10k_board.c", "vendor/netlab/lib/libipc/port_scope.c"],
        "client": ["tests/native_runtime_client_test.c", "vendor/netlab/lib/libipc/ipc_contract.c"],
    }
    for name, sources in cases.items():
        binary = tmp_path / name
        subprocess.run([*common, *(str(root / p) for p in sources), "-Wl,--gc-sections", "-pthread", "-lm", "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)


@pytest.mark.skipif(sys.platform != "linux", reason="uses Linux RPC transport primitives")
def test_rpc_binary_capacity_and_empty_acknowledgement(tmp_path):
    root = Path(__file__).resolve().parents[1]
    binary = tmp_path / "rpc-buffers"
    sources = ["tests/native_rpc_buffer_test.c", "vendor/netlab/lib/libipc/rpc_client.c",
               "vendor/netlab/lib/libipc/ipc_contract.c"]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-pedantic", "-I", str(root / "vendor/netlab/include"),
                    *(str(root / p) for p in sources), "-Wl,--gc-sections", "-pthread", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=15)
