import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux" or os.environ.get("FM10K_CHECK_NATIVE") != "1",
                    reason="requires Debian and pinned SDK headers; no ASIC is opened")
def test_static_mac_delete_and_final_readback_do_not_hide_errors(tmp_path):
    root = Path(__file__).resolve().parents[1]
    sdk = root / "hardware/sdk/ies/include"
    includes = [sdk / p for p in ("", "api", "common", "alos", "alos/linux", "std/intel",
                                  "platforms", "platforms/libertyTrail", "platforms/common",
                                  "platforms/util/boardManager")]
    binary = tmp_path / "mac-readback"
    sources = ["tests/native_mac_readback_test.c", "vendor/netlab/sbin/switchd/hal_port.c",
               "vendor/netlab/sbin/switchd/read_back_verifier.c"]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-pedantic",
                    *[v for p in includes for v in ("-I", str(p))],
                    "-I", str(root / "vendor/netlab/include"), "-I", str(root / "hardware/native"),
                    *(str(root / p) for p in sources), "-Wl,--gc-sections", "-pthread", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=15)
