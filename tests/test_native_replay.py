import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux" or not Path("/opt/netlab-deps/libyang2/include/libyang").is_dir(),
                    reason="requires the isolated Debian libyang 2.x build environment")
def test_configd_l2_replay_without_rpd(tmp_path):
    root = Path(__file__).resolve().parents[1]
    netlab = root / "vendor/netlab"
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "libyang"], text=True))
    binary = tmp_path / "configd-replay-test"
    sources = [root / "tests/native_configd_replay_test.c", netlab / "sbin/configd/l3_client.c",
               netlab / "sbin/configd/public_capabilities.c", netlab / "lib/libconfig/yang_config.c"]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation", "-pedantic",
                    "-I", str(netlab / "include"), "-I", str(netlab / "sbin/configd"),
                    *map(str, sources), *flags, "-Wl,--gc-sections", "-o", str(binary)], check=True)
    subprocess.run([str(binary), str(tmp_path)], cwd=netlab,
                   env={**os.environ, "NETLAB_ROOT": str(netlab)}, check=True, timeout=30)
