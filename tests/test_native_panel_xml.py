import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

from fm10k_controlpanel.models import SwitchConfiguration, Vlan
from fm10k_controlpanel.netlab_codec import compile_configuration


@pytest.mark.skipif(sys.platform != "linux" or not Path("/opt/netlab-deps/libyang2/include/libyang").is_dir(),
                    reason="requires Debian libyang 2.x; no device is opened")
def test_web_xml_candidate_and_checkpoint_boundaries(tmp_path):
    root = Path(__file__).resolve().parents[1]
    netlab = root / "vendor/netlab"
    config = SwitchConfiguration(profile="sil001-hw5-a11")
    active = compile_configuration(config)
    config.vlans.append(Vlan(id=4033, name="panel XML verification"))
    target = compile_configuration(config)
    inputs = [active, target,
              target.replace(b"</netlab-config>", b"<system><host-name>forbidden</host-name></system></netlab-config>"),
              target.replace(b"</netlab-config>", b"<routing-options><autonomous-system>65000</autonomous-system></routing-options></netlab-config>"),
              target.replace(b"sil001-hw5-a11", b"sil001-hw4-b0"),
              compile_configuration(config, "1" * 32),
              target.replace(b"</netlab-config>", b"<unknown/></netlab-config>"),
              target + b"\x00extra"]
    paths = []
    for index, xml in enumerate(inputs):
        path = tmp_path / f"{index}.xml"
        path.write_bytes(xml)
        paths.append(str(path))
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "libyang"], text=True))
    binary = tmp_path / "panel-xml-test"
    sources = [root / "tests/native_panel_xml_test.c", netlab / "sbin/configd/public_capabilities.c",
               netlab / "lib/libconfig/yang_config.c"]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation", "-pedantic",
                    "-I", str(netlab / "include"), "-I", str(netlab / "sbin/configd"),
                    *map(str, sources), *flags, "-Wl,--gc-sections", "-o", str(binary)], check=True)
    subprocess.run([str(binary), *paths], env={**os.environ, "NETLAB_ROOT": str(netlab)}, check=True, timeout=30)
