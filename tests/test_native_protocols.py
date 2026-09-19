import os
from pathlib import Path
import subprocess
import sys

import pytest

from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab_codec import compile_configuration
from fm10k_controlpanel.platform_config import render_netlab_profile

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(sys.platform != "linux", reason="production daemons target Linux")
@pytest.mark.parametrize("minimum_bytes", [0, 65535, 65536, 66522, 262144])
def test_production_lacp_configuration_reload(tmp_path, minimum_bytes):
    from lacp_cases import lacp_configuration_cases
    netlab = ROOT / "vendor/netlab"
    binary = tmp_path / "lacp-reload-test"
    sources = [ROOT / "tests/native_lacp_reload_test.c"] + [netlab / name for name in (
        "sbin/lacpd/lacp_wire.c", "sbin/lacpd/lacp_config.c", "lib/libconfig/interface_id.c",
        "lib/libipc/port_scope.c")]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation", "-pedantic",
                    "-I", str(netlab / "include"), *map(str, sources),
                    "-Wl,--gc-sections", "-pthread", "-o", str(binary)], check=True)
    config, baseline, cases = lacp_configuration_cases()
    def sized(xml):
        # Large, valid documents must reload with identical LACP semantics.
        if minimum_bytes > len(xml):
            xml += b" " * (minimum_bytes - len(xml))
        return xml
    profile = tmp_path / "platform.profile"
    profile.write_text(render_netlab_profile(config, system_mac="02:00:00:00:00:01", serial="fixture"))
    active = tmp_path / "active.xml"
    active.write_bytes(sized(baseline))
    for name, (candidate, groups) in cases.items():
        path = tmp_path / (name + ".xml")
        path.write_bytes(sized(candidate))
        subprocess.run([str(binary), str(active), str(path), f"{sum(1 << ae for ae in groups):x}"],
                       check=True, timeout=20, env={**os.environ, "NETLAB_PLATFORM_PROFILE": str(profile),
                                                  "NETLAB_FM10K_NATIVE": "0"})


@pytest.mark.skipif(sys.platform != "linux", reason="production daemons target Linux")
def test_production_lacp_negotiation_and_scope(tmp_path):
    netlab = ROOT / "vendor/netlab"
    binary = tmp_path / "lacp-runtime-test"
    sources = [ROOT / "tests/native_lacp_runtime_test.c"] + [netlab / name for name in (
        "sbin/lacpd/lacp_wire.c", "sbin/lacpd/lacp_config.c",
        "lib/libconfig/interface_id.c", "lib/libipc/port_scope.c")]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation", "-pedantic",
                    "-I", str(netlab / "include"), *map(str, sources),
                    "-Wl,--gc-sections", "-pthread", "-o", str(binary)], check=True)
    paths = []
    for mode in ("active", "passive", "static"):
        raw = SwitchConfiguration().model_dump()
        for port in (1, 5):
            raw["ports"][port].update(enabled=True, pvid=1)
        raw["lags"] = [{"name": "ae0", "mode": mode, "members": [1, 5], "minimum_links": 2}]
        config = SwitchConfiguration.model_validate(raw)
        path = tmp_path / (mode + ".xml")
        path.write_bytes(compile_configuration(config)); paths.append(str(path))
    profile = tmp_path / "platform.profile"
    profile.write_text(render_netlab_profile(config, system_mac="02:00:00:00:00:01", serial="fixture"))
    subprocess.run([str(binary), *paths], check=True, timeout=20,
                   env={**os.environ, "NETLAB_PLATFORM_PROFILE": str(profile), "NETLAB_FM10K_NATIVE": "0"})


@pytest.mark.skipif(sys.platform != "linux", reason="production daemons target Linux")
def test_production_rstp_transitions_and_lag_mapping(tmp_path):
    netlab = ROOT / "vendor/netlab"
    binary = tmp_path / "stp-runtime-test"
    sources = [ROOT / "tests/native_stp_runtime_test.c"] + [netlab / name for name in (
        "sbin/stpd/stp_wire.c", "sbin/stpd/stp_lag.c", "sbin/stpd/stp_config_text.c",
        "lib/libconfig/interface_id.c", "lib/libipc/port_scope.c")]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation", "-pedantic",
                    "-I", str(netlab / "include"), *map(str, sources),
                    "-Wl,--gc-sections", "-pthread", "-lcrypto", "-o", str(binary)], check=True)
    raw = SwitchConfiguration().model_dump()
    for port in (1, 5):
        raw["ports"][port].update(enabled=True, pvid=1)
    config = SwitchConfiguration.model_validate(raw)
    active = tmp_path / "active.xml"
    active.write_bytes(compile_configuration(config))
    profile = tmp_path / "platform.profile"
    profile.write_text(render_netlab_profile(config, system_mac="02:00:00:00:00:01", serial="fixture"))
    subprocess.run([str(binary), str(active)], check=True, timeout=20,
                   env={**os.environ, "NETLAB_PLATFORM_PROFILE": str(profile), "NETLAB_FM10K_NATIVE": "0"})
