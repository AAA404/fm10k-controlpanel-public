from pathlib import Path
from dataclasses import replace
import hashlib
import json
import re
import subprocess
import sys

import pytest

from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.platform_config import render_sdk_platform, render_netlab_profile
from fm10k_controlpanel.netlab_codec import decode_configuration
from fm10k_controlpanel.profiles import PROFILES
from platform_fixture import reference_text

ROOT = Path(__file__).resolve().parents[1]
BASE = reference_text("sil001-hw4-b0")


@pytest.fixture(autouse=True)
def synthetic_inputs(tmp_path, monkeypatch):
    for name, spec in tuple(PROFILES.items()):
        data = reference_text(name).encode()
        path = tmp_path / (name + ".cfg")
        path.write_bytes(data)
        monkeypatch.setitem(PROFILES, name, replace(
            spec, reference=str(path), sha256=hashlib.sha256(data).hexdigest()))


def test_fixed_boot_inventory_and_internal_ports_survive_mixed_modes():
    config = SwitchConfiguration()
    config.groups[0].mode = "split"
    config.groups[0].lane_speeds = (10, 25, 10, 25)
    config.groups[4].mode = "40g"
    sdk = render_sdk_platform(BASE, config)
    assert "switch.0.numPorts int 30" in sdk and "switch.0.cpuPort int 27" in sdk
    assert "portIndex.27.portMapping text \"LOG=27 PCIE=4\"" in sdk
    assert "portIndex.2.hwResourceId int 0x100" in sdk
    assert "portIndex.17.ethernetMode text 40GBase-SR4" in sdk
    assert "portIndex.18.ethernetMode text DISABLED" in sdk
    assert "portIndex.1.ethernetMode text 10GBase-SR" in sdk
    profile = render_netlab_profile(config, system_mac="02:10:84:00:00:01", serial="test-board")
    assert len(re.findall(r"^port .*role=external", profile, re.M)) == 24
    assert "port-index=27 logical-port=27" in profile
    assert "hw-resource-id=256 epl-port=0 lane=1" in profile
    # SerDes polarity is anchored at the representative of each physical EPL.
    assert "portIndex.5.lane.3.lanePolarity" in sdk
    assert "portIndex.6.lane.3.lanePolarity" not in sdk
    assert config.ports[1].enabled is False


def test_boot_generation_refuses_unknown_base_and_injection():
    with pytest.raises(ValueError):
        render_sdk_platform(BASE.replace("text sil001", "text sil006"), SwitchConfiguration())
    with pytest.raises(ValueError):
        render_netlab_profile(SwitchConfiguration(), system_mac="01:10:84:00:00:01", serial="x")
    with pytest.raises(ValueError):
        render_netlab_profile(SwitchConfiguration(), system_mac="02:10:84:00:00:01", serial="x\nboard")


@pytest.mark.parametrize("profile", PROFILES)
def test_profile_specific_serdes_and_link_optimization_survive_slot_expansion(profile):
    config = SwitchConfiguration(profile=profile)
    source = (ROOT / PROFILES[profile].reference).read_text()
    rendered = render_sdk_platform(source, config)
    assert rendered.splitlines().count("api.perLagManagement bool true") == 1
    assert re.findall(r"(?m)^api\.platform\.config\.switch\.0\.fci\s+text\s+(\w+)$", rendered) == ["off"]
    assert "sharedLibraryName text libLTStdPlatform.so" in rendered
    assert not re.search(r"^api\.(?:mailbox\.ignoreMbxMacUpdates|event\.countLogicalPortEvents)\s", rendered, re.M)
    # Hardware settings follow the physical EPL, including settings that differ
    # per Lane. Compare the complete active key/value set to the locked source.
    from fm10k_controlpanel.platform_config import PORT_VALUE
    def entries(text):
        return {(int(m[1]), m[2]): (m[3], m[4])
                for line in text.splitlines() if (m := PORT_VALUE.match(line))}
    before, after = entries(source), entries(rendered)
    for index in range(6):
        representative = 1 + 4 * index
        for (port, name), value in before.items():
            if port == index + 1 and ((name.startswith("lane.") and not name.endswith(".portMapping"))
                                     or name == "linkOptimMode"):
                assert after[representative, name] == value
        for lane in range(4):
            polarity = after[representative, f"lane.{lane}.lanePolarity"]
            if profile == "sil001-hw5-a11":
                assert polarity == ("text", "INVERT_NONE")
            else:
                assert polarity == before[index + 1, f"lane.{lane}.lanePolarity"]
    assert f"chassis-name={profile} " in render_netlab_profile(
        config, system_mac="02:10:84:00:00:01", serial="fixture")
    other = next(name for name in PROFILES if name != profile)
    with pytest.raises(ValueError, match="cannot be interchanged"):
        render_sdk_platform(source, SwitchConfiguration(profile=other))


@pytest.mark.parametrize("profile", PROFILES)
def test_boot_cli_locks_profile_to_snapshot_and_manifest(tmp_path, profile):
    command = [sys.executable, str(ROOT / "tests/platform_fixture.py"), str(tmp_path / "inputs"),
               "--system-mac", "02:10:84:00:00:01", "--serial", "fixture"]
    output = tmp_path / "boot"
    subprocess.run([*command, "--profile", profile, "--output", str(output)], check=True)
    snapshot = output / "active.conf"
    config = decode_configuration(snapshot.read_bytes())
    assert config.profile == profile and all(not p.enabled for p in config.ports.values())
    manifest = json.loads((output / "boot-manifest.json").read_text())
    assert manifest["profile"] == profile and manifest["reference_sha256"] == PROFILES[profile].sha256
    assert manifest["hardware_write_ready"] is False
    replay = tmp_path / "replay"
    subprocess.run([*command, "--active-xml", str(snapshot), "--output", str(replay)], check=True)
    assert (replay / "fm_platform_attributes.cfg").read_bytes() == (output / "fm_platform_attributes.cfg").read_bytes()
    wrong_profile = next(name for name in PROFILES if name != profile)
    rejected = tmp_path / "rejected"
    result = subprocess.run([*command, "--active-xml", str(snapshot), "--profile", wrong_profile,
                             "--output", str(rejected)], capture_output=True, text=True)
    assert result.returncode != 0 and "disagrees" in result.stderr and not rejected.exists()


def test_production_cli_requires_external_input(tmp_path):
    output = tmp_path / "missing-output"
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/generate_boot.py"),
        "--reference", str(tmp_path / "missing.cfg"), "--output", str(output),
        "--system-mac", "02:10:84:00:00:01", "--serial", "fixture",
    ], capture_output=True, text=True)
    assert result.returncode != 0 and "platform input is not bundled" in result.stderr
    assert not output.exists()


def test_production_cli_rejects_synthetic_input(tmp_path):
    source = tmp_path / "synthetic.cfg"
    source.write_text(BASE)
    output = tmp_path / "rejected-output"
    result = subprocess.run([
        sys.executable, str(ROOT / "scripts/generate_boot.py"),
        "--reference", str(source), "--output", str(output),
        "--system-mac", "02:10:84:00:00:01", "--serial", "fixture",
    ], capture_output=True, text=True)
    assert result.returncode != 0 and "digest does not match" in result.stderr
    assert not output.exists()
