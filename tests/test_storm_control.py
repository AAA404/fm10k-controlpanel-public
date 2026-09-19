import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

from fm10k_controlpanel.models import SwitchConfiguration, StormControl, PortConfig
from fm10k_controlpanel.netlab_codec import compile_configuration, parse_xml
from fm10k_controlpanel.platform_config import render_netlab_profile
from fm10k_controlpanel.profiles import PROFILES


def test_storm_model_rate_capacity_and_native_projection():
    for field in StormControl.model_fields:
        for invalid in (1, 21999):
            with pytest.raises(ValueError, match="22000"):
                StormControl(**{field: invalid})
        assert getattr(StormControl(**{field: 22000}), field) == 22000
    with pytest.raises(ValueError, match="22000"):
        PortConfig(ingress_kbps=1)
    raw = SwitchConfiguration().model_dump()
    for port in (1, 5, 9, 13, 17):
        raw["ports"][port]["storm"] = dict(broadcast_kbps=22000, multicast_kbps=200000, unknown_unicast_kbps=300000)
    raw["ports"][21]["ingress_kbps"] = 22000
    config = SwitchConfiguration.model_validate(raw)
    xml = parse_xml(compile_configuration(config))
    board = xml.find("./interfaces/interface/fm10k-port")
    assert [board.findtext(name) for name in ("broadcast-kbps", "multicast-kbps", "unknown-unicast-kbps")] == ["22000", "200000", "300000"]
    raw["ports"][21]["storm"]["broadcast_kbps"] = 22000
    with pytest.raises(ValueError, match="17.*16"):
        SwitchConfiguration.model_validate(raw)


@pytest.mark.skipif(sys.platform != "linux" or not Path("/opt/netlab-deps/libyang2/include/libyang").is_dir(),
                    reason="requires the isolated Debian libyang 2.x build environment")
@pytest.mark.parametrize("profile_name", PROFILES)
def test_native_typed_storm_planner(tmp_path, profile_name):
    from test_native_plan import build_l2_pipeline_fixture
    _, netlab, binary = build_l2_pipeline_fixture(tmp_path)
    initial = SwitchConfiguration(profile=profile_name)
    profile = tmp_path / "platform.profile"
    profile.write_text(render_netlab_profile(initial, system_mac="02:00:00:00:00:01", serial="fixture"))
    env = {**os.environ, "NETLAB_ROOT": str(netlab), "NETLAB_PLATFORM_PROFILE": str(profile)}

    def plan(before, after, error=None):
        paths = [tmp_path / "active.xml", tmp_path / "candidate.xml"]
        for path, value in zip(paths, (before, after)):
            path.write_bytes(value if isinstance(value, bytes) else compile_configuration(value))
        result = subprocess.run([str(binary), *map(str, paths)], env=env, capture_output=True, text=True, timeout=20)
        if error:
            assert result.returncode == 1 and error in result.stderr, result.stderr
        else:
            assert result.returncode == 0, result.stderr
        return result.stdout

    target = initial.model_copy(deep=True)
    target.ports[1].storm = StormControl(broadcast_kbps=22000, multicast_kbps=200000, unknown_unicast_kbps=300000)
    text = plan(initial, target)
    assert text.startswith("# fm10k-scope-v1 mask=000001\n")
    assert text.count("storm-control-set") == 3
    for kind, rate in (("broadcast", 22000), ("multicast", 200000), ("unknown-unicast", 300000)):
        assert f"storm-control-set port=1 rate={rate} burst=65536 kind={kind}\n" in text
    assert not plan(target, target)
    changed = target.model_copy(deep=True)
    changed.ports[1].storm.broadcast_kbps = 100000
    text = plan(target, changed)
    assert text.count("storm-control-") == 2 and "kind=multicast" not in text and "kind=unknown-unicast" not in text
    assert "storm-control-del port=1 kind=broadcast\n" in text
    removed = changed.model_copy(deep=True)
    removed.ports[1].storm.multicast_kbps = 0
    assert plan(changed, removed).endswith("storm-control-del port=1 kind=multicast\n")

    # Bypass the Web model to check the independent native capacity guard.
    all_policies = initial.model_copy(deep=True)
    for port in (1, 5, 9, 13, 17):
        all_policies.ports[port].storm = target.ports[1].storm.model_copy()
    all_policies.ports[21].ingress_kbps = 22000
    root = ET.fromstring(compile_configuration(all_policies))
    ns = {"n": "urn:netlab:config"}
    for node in root.findall("n:interfaces/n:interface", ns):
        if node.findtext("n:name", namespaces=ns) == "et-0/0/20":
            node.find("n:fm10k-port/n:broadcast-kbps", ns).text = "22000"
    plan(initial, ET.tostring(root), error="use 17 controllers")
    root = ET.fromstring(compile_configuration(target))
    eso = root.find("n:ethernet-switching-options", ns)
    legacy = ET.SubElement(ET.SubElement(eso, "{urn:netlab:config}storm-control"), "{urn:netlab:config}interface")
    ET.SubElement(legacy, "{urn:netlab:config}name").text = "et-0/0/0"
    ET.SubElement(legacy, "{urn:netlab:config}bandwidth").text = "22000"
    plan(initial, ET.tostring(root), error="overlapping storm-control")
