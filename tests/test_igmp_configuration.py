import os
from pathlib import Path
import subprocess
import sys

import pytest

from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab_codec import compile_configuration
from fm10k_controlpanel.platform_config import render_netlab_profile


def configuration():
    raw = SwitchConfiguration(profile="sil001-hw5-a11").model_dump()
    for p in (1, 5, 9):
        raw["ports"][p].update(pvid=1, enabled=True)
    raw["igmp"].update(enabled=True, vlans=[1], router_ports=[5],
                       static_groups=[{"vlan": 1, "address": "239.1.1.1", "ports": [1]}])
    return SwitchConfiguration.model_validate(raw)


def test_igmp_router_vlan_and_expanded_capacity():
    raw = configuration().model_dump()
    raw["ports"][5]["pvid"] = None
    raw["ports"][5]["enabled"] = False
    with pytest.raises(ValueError, match="至少一个侦听 VLAN"):
        SwitchConfiguration.model_validate(raw)
    raw = configuration().model_dump()
    raw["igmp"]["static_groups"] *= 2
    with pytest.raises(ValueError, match="条目重复"):
        SwitchConfiguration.model_validate(raw)
    raw["igmp"]["static_groups"] = [
        {"vlan": 1, "address": f"239.1.1.{i}", "ports": [1]} for i in range(1, 18)]
    with pytest.raises(ValueError, match="32"):
        SwitchConfiguration.model_validate(raw)


@pytest.mark.skipif(sys.platform != "linux" or not Path("/opt/netlab-deps/libyang2/include/libyang").is_dir(),
                    reason="requires Debian libyang 2.x")
def test_igmp_router_uses_production_transaction_plan(tmp_path):
    from test_native_plan import build_l2_pipeline_fixture
    _, netlab, binary = build_l2_pipeline_fixture(tmp_path)
    baseline = configuration()
    profile = tmp_path / "platform.profile"
    profile.write_text(render_netlab_profile(baseline, system_mac="02:00:00:00:00:01", serial="fixture"))
    env = {**os.environ, "NETLAB_ROOT": str(netlab), "NETLAB_PLATFORM_PROFILE": str(profile)}
    old, new = tmp_path / "active.xml", tmp_path / "candidate.xml"
    before = baseline.model_copy(deep=True)
    before.igmp.enabled = False
    old.write_bytes(compile_configuration(before))
    new.write_bytes(compile_configuration(baseline))
    result = subprocess.run([str(binary), str(old), str(new)], env=env, text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "igmp-listener-set vid=1 port=1 group=239.1.1.1" in result.stdout
    assert "igmp-listener-set vid=1 port=5 group=239.1.1.1" in result.stdout
    old.write_bytes(compile_configuration(baseline))
    moved = baseline.model_copy(deep=True)
    moved.igmp.router_ports = [9]
    new.write_bytes(compile_configuration(moved))
    result = subprocess.run([str(binary), str(old), str(new)], env=env, text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "igmp-listener-del vid=1 port=5 group=239.1.1.1" in result.stdout
    assert "igmp-listener-set vid=1 port=9 group=239.1.1.1" in result.stdout
    assert "port=1 group=239.1.1.1" not in result.stdout
