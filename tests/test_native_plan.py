import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab_codec import compile_configuration
from fm10k_controlpanel.profiles import PROFILES


@pytest.mark.skipif(sys.platform != "linux" or not Path("/opt/netlab-deps/libyang2/include/libyang").is_dir(),
                    reason="requires the isolated Debian libyang 2.x build environment")
def test_native_lag_probe_authority(tmp_path):
    root = Path(__file__).resolve().parents[1]
    netlab = root / "vendor/netlab"
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "libyang"], text=True))
    binary = tmp_path / "lag-probe-test"
    sources = [root / "tests/native_lag_probe_test.c", netlab / "sbin/l2d/l2_intent.c",
               netlab / "lib/libipc/stp_snapshot.c"]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation", "-pedantic",
                    "-I", str(netlab / "include"), "-I", str(netlab / "sbin/l2d"),
                    *map(str, sources), *flags, "-Wl,--gc-sections", "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


@pytest.mark.skipif(sys.platform != "linux" or not Path("/opt/netlab-deps/libyang2/include/libyang").is_dir(),
                    reason="requires the isolated Debian libyang 2.x build environment")
@pytest.mark.parametrize("profile", PROFILES)
def test_native_board_yang_plan_and_replay(tmp_path, profile):
    root = Path(__file__).resolve().parents[1]
    netlab = root / "vendor/netlab"
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "libyang"], text=True))
    binary = tmp_path / "board-plan-test"
    config = tmp_path / "candidate.xml"
    config.write_bytes(compile_configuration(SwitchConfiguration(profile=profile)))
    sources = [root / "tests/native_board_plan_test.c", netlab / "lib/libconfig/yang_config.c",
               netlab / "sbin/l2d/l2_fm10k.c", netlab / "sbin/l2d/l2_intent.c",
               netlab / "sbin/l2d/l2_plan_text.c", netlab / "sbin/switchd/l2_plan_parser.c",
               netlab / "sbin/switchd/l2_plan_storage.c"]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation", "-pedantic",
                    "-I", str(netlab / "include"), "-I", str(netlab / "sbin/l2d"),
                    *map(str, sources), *flags, "-Wl,--gc-sections", "-o", str(binary)], check=True)
    subprocess.run([str(binary), str(config)], env={**os.environ, "NETLAB_ROOT": str(netlab)}, check=True)



_l2_pipeline_fixture = None


def build_l2_pipeline_fixture(tmp_path):
    # Profiles and configurations are runtime inputs to the same executable.
    # Keep one compile per pytest process; repeated builds dominate on-board CPU time.
    global _l2_pipeline_fixture
    if _l2_pipeline_fixture is not None and _l2_pipeline_fixture[2].is_file():
        return _l2_pipeline_fixture
    root = Path(__file__).resolve().parents[1]
    netlab = root / "vendor/netlab"
    flags = shlex.split(subprocess.check_output(["pkg-config", "--cflags", "--libs", "libyang"], text=True))
    binary = tmp_path / "l2-pipeline-test"
    sources = [root / "tests/native_l2_pipeline_test.c"]
    sources += [netlab / "sbin/l2d" / name for name in (
        "l2_plan.c", "l2_fm10k.c", "l2_intent.c", "l2_validate.c", "l2_hw_probe.c", "l2_plan_text.c", "igmp_snooping.c", "igmp_state.c")]
    sources += [netlab / name for name in (
        "lib/libconfig/yang_config.c", "lib/libconfig/interface_id.c", "lib/libipc/stp_snapshot.c", "lib/libipc/mac_snapshot.c",
        "sbin/switchd/l2_plan_parser.c", "sbin/switchd/l2_plan_storage.c")]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-O1", "-ffunction-sections", "-fdata-sections",
                    "-Wall", "-Wextra", "-Werror", "-Wno-error=format-truncation", "-pedantic",
                    "-I", str(netlab / "include"), "-I", str(netlab / "sbin/l2d"),
                    *map(str, sources), *flags, "-Wl,--gc-sections", "-pthread", "-o", str(binary)], check=True)
    _l2_pipeline_fixture = root, netlab, binary
    return _l2_pipeline_fixture


@pytest.mark.skipif(sys.platform != "linux" or not Path("/opt/netlab-deps/libyang2/include/libyang").is_dir(),
                    reason="requires the isolated Debian libyang 2.x build environment")
def test_native_dscp_cnp_dcbx_plan_and_exact_disable(tmp_path):
    from test_rdma_extensions import extended
    from fm10k_controlpanel.platform_config import render_netlab_profile
    _, netlab, binary = build_l2_pipeline_fixture(tmp_path)
    after = extended()
    after.qos.roce.watchdog.enabled = True
    before = after.model_copy(deep=True)
    before.qos.roce.enabled = False
    profile = tmp_path / "platform.profile"
    profile.write_text(render_netlab_profile(before, system_mac="02:00:00:00:00:01", serial="fixture"))
    env = {**os.environ, "NETLAB_ROOT":str(netlab), "NETLAB_PLATFORM_PROFILE":str(profile)}
    for a, b, enabled in ((before,after,True),(after,before,False)):
        old, new = tmp_path / "old.xml", tmp_path / "new.xml"
        old.write_bytes(compile_configuration(a)); new.write_bytes(compile_configuration(b))
        result = subprocess.run([str(binary), str(old), str(new)], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stdout.startswith("# fm10k-scope-v1 mask=ffffff\n")
        assert f"qos-dscp-set dscp=26 priority={3 if enabled else 0}" in result.stdout
        assert f"qos-dscp-set dscp=48 priority={6 if enabled else 0}" in result.stdout
        assert f"qos-interface-set port=13 trust={2 if enabled else 0}" in result.stdout
        assert "qos-scheduler-group-set port=13" in result.stdout
        if enabled:
            assert "watchdog-detect-ms=5000 watchdog-recovery-ms=100 watchdog-cooldown-ms=30000" in result.stdout
        else:
            assert "qos-pfc-del port=13" in result.stdout


@pytest.mark.skipif(sys.platform != "linux" or not Path("/opt/netlab-deps/libyang2/include/libyang").is_dir(),
                    reason="requires the isolated Debian libyang 2.x build environment")
def test_egress_limiter_and_scheduler_share_no_mapping_owner(tmp_path):
    from fm10k_controlpanel.platform_config import render_netlab_profile
    _, netlab, binary = build_l2_pipeline_fixture(tmp_path)
    base = SwitchConfiguration(profile="sil001-hw5-a11")
    base.ports[1].pvid = 1
    base.ports[1].enabled = True
    limited = base.model_copy(deep=True)
    limited.ports[1].egress_kbps = 1_000_000
    limited.qos.scheduler = 'strict'
    profile = tmp_path / 'platform.profile'
    profile.write_text(render_netlab_profile(base, system_mac='02:00:00:00:00:01', serial='fixture'))
    env = {**os.environ, 'NETLAB_ROOT':str(netlab), 'NETLAB_PLATFORM_PROFILE':str(profile)}
    for old, new, setting in [(base, limited, True), (limited, base, False)]:
        old_path, new_path = tmp_path/'old.xml', tmp_path/'new.xml'
        old_path.write_bytes(compile_configuration(old))
        new_path.write_bytes(compile_configuration(new))
        result = subprocess.run([str(binary), str(old_path), str(new_path)], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        text = result.stdout
        assert ('egress-rate-limit-set port=1' if setting else 'egress-rate-limit-del port=1') in text
        if setting:
            assert 'qos-scheduler-tc-map-set port=1 ' not in text
            assert 'qos-scheduler-group-set port=1 ' in text
        else:
            assert text.index('egress-rate-limit-del port=1') < text.index('qos-scheduler-tc-map-set port=1 ')


@pytest.mark.skipif(sys.platform != "linux" or not Path("/opt/netlab-deps/libyang2/include/libyang").is_dir(),
                    reason="requires the isolated Debian libyang 2.x build environment")
def test_recovery_skips_removed_lag_only_after_complete_absence_readback(tmp_path):
    from fm10k_controlpanel.models import Lag
    from fm10k_controlpanel.platform_config import render_netlab_profile
    _, netlab, binary = build_l2_pipeline_fixture(tmp_path)
    base = SwitchConfiguration(profile="sil001-hw5-a11")
    for port in (1, 5): base.ports[port].pvid = 1
    old = base.model_copy(deep=True)
    old.lags = [Lag(name='ae0', members=[1,5], mode='passive')]
    profile = tmp_path/'platform.profile'
    profile.write_text(render_netlab_profile(base, system_mac='02:00:00:00:00:01', serial='fixture'))
    a, b = tmp_path/'old.xml', tmp_path/'new.xml'
    a.write_bytes(compile_configuration(old)); b.write_bytes(compile_configuration(base))
    env = {**os.environ, 'NETLAB_ROOT':str(netlab), 'NETLAB_PLATFORM_PROFILE':str(profile)}
    for absent in (False, True):
        controlled = dict(env)
        controlled.pop('NETLAB_TEST_EMPTY_LAGS', None)
        if absent: controlled['NETLAB_TEST_EMPTY_LAGS'] = '1'
        result = subprocess.run([str(binary),str(a),str(b)],env=controlled,capture_output=True,text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'port-set-mtu ae=0' not in result.stdout
        for command in ('lag-del-port ae=0', 'vlan-rem-port vid=1 ae=0', 'lag-delete ae=0'):
            assert (command in result.stdout) == (not absent), (command, result.stdout)


@pytest.mark.skipif(sys.platform != "linux" or not Path("/opt/netlab-deps/libyang2/include/libyang").is_dir(),
                    reason="requires the isolated Debian libyang 2.x build environment")
@pytest.mark.parametrize("profile_name", PROFILES)
def test_native_lag_classifier_and_recovery(tmp_path, profile_name):
    from xml.etree import ElementTree as ET
    from fm10k_controlpanel.models import Lag, StaticMac
    from fm10k_controlpanel.platform_config import render_netlab_profile
    _, netlab, binary = build_l2_pipeline_fixture(tmp_path)
    base = SwitchConfiguration(profile=profile_name)
    for port in (1, 5):
        base.ports[port].pvid = 1
        base.ports[port].mtu = 9000
    configured = base.model_copy(deep=True)
    configured.lags = [Lag(name="ae0", members=[1, 5], mode="passive")]
    configured.static_macs = [StaticMac(mac="02:00:00:00:01:01", vlan=1, port=1)]
    profile = tmp_path / "platform.profile"
    profile.write_text(render_netlab_profile(base, system_mac="02:00:00:00:00:01", serial="fixture"))
    env = {**os.environ, "NETLAB_ROOT": str(netlab), "NETLAB_PLATFORM_PROFILE": str(profile)}

    def plan(before, after, *, cold=False, success=True):
        old, new = tmp_path / "old.xml", tmp_path / "new.xml"
        old.write_bytes(before if isinstance(before, bytes) else compile_configuration(before))
        new.write_bytes(after if isinstance(after, bytes) else compile_configuration(after))
        controlled = dict(env)
        controlled.pop("NETLAB_TEST_EMPTY_LAGS", None)
        if cold:
            controlled["NETLAB_TEST_EMPTY_LAGS"] = "1"
        result = subprocess.run([str(binary), str(old), str(new)], env=controlled, capture_output=True, text=True)
        assert (result.returncode == 0) == success, result.stdout + result.stderr
        return result.stdout + result.stderr

    text = plan(base, configured)
    assert "qos-interface-set ae=0 trust=0 default-priority=0" in text
    assert "qos-interface-del port=1\n" not in text and "qos-interface-del port=5\n" not in text
    assert "qos-interface-set port=1 " not in text and "qos-interface-set port=5 " not in text
    assert text.count("qos-interface-set ae=0 ") == 1
    text = plan(configured, configured, cold=True)
    for command in ("port-set-mtu ae=0 mtu=9000", "qos-interface-set ae=0 trust=0 default-priority=0",
                    "static-mac-add vid=1 mac=02:00:00:00:01:01 ae=0"):
        assert command in text, text
        assert text.index("lag-create ae=0") < text.index(command)
    assert "lag-add-port" not in text  # lacpd still owns member selection.
    assert "qos-interface-set port=9 " not in text
    changed = configured.model_copy(deep=True)
    changed.qos.trust = "ieee-802.1p"
    changed.qos.default_priority = 3
    for port in (1, 5):
        changed.ports[port].mtu = 8000
    text = plan(configured, changed)
    assert "qos-interface-set ae=0 trust=1 default-priority=3" in text
    assert "port-set-mtu ae=0 mtu=8000" in text
    assert "port-set-mtu port=1 " not in text and "port-set-mtu port=5 " not in text
    text = plan(configured, base)
    assert "qos-interface-del ae=0" not in text
    for port in (1, 5):
        assert f"qos-interface-set port={port} trust=0 default-priority=0" in text
        assert f"port-set-mtu port={port} mtu=9000" in text
        assert text.index(f"lag-del-port ae=0 port={port}") < text.index(f"port-set-mtu port={port}")

    # Check native candidates which do not come from the global Web classifier.
    root = ET.fromstring(compile_configuration(configured))
    ns = {"n": root.tag.split("}")[0][1:]}
    entries = root.findall("n:class-of-service/n:interfaces/n:interface", ns)
    entries[1].find("n:trust", ns).text = "ieee-802.1p"  # P5 with default 100G groups.
    inconsistent = ET.tostring(root)
    assert "identical QoS classifier" in plan(configured, inconsistent, success=False)
    plan(inconsistent, configured)  # An older inconsistent source can be repaired.

@pytest.mark.skipif(sys.platform != "linux" or not Path("/opt/netlab-deps/libyang2/include/libyang").is_dir(),
                    reason="requires the isolated Debian libyang 2.x build environment")
@pytest.mark.parametrize("profile_name", PROFILES)
def test_native_complete_l2_pipeline(tmp_path, profile_name):
    from lacp_cases import lacp_configuration_cases
    from fm10k_controlpanel.platform_config import render_netlab_profile
    root, netlab, binary = build_l2_pipeline_fixture(tmp_path)
    initial = SwitchConfiguration(profile=profile_name)
    profile = tmp_path / "platform.profile"
    profile.write_text(render_netlab_profile(initial, system_mac="02:00:00:00:00:01", serial="fixture"))
    env = {**os.environ, "NETLAB_ROOT": str(netlab), "NETLAB_PLATFORM_PROFILE": str(profile)}
    def plan(before, after):
        old, new = tmp_path / "active.xml", tmp_path / "candidate.xml"
        old.write_bytes(before if isinstance(before, bytes) else compile_configuration(before))
        new.write_bytes(after if isinstance(after, bytes) else compile_configuration(after))
        result = subprocess.run([str(binary), str(old), str(new)], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr + result.stdout
        return result.stdout
    assert "port-set-speed" not in plan(initial, initial)
    raw = initial.model_dump()
    raw["ports"][1].update(pvid=1, enabled=True)
    configured = SwitchConfiguration.model_validate(raw)
    assert "pvid-set port=1 vid=1" in plan(initial, configured)
    assert "port-ingress-filter-set port=1 enabled=1" in plan(initial, configured)
    unfiltered = configured.model_copy(deep=True)
    unfiltered.ports[1].ingress_filtering = False
    assert plan(configured, unfiltered) == "# fm10k-scope-v1 mask=000001\nport-ingress-filter-set port=1 enabled=0\n"
    assert "port-ingress-filter-set port=1 enabled=1" in plan(unfiltered, configured)
    raw["groups"][0].update(mode="split", lane_speeds=[10, 25, 10, 25])
    split = SwitchConfiguration.model_validate(raw)
    text = plan(configured, split)
    # Changing speed/MTU recalculates watermarks across the whole chip.
    assert text.startswith("# fm10k-scope-v1 mask=ffffff\n"), text
    assert text.count("fm10k-group-set epl=0 ") == 3
    assert "fm10k-group-set epl=1 " not in text and "port-set-speed" not in text
    assert text.index("enabled=0") < text.index("mode=0 lane0=10 lane1=25 lane2=10 lane3=25")
    assert text.rfind("fm10k-group-set epl=0") > text.index("port-set-mtu port=1")
    for mode in ("100g", "40g"):
        raw["groups"][0]["mode"] = mode
        target = SwitchConfiguration.model_validate(raw)
        assert "port-set-speed" not in plan(split, target)
    for mode in ("active", "passive", "static"):
        raw = configured.model_dump()
        raw["ports"][5].update(pvid=1, enabled=True)
        raw["lags"] = [{"name": "ae0", "members": [1, 5], "mode": mode}]
        target = SwitchConfiguration.model_validate(raw)
        text = plan(configured, target)
        assert "lag-create ae=0" in text
        assert "lag-add-port" not in text
        assert "vlan-rem-port vid=1 port=1" in text
        assert "vlan-add-port vid=1 ae=0" in text
        assert "stp-set vid=1 ae=0 state=4" in text
        assert "port-ingress-filter-set port=1 enabled=1" in text
        assert "port-ingress-filter-set ae=0 enabled=1" in text
        assert "port-set-mtu ae=0" in text
        assert text.startswith("# fm10k-scope-v1 mask=ffffff\n"), text
        unfiltered_lag = target.model_copy(deep=True)
        for port in (1, 5):
            unfiltered_lag.ports[port].ingress_filtering = False
        assert plan(target, unfiltered_lag) == "# fm10k-scope-v1 mask=000011\nport-ingress-filter-set ae=0 enabled=0\n"
        # Renegotiation restores a filtered physical baseline even when the
        # aggregate accepts frames from VLANs outside its member set.
        changed = unfiltered_lag.model_copy(deep=True)
        changed.lags[0].minimum_links = 2
        text = plan(unfiltered_lag, changed)
        assert "port-ingress-filter-set port=1 enabled=1" in text
        assert "port-ingress-filter-set port=5 enabled=1" in text
        assert "port-ingress-filter-set ae=0" not in text
    _, baseline, cases = lacp_configuration_cases(profile_name)
    for name, (candidate, groups) in cases.items():
        text = plan(baseline, candidate)
        expected = {f"lag-del-port ae={ae} port={port}" for ae in groups for port in (1 + ae * 8, 5 + ae * 8)}
        actual = {line for line in text.splitlines() if line.startswith("lag-del-port ")}
        assert actual == expected, (name, text)
        assert "lag-add-port" not in text, (name, text)
        if groups:
            # Releasing members reapplies their MTU, which recalculates the
            # shared watermarks even though only these LAGs renegotiate.
            assert "port-set-mtu port=" in text, (name, text)
            assert text.startswith("# fm10k-scope-v1 mask=ffffff\n"), (name, text)
    mismatch = initial.model_copy(deep=True)
    mismatch.profile = next(name for name in PROFILES if name != profile_name)
    old, new = tmp_path / "active.xml", tmp_path / "candidate.xml"
    old.write_bytes(compile_configuration(initial))
    new.write_bytes(compile_configuration(mismatch))
    result = subprocess.run([str(binary), str(old), str(new)], env=env, capture_output=True, text=True)
    assert result.returncode != 0 and "profile" in (result.stderr + result.stdout).lower()
