import copy
import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest
from pydantic import ValidationError

from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab_codec import compile_configuration, decode_configuration, parse_xml
from fm10k_controlpanel.roce import dcbx_policy, preflight
from fm10k_controlpanel.dcbx import decode
from test_roce import roce_configuration


def extended():
    raw = roce_configuration().model_dump()
    raw["qos"]["roce"].update(classification="dscp", dcbx="ieee")
    raw["qos"]["priority_map"][6:] = [7, 6]
    raw["ports"][17].update(vlan_mode="access", pvid=10, tagged_vlans=[])
    return SwitchConfiguration.model_validate(raw)


def test_legacy_migration_and_extended_compile_disable():
    old = roce_configuration().model_dump()
    for key in ("mode", "classification", "dscp", "cnp_dscp", "dcbx"):
        old["qos"]["roce"].pop(key)
    migrated = SwitchConfiguration.model_validate(old)
    assert migrated.qos.roce.mode == "static-pfc" and migrated.qos.roce.classification == "pcp"
    c = extended()
    assert preflight(c.model_dump())["common_vlans"] == [10]
    assert decode_configuration(compile_configuration(c)) == c
    root = parse_xml(compile_configuration(c))
    values = {int(n.findtext("dscp")): int(n.findtext("switch-priority")) for n in root.findall("./class-of-service/dscp-map/entry")}
    assert len(values) == 64 and values[26] == 3 and values[48] == 6
    assert all(v == 0 for k, v in values.items() if k not in (26, 48))
    assert root.findtext("./class-of-service/forwarding/switch-priority[priority='15']/traffic-class") == "0"
    iface = root.find("./class-of-service/scheduler/interfaces/interface[name='et-0/0/12']")
    assert iface.findtext("group[id='7']/strict-priority") == "true"
    assert iface.findtext("group[id='3']/strict-priority") == "false"
    assert root.findtext("./class-of-service/shared-memory/traffic-class[class='7']/partition") == "0"
    policy = dcbx_policy(c)
    assert sum(policy["bandwidth"]) == 100 and policy["bandwidth"][7] == 0
    assert int(iface.findtext("group[id='3']/weight")) == policy["bandwidth"][3] * 3080
    local = root.find("./protocols/lldp/interface[name='et-0/0/12']/dcbx")
    assert local.findtext("pfc-mask") == "8" and len(local.findall("application")) == 2
    c.qos.roce.enabled = False
    disabled = parse_xml(compile_configuration(c))
    assert not disabled.findall(".//dcbx")
    assert all(n.text == "0" for n in disabled.findall("./class-of-service/dscp-map/entry/switch-priority"))
    assert disabled.findtext("./class-of-service/scheduler/interfaces/interface[name='et-0/0/12']/group[id='7']/strict-priority") == "false"


@pytest.mark.parametrize("fault", ["same-dscp", "ecn", "global-lldp", "port-lldp", "cnp-map", "cnp-default", "egress-shaper"])
def test_extended_conflicts_are_rejected_by_preflight_and_commit(fault):
    raw = extended().model_dump()
    if fault == "same-dscp": raw["qos"]["roce"]["cnp_dscp"] = 26
    if fault == "ecn": raw["qos"]["roce"]["mode"] = "pfc-ecn"
    if fault == "global-lldp": raw["lldp"]["enabled"] = False
    if fault == "port-lldp": raw["ports"][13]["lldp"] = False
    if fault == "cnp-map": raw["qos"]["priority_map"][0] = 7
    if fault == "cnp-default": raw["qos"]["default_priority"] = 6
    if fault == "egress-shaper": raw["ports"][13]["egress_kbps"] = 1000000
    original = copy.deepcopy(raw)
    assert not preflight(raw)["valid"] and original == raw
    with pytest.raises(ValidationError): SwitchConfiguration.model_validate(raw)


def dcbx_readback(config):
    root = ET.Element("dcbx", {"mode": "ieee-local", "peer-policy-applied": "false"})
    policy = dcbx_policy(config)
    for p in config.qos.roce.ports:
        row = ET.SubElement(root, "interface", {"port": str(p), "lldp-enabled": "true", "tx-frames": "0"})
        local = ET.SubElement(row, "local", {"enabled": "true", "malformed": "false", "pfc-present": "true", "ets-present": "true", "app-present": "true",
            "pfc-mask": "8", "pfc-willing": "false", "ets-willing": "false"})
        for key in ("priority_map", "bandwidth", "tsa_map"):
            local.set(key.replace("_", "-"), " ".join(map(str, policy[key])))
        for app in policy["applications"]:
            ET.SubElement(local, "application", {k: str(v) for k, v in app.items()})
    return root


def test_dcbx_configuration_is_separate_from_peers_and_link():
    c = extended(); root = dcbx_readback(c)
    result = decode(root, c, {13: "down", 17: "down"})
    assert result["configuration_matches"]
    assert {r["state"] for r in result["ports"]} == {"link-down"}
    assert not result["peer_policy_applied"]
    result = decode(root, c, {13: "up", 17: "up"})
    assert all(r["state"] == "no-peer" for r in result["ports"])
    root.find("interface/local").set("pfc-mask", "0")
    result = decode(root, c, {13: "up", 17: "up"})
    assert not result["configuration_matches"] and result["ports"][0]["state"] == "local-mismatch"
    root = dcbx_readback(c); root.remove(root.find("interface"))
    result = decode(root, c, {13: "up", 17: "up"})
    assert not result["configuration_matches"] and result["ports"][0]["state"] == "local-missing"


def test_ieee_dcbx_wire_protocol(tmp_path):
    root = Path(__file__).resolve().parents[1]
    daemon = root / "vendor/netlab/sbin/lldpd"
    binary = tmp_path / "dcbx-wire-test"
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror", "-pedantic",
        "-I", str(root / "vendor/netlab/include"), str(root / "tests/native_dcbx_test.c"),
        str(daemon / "lldp_tlv.c"), str(daemon / "dcbx.c"), str(daemon / "lldp_xml.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=10)


def test_pause_observation_handles_epoch_gaps_and_never_recovers_hardware():
    from fm10k_controlpanel.roce_monitor import RoceMonitor
    monitor = RoceMonitor()
    sample = {"revision": 1, "quality": "valid", "configuration_applied": True, "ports": [{
        "port": 13, "selected": True, "link": "up", "quality": "valid", "tc3_usage_bytes": 4096,
        "counters": {"tx_bytes": 10, "rx_pfc_packets": 100000}, "pause": {"quality": "valid", "paused_class_mask": 8}}]}
    def observe(tick, generation=None):
        sample.update(sampled_at=1000-tick, sample_generation=tick if generation is None else generation)
        return monitor.observe(sample, tick)
    for tick in (10,20,30,40): result = observe(tick)
    assert result["ports"][0]["suspected_stall"] and len(result["events"]) == 1
    assert not result["automatic_recovery"] and not result["events"][0]["automatic_action"]
    sample["ports"][0]["counters"]["tx_bytes"] = 20
    result = observe(50)
    assert not result["ports"][0]["suspected_stall"] and result["events"][-1]["kind"] == "pause-stall-cleared"
    result = observe(100)  # Gap exceeds three intervals.
    assert result["ports"][0]["observed_stall_seconds"] == 0
    result = observe(110,1)  # SDK sampling generation reset.
    assert result["ports"][0]["observed_stall_seconds"] == 0
    sample["ports"][0]["pause"] = {"quality": "unavailable"}
    result = observe(120)
    assert result["ports"][0]["pause_observed"] is None
    assert not result["ports"][0]["suspected_stall"]  # A large PFC counter alone proves nothing.
    sample["revision"] = 2; sample["ports"][0]["tc3_usage_bytes"] = 0
    result = observe(130)
    assert len(result["history"]) == 1 and result["ports"][0]["tc3_peak_bytes"] == 0
