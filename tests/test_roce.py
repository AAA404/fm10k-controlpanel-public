import copy
import xml.etree.ElementTree as ET

import pytest
from pydantic import ValidationError

from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab_codec import compile_configuration, decode_configuration, parse_xml
from fm10k_controlpanel.roce import PAUSE_BUFFER_BYTES, buffer_budget, decode_operational, headroom_bytes


def roce_configuration():
    c = SwitchConfiguration(profile="sil001-hw5-a11").model_dump()
    for group in c["groups"]:
        group["mode"] = "40g"
    c["vlans"] = [{"id": 10, "name": "RoCE"}]
    for p in (13, 17):
        c["ports"][p].update(enabled=True, vlan_mode="trunk", pvid=None, tagged_vlans=[10])
    c["qos"]["roce"].update(enabled=True, ports=[13, 17])
    return SwitchConfiguration.model_validate(c)


def test_legacy_and_roce_roundtrip():
    old = SwitchConfiguration().model_dump()
    del old["qos"]["roce"]
    assert not SwitchConfiguration.model_validate(old).qos.roce.enabled
    c = roce_configuration()
    wire = compile_configuration(c)
    assert decode_configuration(wire) == c
    root = parse_xml(wire)
    assert root.findtext("./class-of-service/shared-memory/traffic-class[class='3']/partition") == "1"
    pfc = root.find("./class-of-service/interfaces/interface[name='et-0/0/12']/priority-flow-control")
    assert pfc.findtext("rx-class-mask") == "8"
    assert pfc.findtext("lossless-smp-mask") == "2"
    c.qos.roce.enabled = False
    disabled = parse_xml(compile_configuration(c))
    assert {p.text for p in disabled.findall("./class-of-service/shared-memory/traffic-class/partition")} == {"0"}
    assert disabled.find(".//priority-flow-control") is None


@pytest.mark.parametrize("fault", ["duplicate", "inactive", "vlan", "tc", "default", "policer", "headroom", "lag"])
def test_invalid_lossless_topologies(fault):
    c = roce_configuration().model_dump()
    if fault == "duplicate": c["qos"]["roce"]["ports"] = [13, 13]
    if fault == "inactive": c["qos"]["roce"]["ports"] = [13, 14]
    if fault == "vlan": c["ports"][17].update(vlan_mode="access", pvid=10, tagged_vlans=[])
    if fault == "tc": c["qos"]["priority_map"][0] = 3
    if fault == "default": c["qos"]["default_priority"] = 3
    if fault == "policer": c["ports"][13]["ingress_kbps"] = 22000
    if fault == "headroom": c["qos"]["roce"]["response_time_ns"] = 10000
    if fault == "lag": c["lags"] = [{"name": "ae0", "members": [13, 17]}]
    with pytest.raises(ValidationError): SwitchConfiguration.model_validate(c)


def test_headroom_speed_mtu_and_cardinal_budget():
    assert headroom_bytes(40, 9216, 100, 3000) <= PAUSE_BUFFER_BYTES
    assert headroom_bytes(100, 1518, 10, 3000) <= PAUSE_BUFFER_BYTES
    assert headroom_bytes(100, 9216, 100, 3000) > PAUSE_BUFFER_BYTES
    assert headroom_bytes(40, 9216, 10, 3000) % 192 == 0
    assert buffer_budget(9216)["valid"]
    assert not buffer_budget(9216, 48)["valid"]
    assert not buffer_budget(100000)["valid"]


def diagnostic_parts(c):
    parts = {name: ET.Element("class-of-service") for name in ("flow-control", "watermarks", "forwarding", "interfaces", "queues")}
    flow = ET.SubElement(parts["flow-control"], "flow-control", {"roce-buffer-status": "0", "pause-smac": "02:10:84:00:00:01"})
    ET.SubElement(parts["watermarks"], "watermarks")
    fw = ET.SubElement(parts["forwarding"], "forwarding")
    classifiers = ET.SubElement(parts["interfaces"], "interfaces")
    parts["ports"] = ET.Element("port-snapshot", status="ok", counters="true")
    for tc in range(8):
        ET.SubElement(flow, "traffic-class", id=str(tc), smp="smp-1" if tc == 3 else "smp-0")
        ET.SubElement(fw, "switch-priority", {"priority": str(tc), "traffic-class": str(tc)})
    for p in range(8, 16):
        ET.SubElement(fw, "switch-priority", {"priority": str(p), "traffic-class": str(0 if p == 11 else p & 7)})
    for port in c.active_ports():
        selected = port in (13, 17)
        ET.SubElement(flow, "interface", {"port": str(port), "rx-class-mask": "8" if selected else "0", "tx-class-mask": "8" if selected else "255",
                      "smp-lossless-mask": "2" if selected else "0", "shared-pause-mask": "2" if selected else "0",
                      "tc3-pause-class": "3", "pc3-smp": "1" if selected else "2",
                      "tx-pause-mode": "class-based", "rx-pause": "off"})
        ET.SubElement(classifiers, "interface", port=str(port), trust="ieee-802.1p")
        ET.SubElement(parts["ports"], "port", {"id": str(port), "state-status": "0", "counter-status": "1"})
    return parts


def test_diagnostics_never_infer_traffic_validation():
    c = roce_configuration()
    parts = diagnostic_parts(c)
    result = decode_operational(parts, c, 10)
    assert result["configuration_applied"]
    assert result["traffic_validation"] == "not-run"
    assert result["ports"][0]["counters"]["rx_pfc_packets"] is None
    assert result["ports"][0]["quality"] == "unavailable"
    changed = copy.deepcopy(parts)
    changed["flow-control"].find("flow-control").set("roce-buffer-status", "unsupported")
    assert not decode_operational(changed, c, 10)["configuration_applied"]


def test_pause_receive_mapping_does_not_imply_pause_generation_is_configured():
    c = roce_configuration()
    for mapping in (None, "0", "2"):
        parts = diagnostic_parts(c)
        node = parts["flow-control"].find("./flow-control/interface[@port='13']")
        if mapping is None:
            node.attrib.pop("pc3-smp")
        else:
            node.set("pc3-smp", mapping)
        result = decode_operational(parts, c, 10)
        assert not result["configuration_applied"]
        assert not next(p for p in result["ports"] if p["port"] == 13)["configuration_matches"]
    parts = diagnostic_parts(c)
    parts["flow-control"].find("./flow-control/interface[@port='1']").set("pc3-smp", "1")
    result = decode_operational(parts, c, 10)
    assert not result["configuration_applied"]
    assert not next(p for p in result["ports"] if p["port"] == 1)["configuration_matches"]


def test_roce_state_and_counter_failures_keep_their_own_quality():
    c = roce_configuration()
    parts = diagnostic_parts(c)
    node = parts["ports"].find("port[@id='13']")
    node.attrib.update({"link": "up", "state-status": "-1", "counter-status": "0"})
    for field in ("rx-pfc-packets", "tx-pfc-packets", "rx-pause-packets", "tx-pause-packets",
                  "rx-congestion-drops", "tx-congestion-drops", "rx-errors", "tx-errors", "rx-bytes", "tx-bytes"):
        node.set(field, "42")
    def port():
        return next(p for p in decode_operational(parts, c, 10)["ports"] if p["port"] == 13)
    result = port()
    assert result["link"] == "unknown" and result["quality"] == "unavailable"
    assert result["counter_quality"] == "valid" and result["counters"]["rx_pfc_packets"] == 42
    node.set("state-status", "0")
    parts["ports"].set("counters", "false")
    result = port()
    assert result["link"] == "up" and result["state_quality"] == "valid"
    assert result["counter_quality"] == "unavailable" and result["counters"]["rx_pfc_packets"] is None


def test_watchdog_policy_roundtrip_and_legacy_default():
    c = roce_configuration()
    legacy = c.model_dump()
    del legacy["qos"]["roce"]["watchdog"]
    assert not SwitchConfiguration.model_validate(legacy).qos.roce.watchdog.enabled
    c.qos.roce.watchdog.enabled = True
    c.qos.roce.watchdog.detect_ms = 2000
    encoded = compile_configuration(c)
    assert decode_configuration(encoded) == c
    nodes = parse_xml(encoded).findall(".//priority-flow-control")
    assert len(nodes) == 2 and all(n.findtext("watchdog-detect-ms") == "2000" for n in nodes)
    c.qos.roce.watchdog.enabled = False
    assert all(n.findtext("watchdog-detect-ms") == "0" for n in parse_xml(compile_configuration(c)).findall(".//priority-flow-control"))
    raw = c.model_dump()
    raw["qos"]["roce"]["watchdog"].update(detect_ms=60000, cooldown_ms=10000)
    with pytest.raises(ValidationError, match="冷却时间"):
        SwitchConfiguration.model_validate(raw)


def test_watchdog_readback_distinguishes_temporary_release_and_failed_restore():
    import time
    c = roce_configuration()
    c.qos.roce.watchdog.enabled = True
    parts = diagnostic_parts(c)
    assert not decode_operational(parts, c, 10)["configuration_applied"]
    for node in parts["flow-control"].findall("./flow-control/interface"):
        selected = int(node.get("port")) in c.qos.roce.ports
        node.attrib.update({"watchdog-supported": "1", "watchdog-phase": "1" if selected else "0",
                            "watchdog-detect-ms": "5000" if selected else "0",
                            "watchdog-recovery-ms": "100", "watchdog-cooldown-ms": "30000",
                            "watchdog-sample-status": "0", "watchdog-sampled-ms": str(int(time.monotonic() * 1000)),
                            "watchdog-saved-rx-mask": "-1", "rx-class-mask-hardware": "8" if selected else "0"})
    assert decode_operational(parts, c, 10)["configuration_applied"]
    node = parts["flow-control"].find("./flow-control/interface[@port='13']")
    node.attrib.update({"watchdog-phase": "3", "watchdog-saved-rx-mask": "8", "rx-class-mask": "0", "rx-class-mask-hardware": "0"})
    result = decode_operational(parts, c, 10)
    assert result["configuration_applied"] and result["traffic_validation"] == "not-run"
    assert next(p for p in result["ports"] if p["port"] == 13)["watchdog"]["phase"] == "recovering"
    node.set("watchdog-phase", "6")
    assert not decode_operational(parts, c, 10)["configuration_applied"]
    node.set("watchdog-phase", "3")
    node.set("watchdog-supported", "0")
    assert not decode_operational(parts, c, 10)["configuration_applied"]


def test_preflight_collects_conflicts_and_never_mutates_draft():
    from fm10k_controlpanel.roce import preflight
    raw = roce_configuration().model_dump(mode="json")
    raw["ports"]["13"]["enabled"] = False
    raw["ports"]["17"]["ingress_kbps"] = 22000
    raw["qos"]["priority_map"][0] = 3
    before = copy.deepcopy(raw)
    result = preflight(raw)
    assert not result["valid"]
    assert {"ports.13.enabled", "ports.17.ingress_kbps", "qos.priority_map"} <= {x["path"] for x in result["issues"]}
    assert len(result["ports"]) == 24
    assert raw == before
    for fix in result["suggestions"]:
        target = raw
        keys = fix["path"].split(".")
        for key in keys[:-1]: target = target[key]
        target[keys[-1]] = fix["after"]
    assert preflight(raw)["valid"]
    SwitchConfiguration.model_validate(raw)


@pytest.mark.parametrize("fault", ["vlan", "headroom", "inactive", "too-few", "range"])
def test_preflight_and_commit_agree_on_invalid_roce(fault):
    from fm10k_controlpanel.roce import preflight
    raw = roce_configuration().model_dump(mode="json")
    if fault == "vlan": raw["ports"]["17"].update(vlan_mode="access", pvid=10, tagged_vlans=[])
    if fault == "headroom": raw["qos"]["roce"]["response_time_ns"] = 10000
    if fault == "inactive": raw["qos"]["roce"]["ports"] = [13, 14]
    if fault == "too-few": raw["qos"]["roce"]["ports"] = [13]
    if fault == "range": raw["qos"]["roce"]["cable_length_m"] = -1
    assert not preflight(raw)["valid"]
    with pytest.raises(ValidationError): SwitchConfiguration.model_validate(raw)


def test_preflight_budget_and_disabled_configuration():
    from fm10k_controlpanel.roce import preflight
    raw = roce_configuration().model_dump(mode="json")
    result = preflight(raw)
    assert result["valid"] and result["common_vlans"] == [10]
    p13 = next(p for p in result["ports"] if p["port"] == 13)
    assert p13["headroom_bytes"] == headroom_bytes(40, raw["ports"]["13"]["mtu"], 10, 3000)
    assert p13["obt"] == 2 and p13["epl"] == 5
    assert not next(p for p in result["ports"] if p["port"] == 14)["eligible"]
    raw["qos"]["roce"]["enabled"] = False
    raw["qos"]["roce"]["ports"] = []
    assert preflight(raw)["valid"]


def test_100g_roce_is_allowed_when_link_profile_and_headroom_are_valid():
    from fm10k_controlpanel.roce import capabilities, preflight
    raw = roce_configuration().model_dump(mode="json")
    raw["groups"][3]["mode"] = "100g"
    raw["groups"][4]["mode"] = "100g"
    result = preflight(raw)
    assert result["valid"]
    assert next(p for p in result["ports"] if p["port"] == 13)["speed_gbps"] == 100
    assert next(p for p in result["ports"] if p["port"] == 17)["speed_gbps"] == 100
    assert capabilities()["speeds_gbps"] == [10, 25, 40, 100]


@pytest.mark.parametrize("value", [None, [], "invalid"])
def test_preflight_rejects_malformed_nested_configuration(value):
    from fm10k_controlpanel.roce import preflight
    raw = roce_configuration().model_dump(mode="json")
    raw["qos"] = value
    assert not preflight(raw)["valid"]
    raw["qos"] = {"roce": value}
    assert not preflight(raw)["valid"]
