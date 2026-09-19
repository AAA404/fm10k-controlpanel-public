import copy
import json
import xml.etree.ElementTree as ET

import pytest

from fm10k_controlpanel.board import HardwareError
from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab import NetlabBackend
from fm10k_controlpanel.netlab_codec import compile_configuration, decode_configuration, parse_xml
from fm10k_controlpanel.profiles import PROFILES


@pytest.mark.parametrize("profile", PROFILES)
def test_canonical_roundtrip_keeps_slots_and_escapes_names(profile):
    config = SwitchConfiguration(profile=profile)
    config.ports[1].name = 'MPO1 <uplink> "A" & B'
    xml = compile_configuration(config)
    assert b"&lt;uplink&gt;" in xml and b"&amp;" in xml
    restored = decode_configuration(xml)
    assert restored == config and set(restored.ports) == set(range(1, 25))
    root = parse_xml(xml)
    assert len(root.findall("./chassis/fm10k-panel/port-group")) == 6
    assert root.find("./routing-options") is None
    assert root.find("./system") is None
    assert root.findtext("./interfaces/interface/name") == "et-0/0/0"


def test_native_l2_vlan_lag_and_mirror_translation():
    raw = SwitchConfiguration().model_dump()
    for port in (1, 5):
        raw["ports"][port].update(pvid=1, enabled=True)
    raw["lags"] = [{"name": "ae0", "members": [1, 5]}]
    raw["mirror"] = {"enabled": True, "source": 1, "destination": 9, "direction": "tx"}
    root = parse_xml(compile_configuration(SwitchConfiguration.model_validate(raw)))
    nodes = {n.findtext("name"): n for n in root.findall("./interfaces/interface")}
    assert nodes["et-0/0/0"].findtext("./ether-options/ieee8023ad") == "ae0"
    assert nodes["ae0"].findtext("./aggregated-ether-options/lacp/mode") == "active"
    assert nodes["ae0"].findtext("./unit/logical-unit/family/ethernet-switching/vlan-members") == "V1"
    assert root.findtext("./forwarding-options/port-mirroring/instance/input/interface/direction") == "egress"


def test_lag_ingress_filter_is_consistent_and_translated_to_aggregate():
    raw = SwitchConfiguration().model_dump()
    raw["lags"] = [{"name": "ae0", "members": [1, 5]}]
    for port in (1, 5):
        raw["ports"][port].update(pvid=1, enabled=True, ingress_filtering=False)
    root = parse_xml(compile_configuration(SwitchConfiguration.model_validate(raw)))
    nodes = {node.findtext("name"): node for node in root.findall("./interfaces/interface")}
    for name in ("et-0/0/0", "et-0/0/4", "ae0"):
        assert nodes[name].findtext("./fm10k-port/ingress-filtering") == "false"
    raw["ports"][5]["ingress_filtering"] = True
    with pytest.raises(ValueError, match="入口过滤"):
        SwitchConfiguration.model_validate(raw)


def test_port_egress_shaping_keeps_independent_scheduler_and_relative_weights():
    config = SwitchConfiguration()
    config.ports[1].egress_kbps = 1_000_000
    config.ports[1].mtu = 9000
    config.qos.weights = [1, 2, 3, 4, 5, 6, 7, 255]
    root = parse_xml(compile_configuration(config))
    nodes = {n.findtext('name'): n for n in root.findall('./class-of-service/scheduler/interfaces/interface')}
    assert not nodes['et-0/0/0'].findall('traffic-class')
    assert len(nodes['et-0/0/4'].findall('traffic-class')) == 8
    assert [int(n.findtext('weight')) for n in nodes['et-0/0/0'].findall('group')] == [18048 * w for w in config.qos.weights]
    assert all(n.findtext('strict-priority') == 'false' for n in nodes['et-0/0/0'].findall('group'))
    assert root.findtext('./ethernet-switching-options/egress-rate-limit/interface/bandwidth') == '1000000'


@pytest.mark.parametrize("payload", [b"<!DOCTYPE x [<!ENTITY a 'x'>]><x/>", b"<bad", b"x" * 262145])
def test_untrusted_xml_rejected(payload):
    with pytest.raises(HardwareError):
        parse_xml(payload)


class NativeFixture:
    def __init__(self, bound=True):
        self.calls = []
        self.bound = bound
        self.configuration = SwitchConfiguration()
        self.revision = 1
        self.pending = None
        self.before = None
        self.transaction_revision = 0
        self.transaction_state = "unknown"
        self.lose_finish_reply = False

    def close(self):
        pass

    def send_request(self, service, method, payload=b"", **options):
        self.calls.append((service, method, payload))
        if method == 19:
            pending = self.pending is not None
            root = ET.Element("fm10k-panel-state", api="1", revision=str(self.revision),
                              pending=str(pending).lower(), **{"job-id": self.pending or "",
                              "deadline": "9999999999", "board-hal": "bound" if self.bound else "unbound",
                              "synchronized": "true", "transaction-revision": str(self.transaction_revision),
                              "transaction-state": self.transaction_state})
            root.append(ET.fromstring(compile_configuration(self.configuration)))
            data = ET.tostring(root)
            return 0, len(data), data
        if method in (20, 21):
            revision, job, timeout, xml = payload.split(b"\n", 3)
            if int(revision) != self.revision:
                return 1, 5, b"stale"
            if method == 21:
                self.before = self.configuration.model_copy(deep=True)
                self.configuration = decode_configuration(xml)
                self.revision += 1
                self.pending = job.decode()
                self.transaction_revision = self.revision
                self.transaction_state = "awaiting_confirmation"
            return 0, 0, b""
        if method in (22, 23):
            assert payload.decode() == self.pending
            self.pending = None
            self.transaction_state = "confirmed" if method == 22 else "rolled_back"
            if method == 23:
                self.configuration = self.before
                self.revision += 1
            if self.lose_finish_reply:
                raise TimeoutError("reply lost after configd persisted the outcome")
            return 0, 0, b""
        raise AssertionError((service, method))


def test_native_adapter_delegates_atomic_commit_and_confirmation():
    fixture = NativeFixture()
    native = NetlabBackend(fixture)
    config = SwitchConfiguration()
    config.ports[1].name = "new"
    native.validate(config)
    state = native.apply(config, 1, "a" * 32, 60)
    assert state["pending"]["job_id"] == "a" * 32
    assert native.confirm("a" * 32)["pending"] is None
    # No sequence of SET/DELETE calls can interleave with another writer.
    assert all(method not in (1, 2, 3, 4, 7) for _, method, _ in fixture.calls)


def test_unbound_native_board_cannot_accept_writes():
    fixture = NativeFixture(bound=False)
    native = NetlabBackend(fixture)
    with pytest.raises(HardwareError, match="HAL"):
        native.validate(SwitchConfiguration())
    assert [method for _, method, _ in fixture.calls] == [19]


@pytest.mark.parametrize("action", ["confirm", "rollback"])
def test_finish_recovers_lost_reply_only_from_durable_authority(action):
    fixture = NativeFixture()
    native = NetlabBackend(fixture)
    config = SwitchConfiguration()
    config.ports[1].name = "pending"
    native.apply(config, 1, "a" * 32, 60)
    fixture.lose_finish_reply = True
    # A real reconnect constructs another transport. Keep the fixture's
    # persisted configd state while simulating that reconnect.
    native.close = lambda: None
    result = getattr(native, action)("a" * 32)
    assert result["last_transaction"]["state"] == ("confirmed" if action == "confirm" else "rolled_back")
    assert result["configuration"]["ports"]["1"]["name"] == ("pending" if action == "confirm" else "")


class OperationalFixture:
    def __init__(self, xml):
        self.xml = xml

    def send_request(self, *args, **kwargs):
        return 0, len(self.xml), self.xml

    def close(self):
        pass


def test_lag_link_up_does_not_claim_lacp_synchronization():
    payload = b'<lags><lag name="ae0" status="up" mode="active"><member port="1" selected="true" sync="false"/></lag><lag name="ae1" status="up" mode="static"/></lags>'
    result = NetlabBackend(OperationalFixture(payload)).operational("lags")
    assert result[0]["synchronized"] is False
    assert result[1]["synchronized"] is None


@pytest.mark.parametrize("feature,root", [("lldp", "lldp-neighbors"), ("lags", "lags"),
                                          ("rstp", "stp-state"), ("igmp", "igmp-snooping")])
def test_operational_tables_distinguish_empty_from_unexpected_native_reply(feature, root):
    valid = NetlabBackend(OperationalFixture(f"<{root}/>".encode()))
    result = valid.operational(feature)
    entries = result["ports"] if feature == "rstp" else result
    assert entries == []
    with pytest.raises(HardwareError, match="响应类型错误"):
        NetlabBackend(OperationalFixture(b'<unexpected-response/>')).operational(feature)


def test_native_counter_error_does_not_fabricate_zero_or_port_shutdown():
    # Attribute spelling and units are taken from rpc_server.c method 120.
    root = ET.Element("port-snapshot", counters="true", generation="17")
    for number in range(1, 25):
        ET.SubElement(root, "port", id=str(number), **{
            "state-status": "0", "counter-status": "-1" if number == 1 else "0",
            "admin": "up", "link": "up", "speed": "95000", "ethernet-mode": "100GBase-SR4",
            "rx-bytes": "12345", "tx-bytes": "23456", "rx-fcs-errors": "3"})
    native = NetlabBackend(OperationalFixture(ET.tostring(root)))
    native._configuration = SwitchConfiguration()
    ports = native.ports()
    assert ports[0]["rx_bytes"] is None
    assert ports[0]["quality"] == "unavailable" and ports[0]["link"] == "up"
    assert ports[0]["degraded"] is False  # telemetry failure is not a forced shutdown
    assert ports[1]["rx_bytes"] == 12345 and ports[1]["crc_errors"] == 3
    assert ports[0]["speed_gbps"] == 100
    assert ports[0]["scheduler_speed_gbps"] == 95
    assert ports[0]["counter_epoch"] is None


def test_native_igmp_members_group_by_vlan_and_address():
    xml = b'''<igmp-snooping enabled="true"><member source="static" vlan="10" port="1" group="239.1.1.1"/>
        <member source="dynamic" vlan="10" port="5" group="239.1.1.1" expires-in="45"/>
        <member source="dynamic" vlan="20" port="9" group="239.1.1.1" expires-in="12"/></igmp-snooping>'''
    native = NetlabBackend(OperationalFixture(xml))
    groups = native.operational("igmp")
    assert len(groups) == 2 and groups[0]["ports"] == [1, 5]
    assert groups[1]["vlan"] == 20 and groups[1]["ports"] == [9]


def test_native_igmp_router_pending_is_not_reported_as_installed():
    xml = b'''<igmp-snooping><member source="dynamic" vlan="10" port="1" group="239.1.1.1"/>
        <router-group vlan="10" group="239.1.1.1" applied-mask="000110" desired-mask="001110" uncertain-mask="000100"/>
        </igmp-snooping>'''
    group = NetlabBackend(OperationalFixture(xml)).operational("igmp")[0]
    assert group["ports"] == [1, 5] and group["listener_ports"] == [1]
    assert group["router_ports"] == [5] and group["pending_router_ports"] == [9, 13]


def test_native_igmp_uncertain_receivers_are_not_reported_as_installed():
    xml = b'''<igmp-snooping><member source="static" vlan="10" port="1" group="239.1.1.1"/>
        <member source="dynamic" vlan="10" port="5" group="239.1.1.1" hardware-state="pending"/>
        <member source="dynamic" vlan="10" port="9" group="239.1.1.1" hardware-state="retiring"/>
        <member source="dynamic" vlan="10" port="13" group="239.1.1.1" hardware-state="installed"/>
        </igmp-snooping>'''
    group = NetlabBackend(OperationalFixture(xml)).operational("igmp")[0]
    assert group["ports"] == group["listener_ports"] == [1, 13]
    assert group["pending_listener_ports"] == [5]
    assert group["retiring_listener_ports"] == [9]
    assert len(group["members"]) == 4


def test_native_igmp_checkpoint_failure_is_visible():
    with pytest.raises(HardwareError, match="运行记录保存失败"):
        NetlabBackend(OperationalFixture(b'<igmp-snooping recovery-state="retrying"/>')).operational("igmp")


@pytest.mark.parametrize("status", ["unavailable", "partial"])
def test_native_igmp_hardware_multicast_failure_is_visible(status):
    xml = f'<igmp-snooping><member source="dynamic" vlan="1" port="1" group="239.1.1.1"/><multicast-owner status="{status}"/></igmp-snooping>'
    with pytest.raises(HardwareError, match="硬件成员回读不可用"):
        NetlabBackend(OperationalFixture(xml.encode())).operational("igmp")


def test_native_lldp_uses_actual_sys_name_leaf():
    native = NetlabBackend(OperationalFixture(b'''<lldp-neighbors><neighbor>
        <local-interface>et-0/0/0</local-interface><sys-name>test-peer</sys-name>
        <chassis-id>00:11:22:33:44:55</chassis-id><port-id>Ethernet1</port-id><ttl>120</ttl>
        </neighbor></lldp-neighbors>'''))
    assert native.operational("lldp")[0]["system_name"] == "test-peer"


@pytest.mark.parametrize("profile", PROFILES)
def test_sensor_cache_requires_active_profile_and_preserves_unbound_status(profile):
    class TelemetryFixture(NativeFixture):
        reported_profile = profile

        def send_request(self, service, method, payload=b"", **options):
            if method == 132:
                self.calls.append((service, method, payload))
                sample = {"api": 1, "profile": self.reported_profile, "board_hal": "unbound",
                          "sensors": {"quality": "pending", "temperatures": [], "fan": {"rpm": None}}, "optics": []}
                data = json.dumps(sample).encode()
                return 0, len(data), data
            return super().send_request(service, method, payload, **options)
    fixture = TelemetryFixture(bound=False)
    fixture.configuration = SwitchConfiguration(profile=profile)
    native = NetlabBackend(fixture)
    assert native.sensors()["fan"]["rpm"] is None
    assert [method for _, method, _ in fixture.calls] == [19, 132]
    assert native._board_sample["board_hal"] == "unbound"
    fixture.reported_profile = next(name for name in PROFILES if name != profile)
    with pytest.raises(HardwareError, match="Profile"):
        native.sensors()
