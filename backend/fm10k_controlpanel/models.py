from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer, model_validator

EPLS = (0, 1, 2, 5, 6, 7)
PHYSICAL = {
    epl: {"epl": epl, "mpo": index // 3 + 1, "resource": index,
          "position": index % 3, "mux": 1 << (index // 3), "base": index * 4 + 1}
    for index, epl in enumerate(EPLS)
}
PortNumber = Annotated[int, Field(ge=1, le=24)]
VlanNumber = Annotated[int, Field(ge=1, le=4094)]
Label = Annotated[str, Field(max_length=64, pattern=r"^[^\x00-\x1f\x7f]*$")]
STORM_CONTROLLER_CAPACITY = 16
STORM_MIN_RATE_KBPS = 22_000


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class SplitVlanBackup(Model):
    """Dormant settings, stored in the same confirmed snapshot as the group."""
    enabled: bool = False
    vlan_mode: Literal["access", "trunk"] = "access"
    pvid: VlanNumber | None = None
    tagged_vlans: list[VlanNumber] = Field(default_factory=list, max_length=64)
    ingress_filtering: bool = True

    @model_validator(mode="after")
    def valid_profile(self):
        if len(set(self.tagged_vlans)) != len(self.tagged_vlans):
            raise ValueError("拆分恢复记录的 Tagged VLAN 不能重复")
        if self.vlan_mode == "access" and self.tagged_vlans or self.pvid in self.tagged_vlans:
            raise ValueError("拆分恢复记录的 Native/Tagged VLAN 不一致")
        if self.enabled and self.pvid is None and not self.tagged_vlans:
            raise ValueError("拆分恢复记录中的启用端口必须有 VLAN")
        return self


class PortGroup(Model):
    epl: int
    mode: Literal["100g", "40g", "split"] = "100g"
    lane_speeds: tuple[Literal[10, 25], Literal[10, 25], Literal[10, 25], Literal[10, 25]] = (25, 25, 25, 25)
    split_vlan_backup: tuple[SplitVlanBackup, SplitVlanBackup, SplitVlanBackup, SplitVlanBackup] | None = None

    @model_serializer(mode="wrap")
    def omit_empty_history(self, handler):
        data = handler(self)
        if self.split_vlan_backup is None:
            data.pop("split_vlan_backup", None)
        return data

    @field_validator("epl")
    @classmethod
    def valid_epl(cls, value: int) -> int:
        if value not in EPLS:
            raise ValueError("EPL 必须为 0/1/2/5/6/7")
        return value

    def active_ports(self) -> list[int]:
        base = PHYSICAL[self.epl]["base"]
        return list(range(base, base + 4)) if self.mode == "split" else [base]

    def speed(self, port: int) -> int:
        if port not in self.active_ports():
            return 0
        return self.lane_speeds[port - PHYSICAL[self.epl]["base"]] if self.mode == "split" else int(self.mode[:-1])


class StormControl(Model):
    broadcast_kbps: int = Field(default=0, ge=0, le=100_000_000)
    multicast_kbps: int = Field(default=0, ge=0, le=100_000_000)
    unknown_unicast_kbps: int = Field(default=0, ge=0, le=100_000_000)

    @field_validator("broadcast_kbps", "multicast_kbps", "unknown_unicast_kbps")
    @classmethod
    def hardware_minimum(cls, value: int) -> int:
        if 0 < value < STORM_MIN_RATE_KBPS:
            raise ValueError("风暴抑制速率须为 0（关闭）或至少 22000 kbps")
        return value


class PortConfig(Model):
    name: Label = ""
    enabled: bool = False
    mtu: int = Field(default=1518, ge=1514, le=9216, description="Maximum L2 frame bytes")
    vlan_mode: Literal["access", "trunk"] = "access"
    pvid: VlanNumber | None = None
    tagged_vlans: list[VlanNumber] = Field(default_factory=list, max_length=64)
    ingress_filtering: bool = True
    edge: bool = False
    bpdu_guard: bool = False
    path_cost: int = Field(default=0, ge=0, le=200_000_000)
    port_priority: int = Field(default=128, ge=0, le=240, multiple_of=16)
    lldp: bool = True
    direct_receiver: bool = False
    storm: StormControl = Field(default_factory=StormControl)
    ingress_kbps: int = Field(default=0, ge=0, le=100_000_000)
    egress_kbps: int = Field(default=0, ge=0, le=100_000_000)

    @field_validator("ingress_kbps")
    @classmethod
    def ingress_hardware_minimum(cls, value: int) -> int:
        if 0 < value < STORM_MIN_RATE_KBPS:
            raise ValueError("入口限速须为 0（关闭）或至少 22000 kbps")
        return value

    @model_validator(mode="after")
    def valid_vlans(self):
        if len(set(self.tagged_vlans)) != len(self.tagged_vlans):
            raise ValueError("Tagged VLAN 不能重复")
        if self.vlan_mode == "access" and self.tagged_vlans:
            raise ValueError("Access 端口不能配置 Tagged VLAN")
        if self.pvid in self.tagged_vlans:
            raise ValueError("Native/PVID VLAN 不能同时作为 Tagged VLAN")
        if self.bpdu_guard and not self.edge:
            raise ValueError("BPDU 保护只适用于边缘端口")
        return self


class Vlan(Model):
    id: VlanNumber
    name: Label = ""


class Lag(Model):
    name: str = Field(pattern=r"^ae(?:[0-9]|[1-5][0-9]|6[0-3])$")
    members: list[PortNumber] = Field(min_length=1, max_length=16)
    mode: Literal["static", "active", "passive"] = "active"
    minimum_links: int = Field(default=1, ge=1, le=16)
    periodic: Literal["fast", "slow"] = "fast"


class StaticMac(Model):
    mac: str
    vlan: VlanNumber
    port: PortNumber

    @field_validator("mac")
    @classmethod
    def mac_address(cls, value):
        if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", value):
            raise ValueError("MAC 地址格式无效")
        if int(value[:2], 16) & 1 or value.lower() == "00:00:00:00:00:00":
            raise ValueError("静态 MAC 必须为非零单播地址")
        return value.lower()


class Rstp(Model):
    enabled: bool = True
    bridge_priority: int = Field(default=32768, ge=0, le=61440, multiple_of=4096)


class Lldp(Model):
    enabled: bool = True
    transmit_interval: int = Field(default=30, ge=5, le=3600)
    hold_multiplier: int = Field(default=4, ge=2, le=10)


class MulticastGroup(Model):
    address: str
    vlan: VlanNumber
    ports: list[PortNumber] = Field(min_length=1, max_length=24)

    @field_validator("address")
    @classmethod
    def multicast(cls, value):
        address = ipaddress.IPv4Address(value)
        if not address.is_multicast:
            raise ValueError("组地址必须是 IPv4 组播地址")
        return str(address)


class Igmp(Model):
    enabled: bool = False
    vlans: list[VlanNumber] = Field(default_factory=list, max_length=256)
    router_ports: list[PortNumber] = Field(default_factory=list)
    fast_leave_ports: list[PortNumber] = Field(default_factory=list)
    membership_timeout: int = Field(default=260, ge=10, le=3600)
    static_groups: list[MulticastGroup] = Field(default_factory=list, max_length=256)


class PfcWatchdog(Model):
    enabled: bool = False
    detect_ms: int = Field(default=5000, ge=1000, le=60000)
    recovery_ms: int = Field(default=100, ge=100, le=1000)
    cooldown_ms: int = Field(default=30000, ge=10000, le=600000)

    @model_validator(mode="after")
    def interval_order(self):
        if self.cooldown_ms < self.detect_ms:
            raise ValueError("PFC watchdog 冷却时间不能小于检测时间")
        return self


class Roce(Model):
    enabled: bool = False
    ports: list[PortNumber] = Field(default_factory=list, max_length=24)
    mode: Literal["static-pfc"] = "static-pfc"
    classification: Literal["pcp", "dscp"] = "pcp"
    dscp: int = Field(default=26, ge=0, le=63)
    cnp_dscp: int = Field(default=48, ge=0, le=63)
    dcbx: Literal["off", "ieee"] = "off"
    watchdog: PfcWatchdog = Field(default_factory=PfcWatchdog)
    priority: Literal[3] = 3
    cable_length_m: int = Field(default=10, ge=0, le=100)
    response_time_ns: int = Field(default=3000, ge=500, le=10000)

    @model_validator(mode="after")
    def unique_ports(self):
        if len(self.ports) != len(set(self.ports)):
            raise ValueError("RoCE 端口不能重复")
        if self.enabled and len(self.ports) < 2:
            raise ValueError("RoCE 至少需要两个参与端口")
        if self.classification == "dscp" and self.dscp == self.cnp_dscp:
            raise ValueError("RoCE 数据与 CNP 必须使用不同的 DSCP")
        return self


class Qos(Model):
    roce: Roce = Field(default_factory=Roce)
    trust: Literal["none", "ieee-802.1p"] = "none"
    default_priority: int = Field(default=0, ge=0, le=7)
    priority_map: list[Annotated[int, Field(ge=0, le=7)]] = Field(default_factory=lambda: list(range(8)), min_length=8, max_length=8)
    scheduler: Literal["strict", "drr"] = "drr"
    weights: list[Annotated[int, Field(ge=1, le=255)]] = Field(default_factory=lambda: [1] * 8, min_length=8, max_length=8)


class Mirror(Model):
    enabled: bool = False
    source: PortNumber | None = None
    destination: PortNumber | None = None
    direction: Literal["rx", "tx", "both"] = "both"

    @model_validator(mode="after")
    def endpoints(self):
        if self.enabled and (not self.source or not self.destination or self.source == self.destination):
            raise ValueError("镜像源和目的必须是不同的有效物理端口")
        return self


class FanCurve(Model):
    sensor: Literal["fm10840_core"] = "fm10840_core"
    idle_temperature_c: int = Field(default=35, ge=10, le=80)
    load_temperature_c: int = Field(default=70, ge=20, le=90)
    critical_temperature_c: int = Field(default=80, ge=30, le=100)
    idle_speed_percent: int = Field(default=50, ge=25, le=100)
    load_speed_percent: int = Field(default=80, ge=25, le=100)
    hysteresis_c: int = Field(default=4, ge=1, le=15)
    response_time_s: Literal[5.45, 10.9, 21.6, 43.7] = 10.9

    @model_validator(mode="after")
    def monotonic(self):
        if not self.idle_temperature_c + 10 <= self.load_temperature_c < self.critical_temperature_c:
            raise ValueError("负载温度至少比闲置高 10°C，临界温度必须更高")
        if self.load_speed_percent < self.idle_speed_percent:
            raise ValueError("负载 PWM 不能低于闲置 PWM")
        return self


class SwitchConfiguration(Model):
    schema_version: Literal[1] = 1
    profile: Literal["sil001-hw4-b0", "sil001-hw5-a11"] = "sil001-hw4-b0"
    groups: list[PortGroup] = Field(default_factory=lambda: [PortGroup(epl=e) for e in EPLS], min_length=6, max_length=6)
    ports: dict[int, PortConfig] = Field(default_factory=lambda: {p: PortConfig() for p in range(1, 25)})
    vlans: list[Vlan] = Field(default_factory=lambda: [Vlan(id=1, name="default")], max_length=4094)
    lags: list[Lag] = Field(default_factory=list, max_length=64)
    static_macs: list[StaticMac] = Field(default_factory=list, max_length=1024)
    mac_aging_seconds: int = Field(default=300, ge=10, le=1_000_000)
    rstp: Rstp = Field(default_factory=Rstp)
    lldp: Lldp = Field(default_factory=Lldp)
    igmp: Igmp = Field(default_factory=Igmp)
    qos: Qos = Field(default_factory=Qos)
    mirror: Mirror = Field(default_factory=Mirror)
    fan: FanCurve = Field(default_factory=FanCurve)

    def active_ports(self) -> set[int]:
        return {p for group in self.groups for p in group.active_ports()}

    def speed(self, port: int) -> int:
        return next((g.speed(port) for g in self.groups if port in g.active_ports()), 0)

    def references(self, port: int) -> list[str]:
        refs = []
        if self.qos.roce.enabled and port in self.qos.roce.ports: refs.append("RoCE")
        p = self.ports[port]
        if p.enabled: refs.append("管理启用")
        if p.pvid is not None or p.tagged_vlans: refs.append("VLAN")
        if p.edge or p.bpdu_guard or p.path_cost: refs.append("RSTP")
        if p.ingress_kbps or p.egress_kbps or any(p.storm.model_dump().values()): refs.append("流量策略")
        refs += [lag.name for lag in self.lags if port in lag.members]
        if any(entry.port == port for entry in self.static_macs): refs.append("静态 MAC")
        if self.mirror.enabled and port in (self.mirror.source, self.mirror.destination): refs.append("镜像")
        if port in self.igmp.router_ports or port in self.igmp.fast_leave_ports or any(port in g.ports for g in self.igmp.static_groups): refs.append("IGMP")
        return refs

    @model_validator(mode="after")
    def cross_validate(self):
        if {g.epl for g in self.groups} != set(EPLS):
            raise ValueError("必须且只能包含六个不同 EPL")
        if set(self.ports) != set(range(1, 25)):
            raise ValueError("必须保留 1–24 全部固定逻辑槽位")
        vids = {v.id for v in self.vlans}
        if len(vids) != len(self.vlans):
            raise ValueError("VLAN ID 不能重复")
        active = self.active_ports()
        controllers = sum(bool(p.ingress_kbps) + sum(bool(rate) for rate in p.storm.model_dump().values())
                          for p in self.ports.values())
        if controllers > STORM_CONTROLLER_CAPACITY:
            raise ValueError(f"风暴抑制与入口限速共需 {controllers} 个控制器，全卡最多 16 个")
        for port, cfg in self.ports.items():
            if port not in active and self.references(port):
                raise ValueError(f"端口 {port} 将被禁用，请先解除引用：{', '.join(self.references(port))}")
            if (set(cfg.tagged_vlans) | ({cfg.pvid} if cfg.pvid else set())) - vids:
                raise ValueError(f"端口 {port} 引用了不存在的 VLAN")
            if cfg.enabled and cfg.pvid is None and not cfg.tagged_vlans:
                raise ValueError(f"端口 {port} 启用前必须配置业务 VLAN")
            if any(rate > self.speed(port) * 1_000_000 for rate in [cfg.ingress_kbps, cfg.egress_kbps, *cfg.storm.model_dump().values()] if rate):
                raise ValueError(f"端口 {port} 的限速不能超过端口速率")
        if any(group.mode == "split" and group.split_vlan_backup is not None for group in self.groups):
            raise ValueError("拆分后的 VLAN 恢复记录应已还原到端口配置")
        members: set[int] = set()
        names = set()
        for lag in self.lags:
            if lag.name in names or len(set(lag.members)) != len(lag.members):
                raise ValueError("LAG 名称或成员重复")
            names.add(lag.name)
            if set(lag.members) - active or members & set(lag.members):
                raise ValueError("LAG 成员必须是有效端口，且不能属于其他 LAG")
            members.update(lag.members)
            if lag.minimum_links > len(lag.members):
                raise ValueError("minimum-links 不能超过成员数")
            profiles = {(self.speed(p), self.ports[p].mtu, self.ports[p].vlan_mode, self.ports[p].pvid,
                         tuple(sorted(self.ports[p].tagged_vlans)), self.ports[p].ingress_filtering) for p in lag.members}
            if len(profiles) != 1:
                raise ValueError(f"{lag.name} 成员的速率、MTU、VLAN 和入口过滤必须一致")
        from .roce import configuration_issues
        roce_errors = configuration_issues(self)
        if roce_errors:
            raise ValueError(roce_errors[0]["message"])
        seen_macs = set()
        for entry in self.static_macs:
            if entry.vlan not in vids or entry.port not in active:
                raise ValueError("静态 MAC 引用不存在的 VLAN/端口")
            p = self.ports[entry.port]
            if entry.vlan not in {p.pvid, *p.tagged_vlans}:
                raise ValueError("静态 MAC 的端口不是对应 VLAN 成员")
            key = (entry.mac, entry.vlan)
            if key in seen_macs: raise ValueError("静态 MAC/VLAN 条目重复")
            seen_macs.add(key)
        if self.mirror.enabled and ({self.mirror.source, self.mirror.destination} - active):
            raise ValueError("镜像引用了禁用的逻辑槽位")
        if self.mirror.enabled and self.mirror.destination in members:
            raise ValueError("镜像目的不能是 LAG 成员")
        if set(self.igmp.vlans) - vids:
            raise ValueError("IGMP 引用不存在的 VLAN")
        if (set(self.igmp.router_ports) | set(self.igmp.fast_leave_ports)) - active:
            raise ValueError("IGMP 引用无效端口")
        snooped_vlans = set(self.igmp.vlans) | {g.vlan for g in self.igmp.static_groups}
        for port in {*self.igmp.router_ports, *self.igmp.fast_leave_ports}:
            if not snooped_vlans.intersection({self.ports[port].pvid, *self.ports[port].tagged_vlans}):
                raise ValueError("IGMP 路由器/fast-leave 端口必须属于至少一个侦听 VLAN")
        for port in self.igmp.fast_leave_ports:
            if not self.ports[port].direct_receiver:
                raise ValueError("fast-leave 仅允许明确标记为直连接收器的端口")
        static_members = set()
        group_macs = {}
        group_keys = set()
        for group in self.igmp.static_groups:
            key = (group.vlan, group.address)
            if key in group_keys:
                raise ValueError("静态组播/VLAN 条目重复")
            group_keys.add(key)
            if group.vlan not in vids or set(group.ports) - active:
                raise ValueError("静态组播引用无效 VLAN/端口")
            if any(group.vlan not in {self.ports[p].pvid, *self.ports[p].tagged_vlans} for p in group.ports):
                raise ValueError("组播成员端口必须属于相应 VLAN")
            mac_key = (group.vlan, int(ipaddress.IPv4Address(group.address)) & 0x7fffff)
            if mac_key in group_macs and group_macs[mac_key] != group.address:
                raise ValueError("同一 VLAN 的静态组播地址不能映射到同一 MAC")
            group_macs[mac_key] = group.address
            routers = {p for p in self.igmp.router_ports
                       if group.vlan in {self.ports[p].pvid, *self.ports[p].tagged_vlans}}
            static_members.update((group.vlan, group.address, p) for p in set(group.ports) | routers)
        if len(static_members) > 32:
            raise ValueError("静态组播最多 32 个端口成员，包含各组的路由器端口")
        return self


class Proposal(Model):
    expected_revision: int = Field(ge=1)
    configuration: SwitchConfiguration


class CommitRequest(Model):
    draft_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    confirm_timeout: int = Field(default=60, ge=30, le=300)
    accept_bandwidth_warning: bool = False


class ManualPwm(Model):
    pwm_percent: int = Field(ge=25, le=100)
    duration_seconds: int = Field(default=60, ge=1, le=60)


class Credentials(Model):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{3,64}$")
    password: str = Field(min_length=12, max_length=256)


class AdministratorUpdate(Model):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{3,64}$")
    current_password: str = Field(min_length=1, max_length=256, repr=False)
    new_password: str | None = Field(default=None, min_length=12, max_length=256, repr=False)
    confirm_password: str | None = Field(default=None, min_length=12, max_length=256, repr=False)

    @model_validator(mode="after")
    def matching_passwords(self):
        if self.new_password != self.confirm_password:
            raise ValueError("两次输入的新密码不一致")
        return self
