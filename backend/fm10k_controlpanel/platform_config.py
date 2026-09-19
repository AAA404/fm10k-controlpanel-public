"""Generate boot artifacts from configd's intent; never an active config store.

The fixed resource encoding and lane-zero SerDes anchoring follow the supplied
Switch Stack v1.3.2 generate_platform implementation. Original source hashes
are recorded in SOURCE_MANIFEST.json.
"""
from __future__ import annotations

import hashlib
import re

from .models import PHYSICAL, SwitchConfiguration
from .profiles import PROFILES

PREFIX = "api.platform.config.switch.0.portIndex."
PORT_VALUE = re.compile(r"^api\.platform\.config\.switch\.0\.portIndex\.(\d+)\.(\S+)\s+(\w+)\s+(.+?)\s*$")
# The factory image used a newer SDK. These keys are absent from the pinned
# IES 4.3.2 property table and were rejected during native A11 startup. Keep
# the factory file/hash intact; remove only these keys in generated artifacts.
IES432_UNSUPPORTED_PROPERTIES = frozenset((
    "api.mailbox.ignoreMbxMacUpdates", "api.event.countLogicalPortEvents",
))


def sdk_mode(config, epl, lane):
    group = next(g for g in config.groups if g.epl == epl)
    if group.mode != "split":
        return f"{group.mode[:-1]}GBase-SR4" if lane == 0 else "DISABLED"
    return f"{group.lane_speeds[lane]}GBase-SR"


def render_sdk_platform(base: str, config: SwitchConfiguration) -> str:
    profile = PROFILES[config.profile]
    if hashlib.sha256(base.encode()).hexdigest() != profile.sha256:
        raise ValueError(f"SDK reference digest does not match {config.profile}; board inputs cannot be interchanged")
    values = {}
    for line in base.splitlines():
        match = PORT_VALUE.match(line)
        if match:
            port, name, kind, value = match.groups()
            values.setdefault(int(port), {})[name] = (kind, value)
    if "api.platform.config.platformName text sil001" not in base:
        raise ValueError("SDK base is not the supplied sil001 profile")
    default_polarity = re.findall(
        r"(?m)^api\.platform\.config\.switch\.0\.port\.default\.lanePolarity\s+(text)\s+(INVERT_(?:NONE|RX|TX|RX_TX))\s*$", base)
    if len(default_polarity) > 1:
        raise ValueError("duplicate default Lane polarity")
    lines = [line for line in base.splitlines()
             if (not (match := PORT_VALUE.match(line)) or int(match[1]) == 0)
             and not re.match(r"^api\.perLagManagement\s", line)
             and not re.match(r"^api\.platform\.config\.switch\.0\.fci\s", line)
             and not re.match(r"^api\.FM10000\.(wmSelect|cmPauseBufferBytes)\s", line)
             and (not line.split() or line.split()[0] not in IES432_UNSUPPORTED_PROPERTIES)]
    rendered = "\n".join(lines).rstrip()
    for name, value in (("numPorts", 30), ("cpuPort", 27)):
        rendered, count = re.subn(rf"(?m)^(api\.platform\.config\.switch\.0\.{name}\s+int\s+)\d+\s*$",
                                  lambda match: match[1] + str(value), rendered)
        if count != 1:
            raise ValueError(f"base has an invalid {name} entry")
    lines = [rendered, "", "# Generated from configd; edit intent through its transaction interface.",
             "# IES 4.3.2 compatibility: omit unsupported ignoreMbxMacUpdates/countLogicalPortEvents.",
             "# The SDK hardcodes OBT setup to logical ports 1/4. Both are on MPO1 in this inventory.",
             "# switchd initializes each physical mux with ports closed and verified readback.",
             "api.platform.config.switch.0.fci text off",
             "api.perLagManagement bool true",
             "# Static PFC buffer envelope; enabling PFC remains a configd transaction.",
             "api.FM10000.wmSelect text lossy_lossless",
             "api.FM10000.cmPauseBufferBytes int 49152"]
    def add(port, suffix, kind, value):
        lines.append(f"{PREFIX}{port}.{suffix} {kind} {value}")
    for index, (epl, physical) in enumerate(PHYSICAL.items()):
        source = values.get(index + 1, {})
        lines.extend(["", f"# OBT{physical['mpo']}, EPL{epl}, fixed slots {physical['base']}..{physical['base'] + 3}"])
        for lane in range(4):
            number = physical["base"] + lane
            add(number, "portMapping", "text", f'"LOG={number} EPL={epl} LANE={lane}"')
            add(number, "interfaceType", "text", f"QSFP_LANE{lane}")
            add(number, "dfeMode", "text", "ONE_SHOT")
            if "linkOptimMode" in source:
                add(number, "linkOptimMode", *source["linkOptimMode"])
            # These are allocated capacities, not measured/guaranteed throughput.
            add(number, "speed", "int", 100000 if lane == 0 else 25000)
            add(number, "ethernetMode", "text", sdk_mode(config, epl, lane))
            add(number, "capability", "text", "LAG,ROUTE,10G,25G,40G,100G")
            add(number, "hwResourceId", "int", f"0x{(lane << 8) | index:03x}")
        for lane in range(4):
            names = ("lanePolarity", "rxTermination", "preCursor25GOptical", "cursor25GOptical", "postCursor25GOptical")
            if f"lane.{lane}.lanePolarity" not in source and not default_polarity:
                raise ValueError(f"missing physical EPL{epl} lane{lane} polarity in the reference")
            for name in names:
                entry = source.get(f"lane.{lane}.{name}")
                if name == "lanePolarity" and entry is None and default_polarity:
                    entry = default_polarity[0]
                if entry:
                    add(physical["base"], f"lane.{lane}.{name}", *entry)
    for port, mapping, speed in ((25, "PCIE=0", 0), (26, "PCIE=2", 0),
                                  (27, "PCIE=4", 10000), (28, "TE=0", 0), (29, "TE=1", 0)):
        add(port, "portMapping", "text", f'"LOG={port} {mapping}"')
        add(port, "speed", "int", speed)
    return "\n".join(lines) + "\n"


def render_netlab_profile(config: SwitchConfiguration, *, system_mac: str, serial: str) -> str:
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", system_mac) or int(system_mac[:2], 16) & 1:
        raise ValueError("a unicast system MAC is required")
    if system_mac.lower() == "00:00:00:00:00:00":
        raise ValueError("zero is not a system MAC")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", serial):
        raise ValueError("serial must be a plain profile token")
    lines = [
        "# Generated boot inventory. Runtime topology changes are owned by switchd/configd.",
        f'platform model=FM10840 chassis-name={config.profile} serial={serial} system-name=FM10K '
        f'system-description="FM10840 L2 Control Panel" system-mac={system_mac.lower()} max-ae=64 '
        'rstp-bridge-priority=32768 rstp-hello-sec=2 rstp-bpdu-stale-sec=180 '
        'lacp-system-priority=32768 lacp-port-priority=32768 lacp-ttl-sec=90',
        'board model=PE31625G24DiRA-MPS asic=FM10840 fci-count=2 i2c-bus=0 mux-address=0x58 '
        'cpld-ram-address=0x59 reset-gpio-address=0x64 fci0-mux=0x01 fci1-mux=0x02 '
        'environment-mux=0x04 power-mux=0x08 shared-memory-bytes=4194304 tcam-entries=32768 mac-nexthop-entries=16384',
        'switch index=0 number=0 uio-dev=/dev/uio0 cpu-port=27 management-pep=4',
        'ffu ipv4-uc-first=-1 ipv4-uc-last=-1 ipv4-mc-first=-1 ipv4-mc-last=-1 ipv6-uc-first=-1 '
        'ipv6-uc-last=-1 ipv6-mc-first=-1 ipv6-mc-last=-1 acl-first=0 acl-last=31 '
        'cvlan-first=-1 cvlan-last=-1 bst-routing-first=-1 bst-routing-last=-1',
    ]
    for index, (epl, physical) in enumerate(PHYSICAL.items()):
        for lane in range(4):
            resource = (lane << 8) | index
            lines.append(f"xcvr resource-id={resource} type=QSFP i2c-bus=switchI2C mux-index=0 "
                         f"mux-value={physical['mpo']} state-gpio-index=0 state-gpio-base={physical['mpo'] - 1}")
            number = physical["base"] + lane
            speed = config.speed(number) * 1_000_000_000
            lines.append(
                f"port name=et-0/0/{number - 1} interface-id={1000 + number} media=et fpc=0 pic=0 port={number - 1} "
                f"switch-index=0 port-index={number} logical-port={number} front-panel-port={number} role=external "
                f"interface-type=QSFP_LANE{lane} ethernet-mode={sdk_mode(config, epl, lane)} "
                f"capabilities=LAG,10G,25G,40G,100G hw-resource-id={resource} epl-port={epl} lane={lane} "
                f"default-speed={speed} line-rate={speed} scheduler-speed={speed} "
                "supported-speeds=10000000000,25000000000,40000000000,100000000000 "
                "rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp")
    for number, name, pcie, role, speed in ((25, "pcie0", 0, "internal", 0),
                                           (26, "pcie2", 2, "internal", 0),
                                           (27, "cpu0", 4, "cpu-control", 10_000_000_000)):
        flags = "hidden,cpu-control" if number == 27 else "hidden"
        lines.append(f"port name={name} interface-id={2000 + number} media=et fpc=0 pic=0 port={number - 1} "
                     f"switch-index=0 port-index={number} logical-port={number} front-panel-port={number} "
                     f"role={role} pcie-port={pcie} default-speed={speed} line-rate={speed} scheduler-speed={speed} flags={flags}")
    return "\n".join(lines) + "\n"
