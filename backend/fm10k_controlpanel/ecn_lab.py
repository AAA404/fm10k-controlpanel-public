"""Software ECN commissioning primitives, deliberately outside the ASIC backend.

Linux RED owns the marking decision and the queued packets. Nothing here polls
ASIC occupancy, writes SDK state, or enables an unsupported switch RoCE mode.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import math
from pathlib import Path
import struct


MAGIC = b"FMECN001"
PAYLOAD_SIZE = 1024
PCAP_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


@dataclass(frozen=True)
class EcnLabProfile:
    rate_kbit: int = 1000
    min_bytes: int = 8192
    max_bytes: int = 24576
    limit_bytes: int = 65536
    probability: float = 1.0
    data_dscp: int = 26
    cnp_dscp: int = 48
    vlan: int = 10

    def __post_init__(self):
        for key in ("rate_kbit", "min_bytes", "max_bytes", "limit_bytes",
                    "data_dscp", "cnp_dscp", "vlan"):
            if type(getattr(self, key)) is not int:
                raise ValueError(f"{key} must be an integer")
        if not 100 <= self.rate_kbit <= 100_000:
            raise ValueError("software lab rate must be 100..100000 kbit/s")
        if not 2048 <= self.min_bytes < self.max_bytes < self.limit_bytes <= 1_048_576:
            raise ValueError("require 2048 <= min < max < limit <= 1048576 bytes")
        if (isinstance(self.probability, bool) or
                not isinstance(self.probability, (int, float)) or
                not math.isfinite(self.probability) or not 0 < self.probability <= 1):
            raise ValueError("probability must be finite and in (0, 1]")
        if not 0 <= self.data_dscp <= 63 or not 0 <= self.cnp_dscp <= 63:
            raise ValueError("DSCP must be 0..63")
        if self.data_dscp == self.cnp_dscp:
            raise ValueError("data and CNP DSCP must differ")
        if not 1 <= self.vlan <= 4094:
            raise ValueError("VLAN must be 1..4094")

    def commands(self) -> list[list[str]]:
        """Commands for the owned lab's `out` veth, never a hardware interface.

        Data UDP/4791 gets a shaped RED queue. CNP DSCP and all unmatched
        traffic have separate FIFO queues. Both untagged and 802.1Q IPv4/6
        are classified with a six-bit DSCP mask, preserving ECN bits.
        """
        parent_rate = f"{self.rate_kbit * 20}kbit"
        rate = f"{self.rate_kbit}kbit"
        commands = [
            ["qdisc", "add", "dev", "out", "root", "handle", "1:", "htb", "default", "30"],
            ["class", "add", "dev", "out", "parent", "1:", "classid", "1:1", "htb",
             "rate", parent_rate, "ceil", parent_rate],
        ]
        for class_id, priority, ceiling in (("10", "1", rate), ("20", "0", parent_rate),
                                            ("30", "2", parent_rate)):
            commands.append(["class", "add", "dev", "out", "parent", "1:1", "classid",
                             f"1:{class_id}", "htb", "rate", rate, "ceil", ceiling,
                             "prio", priority, "quantum", "1514", "burst", "4096"])
        burst = max(2, (self.min_bytes + self.max_bytes) // (3 * 1100))
        commands.append(["qdisc", "add", "dev", "out", "parent", "1:10", "handle", "10:",
                         "red", "limit", str(self.limit_bytes), "min", str(self.min_bytes),
                         "max", str(self.max_bytes), "avpkt", "1100", "burst", str(burst),
                         "bandwidth", rate, "probability", str(self.probability), "ecn"])
        for class_id in ("20", "30"):
            commands.append(["qdisc", "add", "dev", "out", "parent", f"1:{class_id}",
                             "handle", f"{class_id}:", "pfifo", "limit", "4096"])
        for dscp, class_id, priority in ((self.cnp_dscp, "20", 1), (self.data_dscp, "10", 10)):
            for family_index, family in enumerate(("ip", "ipv6")):
                for tagged in (False, True):
                    protocol = "802.1Q" if tagged else family
                    vlan = ["vlan_id", str(self.vlan), "vlan_ethtype", family] if tagged else []
                    commands.append(["filter", "add", "dev", "out", "parent", "1:", "protocol",
                                     protocol, "prio", str(priority + family_index * 2 + int(tagged)),
                                     "flower", "skip_hw", *vlan, "ip_proto", "udp", "ip_tos",
                                     f"0x{dscp << 2:02x}/0xfc", "dst_port", "4791",
                                     "classid", f"1:{class_id}"])
        return commands

    def describe(self):
        return {"backend": "linux-red-lab", "scope": "isolated-veth-bridge",
                "hardware_offload": False, "asic_ecn": "unsupported",
                "rdma_validation": "not-run", "profile": asdict(self),
                "tc_commands": self.commands()}


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return ~total & 65535


def cases(profile: EcnLabProfile) -> list[dict]:
    result = []
    other_dscp = next(n for n in range(64) if n not in (profile.data_dscp, profile.cnp_dscp))
    for family in (4, 6):
        for vlan in (None, profile.vlan):
            for ecn in range(4):
                result.append({"family": family, "vlan": vlan, "dscp": profile.data_dscp,
                               "ecn": ecn, "port": 4791, "queue": "data"})
            for dscp, port, queue in ((profile.cnp_dscp, 4791, "cnp"),
                                      (profile.data_dscp, 4792, "other-port"),
                                      (other_dscp, 4791, "other-dscp")):
                result.append({"family": family, "vlan": vlan, "dscp": dscp,
                               "ecn": 2, "port": port, "queue": queue})
    return result


def make_frame(case: dict, run_id: bytes, stage: int, case_id: int, sequence: int) -> bytes:
    """Synthetic UDP probes; these are not valid RDMA operations or CNPs."""
    if len(run_id) != 16:
        raise ValueError("run id must contain 16 bytes")
    marker = struct.pack("!8s16sBBI", MAGIC, run_id, stage, case_id, sequence)
    payload = marker + bytes((i & 255 for i in range(PAYLOAD_SIZE - len(marker))))
    udp = struct.pack("!HHHH", 49152 + case_id, case["port"], 8 + len(payload), 0) + payload
    tos = (case["dscp"] << 2) | case["ecn"]
    if case["family"] == 4:
        addresses = ipaddress.ip_address("198.18.0.1").packed + ipaddress.ip_address("198.18.0.2").packed
        pseudo = addresses + struct.pack("!BBH", 0, 17, len(udp))
        header = struct.pack("!BBHHHBBH", 0x45, tos, 20 + len(udp), sequence & 65535,
                             0x4000, 64, 17, 0) + addresses
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        ethertype = 0x0800
    else:
        addresses = ipaddress.ip_address("2001:db8:ec::1").packed + ipaddress.ip_address("2001:db8:ec::2").packed
        pseudo = addresses + struct.pack("!I3xB", len(udp), 17)
        header = struct.pack("!IHBB", (6 << 28) | (tos << 20) | 0x12345, len(udp), 17, 64) + addresses
        ethertype = 0x86DD
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 65535) + udp[8:]
    ethernet = bytes.fromhex("02ec0000000202ec00000001")
    if case["vlan"] is not None:
        ethernet += struct.pack("!HH", 0x8100, (3 << 13) | case["vlan"])
    return ethernet + struct.pack("!H", ethertype) + header + udp


def parse_frame(frame: bytes) -> dict | None:
    """Decode a lab probe and retain independent checksum/header evidence."""
    if MAGIC not in frame:
        return None
    if len(frame) < 14:
        raise ValueError("short Ethernet frame")
    offset, ethertype, tags = 14, struct.unpack_from("!H", frame, 12)[0], []
    while ethertype in (0x8100, 0x88A8):
        if len(tags) >= 2 or len(frame) < offset + 4:
            raise ValueError("invalid VLAN header")
        tci, inner = struct.unpack_from("!HH", frame, offset)
        tags.append([ethertype, tci])
        ethertype, offset = inner, offset + 4
    ip_offset = offset
    normalized = bytearray(frame)
    if ethertype == 0x0800:
        if len(frame) < offset + 20 or frame[offset] != 0x45 or frame[offset + 9] != 17:
            raise ValueError("probe must be unfragmented IPv4 UDP without options")
        length = struct.unpack_from("!H", frame, offset + 2)[0]
        if struct.unpack_from("!H", frame, offset + 6)[0] & 0x3FFF:
            raise ValueError("fragmented probe")
        end = offset + length
        tos, family = frame[offset + 1], 4
        valid_ip = checksum(frame[offset:offset + 20]) == 0
        pseudo_address = frame[offset + 12:offset + 20]
        normalized[offset + 1] &= 0xFC
        normalized[offset + 10:offset + 12] = b"\0\0"
        offset += 20
    elif ethertype == 0x86DD:
        if len(frame) < offset + 40 or frame[offset] >> 4 != 6 or frame[offset + 6] != 17:
            raise ValueError("probe must be IPv6 UDP without extension headers")
        end = offset + 40 + struct.unpack_from("!H", frame, offset + 4)[0]
        tos, family, valid_ip = ((frame[offset] & 15) << 4) | (frame[offset + 1] >> 4), 6, True
        pseudo_address = frame[offset + 8:offset + 40]
        normalized[offset + 1] &= 0xCF
        offset += 40
    else:
        raise ValueError("probe has unexpected Ethernet type")
    if end != len(frame) or end < offset + 8 + 30:
        raise ValueError("inconsistent IP length")
    source, destination, udp_length, udp_checksum = struct.unpack_from("!HHHH", frame, offset)
    if udp_length != end - offset or udp_checksum == 0:
        raise ValueError("missing probe UDP checksum or inconsistent UDP length")
    payload = frame[offset + 8:end]
    magic, run_id, stage, case_id, sequence = struct.unpack_from("!8s16sBBI", payload)
    if magic != MAGIC:
        raise ValueError("invalid probe marker")
    pseudo = pseudo_address + (struct.pack("!BBH", 0, 17, udp_length) if family == 4
                               else struct.pack("!I3xB", udp_length, 17))
    return {"key": (run_id.hex(), stage, case_id, sequence), "family": family,
            "dscp": tos >> 2, "ecn": tos & 3, "tags": tags, "source_port": source,
            "destination_port": destination, "ip_checksum_valid": valid_ip,
            "udp_checksum_valid": checksum(pseudo + frame[offset:end]) == 0,
            "unchanged_digest": hashlib.sha256(normalized).hexdigest(), "ip_offset": ip_offset}


def write_packet(file, frame: bytes, timestamp: float):
    seconds = int(timestamp)
    file.write(struct.pack("<IIII", seconds, int((timestamp - seconds) * 1_000_000), len(frame), len(frame)))
    file.write(frame)


def read_capture(path: Path) -> dict[tuple, dict]:
    frames = {}
    with path.open("rb") as file:
        if file.read(24) != PCAP_HEADER:
            raise ValueError(f"unexpected pcap header: {path}")
        while header := file.read(16):
            if len(header) != 16:
                raise ValueError("truncated pcap packet header")
            _, _, captured, original = struct.unpack("<IIII", header)
            if captured != original or not 14 <= captured <= 65535:
                raise ValueError("truncated or invalid pcap frame")
            raw = file.read(captured)
            if len(raw) != captured:
                raise ValueError("truncated pcap packet")
            item = parse_frame(raw)
            if item:
                if item["key"] in frames:
                    raise ValueError("duplicate probe captured")
                frames[item["key"]] = item
    return frames


def verify_stage(profile: EcnLabProfile, stage: int, sent: dict, ingress: dict, egress: dict) -> dict:
    """Fail closed: empty captures and kernel-only counters cannot pass."""
    errors, rows = [], []
    entries = cases(profile)
    if stage not in (0, 1, 2):
        raise ValueError("invalid verification stage")
    if not sent or set(sent) != set(ingress):
        errors.append("sender and bridge ingress captures differ or are empty")
    if len({k[0] for k in sent}) != 1:
        errors.append("missing or mixed run identifiers")
    for key, packet in sent.items():
        if key[1] != stage or not 0 <= key[2] < len(entries):
            errors.append("unexpected probe stage or case")
            continue
        case = entries[key[2]]
        tags = [[0x8100, (3 << 13) | case["vlan"]]] if case["vlan"] is not None else []
        if (any(packet[field] != case[field] for field in ("family", "dscp", "ecn")) or
                packet["tags"] != tags or packet["destination_port"] != case["port"] or
                packet["source_port"] != 49152 + key[2]):
            errors.append(f"submitted probe does not match the declared case: {key}")
    if not set(egress) <= set(ingress):
        errors.append("egress contains probes absent from ingress")
    for key, before in ingress.items():
        after = egress.get(key)
        if not before["ip_checksum_valid"] or not before["udp_checksum_valid"]:
            errors.append(f"invalid ingress checksum: {key}")
        if key in sent and before != sent[key]:
            errors.append(f"probe changed before the ECN bridge: {key}")
        if not after:
            continue
        if not after["ip_checksum_valid"] or not after["udp_checksum_valid"]:
            errors.append(f"invalid egress checksum: {key}")
        if before["unchanged_digest"] != after["unchanged_digest"]:
            errors.append(f"fields other than ECN/IPv4 checksum changed: {key}")
        allowed = (before["ecn"], 3) if before["ecn"] in (1, 2) else (before["ecn"],)
        if after["ecn"] not in allowed:
            errors.append(f"illegal ECN transition: {key}")
    for index, case in enumerate(entries):
        keys = {k for k in ingress if k[1] == stage and k[2] == index}
        received = keys & egress.keys()
        marked = sum(ingress[k]["ecn"] in (1, 2) and egress[k]["ecn"] == 3 for k in received)
        dropped = len(keys - received)
        label = f"IPv{case['family']}/vlan={case['vlan']}/{case['queue']}/ecn={case['ecn']}"
        rows.append({"case": label, "ingress": len(keys), "egress": len(received),
                     "marked_ce": marked, "not_received": dropped})
        # It is valid for congestion to drop every Not-ECT data probe. The
        # idle/recovery stages independently require those probes to pass.
        all_non_ect_dropped = stage == 1 and case["queue"] == "data" and case["ecn"] == 0
        if not keys or (not received and not all_non_ect_dropped):
            errors.append(f"missing packet evidence: {label}")
        if stage == 2 and case["queue"] == "data":
            # RED uses an exponentially weighted average. Preserve and report
            # the settling transient, then require two clean final probes per
            # case without resetting/replacing the qdisc to manufacture a pass.
            window = set(sorted(keys, key=lambda k: k[3])[-2:])
            window_received = window & egress.keys()
            window_marks = sum(ingress[k]["ecn"] in (1, 2) and egress[k]["ecn"] == 3
                               for k in window_received)
            rows[-1]["steady_window"] = {"ingress": len(window), "egress": len(window_received),
                                         "marked_ce": window_marks}
            if len(keys) < 3 or len(window_received) != 2 or window_marks:
                errors.append(f"ECN did not settle after congestion: {label}")
        elif stage != 1 or case["queue"] != "data":
            if dropped or marked:
                errors.append(f"uncongested or bypass traffic changed/lost: {label}")
        elif case["ecn"] in (1, 2) and not marked:
            errors.append(f"no ECT to CE transition under congestion: {label}")
        elif case["ecn"] == 0 and not dropped:
            errors.append(f"no non-ECT congestion drop observed: {label}")
    return {"stage": ("idle", "congested", "recovered")[stage], "passed": not errors,
            "cases": rows, "errors": errors[:50], "error_count": len(errors)}
