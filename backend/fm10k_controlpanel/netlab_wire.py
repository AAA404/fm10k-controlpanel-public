"""Versioned native read contracts, matching libipc/mac_snapshot.c exactly."""
import struct

from .board import HardwareError

MAC_HEADER = struct.Struct("!IHHQIII")
MAC_ENTRY = struct.Struct("!HHb6sI")


def decode_mac_snapshot(payload: bytes) -> list[dict]:
    if len(payload) < MAC_HEADER.size:
        raise HardwareError("MAC 快照头不完整")
    magic, version, size, generation, total, count, flags = MAC_HEADER.unpack_from(payload)
    if (magic != 0x4E4D4143 or version != 1 or size != MAC_ENTRY.size or
            flags != 1 or total != count or count > 16384 or
            len(payload) != MAC_HEADER.size + count * MAC_ENTRY.size):
        raise HardwareError("MAC 快照不完整或协议不匹配；不会将截断结果显示为空表")
    result = []
    for vlan, port, ae_id, mac, age_flags in MAC_ENTRY.iter_unpack(payload[MAC_HEADER.size:]):
        if not 1 <= vlan <= 4094 or port == 0 or not -1 <= ae_id <= 63:
            raise HardwareError("MAC 快照包含无效条目")
        age_raw = age_flags & 0x7FFFFFFF
        is_static = bool(age_flags & 0x80000000)
        # IES 4.3.2 fm10000FillInUserEntryFromTable returns a YOUNG bit,
        # not elapsed seconds or a remaining aging timeout.
        age_state = "static" if is_static else {0: "aging", 1: "young"}.get(age_raw, "unknown")
        result.append({"vlan": vlan, "port": port, "lag": f"ae{ae_id}" if ae_id >= 0 else None,
                       "mac": ":".join(f"{octet:02x}" for octet in mac),
                       "age_seconds": None, "age_raw": age_raw, "age_state": age_state,
                       "type": "static" if is_static else "dynamic",
                       "quality": "valid", "source": "switchd", "generation": generation})
    return result
