import struct

import pytest

from fm10k_controlpanel.board import HardwareError
from fm10k_controlpanel.netlab_wire import decode_mac_snapshot


def fixture(count=2, flags=1):
    # Independent byte contract from the vendored C encoder's packed structs.
    header = struct.pack("!IHHQIII", 0x4E4D4143, 1, 15, 0x0102030405060708, count, count, flags)
    entries = [struct.pack("!HHb6sI", 100, i % 24 + 1, -1 if i % 2 else 0,
                           b"\x02\x00\x00\x00" + i.to_bytes(2, "big"),
                           0x80000000 if i % 2 else 37) for i in range(count)]
    return header + b"".join(entries)


def test_native_fdb_all_16384_entries_and_aggregation():
    entries = decode_mac_snapshot(fixture(16384))
    assert len(entries) == 16384
    assert entries[0]["lag"] == "ae0" and entries[1]["lag"] is None
    assert entries[0]["type"] == "dynamic" and entries[0]["age_seconds"] is None
    assert entries[0]["age_raw"] == 37 and entries[0]["age_state"] == "unknown"
    assert entries[1]["type"] == "static" and entries[-1]["mac"] == "02:00:00:00:3f:ff"


@pytest.mark.parametrize("payload", [b"", fixture()[:-1], fixture(flags=0), fixture(flags=2), fixture() + b"x"])
def test_native_fdb_never_silently_accepts_partial_results(payload):
    with pytest.raises(HardwareError):
        decode_mac_snapshot(payload)


@pytest.mark.parametrize("raw,expected", [(0, "aging"), (1, "young"), (37, "unknown"), (0x80000001, "static")])
def test_native_fdb_age_is_an_sdk_flag_not_seconds(raw, expected):
    header = struct.pack("!IHHQIII", 0x4E4D4143, 1, 15, 1, 1, 1, 1)
    entry = struct.pack("!HHb6sI", 10, 100, 63, bytes.fromhex("020000000001"), raw)
    decoded = decode_mac_snapshot(header + entry)[0]
    assert decoded["age_seconds"] is None
    assert decoded["age_raw"] == raw & 0x7FFFFFFF
    assert decoded["age_state"] == expected and decoded["lag"] == "ae63"


def test_native_fdb_rejects_unsupported_lag_identity():
    header = struct.pack("!IHHQIII", 0x4E4D4143, 1, 15, 1, 1, 1, 1)
    entry = struct.pack("!HHb6sI", 10, 100, 64, bytes.fromhex("020000000001"), 1)
    with pytest.raises(HardwareError, match="无效条目"):
        decode_mac_snapshot(header + entry)
