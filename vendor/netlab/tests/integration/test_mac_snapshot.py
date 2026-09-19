#!/usr/bin/env python3.11
"""Versioned MAC snapshot boundary and formatter tests."""
from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bin" / "cli"))

from output_l2 import format_mac_snapshot  # noqa: E402


HEADER = struct.Struct("!IHHQIII")
ENTRY = struct.Struct("!HHb6sI")
MAGIC = 0x4E4D4143
COMPLETE = 1


C_ROUNDTRIP = r'''
#include "netlab/mac_snapshot.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int run_count(uint32_t count) {
    const size_t capacity = 28U + 15U * count;
    nl_mac_snapshot source = {0};
    nl_mac_snapshot decoded = {0};
    unsigned char *wire = malloc(capacity);
    int encoded;

    source.generation = UINT64_C(0x0102030405060708);
    source.total_entries = count;
    source.n_entries = count;
    source.complete = true;
    source.entries = calloc(count ? count : 1, sizeof(*source.entries));
    if (!wire || !source.entries)
        return 10;
    for (uint32_t i = 0; i < count; i++) {
        source.entries[i].vlan = (uint16_t)(i % 4094U + 1U);
        source.entries[i].port = (uint16_t)(i % 24U + 1U);
        source.entries[i].ae_id = (i % 2U) ? -1 : 0;
        source.entries[i].mac[0] = 0x02;
        source.entries[i].mac[5] = (unsigned char)i;
        source.entries[i].age = i & INT32_MAX;
        source.entries[i].is_static = (i % 3U) == 0;
    }
    encoded = nl_mac_snapshot_encode(&source, wire, capacity);
    if (encoded != (int)capacity ||
        nl_mac_snapshot_decode(wire, capacity, &decoded) != 0 ||
        decoded.generation != source.generation ||
        decoded.n_entries != count || !decoded.complete)
        return 11;
    if (count && (decoded.entries[count - 1U].vlan !=
                  source.entries[count - 1U].vlan ||
                  decoded.entries[count - 1U].is_static !=
                  source.entries[count - 1U].is_static))
        return 12;
    nl_mac_snapshot_reset(&source);
    nl_mac_snapshot_reset(&decoded);
    free(wire);
    return 0;
}

int main(void) {
    static const uint32_t counts[] = {0, 255, 256, 257, 2048, 16384};
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        int rc = run_count(counts[i]);
        if (rc)
            return rc;
    }
    return 0;
}
'''


def build_payload(count: int, *, complete: bool = True,
                  total: int | None = None) -> bytes:
    if total is None:
        total = count
    flags = COMPLETE if complete else 0
    payload = bytearray(HEADER.pack(
        MAGIC, 1, ENTRY.size, 0x0102030405060708, total, count, flags))
    for index in range(count):
        mac = bytes((0x02, (index >> 24) & 0xFF, (index >> 16) & 0xFF,
                     (index >> 8) & 0xFF, index & 0xFF, 1))
        payload.extend(ENTRY.pack(index % 4094 + 1, 1, 0, mac, index))
    return bytes(payload)


def check_c_roundtrip() -> None:
    with tempfile.TemporaryDirectory(prefix="netlab-mac-snapshot-") as td:
        binary = Path(td) / "roundtrip"
        compiled = subprocess.run(
            ["gcc", "-std=c11", "-Wall", "-Werror",
             "-I", str(ROOT / "include"), "-x", "c", "-",
             str(ROOT / "lib" / "libipc" / "mac_snapshot.c"),
             "-o", str(binary)],
            input=C_ROUNDTRIP,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=ROOT,
            env={**os.environ, "LC_ALL": "C"},
            check=False,
        )
        assert compiled.returncode == 0, compiled.stdout
        ran = subprocess.run(
            [str(binary)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, check=False,
        )
        assert ran.returncode == 0, ran.stdout


def check_python_boundaries() -> None:
    for count in (0, 255, 256, 257, 2048, 16384):
        rendered = format_mac_snapshot(build_payload(count))
        assert not rendered.startswith("error:"), rendered
        assert f"Total learned addresses : {count}" in rendered

    assert format_mac_snapshot(b"").startswith(
        "error: invalid MAC snapshot")
    assert format_mac_snapshot(build_payload(1)[:-1]).startswith(
        "error: invalid MAC snapshot")
    assert format_mac_snapshot(build_payload(
        1, complete=False, total=2)) == "error: incomplete MAC snapshot"
    corrupt = bytearray(build_payload(1))
    corrupt[0:4] = struct.pack("!I", 0)
    assert format_mac_snapshot(corrupt).startswith(
        "error: invalid MAC snapshot")


def main() -> int:
    check_c_roundtrip()
    check_python_boundaries()
    print("OK: versioned MAC snapshot boundaries are exact through 16384")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
