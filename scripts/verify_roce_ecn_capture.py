#!/usr/bin/env python3
"""Check original IPv4 RoCE packets across an external ECN marking queue.

Validates equal, unique QP/PSN samples, IP/UDP checksums, ECT -> CE, and byte
preservation (including payload and ICRC). Also checks actual returning CNPs.
ICRC is compared, not recalculated. NIC counters and successful verbs transfers
are separate evidence. A passing captured prefix is not a losslessness, rate,
whole-run CNP count, ASIC capability, or complete DCQCN acceptance result.
Python 3.6+, standard library only.
"""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import struct


def checksum(raw):
    if len(raw) % 2:
        raw += b"\0"
    total = sum(struct.unpack("!%dH" % (len(raw) // 2), raw))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def decode(raw):
    if len(raw) < 14:
        raise ValueError("truncated Ethernet header")
    offset, ether = 14, int.from_bytes(raw[12:14], "big")
    while ether in (0x8100, 0x88a8) and len(raw) >= offset + 4:
        ether = int.from_bytes(raw[offset + 2:offset + 4], "big")
        offset += 4
    if ether != 0x0800 or len(raw) < offset + 20 or raw[offset] >> 4 != 4:
        raise ValueError("expected complete IPv4 RoCE frame")
    ihl = (raw[offset] & 15) * 4
    total = int.from_bytes(raw[offset + 2:offset + 4], "big")
    if ihl < 20 or total < ihl + 24 or len(raw) < offset + total:
        raise ValueError("truncated IPv4/UDP/BTH/ICRC")
    if raw[offset + 9] != 17 or int.from_bytes(raw[offset + 6:offset + 8], "big") & 0x3fff:
        raise ValueError("expected unfragmented UDP")
    if checksum(raw[offset:offset + ihl]):
        raise ValueError("invalid IPv4 checksum")
    udp = offset + ihl
    sport, dport, length, udp_sum = struct.unpack_from("!4H", raw, udp)
    if dport != 4791 or length != total - ihl:
        raise ValueError("invalid RoCE UDP port/length")
    pseudo = raw[offset + 12:offset + 20] + struct.pack("!BBH", 0, 17, length)
    if udp_sum and checksum(pseudo + raw[udp:udp + length]):
        raise ValueError("invalid UDP checksum")
    bth = udp + 8
    source = str(ipaddress.IPv4Address(raw[offset + 12:offset + 16]))
    destination = str(ipaddress.IPv4Address(raw[offset + 16:offset + 20]))
    qpn = int.from_bytes(raw[bth + 5:bth + 8], "big")
    psn = int.from_bytes(raw[bth + 9:bth + 12], "big")
    unchanged = bytearray(raw)
    unchanged[offset + 1] &= 0xfc
    unchanged[offset + 10:offset + 12] = b"\0\0"
    return {"key": (source, destination, sport, dport, qpn, psn), "qpn": qpn,
            "source": source, "destination": destination, "psn": psn, "opcode": raw[bth],
            "dscp": raw[offset + 1] >> 2, "ecn": raw[offset + 1] & 3,
            "unchanged_sha256": hashlib.sha256(unchanged).hexdigest()}


def capture(path):
    packets = []
    with Path(path).open("rb") as stream:
        header = stream.read(24)
        magics = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                  b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
        endian = magics.get(header[:4])
        if len(header) != 24 or endian is None or struct.unpack_from(endian + "I", header, 20)[0] != 1:
            raise ValueError("expected Ethernet pcap")
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError("truncated pcap record")
            _sec, _subsec, saved, original = struct.unpack(endian + "IIII", record)
            if saved != original or not 14 <= saved <= 65535:
                raise ValueError("pcap contains a truncated or oversized frame")
            raw = stream.read(saved)
            if len(raw) != saved:
                raise ValueError("truncated pcap frame")
            packets.append(decode(raw))
            if len(packets) > 1_000_000:
                raise ValueError("capture exceeds the analysis packet limit")
    return packets


def verify(ingress, egress, cnps, source, destination, receiver_qpn, sender_qpn,
           data_dscp=26, cnp_dscp=48):
    errors = []
    before, after = {}, {}
    for label, packets, indexed in (("ingress", ingress, before), ("egress", egress, after)):
        for p in packets:
            if p["key"] in indexed:
                if len(errors) < 20:
                    errors.append(label + ": duplicate QP/PSN; cannot prove original delivery")
            indexed[p["key"]] = p
            if (p["source"], p["destination"], p["qpn"], p["dscp"]) != (source, destination, receiver_qpn, data_dscp) or p["opcode"] not in (6, 7, 8, 10):
                if len(errors) < 20:
                    errors.append(label + ": unexpected flow, DSCP or Write opcode")
    if not before or set(before) != set(after):
        errors.append("nonempty identical QP/PSN samples required on both sides")
    marked = 0
    for key in set(before) & set(after):
        a, b = before[key], after[key]
        if a["unchanged_sha256"] != b["unchanged_sha256"]:
            if len(errors) < 20:
                errors.append("bytes other than ECN and IPv4 checksum changed")
        if a["ecn"] in (1, 2) and b["ecn"] == 3:
            marked += 1
        elif a["ecn"] != b["ecn"] and len(errors) < 20:
            errors.append("invalid ECN transition")
    if not marked:
        errors.append("no observed ECT -> CE conversion")
    if not cnps:
        errors.append("no returning CNP captured")
    for p in cnps:
        if (p["source"], p["destination"], p["qpn"], p["opcode"], p["dscp"]) != (destination, source, sender_qpn, 0x81, cnp_dscp):
            if len(errors) < 20:
                errors.append("unexpected CNP IP pair, target QP, opcode or DSCP")
    return {"scope": "observed IPv4 Write/CNP samples across an external RED queue",
            "passed": not errors, "errors": errors, "ingress_packets": len(ingress),
            "egress_packets": len(egress), "new_ce": marked, "cnp_samples": len(cnps),
            "ingress_ecn": dict(Counter(p["ecn"] for p in ingress)),
            "egress_ecn": dict(Counter(p["ecn"] for p in egress)),
            "receiver_qpn": receiver_qpn, "sender_qpn": sender_qpn,
            "preservation": "all captured bytes except ECN and IPv4 checksum, including ICRC"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("ingress", "egress", "cnp", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source", "destination"):
        parser.add_argument("--" + name, type=ipaddress.IPv4Address, required=True)
    for name in ("receiver-qpn", "sender-qpn"):
        parser.add_argument("--" + name, type=lambda value: int(value, 0), required=True)
    args = parser.parse_args()
    if not all(0 < n < 1 << 24 for n in (args.receiver_qpn, args.sender_qpn)):
        parser.error("QP numbers must fit 24 bits and be nonzero")
    result = verify(capture(args.ingress), capture(args.egress), capture(args.cnp),
                    str(args.source), str(args.destination), args.receiver_qpn, args.sender_qpn)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
