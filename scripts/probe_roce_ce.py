#!/usr/bin/env python3
"""Stimulate a dedicated live IPv4 RoCE Write QP with bounded packet copies.

Requires root, tcpdump and an RX mirror to a separate capture interface. Copies
only the explicitly selected IP pair, receiver QP and sender MAC. 'copy' is the
duplicate-packet control; 'ce' changes ECN to CE and repairs the IPv4 checksum.
RoCE invariant CRC masks the IP traffic-class/checksum fields, so the original
ICRC is retained. Receiver ICRC counters must still be checked independently.

This is an endpoint notification probe, NOT a congestion-based ECN marker or a
losslessness test. It does not change switch/NIC configuration. Python 3.6+.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-interface", required=True)
    parser.add_argument("--inject-interface", required=True)
    parser.add_argument("--source", type=ipaddress.IPv4Address, required=True)
    parser.add_argument("--destination", type=ipaddress.IPv4Address, required=True)
    parser.add_argument("--receiver-qpn", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--mode", choices=("copy", "ce"), required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--duration", type=float, default=4)
    args = parser.parse_args()
    if os.geteuid(): parser.error("run as root on the dedicated test host")
    if not 1 <= args.duration <= 6 or not 1 <= args.receiver_qpn < 1 << 24:
        parser.error("invalid duration or receiver QP")
    if args.capture_interface == args.inject_interface:
        parser.error("use a separate mirror capture interface")
    for name in (args.capture_interface, args.inject_interface):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name): parser.error("invalid interface")
        interface = Path("/sys/class/net") / name
        if (interface / "master").exists() or (interface / "type").read_text().strip() != "1":
            parser.error("requires dedicated standalone Ethernet test interfaces")
    source_mac = bytes.fromhex((Path("/sys/class/net") / args.inject_interface / "address").read_text().strip().replace(":", ""))
    args.evidence.mkdir(parents=True, exist_ok=False)
    report = {"mode": args.mode, "scope": "bounded duplicate-packet endpoint CE stimulus; not congestion marking",
              "source": str(args.source), "destination": str(args.destination), "receiver_qpn": args.receiver_qpn,
              "capture_interface": args.capture_interface, "inject_interface": args.inject_interface,
              "started_at": time.time(), "sent": 0, "observed": 0, "complete": False}
    interrupted = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda number, _frame: interrupted.append(number))
    packet_filter = "ip src %s and ip dst %s and udp dst port 4791 and (ip[1] & 3 = 2) and (udp[18:2] & 2047 = 0)" % (args.source, args.destination)
    log = (args.evidence / "capture.log").open("wb")
    capture = subprocess.Popen(["timeout", "--preserve-status", "--signal=INT", str(args.duration + 3) + "s",
                                "tcpdump", "-U", "-n", "-i", args.capture_interface, "-s", "0", "-w", "-", packet_filter],
                               stdout=subprocess.PIPE, stderr=log)
    sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    sender.bind((args.inject_interface, 0))
    sender.settimeout(0.2)
    os.set_blocking(capture.stdout.fileno(), False)
    original = (args.evidence / "observed.pcap").open("wb")
    submitted = (args.evidence / "submitted.pcap").open("wb")
    header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    original.write(header); submitted.write(header)

    def save_packet(stream, packet):
        now = time.time(); seconds = int(now)
        stream.write(struct.pack("<IIII", seconds, int((now - seconds) * 1000000), len(packet), len(packet)))
        stream.write(packet)

    started = time.monotonic(); last_send = 0; buffered = bytearray(); endian = None; seen = set()
    try:
        while not interrupted and time.monotonic() - started < args.duration:
            if not select.select([capture.stdout], [], [], 0.1)[0]: continue
            block = os.read(capture.stdout.fileno(), 65536)
            if not block: raise RuntimeError("capture stopped before the probe deadline")
            buffered.extend(block)
            if endian is None:
                if len(buffered) < 24: continue
                if buffered[:4] == b"\xd4\xc3\xb2\xa1": endian = "<"
                elif buffered[:4] == b"\xa1\xb2\xc3\xd4": endian = ">"
                else: raise RuntimeError("unsupported capture format")
                if struct.unpack_from(endian + "I", buffered, 20)[0] != 1:
                    raise RuntimeError("capture is not Ethernet")
                del buffered[:24]
            while len(buffered) >= 16:
                _sec, _usec, length, wire_length = struct.unpack_from(endian + "IIII", buffered)
                if length > 65535: raise RuntimeError("invalid capture length")
                if len(buffered) < 16 + length: break
                packet = bytes(buffered[16:16 + length]); del buffered[:16 + length]
                if length != wire_length or length < 54 or packet[6:12] != source_mac: continue
                ip = 14; ether = int.from_bytes(packet[12:14], "big")
                while ether in (0x8100, 0x88a8) and len(packet) >= ip + 4:
                    ether = int.from_bytes(packet[ip + 2:ip + 4], "big"); ip += 4
                if ether != 0x0800 or len(packet) < ip + 20 or packet[ip] >> 4 != 4: continue
                ihl = (packet[ip] & 15) * 4; udp = ip + ihl; bth = udp + 8
                total = int.from_bytes(packet[ip + 2:ip + 4], "big")
                if ihl < 20 or len(packet) < ip + total or total < ihl + 24 or packet[ip + 9] != 17: continue
                if packet[ip + 12:ip + 16] != args.source.packed or packet[ip + 16:ip + 20] != args.destination.packed: continue
                if int.from_bytes(packet[udp + 2:udp + 4], "big") != 4791 or packet[ip + 1] & 3 != 2: continue
                if packet[bth] not in (6, 7, 8, 10) or int.from_bytes(packet[bth + 5:bth + 8], "big") != args.receiver_qpn: continue
                key = packet[bth:bth + 12]
                if key in seen: continue  # Includes copies returning through the RX mirror.
                seen.add(key); report["observed"] += 1
                if len(seen) > 8192: raise RuntimeError("probe deduplication limit reached")
                now = time.monotonic()
                if now - started >= args.duration or now - last_send < 0.002 or report["sent"] >= 3000: continue
                marked = bytearray(packet)
                if args.mode == "ce":
                    marked[ip + 1] = (marked[ip + 1] & 0xfc) | 3
                    marked[ip + 10:ip + 12] = b"\0\0"
                    checksum = sum(int.from_bytes(marked[n:n + 2], "big") for n in range(ip, ip + ihl, 2))
                    while checksum >> 16: checksum = (checksum & 65535) + (checksum >> 16)
                    marked[ip + 10:ip + 12] = struct.pack("!H", checksum ^ 65535)
                save_packet(original, packet)
                if sender.send(marked) != len(marked): raise RuntimeError("partial packet copy send")
                save_packet(submitted, marked)
                report["sent"] += 1; last_send = now
        report["complete"] = not interrupted and report["sent"] > 0
    except Exception as error:
        report["error"] = str(error)
    finally:
        sender.close()
        if capture.poll() is None: capture.send_signal(signal.SIGINT)
        try: capture.communicate(timeout=2)
        except subprocess.TimeoutExpired: capture.kill(); capture.communicate(timeout=2)
        capture.stdout.close(); log.close(); original.close(); submitted.close()
        report.update(elapsed_seconds=time.monotonic() - started, interrupted=interrupted,
                      capture_exit_code=capture.returncode)
        (args.evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report), flush=True)
    return 0 if report["complete"] and capture.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
