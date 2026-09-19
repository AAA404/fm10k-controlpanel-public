#!/usr/bin/env python3
"""Bounded priority-3 PFC fault injection on a dedicated Linux test NIC.

Run only on the explicitly selected, isolated test link. Changes no NIC
configuration. PFC intentionally stops the peer's priority-3 egress; the peer's
watchdog may drop data during recovery. Socket sends are not wire acceptance:
pair this record with switch PFC counters, uncached mask readback and RDMA logs.
Requires Python 3.8 or later on the transmitting test host.
"""
import argparse
import json
from pathlib import Path
import re
import signal
import socket
import struct
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--rdma-device", required=True, help="local receiving RDMA device for the progress timeline")
    parser.add_argument("--duration", type=float, default=6)
    parser.add_argument("--interval-us", type=int, default=50)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    for value in (args.interface, args.rdma_device):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", value): parser.error("invalid device name")
    if not 1 <= args.duration <= 8 or not 25 <= args.interval_us <= 100:
        parser.error("duration must be 1..8 seconds and interval 25..100 microseconds")
    interface = Path("/sys/class/net") / args.interface
    if (interface / "master").exists() or (interface / "type").read_text().strip() != "1":
        parser.error("requires a standalone Ethernet test NIC")
    if (interface / "carrier").read_text().strip() != "1": parser.error("test link is not Up")
    rdma = Path("/sys/class/infiniband") / args.rdma_device / "ports/1"
    names = set()
    for entry in (rdma / "gid_attrs/ndevs").iterdir():
        try:
            names.add(entry.read_text().strip())
        except OSError:
            pass  # Unpopulated hardware GID slots can return ENODEV.
    if args.interface not in names: parser.error("RDMA device does not belong to the selected NIC")
    source = bytes.fromhex((interface / "address").read_text().strip().replace(":", ""))
    counter = rdma / "counters/port_rcv_data"
    initial_bytes = int(counter.read_text().strip()) * 4
    args.evidence.mkdir(parents=True, exist_ok=False)
    frame = bytes.fromhex("0180c2000001") + source + bytes.fromhex("8808")
    quanta = [0, 0, 0, 65535, 0, 0, 0, 0]
    pause = (frame + struct.pack("!HH8H", 0x0101, 8, *quanta)).ljust(60, b"\0")
    release = (frame + struct.pack("!HH8H", 0x0101, 8, *([0] * 8))).ljust(60, b"\0")
    (args.evidence / "submitted-pfc-frame.bin").write_bytes(pause)
    stop = threading.Event()
    interrupted = []

    def interrupt(signum, _frame):
        interrupted.append(signum)
        stop.set()

    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    started = time.monotonic_ns()
    report = {"interface": args.interface, "rdma_device": args.rdma_device,
              "priority": 3, "quanta": 65535, "source_mac": source.hex(":"),
              "scope": "submitted PFC fault injection; not wire acceptance",
              "duration_seconds": args.duration, "interval_us": args.interval_us,
              "started_at": time.time(), "initial_rx_data_bytes": initial_bytes,
              "timeline": [], "sent": 0, "clear_sent": 0, "max_send_gap_us": 0,
              "interrupted": interrupted, "complete": False}

    def sample():
        while not stop.is_set():
            try:
                value = int(counter.read_text().strip()) * 4
                report["timeline"].append({"elapsed_ms": (time.monotonic_ns() - started) / 1e6,
                                           "rx_data_bytes": value})
            except (OSError, ValueError) as error:
                report["counter_error"] = str(error)
                stop.set()
                return
            stop.wait(0.1)

    sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8808))
    sender.bind((args.interface, 0))
    sender.settimeout(0.1)
    monitor = threading.Thread(target=sample, daemon=True)
    monitor.start()
    last = None
    deadline = started + int(args.duration * 1e9)
    next_send = started
    try:
        while not stop.is_set():
            now = time.monotonic_ns()
            if now >= deadline: break
            if now < next_send: continue
            if sender.send(pause) != len(pause): raise RuntimeError("partial PFC send")
            report["sent"] += 1
            if last is not None:
                report["max_send_gap_us"] = max(report["max_send_gap_us"], (now - last) / 1000)
            last = now
            next_send = now + args.interval_us * 1000
        report["complete"] = not interrupted and not report.get("counter_error")
    finally:
        stop.set()
        monitor.join(timeout=1)
        try:
            for _ in range(3):
                if sender.send(release) == len(release): report["clear_sent"] += 1
        finally:
            sender.close()
            report["elapsed_ms"] = (time.monotonic_ns() - started) / 1e6
            (args.evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps({k: v for k, v in report.items() if k != "timeline"}), flush=True)
    return 0 if report["complete"] and report["sent"] and report["clear_sent"] == 3 else 1


if __name__ == "__main__":
    raise SystemExit(main())
