#!/usr/bin/env python3
"""Exercise actual Linux RED ECN marking on an isolated software bridge.

Requires Linux, root, iproute2 and the veth/bridge/HTB/RED/flower kernel modules.
Creates only private namespaces and veths; never reconfigures a physical NIC,
the switch SDK owner, the management link, or the running RoCE policy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from fm10k_controlpanel.ecn_lab import (
    EcnLabProfile, MAGIC, PCAP_HEADER, cases, make_frame, read_capture,
    verify_stage, write_packet,
)


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(path)


def capture(args):
    """Copy ingress bytes synchronously with TPACKET_V2, before RED runs.

    Plain recvmsg queues a shallow skb clone: a downstream qdisc can change
    its ECN byte before userspace copies it. PACKET_RX_RING copies packet data
    at the capture hook, preserving an independent pre-marking observation.
    """
    count = 0
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        frame_size, block_size, blocks = 2048, 1 << 20, 4
        ring_size = block_size * blocks
        frames = ring_size // frame_size
        sock.setsockopt(263, 10, 1)  # SOL_PACKET, PACKET_VERSION, TPACKET_V2
        sock.setsockopt(263, 5, struct.pack("=IIII", block_size, blocks, frame_size, frames))
        sock.bind((args.device, 0))
        deadline = time.monotonic() + 45
        with mmap.mmap(sock.fileno(), ring_size, flags=mmap.MAP_SHARED,
                       prot=mmap.PROT_READ | mmap.PROT_WRITE) as ring, args.pcap.open("xb") as file:
            file.write(PCAP_HEADER)
            args.ready.touch(exist_ok=False)
            position = 0
            while True:
                if time.monotonic() >= deadline:
                    raise TimeoutError("capture worker exceeded its lifetime")
                base = position * frame_size
                status = struct.unpack_from("=I", ring, base)[0]
                if not status & 1:  # TP_STATUS_USER
                    if args.stop.exists():
                        break
                    select.select([sock], [], [], 0.1)
                    continue
                try:
                    _, original, captured, mac, _, seconds, nanos, tci, tpid = struct.unpack_from("=IIIHHIIHH", ring, base)
                    if captured != original or mac < 52 or mac + captured > frame_size:
                        raise RuntimeError("capture ring truncated a packet")
                    if ring[base + 32 + 10] != 4:  # sockaddr_ll.sll_pkttype != PACKET_OUTGOING
                        frame = ring[base + mac:base + mac + captured]
                        if status & (1 << 4):  # TP_STATUS_VLAN_VALID, including VID 0.
                            protocol = tpid if status & (1 << 6) else 0x8100
                            frame = frame[:12] + struct.pack("!HH", protocol, tci) + frame[12:]
                        if MAGIC in frame:
                            write_packet(file, frame, seconds + nanos / 1_000_000_000)
                            count += 1
                finally:
                    struct.pack_into("=I", ring, base, 0)  # TP_STATUS_KERNEL
                    position = (position + 1) % frames
        packets, dropped = struct.unpack_from("=II", sock.getsockopt(263, 6, 12))
        save(args.pcap.with_suffix(".stats.json"),
             {"mode": "TPACKET_V2", "probe_packets": count,
              "socket_packets": packets, "socket_drops": dropped})
        if dropped:
            raise RuntimeError("capture socket dropped packets; evidence is incomplete")


def send(args):
    profile = EcnLabProfile()
    entries = cases(profile)
    congested = args.stage == 1
    rounds, interval = (200, 0.0005) if congested else (5 if args.stage == 2 else 3, 0.025)
    sequence = 0
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock, args.pcap.open("xb") as file:
        sock.bind(("tx", 0))
        file.write(PCAP_HEADER)
        for repetition in range(rounds):
            # Rotate the start case to avoid favoring an ECN value at a full queue.
            for position in range(len(entries)):
                index = (position + repetition) % len(entries)
                frame = make_frame(entries[index], bytes.fromhex(args.run_id), args.stage, index, sequence)
                if sock.send(frame) != len(frame):
                    raise RuntimeError("short packet submission")
                write_packet(file, frame, time.time())
                sequence += 1
                time.sleep(interval)


class Lab:
    def __init__(self, directory):
        self.directory = directory
        self.profile = EcnLabProfile()
        self.run_id = uuid.uuid4().hex
        prefix = f"fmecn-{self.run_id[:10]}"
        self.names = {key: f"{prefix}-{key}" for key in ("src", "sw", "dst")}
        self.owned = []
        self.workers = []
        self.logs = []
        self.started = time.monotonic()
        self.report = {**self.profile.describe(), "run_id": self.run_id,
                       "schema_version": 1, "started_at": time.time(),
                       "kernel": os.uname().release, "namespaces": self.names,
                       "traffic": "synthetic UDP probes, not RDMA or CNP operations",
                       "passed": False, "cleaned_up": False, "stages": [], "commands": []}
        self.report["implementation_sha256"] = {
            "script": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "module": hashlib.sha256(Path(sys.modules[EcnLabProfile.__module__].__file__).read_bytes()).hexdigest(),
        }

    def checkpoint(self):
        save(self.directory / "report.json", self.report)

    def command(self, argv, timeout=10):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        self.report["commands"].append({"argv": argv, "returncode": result.returncode,
                                        "stderr": result.stderr.strip()})
        if result.returncode:
            raise RuntimeError(f"{argv!r}: {result.stderr.strip()}")
        return result.stdout

    def ip(self, namespace, *arguments):
        return self.command(["ip", "-n", self.names[namespace], *arguments])

    def tc(self, *arguments):
        return self.command(["ip", "netns", "exec", self.names["sw"], "tc", *arguments])

    def setup(self):
        self.checkpoint()
        for name in self.names.values():
            # Defer interruption across successful creation and ownership
            # recording, so cleanup cannot lose a newly created namespace.
            old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                self.command(["ip", "netns", "add", name])
                self.owned.append(name)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
            self.checkpoint()
        # Both ends are created inside owned namespaces, never in the host.
        self.ip("src", "link", "add", "name", "tx", "type", "veth", "peer", "name", "in", "netns", self.names["sw"])
        self.ip("sw", "link", "add", "name", "out", "type", "veth", "peer", "name", "rx", "netns", self.names["dst"])
        self.ip("sw", "link", "add", "name", "br0", "type", "bridge", "stp_state", "0", "mcast_snooping", "0")
        for device in ("in", "out"):
            self.ip("sw", "link", "set", "dev", device, "master", "br0")
        for namespace, devices in (("src", ("tx",)), ("sw", ("in", "out", "br0")), ("dst", ("rx",))):
            for device in devices:
                self.ip(namespace, "link", "set", "dev", device, "up")
        for command in self.profile.commands():
            self.tc(*command)
        # Carrier/linkwatch updates are asynchronous even with STP disabled.
        # Fast hosts can finish setup before bridge ports become forwarding.
        deadline = time.monotonic() + 10
        while True:
            links = json.loads(self.ip("sw", "-j", "-d", "link", "show"))
            ports = {p["ifname"]: p for p in links if p["ifname"] in ("in", "out")}
            if len(ports) == 2 and all("LOWER_UP" in p["flags"] and
                    p.get("linkinfo", {}).get("info_slave_data", {}).get("state") == "forwarding"
                    for p in ports.values()):
                self.report["bridge_ready"] = True
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("isolated bridge ports did not become forwarding")
            time.sleep(0.05)
        self.report["filters"] = json.loads(self.tc("-j", "filter", "show", "dev", "out", "parent", "1:"))
        self.checkpoint()

    def start_capture(self, namespace, device, directory, label, stop):
        ready = directory / f"{label}.ready"
        log = (directory / f"{label}.log").open("w")
        self.logs.append(log)
        process = subprocess.Popen(["ip", "netns", "exec", self.names[namespace], sys.executable,
                                    str(Path(__file__).resolve()), "_capture", "--device", device,
                                    "--pcap", str(directory / f"{label}.pcap"), "--ready", str(ready),
                                    "--stop", str(stop)], stdout=log, stderr=log)
        self.workers.append(process)
        deadline = time.monotonic() + 5
        while not ready.exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError(f"{label} capture did not start; see {label}.log")
            time.sleep(0.02)
        return process

    def run_stage(self, stage):
        label = ("idle", "congested", "recovered")[stage]
        directory = self.directory / label
        directory.mkdir()
        stop = directory / "stop"
        ingress = self.start_capture("sw", "in", directory, "ingress", stop)
        egress = self.start_capture("dst", "rx", directory, "egress", stop)
        self.command(["ip", "netns", "exec", self.names["src"], sys.executable,
                      str(Path(__file__).resolve()), "_send", "--stage", str(stage),
                      "--run-id", self.run_id, "--pcap", str(directory / "submitted.pcap")], timeout=20)
        # Drain the bounded software queue before terminating the captures.
        time.sleep(self.profile.limit_bytes * 8 / (self.profile.rate_kbit * 1000) + 0.5)
        qdiscs = json.loads(self.tc("-s", "-j", "qdisc", "show", "dev", "out"))
        save(directory / "qdiscs.json", qdiscs)
        stop.touch()
        for process in (ingress, egress):
            if process.wait(timeout=3):
                raise RuntimeError(f"capture worker failed in {label}; see capture logs")
        result = verify_stage(self.profile, stage, read_capture(directory / "submitted.pcap"),
                              read_capture(directory / "ingress.pcap"), read_capture(directory / "egress.pcap"))
        red = next((q for q in qdiscs if q["kind"] == "red" and q["handle"] == "10:"), None)
        if red is None or red.get("qlen") != 0 or (stage == 1 and
                (not red.get("marked", 0) or not red.get("early", 0))):
            result["errors"].append("missing RED mark statistics or software queue failed to drain")
            result["error_count"] += 1
            result["passed"] = False
        result["red"] = red
        self.report["stages"].append(result)
        self.checkpoint()
        print(f"{label}: {'PASS' if result['passed'] else 'FAIL'}, "
              f"CE transitions={sum(c['marked_ce'] for c in result['cases'])}", flush=True)

    def cleanup(self):
        errors = []
        for process in self.workers:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
            except Exception as error:
                errors.append(f"worker cleanup: {error}")
        for log in self.logs:
            try:
                log.close()
            except Exception as error:
                errors.append(f"log cleanup: {error}")
        for name in reversed(self.owned):
            try:
                self.command(["ip", "netns", "del", name])
            except Exception as error:
                errors.append(str(error))
        self.report["cleanup_errors"] = errors
        self.report["cleaned_up"] = not errors
        self.report["passed"] = self.report["passed"] and not errors
        self.report["elapsed_seconds"] = round(time.monotonic() - self.started, 3)
        self.checkpoint()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("describe", help="print the isolated software profile without changing anything")
    run = commands.add_parser("run", help="create, verify and remove the isolated software path")
    run.add_argument("--evidence", type=Path, required=True, help="new directory for JSON and pcap evidence")
    recv = commands.add_parser("_capture", help=argparse.SUPPRESS)
    for name in ("pcap", "ready", "stop"):
        recv.add_argument(f"--{name}", type=Path, required=True)
    recv.add_argument("--device", required=True)
    sender = commands.add_parser("_send", help=argparse.SUPPRESS)
    sender.add_argument("--stage", type=int, choices=(0, 1, 2), required=True)
    sender.add_argument("--run-id", required=True)
    sender.add_argument("--pcap", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "describe":
        print(json.dumps(EcnLabProfile().describe(), indent=2))
        return 0
    if sys.platform != "linux" or os.geteuid():
        parser.error("requires Linux root; no tests have run")
    if args.command == "_capture":
        capture(args)
        return 0
    if args.command == "_send":
        send(args)
        return 0
    if not shutil.which("ip") or not shutil.which("tc"):
        parser.error("requires iproute2; no tests have run")
    args.evidence = args.evidence.resolve()
    args.evidence.mkdir(parents=True, exist_ok=False)
    lab = Lab(args.evidence)

    def interrupted(signum, _frame):
        raise InterruptedError(f"interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        lab.setup()
        for stage in range(3):
            lab.run_stage(stage)
        lab.report["passed"] = all(s["passed"] for s in lab.report["stages"])
    except Exception as error:
        lab.report["error"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        # Cleanup must also complete after an interrupted sender or capture.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        lab.cleanup()
    print(f"evidence: {args.evidence / 'report.json'}", flush=True)
    return 0 if lab.report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
