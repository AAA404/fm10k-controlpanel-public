#!/usr/bin/env python3
"""Run a bounded, matching perftest matrix on two existing RoCEv2 endpoints.

Run the server side first, then the client side. This script changes no NIC,
IP, PFC, or switch configuration. Its evidence proves verbs transport only;
congestion control and losslessness require separate packet/counter evidence.
Compatible with the SP580 test host's Python 3.6 and perftest 5.60.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time


CASES = [
    ("write-client-to-server", "ib_write_bw", ["-t", "1", "-Q", "1"]),
    ("write-server-to-client", "ib_write_bw", ["--reversed"]),
    ("read-client-initiates", "ib_read_bw", ["-o", "4"]),
    ("read-server-initiates", "ib_read_bw", ["-o", "4", "--reversed"]),
    ("send-client-to-server", "ib_send_bw", []),
    ("send-server-to-client", "ib_send_bw", ["--reversed"]),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--peer", help="client only: peer's test-network IPv4 address")
    parser.add_argument("--binaries", type=Path, default=Path("/usr/bin"))
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--base-port", type=int, default=18570)
    parser.add_argument("--skip-first-write", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.device) or not 0 <= args.gid <= 255:
        parser.error("invalid RDMA device or GID index")
    if not 1024 <= args.base_port <= 65529:
        parser.error("base port must be in 1024..65529")
    port = Path("/sys/class/infiniband") / args.device / "ports/1"
    gid_type = (port / "gid_attrs/types" / str(args.gid)).read_text().strip()
    gid = (port / "gids" / str(args.gid)).read_text().strip()
    if gid_type != "RoCE v2" or not gid.startswith("0000:0000:0000:0000:0000:ffff:"):
        parser.error("this fixture requires an IPv4 RoCE v2 GID")
    args.evidence.mkdir(parents=True, exist_ok=False)
    report = {"side": "client" if args.peer else "server", "device": args.device,
              "gid_index": args.gid, "gid": gid, "gid_type": gid_type,
              "netdev": (port / "gid_attrs/ndevs" / str(args.gid)).read_text().strip(),
              "started_at": time.time(), "traffic_class": 106, "service_level": 3,
              "qp_count": 1, "rdma_mtu": 1024, "message_bytes": 65536,
              "tests": [], "passed": False,
              "scope": "verbs-transport; not ECN/PFC/DCQCN acceptance"}

    def save():
        (args.evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    save()
    for index, (name, executable, extra) in enumerate(CASES):
        if index == 0 and args.skip_first_write:
            continue
        binary = args.binaries / executable
        version = subprocess.run([str(binary), "--version"], stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, universal_newlines=True)
        if "Version: 5.60" not in version.stdout:
            report["error"] = "both peers must use perftest 5.60: " + version.stdout
            save()
            return 1
        # Give the server time to destroy the prior QP and open its next port.
        # No readiness TCP connection is made: it would consume perftest's
        # one control connection and invalidate the real client's handshake.
        if args.peer:
            time.sleep(1)
        command = ["timeout", "--kill-after=5s", "90s", str(binary), "-d", args.device,
                   "-x", str(args.gid), "-p", str(args.base_port + index), "-m", "1024",
                   "-s", "65536", "-D", "10", "-q", "1", "-S", "3", "--tclass", "106",
                   "-F", "--report_gbits"] + extra
        if args.peer:
            command.append(args.peer)
        print("START " + name, flush=True)
        started = time.monotonic()
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True)
        (args.evidence / (name + ".log")).write_text(result.stdout)
        metrics = re.findall(r"^\s*65536\s+(\d+)\s+[\d.]+\s+([\d.]+)\s+([\d.]+)", result.stdout, re.M)
        passed = result.returncode == 0 and len(metrics) == 1 and float(metrics[0][1]) > 0
        record = {"name": name, "command": command, "exit_code": result.returncode,
                  "elapsed_seconds": round(time.monotonic() - started, 3), "passed": passed,
                  "iterations": int(metrics[0][0]) if metrics else None,
                  "average_gbps": float(metrics[0][1]) if metrics else None}
        report["tests"].append(record)
        save()
        print(json.dumps(record), flush=True)
        if not passed:
            print(result.stdout[-6000:], flush=True)
            return 1
    report["passed"] = bool(report["tests"]) and all(t["passed"] for t in report["tests"])
    save()
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
