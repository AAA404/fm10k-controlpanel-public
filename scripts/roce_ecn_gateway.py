#!/usr/bin/env python3
"""Temporarily forward dedicated test NICs through an actual Linux RED queue.

This is an external software marker, not an FM10840 ASIC feature. The caller
must isolate the two physical ports into separate L2 segments before starting
the gateway. Both ports must be idle, without a master or non-link-local IPs.
The management interface and existing switch configuration are never touched.

Two private namespaces prevent ARP replies from other local RDMA interfaces.
RED is attached to an owned veth between the namespaces: capturing the second
veth's RX gives a genuine post-queue observation, including original RoCE PSNs.
Only the selected IPv4 pair, UDP/4791 and data DSCP enter RED; replies, CNP and
other traffic use the bypass queue. No packet copies or RDMA payloads are made.

SIGINT/SIGTERM, the stop file, failures and the bounded lifetime restore the
physical NICs to the original namespace. SIGKILL/power loss need manual
recovery using report.json. Requires Linux, root, iproute2; Python 3.6+.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid


def save(path, value):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2) + "\n")
    tmp.replace(path)


def default_qdiscs(rows):
    """Reject tuned zero-handle queues too: a netns move can reset them."""
    for row in rows:
        if row.get("handle") != "0:":
            return False
        options = row.get("options", {})
        if row.get("kind") == "mq" and not options:
            continue
        if row.get("kind") != "fq_codel":
            return False
        expected = {"limit": (10240,), "flows": (1024,), "quantum": (1514,),
                    "target": (4999, 5000), "interval": (99999, 100000),
                    "memory_limit": (33554432,), "ecn": (True,)}
        if set(options) != set(expected) or any(options[k] not in values for k, values in expected.items()):
            return False
    return bool(rows)


def qdisc_configuration(rows):
    # Refcounts are operational state, not part of the restored policy.
    return sorted(json.dumps({k: q.get(k) for k in ("kind", "handle", "parent", "root", "options")},
                             sort_keys=True) for q in rows)


class Gateway:
    def __init__(self, args):
        self.args = args
        prefix = "fmroce-" + uuid.uuid4().hex[:8]
        self.names = [prefix + "-a", prefix + "-b"]
        self.owned_names = []
        self.moved = []
        self.before = {}
        self.report = {"scope": "external Linux RED; not ASIC ECN or DCQCN acceptance",
                       "pid": os.getpid(), "started_at": time.time(),
                       "namespaces": self.names, "configuration": vars(args).copy(),
                       "commands": [], "ready": False, "cleaned_up": False}
        self.report["configuration"]["evidence"] = str(args.evidence)

    def checkpoint(self):
        self.report["owned_namespaces"] = self.owned_names[:]
        self.report["moved_interfaces"] = self.moved[:]
        save(self.args.evidence / "report.json", self.report)

    def command(self, argv, check=True):
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=10)
        self.report["commands"].append({"argv": argv, "returncode": result.returncode,
                                        "stderr": result.stderr.strip()})
        if check and result.returncode:
            raise RuntimeError("%r: %s" % (argv, result.stderr.strip()))
        return result

    def ip(self, side, *argv):
        return self.command(["ip", "-n", self.names[side]] + list(argv)).stdout

    def tc(self, *argv):
        return self.command(["ip", "netns", "exec", self.names[0], "tc"] + list(argv)).stdout

    def inspect(self, name):
        links = json.loads(self.command(["ip", "-j", "-d", "address", "show", "dev", name]).stdout)
        link = next(row for row in links if row.get("ifname") == name)
        qdiscs = json.loads(self.command(["tc", "-j", "qdisc", "show", "dev", name]).stdout)
        return {"link": link, "qdiscs": qdiscs}

    def preflight(self):
        if self.args.ingress == self.args.egress:
            raise ValueError("ingress and egress must be distinct dedicated NICs")
        for name in (self.args.ingress, self.args.egress):
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name):
                raise ValueError("invalid interface name")
            path = Path("/sys/class/net") / name
            if not (path / "device").exists() or (path / "master").exists():
                raise ValueError("requires standalone physical test NICs")
            row = self.inspect(name)
            link = row["link"]
            if link.get("link_type") != "ether" or "UP" not in link["flags"]:
                raise ValueError("dedicated NIC must be Ethernet and administratively up")
            if any(a.get("scope") != "link" for a in link.get("addr_info", [])):
                raise ValueError("refusing a NIC with non-link-local IP addresses")
            # Moving a NIC drops its qdisc. Restrict use to the kernel defaults,
            # which are re-created when the original namespace regains the NIC.
            if not default_qdiscs(row["qdiscs"]):
                raise ValueError("requires default mq/fq_codel queues; refusing custom/unknown settings")
            # Ubuntu 18.04 iproute2 does not emit JSON for `route` and can
            # otherwise select the IPv6 dump. An explicit IPv4 text dump is
            # sufficient here: no route at all is permitted on a spare NIC.
            routes = self.command(["ip", "-4", "route", "show", "table", "all", "dev", name]).stdout.strip()
            if routes:
                raise ValueError("refusing a NIC with IPv4 routes")
            routes6 = self.command(["ip", "-6", "route", "show", "table", "all", "dev", name]).stdout
            if any(not line.startswith(("fe80::/64 ", "local fe80:", "ff00::/8 ", "multicast ff00::/8 "))
                   for line in routes6.splitlines() if line.strip()):
                raise ValueError("refusing a NIC with non-default IPv6 routes")
            self.before[name] = row
        self.report["before"] = self.before
        self.checkpoint()

    def setup(self):
        self.preflight()
        for name in self.names:
            self.command(["ip", "netns", "add", name])
            self.owned_names.append(name)
            self.checkpoint()
            self.command(["ip", "netns", "exec", name, "sysctl", "-qw",
                          "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1"])
        for side, device in enumerate((self.args.ingress, self.args.egress)):
            # A command timeout does not establish whether the kernel moved
            # the NIC. Persist recovery responsibility before issuing it.
            self.moved.append({"interface": device, "namespace": self.names[side], "side": side})
            self.checkpoint()
            self.command(["ip", "link", "set", "dev", device, "netns", self.names[side]])
        self.ip(0, "link", "add", "out", "type", "veth", "peer", "name", "in", "netns", self.names[1])
        for side, physical, virtual in ((0, self.args.ingress, "out"), (1, self.args.egress, "in")):
            self.ip(side, "link", "add", "br0", "type", "bridge", "stp_state", "0", "mcast_snooping", "0")
            for device in (physical, virtual):
                self.ip(side, "link", "set", device, "master", "br0")
            for device in (physical, virtual, "br0", "lo"):
                self.ip(side, "link", "set", device, "up")
        rate = str(self.args.rate_mbit) + "mbit"
        self.tc("qdisc", "add", "dev", "out", "root", "handle", "1:", "htb", "default", "20")
        self.tc("class", "add", "dev", "out", "parent", "1:", "classid", "1:10", "htb",
                "rate", rate, "ceil", rate, "quantum", "1514", "burst", "4096")
        self.tc("class", "add", "dev", "out", "parent", "1:", "classid", "1:20", "htb",
                "rate", "1000mbit", "ceil", "1000mbit", "prio", "0", "quantum", "1514")
        self.tc("qdisc", "add", "dev", "out", "parent", "1:10", "handle", "10:", "red",
                "limit", "262144", "min", "8192", "max", "24576", "avpkt", "1100",
                "burst", "10", "bandwidth", rate, "probability", "1.0", "ecn")
        self.tc("qdisc", "add", "dev", "out", "parent", "1:20", "handle", "20:", "pfifo", "limit", "1000")
        self.tc("filter", "add", "dev", "out", "parent", "1:", "protocol", "ip", "pref", "10", "flower",
                "skip_hw", "src_ip", self.args.source, "dst_ip", self.args.destination,
                "ip_proto", "udp", "dst_port", "4791", "ip_tos", "%d/0xfc" % (self.args.dscp << 2),
                "classid", "1:10")
        deadline = time.monotonic() + 10
        while True:
            ready = True
            for side, physical, virtual in ((0, self.args.ingress, "out"), (1, self.args.egress, "in")):
                rows = json.loads(self.ip(side, "-j", "-d", "link", "show"))
                ports = [row for row in rows if row.get("ifname", "").split("@")[0] in (physical, virtual)]
                ready &= len(ports) == 2 and all("LOWER_UP" in row["flags"] and
                    row.get("linkinfo", {}).get("info_slave_data", {}).get("state") == "forwarding" for row in ports)
            if ready:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("gateway bridges did not become forwarding")
            time.sleep(0.1)
        self.snapshot("queue-before")
        self.report["ready"] = True
        self.checkpoint()
        save(self.args.evidence / "ready.json", {"pid": os.getpid(), "namespaces": self.names,
             "pre_queue_capture": [self.names[0], self.args.ingress],
             "post_queue_capture": [self.names[1], "in"], "red_device": "out"})

    def snapshot(self, name):
        # Old iproute2 can emit malformed JSON for HTB rates/statistics. Keep
        # the authoritative text dump as well as any usable structured data.
        result = {"time": time.time(), "monotonic": time.monotonic()}
        for kind in ("qdisc", "class"):
            result[kind + "_text"] = self.tc("-s", kind, "show", "dev", "out")
            raw = self.tc("-j", "-s", kind, "show", "dev", "out")
            try:
                result[kind] = json.loads(raw)
            except ValueError as error:
                result[kind + "_raw_json"] = raw
                result[kind + "_json_error"] = str(error)
        save(self.args.evidence / (name + ".json"), result)

    def cleanup(self):
        errors = []
        for entry in reversed(self.moved[:]):
            device, name = entry["interface"], entry["namespace"]
            try:
                wanted = self.before[device]["link"]
                probe = self.command(["ip", "-n", name, "-j", "link", "show", "dev", device], check=False)
                if probe.returncode:
                    # The attempted move may have failed before any mutation.
                    # Only the exact original interface can discharge this duty.
                    original = self.inspect(device)["link"]
                    if original["ifindex"] != wanted["ifindex"] or original["address"] != wanted["address"]:
                        raise RuntimeError(device + ": original interface identity cannot be proved")
                    self.moved.remove(entry)
                    self.checkpoint()
                    continue
                current = json.loads(probe.stdout)
                current = next(row for row in current if row.get("ifname") == device)
                if current["ifindex"] != wanted["ifindex"] or current["address"] != wanted["address"]:
                    raise RuntimeError(device + ": interface identity changed; retaining recovery metadata")
                # Remove bridge membership before returning the physical NIC.
                self.command(["ip", "-n", name, "link", "set", device, "nomaster"])
                self.command(["ip", "-n", name, "link", "set", device, "netns", str(os.getpid())])
                self.moved.remove(entry)
                self.command(["ip", "link", "set", device, "up"])
            except Exception as error:
                errors.append(str(error))
            self.checkpoint()
        for name in reversed(self.owned_names[:]):
            if any(m["namespace"] == name for m in self.moved):
                continue  # Retain recovery metadata instead of losing a NIC.
            try:
                self.command(["ip", "netns", "delete", name])
                self.owned_names.remove(name)
            except Exception as error:
                errors.append(str(error))
        after = {}
        for device, row in self.before.items():
            try:
                actual = self.inspect(device)
                after[device] = actual
                if actual["link"]["address"] != row["link"]["address"] or "UP" not in actual["link"]["flags"]:
                    errors.append(device + ": NIC identity/admin state differs after restore")
                if qdisc_configuration(actual["qdiscs"]) != qdisc_configuration(row["qdiscs"]):
                    errors.append(device + ": qdisc configuration differs after restore")
            except Exception as error:
                errors.append(str(error))
        self.report.update(after=after, cleanup_errors=errors, cleaned_up=not errors and not self.moved and not self.owned_names)
        self.checkpoint()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ingress", required=True)
    parser.add_argument("--egress", required=True)
    parser.add_argument("--source", type=str, required=True)
    parser.add_argument("--destination", type=str, required=True)
    parser.add_argument("--dscp", type=int, default=26)
    parser.add_argument("--cnp-dscp", type=int, default=48)
    parser.add_argument("--rate-mbit", type=int, default=100)
    parser.add_argument("--lifetime", type=int, default=180)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid():
        parser.error("run as root on the dedicated test host")
    args.source = str(ipaddress.IPv4Address(args.source))
    args.destination = str(ipaddress.IPv4Address(args.destination))
    if (args.source == args.destination or not 0 <= args.dscp <= 63 or not 0 <= args.cnp_dscp <= 63
            or args.dscp == args.cnp_dscp or not 1 <= args.rate_mbit <= 1000 or not 10 <= args.lifetime <= 600):
        parser.error("invalid endpoint, DSCP, rate (1..1000 Mbit/s) or lifetime (10..600 seconds)")
    args.evidence.mkdir(parents=True, exist_ok=False)
    gateway = Gateway(args)
    stopped = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda number, _frame: stopped.append(number))
    try:
        gateway.setup()
        print(json.dumps({"ready": True, "namespaces": gateway.names}), flush=True)
        deadline = time.monotonic() + args.lifetime
        while not stopped and not (args.evidence / "stop").exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        gateway.snapshot("queue-after")
    except Exception as error:
        gateway.report["error"] = str(error)
    finally:
        gateway.cleanup()
        gateway.report.update(finished_at=time.time(), signals=stopped)
        gateway.checkpoint()
    print(json.dumps({key: gateway.report.get(key) for key in ("ready", "error", "cleaned_up", "cleanup_errors")}), flush=True)
    return 0 if gateway.report["ready"] and gateway.report["cleaned_up"] and "error" not in gateway.report else 1


if __name__ == "__main__":
    raise SystemExit(main())
