#!/usr/bin/env python3
"""Collect evidence or exercise ONE EPL through the versioned management API.

This records control API evidence. It never certifies data-plane losslessness,
never calls a driver/SDK, and has no restart/reset fallback.
"""
from __future__ import annotations

import argparse
import copy
import getpass
import hashlib
import http.cookiejar
import ipaddress
import json
from pathlib import Path
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

EPLS = (0, 1, 2, 5, 6, 7)
MODES = (("100g", [25] * 4), ("40g", [10] * 4), ("split", [25] * 4),
         ("split", [10] * 4), ("split", [10, 25, 10, 25]), ("split", [25, 10, 25, 10]))


def validate_url(url):
    parts = urllib.parse.urlsplit(url)
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError("use only the panel origin, without credentials, path or query")
    if not parts.hostname or parts.scheme not in {"http", "https"}:
        raise ValueError("invalid HTTP(S) origin")
    if parts.scheme == "http":
        try:
            local = ipaddress.ip_address(parts.hostname).is_loopback
        except ValueError:
            local = parts.hostname == "localhost"
        if not local:
            raise ValueError("HTTP is allowed only on loopback; use verified HTTPS for the board")
    return url.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError("redirects are disabled for authenticated acceptance requests")


class Client:
    def __init__(self, url, ca=None):
        self.url = validate_url(url)
        self.csrf = None
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca) if ca else None)),
            NoRedirect())

    def request(self, path, body=None):
        headers = {"Accept": "application/json"}
        if body is not None:
            headers.update({"Content-Type": "application/json", "Origin": self.url})
            if self.csrf:
                headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(self.url + "/api/v1/" + path,
            data=json.dumps(body).encode() if body is not None else None, headers=headers)
        try:
            with self.opener.open(request, timeout=150) as response:
                raw = response.read(2_000_001)
        except urllib.error.HTTPError as error:
            detail = error.read(4096).decode(errors="replace")
            raise RuntimeError(f"{path}: HTTP {error.code}: {detail}") from None
        if len(raw) > 2_000_000:
            raise RuntimeError("oversized API response")
        return json.loads(raw)

    def login(self, username):
        result = self.request("auth/login", {"username": username, "password": getpass.getpass("管理员密码: ")})
        self.csrf = result["csrf"]


def target_for_mode(configuration, epl, mode):
    target = copy.deepcopy(configuration)
    group = next(group for group in target["groups"] if group["epl"] == epl)
    was_split = group["mode"] == "split"
    group["mode"], group["lane_speeds"] = mode[0], list(mode[1])
    if mode[0] == "split" and not was_split:
        base = EPLS.index(epl) * 4 + 1
        for port in range(base + 1, base + 4):
            target["ports"][str(port)]["enabled"] = False
    # Deliberately leave VLAN/LAG/MAC/SPAN references in place. Native/API
    # validation must refuse incompatible dependencies, never remove them here.
    return target


def compare_other_groups(before, after, epl):
    left = {port["id"]: port for port in before["ports"] if port["epl"] != epl}
    right = {port["id"]: port for port in after["ports"] if port["epl"] != epl}
    if left.keys() != right.keys():
        raise RuntimeError("non-target port inventory changed")
    for number, port in left.items():
        current = right[number]
        if current.get("quality") not in {"valid", "simulated"}:
            raise RuntimeError(f"cannot verify non-target port {number}: telemetry unavailable or stale")
        for field in ("enabled", "active", "speed_gbps", "link"):
            if port.get(field) != current.get(field):
                raise RuntimeError(f"non-target port {number} changed {field}")


def store(directory, name, data):
    path = directory / name
    path.touch(mode=0o600)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def replace(client, target, revision, observe=None):
    preview = client.request("config/preview", {"expected_revision": revision, "configuration": target})
    if preview.get("requires_restart"):
        raise RuntimeError("online EPL test refuses a restart-requiring plan")
    if not preview.get("changes"):
        return client.request("config")
    job = client.request("config/commit", {"draft_id": preview["id"], "confirm_timeout": 120,
                                           "accept_bandwidth_warning": True})
    deadline = time.monotonic() + 130
    while time.monotonic() < deadline:
        state = client.request("jobs/" + job["id"])
        if observe:
            observe()
        if state["state"] == "awaiting_confirmation":
            return client.request("jobs/" + job["id"] + "/confirm", {})
        if state["state"] in {"failed", "rolled_back"}:
            raise RuntimeError(f"configuration job {job['id']} ended as {state['state']}: {state.get('error', '')}")
        if state["state"] == "done":
            raise RuntimeError("the test requires an explicit confirmed transaction")
        time.sleep(0.5)
    raise RuntimeError("job deadline exceeded; configd retains responsibility for confirmed timeout rollback")


def collect(client, output):
    errors = []
    for path in ("health", "capabilities", "config", "telemetry", "system", "l3", "logs",
                 "operational/fdb", "operational/lags", "operational/rstp", "operational/lldp", "operational/igmp"):
        try:
            data = client.request(path)
        except Exception as error:
            data = {"error": str(error)}
            errors.append(path)
        store(output, path.replace("/", "-") + ".json", data)
    return errors


def exercise(client, output, epl, cycles):
    original = client.request("config")
    if original.get("pending"):
        raise RuntimeError("finish the existing pending configuration before testing")
    store(output, "before-backup.json", client.request("backups/export"))
    current = original
    baseline = client.request("telemetry")
    compare_other_groups(baseline, baseline, epl)
    records = []
    failure = None
    try:
        mode_index = 0
        for iteration in range(cycles):
            group = next(g for g in current["configuration"]["groups"] if g["epl"] == epl)
            while (group["mode"], group["lane_speeds"]) == MODES[mode_index % len(MODES)]:
                mode_index += 1
            mode = MODES[mode_index % len(MODES)]
            mode_index += 1
            target = target_for_mode(current["configuration"], epl, mode)
            observed = []
            def observe():
                sample = client.request("telemetry")
                observed.append(sample)
                compare_other_groups(baseline, sample, epl)
            started = time.time()
            current = replace(client, target, current["revision"], observe)
            observe()
            records.append({"iteration": iteration + 1, "epl": epl, "mode": mode,
                            "started_at": started, "completed_at": time.time(), "revision": current["revision"],
                            "telemetry": observed})
            store(output, f"cycle-{iteration + 1:04d}.json", records[-1])
            print(f"EPL {epl}: {iteration + 1}/{cycles}, revision {current['revision']}", flush=True)
    except Exception as error:
        failure = str(error)
    finally:
        try:
            live = client.request("config")
            if live.get("pending"):
                raise RuntimeError("pending transaction remains; allow configd timeout recovery and inspect its outcome")
            if live["revision"] != current["revision"]:
                raise RuntimeError("configuration revision changed outside the completed test; refusing to overwrite it")
            if live["configuration"] != original["configuration"]:
                live = replace(client, original["configuration"], live["revision"])
            if live["configuration"] != original["configuration"]:
                raise RuntimeError("original configuration readback mismatch")
            store(output, "restore.json", {"restored": True, "revision": live["revision"]})
        except Exception as error:
            store(output, "restore.json", {"restored": False, "error": str(error)})
            failure = (failure + "; " if failure else "") + f"restore: {error}"
    return {"completed_cycles": len(records), "requested_cycles": cycles, "epl": epl,
            "control_api_result": "failed" if failure else "passed", "error": failure,
            "data_plane_result": "not-run", "qualification": "external traffic and event evidence is required"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("collect", "epl-cycle"))
    parser.add_argument("--url", required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--ca", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-simulator", action="store_true")
    parser.add_argument("--epl", type=int, choices=EPLS)
    parser.add_argument("--cycles", type=int, default=100)
    args = parser.parse_args()
    if args.command == "epl-cycle" and (args.epl is None or not 100 <= args.cycles <= 10000):
        parser.error("epl-cycle requires --epl and 100..10000 cycles")
    client = Client(args.url, args.ca)
    client.login(args.username)
    capability = client.request("capabilities")
    if capability["mode"] != "netlab" and not args.allow_simulator:
        parser.error("simulator evidence requires --allow-simulator and never qualifies hardware")
    if args.command == "epl-cycle" and capability["mode"] == "netlab":
        if not client.request("config").get("hardware_write_ready"):
            parser.error("the complete native board HAL is not bound; no hardware write attempted")
    args.output.mkdir(parents=True, mode=0o700, exist_ok=False)
    report = {"schema": 1, "started_at": time.time(), "mode": capability["mode"],
              "hardware_acceptance": "not-run", "command": args.command}
    report["collection_errors"] = collect(client, args.output)
    if args.command == "epl-cycle":
        report["exercise"] = exercise(client, args.output, args.epl, args.cycles)
    report["completed_at"] = time.time()
    report["files"] = {file.name: hashlib.sha256(file.read_bytes()).hexdigest()
                       for file in sorted(args.output.glob("*.json"))}
    store(args.output, "manifest.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if report["collection_errors"] or report.get("exercise", {}).get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
