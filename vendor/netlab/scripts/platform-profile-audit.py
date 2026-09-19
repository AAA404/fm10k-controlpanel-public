#!/usr/bin/env python3.11
"""Audit the NetLab platform profile against an SDK RDI platform file."""

import argparse
import os
import re
import sys

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "bin", "cli"))

from platform_profile import PlatformProfileError, load_profile  # noqa: E402


RDI_DEFAULT = "/etc/rdi/fm_platform_attributes.cfg"


def _parse_int(value):
    return int(value, 0)


def _kv_from_mapping(text):
    out = {}
    for part in text.split():
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        out[key] = _parse_int(value)
    return out


def _set_nested(root, path, value):
    cur = root
    for key in path[:-1]:
        cur = cur.setdefault(key, {})
    cur[path[-1]] = value


def parse_rdi(path):
    data = {"switches": {}, "ports": {}, "xcvrs": {}}
    line_re = re.compile(r"^api\.platform\.(?P<key>\S+)\s+\S+\s+(?P<value>.+)$")
    switch_re = re.compile(r"^config\.switch\.(\d+)\.(.+)$")
    port_re = re.compile(r"^config\.switch\.(\d+)\.portIndex\.(\d+)\.(.+)$")
    lane_map_re = re.compile(r"^lane\.(\d+)\.portMapping$")
    xcvr_re = re.compile(r"^lib\.config\.hwResourceId\.(\d+)\.(.+)$")

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = line_re.match(line)
            if not m:
                continue
            key = m.group("key")
            value = m.group("value").strip().strip('"')

            pm = port_re.match(key)
            if pm:
                switch_id = _parse_int(pm.group(1))
                port_index = _parse_int(pm.group(2))
                field = pm.group(3)
                port = data["ports"].setdefault((switch_id, port_index),
                                                 {"switch-index": switch_id,
                                                  "port-index": port_index,
                                                  "lanes": {}})
                lm = lane_map_re.match(field)
                if lm:
                    lane_index = _parse_int(lm.group(1))
                    port["lanes"][lane_index] = _kv_from_mapping(value)
                elif field == "portMapping":
                    port["mapping"] = _kv_from_mapping(value)
                elif field == "speed":
                    port["speed-bps"] = _parse_int(value) * 1000000
                elif field == "hwResourceId":
                    port["hw-resource-id"] = _parse_int(value)
                elif field == "interfaceType":
                    port["interface-type"] = value
                elif field == "ethernetMode":
                    port["ethernet-mode"] = value
                elif field == "capability":
                    port["capabilities"] = value
                continue

            sm = switch_re.match(key)
            if sm:
                switch_id = _parse_int(sm.group(1))
                field = sm.group(2)
                sw = data["switches"].setdefault(switch_id,
                                                 {"index": switch_id})
                if field == "uioDevName":
                    sw["uio-dev"] = value
                elif field == "switchNumber":
                    sw["number"] = _parse_int(value)
                elif field == "cpuPort":
                    sw["cpu-port"] = _parse_int(value)
                elif field == "bootCfg.mgmtPep":
                    sw["management-pep"] = _parse_int(value)
                continue

            xm = xcvr_re.match(key)
            if xm:
                rid = _parse_int(xm.group(1))
                field = xm.group(2)
                xcvr = data["xcvrs"].setdefault(rid, {"resource-id": rid})
                if field == "interfaceType":
                    xcvr["type"] = value
                elif field == "xcvrI2C.pcaMux.index":
                    xcvr["mux-index"] = _parse_int(value)
                elif field == "xcvrI2C.pcaMux.value":
                    xcvr["mux-value"] = _parse_int(value)
                elif field == "xcvrState.pcaIo.index":
                    xcvr["state-gpio-index"] = _parse_int(value)
                elif field == "xcvrState.pcaIo.basePin":
                    xcvr["state-gpio-base"] = _parse_int(value)

    return data


def _profile_int(entry, key, default=None):
    value = entry.get(key)
    if value in (None, ""):
        return default
    return _parse_int(value)


def _cmp(results, label, actual, expected):
    if expected is None:
        return
    if actual == expected:
        results.append(("ok", label, actual, expected))
    else:
        results.append(("fail", label, actual, expected))


def _check(results, label, ok, actual, expected):
    results.append(("ok" if ok else "fail", label, actual, expected))


def _csv_set(value):
    return {part.strip() for part in str(value or "").split(",")
            if part.strip()}


def _speed_set(entry):
    out = set()
    for value in str(entry.get("supported-speeds") or "").split(","):
        value = value.strip()
        if not value:
            continue
        try:
            out.add(_parse_int(value))
        except ValueError:
            out.add(value)
    return out


def _speed_token(speed_bps):
    try:
        speed_bps = int(speed_bps)
    except (TypeError, ValueError):
        return None
    mapping = {
        1000000000: "1G",
        10000000000: "10G",
        25000000000: "25G",
        40000000000: "40G",
        100000000000: "100G",
    }
    return mapping.get(speed_bps)


def _profile_external(port):
    role = (port.get("role") or "").lower()
    flags = {flag.strip().lower() for flag in
             (port.get("flags") or "").split(",") if flag.strip()}
    return role == "external" or "external" in flags


def audit(profile, rdi):
    results = []

    for sw in profile.get("switches", []):
        index = _profile_int(sw, "index")
        got = rdi["switches"].get(index)
        if not got:
            results.append(("fail", f"switch {index}", "missing", "present"))
            continue
        _cmp(results, f"switch {index} number",
             _profile_int(sw, "number", index), got.get("number"))
        _cmp(results, f"switch {index} uio-dev", sw.get("uio-dev"),
             got.get("uio-dev"))
        _cmp(results, f"switch {index} cpu-port",
             _profile_int(sw, "cpu-port"), got.get("cpu-port"))
        _cmp(results, f"switch {index} management-pep",
             _profile_int(sw, "management-pep"), got.get("management-pep"))

    for port in profile.get("ports", []):
        name = port.get("name", "?")
        switch_index = _profile_int(port, "switch-index",
                                    _profile_int(port, "switch-id", 0))
        port_index = _profile_int(port, "port-index",
                                  _profile_int(port, "logical-port"))
        got = rdi["ports"].get((switch_index, port_index))
        if not got:
            results.append(("fail", f"{name} port-index", "missing",
                            f"switch {switch_index} port-index {port_index}"))
            continue
        mapping = got.get("mapping", {})
        if not mapping and got.get("lanes"):
            mapping = next(iter(got["lanes"].values()))
        _cmp(results, f"{name} logical-port",
             _profile_int(port, "logical-port"), mapping.get("LOG"))
        _cmp(results, f"{name} epl-port",
             _profile_int(port, "epl-port", _profile_int(port, "epl")),
             mapping.get("EPL"))
        _cmp(results, f"{name} pcie-port",
             _profile_int(port, "pcie-port", _profile_int(port, "pcie")),
             mapping.get("PCIE"))
        _cmp(results, f"{name} hw-resource-id",
             _profile_int(port, "hw-resource-id"), got.get("hw-resource-id"))
        _cmp(results, f"{name} interface-type", port.get("interface-type"),
             got.get("interface-type"))
        _cmp(results, f"{name} ethernet-mode", port.get("ethernet-mode"),
             got.get("ethernet-mode"))
        _cmp(results, f"{name} scheduler-speed",
             _profile_int(port, "scheduler-speed",
                          _profile_int(port, "line-rate")),
             got.get("speed-bps"))
        if _profile_external(port):
            supported = _speed_set(port)
            current_speed = got.get("speed-bps")
            default_speed = _profile_int(port, "default-speed")
            current_token = _speed_token(current_speed)
            profile_caps = _csv_set(port.get("capabilities"))
            rdi_caps = _csv_set(got.get("capabilities"))
            if supported:
                _check(results, f"{name} current-speed in supported-speeds",
                       current_speed in supported, current_speed,
                       "one of " +
                       ",".join(str(s) for s in sorted(supported, key=str)))
                if default_speed is not None:
                    _check(results,
                           f"{name} default-speed in supported-speeds",
                           default_speed in supported, default_speed,
                           "one of " +
                           ",".join(str(s) for s in sorted(supported, key=str)))
                speed_caps = {_speed_token(speed) for speed in supported}
                speed_caps.discard(None)
                if speed_caps:
                    _check(results,
                           f"{name} capability covers supported-speeds",
                           speed_caps.issubset(profile_caps),
                           ",".join(sorted(profile_caps)),
                           ",".join(sorted(speed_caps)))
                    _check(results,
                           f"{name} RDI capability covers supported-speeds",
                           speed_caps.issubset(rdi_caps),
                           ",".join(sorted(speed_caps)),
                           ",".join(sorted(rdi_caps)))
            if current_token:
                _check(results, f"{name} capability covers current speed",
                       current_token in profile_caps,
                       ",".join(sorted(profile_caps)), current_token)
                _check(results, f"{name} RDI capability covers current speed",
                       current_token in rdi_caps,
                       current_token, ",".join(sorted(rdi_caps)))

    for lane in profile.get("lanes", []):
        ifname = lane.get("ifname") or lane.get("name") or "?"
        switch_index = _profile_int(lane, "switch-index",
                                    _profile_int(lane, "switch-id", 0))
        port_index = _profile_int(lane, "port-index")
        lane_index = _profile_int(lane, "index")
        got_port = rdi["ports"].get((switch_index, port_index), {})
        got = got_port.get("lanes", {}).get(lane_index)
        if not got:
            results.append(("fail",
                            f"{ifname} lane {lane_index}", "missing",
                            "present"))
            continue
        _cmp(results, f"{ifname} lane {lane_index} logical-port",
             _profile_int(lane, "logical-port"), got.get("LOG"))
        _cmp(results, f"{ifname} lane {lane_index} epl",
             _profile_int(lane, "epl", _profile_int(lane, "epl-port")),
             got.get("EPL"))
        _cmp(results, f"{ifname} lane {lane_index} sdk-lane",
             _profile_int(lane, "sdk-lane"), got.get("LANE"))

    for xcvr in profile.get("xcvrs", []):
        rid = _profile_int(xcvr, "resource-id")
        got = rdi["xcvrs"].get(rid)
        if not got:
            results.append(("fail", f"xcvr {rid}", "missing", "present"))
            continue
        _cmp(results, f"xcvr {rid} type", xcvr.get("type"), got.get("type"))
        _cmp(results, f"xcvr {rid} mux-index",
             _profile_int(xcvr, "mux-index"), got.get("mux-index"))
        _cmp(results, f"xcvr {rid} mux-value",
             _profile_int(xcvr, "mux-value"), got.get("mux-value"))
        _cmp(results, f"xcvr {rid} state-gpio-index",
             _profile_int(xcvr, "state-gpio-index"),
             got.get("state-gpio-index"))
        _cmp(results, f"xcvr {rid} state-gpio-base",
             _profile_int(xcvr, "state-gpio-base"),
             got.get("state-gpio-base"))

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile",
                        help="NetLab platform profile (defaults to the active profile)")
    parser.add_argument("--rdi", default=RDI_DEFAULT,
                        help="SDK RDI platform file")
    args = parser.parse_args()

    if args.profile:
        os.environ["NETLAB_PLATFORM_PROFILE"] = args.profile
    try:
        profile = load_profile()
    except PlatformProfileError as exc:
        print(f"FAIL: {exc}")
        return 1
    if not os.path.exists(args.rdi):
        print(f"FAIL: RDI file not found: {args.rdi}")
        return 1

    rdi = parse_rdi(args.rdi)
    results = audit(profile, rdi)
    failed = [r for r in results if r[0] == "fail"]
    for status, label, actual, expected in results:
        print(f"{status.upper()}: {label}: profile={actual} rdi={expected}")
    print(f"\nSummary: {len(results) - len(failed)} ok, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
