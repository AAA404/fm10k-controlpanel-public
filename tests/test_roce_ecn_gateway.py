"""Recovery and evidence regressions for the optional physical software lab."""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import runpy
import struct
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
gateway = runpy.run_path(str(ROOT / "scripts/roce_ecn_gateway.py"))
packets = runpy.run_path(str(ROOT / "scripts/verify_roce_ecn_capture.py"))


def args(tmp_path):
    return argparse.Namespace(ingress="ethA", egress="ethB", source="198.18.77.2",
                              destination="198.18.77.1", dscp=26, cnp_dscp=48,
                              rate_mbit=100, lifetime=10, evidence=tmp_path)


def original():
    return {"link": {"ifindex": 3, "ifname": "ethA", "address": "02:00:00:00:00:01", "flags": ["UP"]},
            "qdiscs": [{"kind": "mq", "handle": "0:", "root": True, "options": {}, "refcnt": 2}]}


def test_restore_failure_retains_the_namespace_and_nic_lease_for_retry(tmp_path):
    lab = gateway["Gateway"](args(tmp_path))
    lab.before = {"ethA": original()}
    lab.owned_names = [lab.names[0]]
    lab.moved = [{"interface": "ethA", "namespace": lab.names[0], "side": 0}]
    seen, fail_move = [], [True]

    def command(argv, **_):
        seen.append(argv)
        if "netns" in argv and str(os.getpid()) in argv and fail_move[0]:
            raise RuntimeError("injected move failure")
        return SimpleNamespace(returncode=0, stdout=json.dumps([original()["link"]]))

    lab.command = command
    lab.inspect = lambda _: original()
    lab.cleanup()
    assert not lab.report["cleaned_up"] and lab.moved and lab.owned_names
    assert not any(cmd[:3] == ["ip", "netns", "delete"] for cmd in seen)
    assert json.loads((tmp_path / "report.json").read_text())["moved_interfaces"]
    fail_move[0] = False
    lab.cleanup()
    assert lab.report["cleaned_up"] and not lab.moved and not lab.owned_names


def test_changed_nic_identity_is_never_moved_or_removed(tmp_path):
    lab = gateway["Gateway"](args(tmp_path))
    lab.before = {"ethA": original()}
    lab.owned_names = [lab.names[0]]
    lab.moved = [{"interface": "ethA", "namespace": lab.names[0], "side": 0}]
    other = dict(original()["link"], ifindex=9)
    seen = []

    def command(argv, **_):
        seen.append(argv)
        return SimpleNamespace(returncode=0, stdout=json.dumps([other]))

    lab.command = command
    lab.inspect = lambda _: original()
    lab.cleanup()
    assert not lab.report["cleaned_up"] and lab.moved
    assert all("set" not in cmd and "delete" not in cmd for cmd in seen)


def test_old_iproute2_broken_statistics_json_retains_plaintext_evidence(tmp_path):
    lab = gateway["Gateway"](args(tmp_path))
    lab.tc = lambda *argv: '{"rate": 100Mbit}' if "-j" in argv else "marked 7 early 0 pdrop 0 other 0"
    lab.snapshot("sample")
    saved = json.loads((tmp_path / "sample.json").read_text())
    assert saved["qdisc_text"].startswith("marked 7")
    assert saved["class_json_error"] and saved["class_raw_json"] == '{"rate": 100Mbit}'


@pytest.mark.parametrize("move_happened", [False, True])
def test_uncertain_move_keeps_recovery_responsibility_until_location_is_proved(tmp_path, move_happened):
    lab = gateway["Gateway"](args(tmp_path))
    lab.before = {"ethA": original()}
    lab.preflight = lambda: None
    in_namespace = [False]

    def inspect(_):
        if in_namespace[0]:
            raise RuntimeError("NIC is still in test namespace")
        return original()

    def command(argv, **_):
        if argv == ["ip", "link", "set", "dev", "ethA", "netns", lab.names[0]]:
            saved = json.loads((tmp_path / "report.json").read_text())
            assert saved["moved_interfaces"][0]["interface"] == "ethA"
            in_namespace[0] = move_happened
            raise RuntimeError("move command timed out; outcome unknown")
        if argv[:3] == ["ip", "netns", "delete"]:
            assert not in_namespace[0], "never delete a namespace containing the leased NIC"
        if "netns" in argv and str(os.getpid()) in argv:
            in_namespace[0] = False
        missing = "show" in argv and not in_namespace[0]
        return SimpleNamespace(returncode=1 if missing else 0, stdout=json.dumps([original()["link"]]))

    lab.command, lab.inspect = command, inspect
    with pytest.raises(RuntimeError, match="outcome unknown"):
        lab.setup()
    assert lab.moved
    lab.cleanup()
    assert lab.report["cleaned_up"] and not lab.moved and not in_namespace[0]


def test_zero_handle_does_not_make_a_tuned_queue_safe_to_reset():
    row = {"kind": "fq_codel", "handle": "0:", "options": {
        "limit": 10240, "flows": 1024, "quantum": 1514, "target": 4999,
        "interval": 99999, "memory_limit": 33554432, "ecn": True}}
    assert gateway["default_qdiscs"]([row])
    changed = copy.deepcopy(row)
    changed["options"]["limit"] = 1000
    assert not gateway["default_qdiscs"]([changed])
    assert gateway["qdisc_configuration"]([dict(row, refcnt=3)]) == gateway["qdisc_configuration"]([row])


def synthetic_frame(ecn=2, cnp=False):
    # Parser fixtures only; the final four sentinel bytes are not a valid ICRC.
    source, destination = ("198.18.77.2", "198.18.77.1")
    if cnp:
        source, destination = destination, source
    bth = bytearray(12)
    bth[0] = 0x81 if cnp else 10
    bth[5:8] = (15 if cnp else 333).to_bytes(3, "big")
    bth[9:12] = (123).to_bytes(3, "big")
    payload = bytes(bth) + b"test payloadICRC"
    udp = struct.pack("!HHHH", 49000, 4791, 8 + len(payload), 0) + payload
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, ((48 if cnp else 26) << 2) | ecn,
                               20 + len(udp), 1, 0, 64, 17, 0,
                               ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed))
    ip[10:12] = struct.pack("!H", packets["checksum"](ip))
    return bytes.fromhex("0200000000010200000000020800") + bytes(ip) + udp


def check(before, after, cnps=None):
    return packets["verify"](before, after, cnps or [packets["decode"](synthetic_frame(cnp=True))],
                             "198.18.77.2", "198.18.77.1", 333, 15)


def test_evidence_rejects_corruption_and_duplicate_psns_instead_of_counting_copies():
    before = packets["decode"](synthetic_frame())
    after = packets["decode"](synthetic_frame(ecn=3))
    assert check([before], [after])["passed"]
    corrupt = bytearray(synthetic_frame(ecn=3)); corrupt[-5] ^= 1
    assert not check([before], [packets["decode"](bytes(corrupt))])["passed"]
    assert not check([before, before], [after, after])["passed"]
    corrupt = bytearray(synthetic_frame()); corrupt[15] |= 3
    with pytest.raises(ValueError, match="IPv4 checksum"):
        packets["decode"](bytes(corrupt))


def test_cnp_must_target_the_real_sender_and_ecn_cannot_mark_not_ect():
    before = packets["decode"](synthetic_frame(ecn=0))
    after = packets["decode"](synthetic_frame(ecn=3))
    assert not check([before], [after])["passed"]
    before = packets["decode"](synthetic_frame())
    cnp = packets["decode"](synthetic_frame(cnp=True)); cnp["qpn"] = 99
    assert not check([before], [after], [cnp])["passed"]
