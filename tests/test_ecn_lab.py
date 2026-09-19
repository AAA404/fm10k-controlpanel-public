import copy
import runpy
from pathlib import Path
import struct

import pytest

from fm10k_controlpanel.ecn_lab import (
    EcnLabProfile, PCAP_HEADER, cases, checksum, make_frame, parse_frame,
    read_capture, verify_stage, write_packet,
)


def changed(frame, ecn=3, dscp=None, recalculate=True):
    packet = parse_frame(frame)
    raw = bytearray(frame)
    offset = packet["ip_offset"]
    tos = ((packet["dscp"] if dscp is None else dscp) << 2) | ecn
    if packet["family"] == 4:
        raw[offset + 1] = tos
        if recalculate:
            raw[offset + 10:offset + 12] = b"\0\0"
            raw[offset + 10:offset + 12] = struct.pack("!H", checksum(raw[offset:offset + 20]))
    else:
        raw[offset] = (raw[offset] & 0xF0) | (tos >> 4)
        raw[offset + 1] = (raw[offset + 1] & 15) | ((tos & 15) << 4)
    return bytes(raw)


def captures(stage):
    profile = EcnLabProfile()
    sent, received, raw = {}, {}, {}
    for index, case in enumerate(cases(profile)):
        for sequence in range(3):
            frame = make_frame(case, b"x" * 16, stage, index, sequence)
            packet = parse_frame(frame)
            key = packet["key"]
            sent[key], raw[key] = packet, frame
            if stage == 1 and case["queue"] == "data":
                if case["ecn"] == 0 and sequence == 0:
                    continue
                if case["ecn"] in (1, 2):
                    frame = changed(frame)
            received[key] = parse_frame(frame)
    return profile, sent, received, raw


def test_profile_rejects_ambiguous_or_unsafe_thresholds():
    for values in ({"data_dscp": 48}, {"min_bytes": 24576}, {"max_bytes": 65536},
                   {"rate_kbit": True}, {"vlan": 4095}, {"probability": float("nan")},
                   {"probability": 0}, {"limit_bytes": 2_000_000}):
        with pytest.raises(ValueError):
            EcnLabProfile(**values)


def test_wire_checksums_and_vlan_ipv6_flow_label_survive_ecn_change():
    for case in cases(EcnLabProfile()):
        frame = make_frame(case, b"x" * 16, 0, 0, 0)
        before, after = parse_frame(frame), parse_frame(changed(frame))
        assert before["ip_checksum_valid"] and before["udp_checksum_valid"]
        assert after["ip_checksum_valid"] and after["udp_checksum_valid"]
        assert before["unchanged_digest"] == after["unchanged_digest"]
        assert after["ecn"] == 3 and after["dscp"] == case["dscp"]


def test_packet_evidence_distinguishes_idle_congestion_and_recovery():
    for stage in range(3):
        profile, sent, received, _ = captures(stage)
        result = verify_stage(profile, stage, sent, sent, received)
        assert result["passed"], result["errors"]
        assert len(result["cases"]) == 28
    assert not verify_stage(EcnLabProfile(), 1, {}, {}, {})["passed"]


def test_recovery_preserves_transient_evidence_but_rejects_persistent_marking():
    profile, sent, received, raw = captures(2)
    ect_case = next(k[2] for k in sent if sent[k]["ecn"] == 1)
    keys = sorted(k for k in sent if k[2] == ect_case)
    received[keys[0]] = parse_frame(changed(raw[keys[0]]))
    result = verify_stage(profile, 2, sent, sent, received)
    assert result["passed"] and result["cases"][ect_case]["marked_ce"] == 1
    assert result["cases"][ect_case]["steady_window"]["marked_ce"] == 0
    received[keys[-1]] = parse_frame(changed(raw[keys[-1]]))
    assert not verify_stage(profile, 2, sent, sent, received)["passed"]


def test_congestion_may_drop_all_not_ect_data_but_idle_must_deliver():
    for stage in (0, 1):
        profile, sent, received, _ = captures(stage)
        received = {key: packet for key, packet in received.items() if packet["ecn"] != 0}
        assert verify_stage(profile, stage, sent, sent, received)["passed"] == (stage == 1)


@pytest.mark.parametrize("fault", ["dscp", "not-ect", "checksum", "no-mark", "bypass", "missing-capture"])
def test_verification_rejects_false_success(fault):
    profile, sent, received, raw = captures(1)
    if fault == "dscp":
        key = next(k for k in received if sent[k]["ecn"] == 1)
        received[key] = parse_frame(changed(raw[key], dscp=1))
    elif fault == "not-ect":
        key = next(k for k in received if sent[k]["ecn"] == 0)
        received[key] = parse_frame(changed(raw[key]))
    elif fault == "checksum":
        key = next(k for k in received if sent[k]["family"] == 4 and sent[k]["ecn"] == 1)
        received[key] = parse_frame(changed(raw[key], recalculate=False))
    elif fault == "no-mark":
        received = {key: sent[key] for key in received}
    elif fault == "bypass":
        key = next(k for k in received if sent[k]["dscp"] == profile.cnp_dscp)
        received[key] = parse_frame(changed(raw[key]))
    else:
        sent = copy.deepcopy(sent)
        del sent[next(iter(sent))]
    assert not verify_stage(profile, 1, sent, sent, received)["passed"]


def test_capture_truncation_and_duplicates_are_errors(tmp_path):
    frame = make_frame(cases(EcnLabProfile())[0], b"x" * 16, 0, 0, 0)
    path = tmp_path / "sample.pcap"
    with path.open("wb") as file:
        file.write(PCAP_HEADER)
        write_packet(file, frame, 123.5)
    assert len(read_capture(path)) == 1
    with path.open("ab") as file:
        write_packet(file, frame, 124.5)
    with pytest.raises(ValueError, match="duplicate"):
        read_capture(path)
    path.write_bytes(path.read_bytes()[:-10])
    with pytest.raises(ValueError, match="truncated"):
        read_capture(path)


def test_partial_setup_failure_removes_only_owned_namespaces(tmp_path):
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/verify_ecn_marking.py"))
    lab = module["Lab"](tmp_path)
    seen = []

    def command(argv, **_kwargs):
        seen.append(argv)
        if argv[:3] == ["ip", "netns", "add"] and argv[3] == lab.names["dst"]:
            raise RuntimeError("injected namespace creation failure")
        return ""

    lab.command = command
    with pytest.raises(RuntimeError, match="injected"):
        lab.setup()
    lab.cleanup()
    assert lab.report["cleaned_up"]
    assert [c[3] for c in seen if c[:3] == ["ip", "netns", "del"]] == [lab.names["sw"], lab.names["src"]]
    assert not lab.report["passed"]
