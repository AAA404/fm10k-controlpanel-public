from pathlib import Path

import pytest

from fm10k_controlpanel.preflight import inspect_pci_device, inventory, parse_vpd
from fm10k_controlpanel.profiles import PROFILES


def vpd(revision=b"0490", model=b"PE31625G24DIRA-MPS", serial=b"S000000000001"):
    fields = b"V1" + bytes([len(revision)]) + revision + b"SN" + bytes([len(serial)]) + serial
    raw = b"\x82" + len(model).to_bytes(2, "little") + model + b"\x90" + (len(fields) + 4).to_bytes(2, "little") + fields + b"RV\x01"
    return raw + bytes([-sum(raw) % 256]) + b"\x78"


def silicom_vpd(revision=b"0680", serial=b"F100000000001"):
    # Captured 01v00/PRDi resource layout. The physical serial is anonymized.
    raw = (b"\x82\x7d\x00" + b"01v00       \x00" + b"\xff" * 32
           + bytes.fromhex("505244690106044c0400ffffffffffff")
           + b"PE31625G24DiRA-MPS" + b"\x00" * 10 + revision
           + b"\xff" * 16 + serial + b"\x00" * 3
           + bytes.fromhex("900e0056530230005650023400525601"))
    return raw + bytes([-sum(raw) % 256]) + b"\x78"


@pytest.mark.parametrize("revision,family", [(b"0490", "B0"), (b"0690", "A11")])
def test_vpd_revision_rule_is_separate_from_identity(revision, family):
    identity = parse_vpd(vpd(revision))
    assert identity["family"] == family and identity["vpd_version"] == revision.decode()
    assert identity["model"] == "PE31625G24DIRA-MPS"


@pytest.mark.parametrize("raw", [b"", b"PE31625G24DIRA 0490 S000000000001", vpd()[:-1], b"\x90\xff\xff"])
def test_invalid_vpd_never_unlocks_profile(raw):
    with pytest.raises(ValueError):
        parse_vpd(raw)


def test_subsystem_and_vpd_are_both_required(tmp_path):
    device = tmp_path / "0000:03:00.0"
    device.mkdir()
    fields = {"vendor": "0x8086", "device": "0x15a4", "subsystem_vendor": "0x1374", "subsystem_device": "0x01d0"}
    for name, value in fields.items():
        (device / name).write_text(value + "\n")
    (device / "vpd").write_bytes(vpd())
    assert inspect_pci_device(device)["identity_matched"]
    (device / "subsystem_device").write_text("0xffff")
    assert not inspect_pci_device(device)["identity_matched"]
    (device / "subsystem_device").write_text("0x01d0")
    (device / "vpd").write_bytes(vpd(b"0690"))
    assert inspect_pci_device(device)["candidate_profile"] == "sil001-hw5-a11"
    (device / "vpd").write_bytes(vpd(b"0000"))
    assert not inspect_pci_device(device)["identity_matched"]


def test_real_silicom_binary_identifier_and_f_serial(tmp_path):
    raw = silicom_vpd()
    assert len(raw) == 146
    identity = parse_vpd(raw)
    assert identity == {"model": "PE31625G24DIRA-MPS", "serial": "F100000000001",
                        "vpd_version": "0680", "family": "A11", "checksum_valid": True,
                        "family_source": "supplied Aurum VPD-version rule; not an ASIC register"}
    device = tmp_path / "0000:01:00.0"
    device.mkdir()
    for name, value in {"vendor": "0x8086", "device": "0x15a4", "subsystem_vendor": "0x1374", "subsystem_device": "0x01d0"}.items():
        (device / name).write_text(value)
    (device / "vpd").write_bytes(raw)
    report = inspect_pci_device(device)
    assert report["identity_matched"] and report["candidate_profile"] == "sil001-hw5-a11"
    assert report["profile_qualification"] == "unqualified"
    assert report["vpd_error"] is None and report["profile_rejection"] is None
    (device / "vpd").write_bytes(silicom_vpd(b"0490"))
    assert inspect_pci_device(device)["identity_matched"]


@pytest.mark.parametrize("offset", [0, 1, 64, 93, 112, 144, 145])
def test_silicom_vpd_corruption_rejected(offset):
    raw = bytearray(silicom_vpd())
    raw[offset] ^= 1
    with pytest.raises(ValueError):
        parse_vpd(bytes(raw))


def test_writable_and_trailing_strings_cannot_claim_identity():
    raw = silicom_vpd()
    payload = b"PE31625G24DIRA-MPS 0490 S000000000000"
    writable = b"\x91" + len(payload).to_bytes(2, "little") + payload
    assert parse_vpd(raw[:-1] + writable + b"\x78")["family"] == "A11"
    with pytest.raises(ValueError):
        parse_vpd(raw + payload)


def test_missing_checksum_never_matches_supported_profile(tmp_path):
    device = tmp_path / "0000:01:00.0"
    device.mkdir()
    for name, value in {"vendor": "0x8086", "device": "0x15a4", "subsystem_vendor": "0x1374", "subsystem_device": "0x01d0"}.items():
        (device / name).write_text(value)
    raw = silicom_vpd(b"0490")
    (device / "vpd").write_bytes(raw[:128] + b"\x78")
    report = inspect_pci_device(device)
    assert report["identity"]["family"] == "B0" and not report["identity_matched"]
    assert report["profile_rejection"] == "missing_vpd_checksum"


@pytest.mark.parametrize("profile,revision", [("sil001-hw4-b0", b"0490"), ("sil001-hw5-a11", b"0680")])
def test_recognized_inventory_never_authorizes_hardware_writes(tmp_path, monkeypatch, profile, revision):
    monkeypatch.setattr("fm10k_controlpanel.preflight.platform.machine", lambda: "x86_64")
    device = tmp_path / "sys/bus/pci/devices/0000:01:00.0"
    device.mkdir(parents=True)
    for name, value in {"vendor": "0x8086", "device": "0x15a4", "subsystem_vendor": "0x1374", "subsystem_device": "0x01d0"}.items():
        (device / name).write_text(value)
    (device / "vpd").write_bytes(silicom_vpd(revision))
    (device / "uio/uio0").mkdir(parents=True)
    (device / "driver").symlink_to(tmp_path / "sys/bus/pci/drivers/fm10k")
    driver = tmp_path / "sys/module/fm10k"
    driver.mkdir(parents=True)
    (driver / "version").write_text("6.12.101-ies2")
    release = tmp_path / "os-release"
    release.write_text('ID=debian\nVERSION_ID="13"\n')
    result = inventory(sysfs=tmp_path / "sys", os_release=release)
    assert result["preflight_passed"] and result["profile"] == profile
    assert not result["hardware_write_ready"] and result["hardware_qualification"] == "not-run"
    assert result["devices"][0]["identity"]["family"] == PROFILES[profile].family
    (device / "vpd").write_bytes(silicom_vpd(b"0000"))
    result = inventory(sysfs=tmp_path / "sys", os_release=release)
    assert not result["preflight_passed"] and result["profile"] is None
    assert result["checks"]["uio_bound"]  # driver observation is independent of board matching
