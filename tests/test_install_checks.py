import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fm10k_controlpanel import install_checks as checks
from fm10k_controlpanel.profiles import PROFILES
from test_preflight import vpd


@pytest.fixture
def installation_host(tmp_path, monkeypatch):
    host = tmp_path / "host"
    source, sdk, platform_file = tmp_path / "source", tmp_path / "sdk", tmp_path / "platform.cfg"
    source.mkdir(); sdk.mkdir(); platform_file.write_text("synthetic input")
    def put(name, raw):
        path = host / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw if isinstance(raw, bytes) else raw.encode())
        return path
    put("etc/os-release", 'ID=debian\nVERSION_ID="13"\n')
    put("proc/1/comm", "systemd\n")
    put("proc/meminfo", "MemTotal: 4194304 kB\n")
    (host / "run/systemd/system").mkdir(parents=True)
    (host / "opt").mkdir(); (host / "var").mkdir()
    pci = f"sys/bus/pci/devices/{checks.BDF}"
    for name, value in {"vendor":"0x8086","device":"0x15a4","subsystem_vendor":"0x1374","subsystem_device":"0x01d0","revision":"0x01"}.items():
        put(pci + "/" + name, value)
    put(pci + "/vpd", vpd())
    (host / pci / "net/asic0").mkdir(parents=True)
    (host / "sys/class/net/mgmt0").mkdir(parents=True)
    (host / "sys/class/net/asic0").symlink_to(host / pci / "net/asic0", target_is_directory=True)
    calls = []
    def read(*arguments):
        calls.append(arguments)
        if arguments[0] == "systemctl": return "LoadState=not-found\nActiveState=inactive\n"
        if arguments[0] == "apt-cache": return "  Candidate: 6.12.99-1\n"
        assert arguments[:4] == ("ip","-j","address","show")
        return json.dumps([{"addr_info":[{"local":"192.0.2.10","scope":"global"}]}]) if arguments[-1] == "mgmt0" else '[{"addr_info":[]}]'
    monkeypatch.setattr(checks, "inspect_sdk", lambda *_:{"valid":True})
    monkeypatch.setattr(checks, "sha256", lambda _:PROFILES["sil001-hw4-b0"].sha256)
    monkeypatch.setattr(checks.shutil, "disk_usage", lambda _:SimpleNamespace(free=10*1024**3))
    arguments = dict(source=source,sdk=sdk,platform_file=platform_file,interface="mgmt0",management_ip="192.0.2.10",
                     root=host,runner=read,host={"system":"Linux","architecture":"x86_64","kernel":"6.12.99+deb13-amd64"},euid=0)
    return arguments, put, calls


def failed(report):
    return {entry["name"] for entry in report["checks"] if not entry["passed"]}


def test_fresh_host_allows_missing_driver_without_loading_it(installation_host):
    arguments, _, calls = installation_host
    before = {p.relative_to(arguments["root"]).as_posix():p.read_bytes() for p in arguments["root"].rglob("*") if p.is_file()}
    report = checks.preflight(**arguments)
    assert report["passed"], report
    assert report["driver_install_required"]
    assert report["read_only"] and report["profile"] == "sil001-hw4-b0"
    assert all(call[0] in {"ip","systemctl","apt-cache"} for call in calls)
    after = {p.relative_to(arguments["root"]).as_posix():p.read_bytes() for p in arguments["root"].rglob("*") if p.is_file()}
    assert after == before


@pytest.mark.parametrize("key,value,expected", [
    ("etc/os-release",'ID=ubuntu\nVERSION_ID="24.04"\n',"debian13"),
    ("proc/1/comm","bash\n","systemd"),
    (f"sys/bus/pci/devices/{checks.BDF}/subsystem_device","0x0001","board_identity"),
    (f"sys/bus/pci/devices/{checks.BDF}/vpd",b"not a VPD","board_identity"),
    ("sys/firmware/efi/efivars/SecureBoot-fixture",b"\x00\x00\x00\x00\x01","secure_boot"),
    ("sys/firmware/efi/efivars/OtherVariable-fixture",b"unreadable secure boot state","secure_boot"),
    ("proc/meminfo","MemTotal: 10000 kB\n","memory"),
    ("proc/123/comm","switchd\n","asic_owner"),
    ("proc/123/maps","address r--p /dev/uio0\n","asic_owner"),
])
def test_incompatible_host_fails_closed(installation_host,key,value,expected):
    arguments, put, _ = installation_host
    put(key,value)
    report = checks.preflight(**arguments)
    assert not report["passed"] and expected in failed(report)


def test_wrong_sdk_platform_management_and_old_stack_are_rejected(installation_host,monkeypatch):
    arguments, _, _ = installation_host
    monkeypatch.setattr(checks,"inspect_sdk",lambda *_:{"valid":False})
    monkeypatch.setattr(checks,"sha256",lambda _:PROFILES["sil001-hw5-a11"].sha256)
    def read(*args):
        if args[0] == "systemctl": return "LoadState=loaded\nActiveState=inactive\n"
        return '[{"addr_info":[]}]'
    report = checks.preflight(**{**arguments,"runner":read})
    assert {"sdk","platform","management","legacy_owner"} <= failed(report)


def test_a11_uses_its_own_platform_digest(installation_host,monkeypatch):
    arguments, put, _ = installation_host
    put(f"sys/bus/pci/devices/{checks.BDF}/vpd", vpd(revision=b"0600"))
    monkeypatch.setattr(checks,"sha256",lambda _:PROFILES["sil001-hw5-a11"].sha256)
    report = checks.preflight(**arguments)
    assert report["passed"] and report["profile"] == "sil001-hw5-a11"


def test_upgrade_requires_existing_driver_and_uio(installation_host):
    arguments, _, _ = installation_host
    report = checks.preflight(**arguments,upgrading=True)
    assert not report["passed"] and {"driver_runtime","uio_mapping"} <= failed(report)


def test_nonlinux_host_returns_without_any_commands(installation_host):
    arguments, _, calls = installation_host
    report = checks.preflight(**{**arguments,"host":{"system":"Darwin","architecture":"arm64","kernel":"25.0"}})
    assert not report["passed"] and failed(report) == {"linux_amd64"}
    assert calls == []


def test_existing_install_and_multiple_boards_refused(installation_host):
    arguments, put, _ = installation_host
    put("etc/fm10k-controlpanel/native.env","existing settings")
    import shutil
    pci = arguments["root"] / "sys/bus/pci/devices"
    shutil.copytree(pci / checks.BDF, pci / "0000:02:00.0")
    report = checks.preflight(**arguments)
    assert {"fresh_install","board_identity"} <= failed(report)


def test_unbound_card_without_netdev_is_valid_for_fresh_install(installation_host):
    import shutil
    arguments, _, _ = installation_host
    shutil.rmtree(arguments["root"] / f"sys/bus/pci/devices/{checks.BDF}/net")
    assert checks.preflight(**arguments)["passed"]


def test_management_vlan_or_bridge_must_not_depend_on_asic(installation_host):
    arguments, _, _ = installation_host
    links = arguments["root"] / "sys/class/net"
    (links / "mgmt0/lower_asic0").symlink_to(links / "asic0", target_is_directory=True)
    report = checks.preflight(**arguments)
    assert "management" in failed(report)


def test_asic_with_upper_interface_is_not_an_empty_host(installation_host):
    arguments, _, _ = installation_host
    links = arguments["root"] / "sys/class/net"
    (links / "asic0/upper_mgmt0").symlink_to(links / "mgmt0", target_is_directory=True)
    assert "asic_not_management_asic0" in failed(checks.preflight(**arguments))


def test_current_kernel_headers_must_exist_or_be_available(installation_host):
    arguments, put, _ = installation_host
    original = arguments["runner"]
    arguments["runner"] = lambda *a: "  Candidate: (none)\n" if a[0] == "apt-cache" else original(*a)
    assert "kernel_headers" in failed(checks.preflight(**arguments))
    put("lib/modules/6.12.99+deb13-amd64/build/Makefile", "# installed matching headers\n")
    assert checks.preflight(**arguments)["passed"]


def test_prepared_dependency_is_only_allowed_during_second_internal_check(installation_host):
    arguments, put, _ = installation_host
    put("opt/netlab-deps/libyang2/lib/libyang.so", "synthetic library")
    assert "dependency_prefix" in failed(checks.preflight(**arguments))
    assert checks.preflight(**arguments, prepared_libyang=True)["passed"]


def test_open_unmapped_uio_descriptor_refuses_install(installation_host):
    arguments, put, _ = installation_host
    put("proc/123/comm", "other-owner\n")
    descriptors = arguments["root"] / "proc/123/fd"
    descriptors.mkdir()
    (descriptors / "5").symlink_to("/dev/uio0")
    assert "asic_owner" in failed(checks.preflight(**arguments))
