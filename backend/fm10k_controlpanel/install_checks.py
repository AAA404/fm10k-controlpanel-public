"""Read-only installation admission; never load modules or open device nodes."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

from .preflight import inventory, inspect_sdk
from .profiles import PROFILES
from .release import COMPATIBILITY, sha256

LEGACY_UNITS = (
    "pe31625g24dira-switch-manager.service", "pe31625g24dira-fan-init.service",
    "pe31625g24dira-switch.service", "pe31625g24dira-board-init.service",
    "fm10k-testpoint.service", "rrcd.service", "netfabagent.service", "hmonagent.service",
)
BDF = COMPATIBILITY["pci_bdf"]
MIN_FREE = 4 * 1024 ** 3
IORESOURCE_MEM = 0x200
BAR0_MIN_SIZE = 0x100000  # FM10K_UC_ADDR_SIZE in the paired driver.


def read_command(*arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=15,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if result.returncode:
        raise ValueError("read-only host query failed: " + arguments[0])
    return result.stdout


def _text(path, default=""):
    try:
        return path.read_text().strip()
    except OSError:
        return default


def required_pci_apertures(device: Path) -> bool:
    """Require the BARs mapped by the paired driver before changing the host."""
    try:
        resources = (device / "resource").read_text().splitlines()
        for index, minimum_size in ((0, BAR0_MIN_SIZE), (4, 1)):
            start, end, flags = (int(value, 16) for value in resources[index].split()[:3])
            if not start or end < start or end - start + 1 < minimum_size or not flags & IORESOURCE_MEM:
                return False
    except (OSError, ValueError, IndexError):
        return False
    return True


def network_dependencies(root, interface):
    """Include the physical links behind VLANs, bridges and bonds."""
    pending, seen = [interface], set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        if len(seen) >= 128:
            raise ValueError("management interface topology is too large")
        path = root / "sys/class/net" / name
        if not path.is_dir():
            raise ValueError("management interface is missing from sysfs")
        seen.add(name)
        pending.extend(item.name.removeprefix("lower_") for item in path.glob("lower_*"))
    return seen


def preflight(source: Path, sdk: Path, platform_file: Path, interface: str, management_ip: str,
              *, upgrading=False, root=Path("/"), runner=read_command, host=None, euid=None,
              eye_firmware=None, prepared_libyang=False):
    """The root/runner/host seams are for synthetic fixtures, never CLI options."""
    host = host or {"system": platform.system(), "architecture": platform.machine(), "kernel": platform.release()}
    result = {"schema": 1, "read_only": True, "hardware_access": "PCI identity/sysfs only",
              "host": host, "checks": [], "passed": False, "profile": None, "driver_install_required": False}

    def check(name, passed, message):
        result["checks"].append({"name": name, "passed": bool(passed), "message": message})

    check("linux_amd64", host["system"] == "Linux" and host["architecture"] == "x86_64", "需要 Linux x86_64；模拟环境不能授权安装。")
    if not result["checks"][-1]["passed"]:
        return result
    release = dict(line.split("=", 1) for line in _text(root / "etc/os-release").splitlines() if "=" in line)
    check("debian13", release.get("ID", "").strip('"') == "debian" and release.get("VERSION_ID", "").strip('"') == "13", "仅支持 Debian 13。")
    kernel_ok = bool(re.fullmatch(r"6\.12\.[0-9]+[-+.A-Za-z0-9]*", host["kernel"]))
    check("kernel", kernel_ok, "需要 Debian 13 的 6.12 系列内核及匹配 headers。")
    if not upgrading and kernel_ok:
        headers = root / "lib/modules" / host["kernel"] / "build/Makefile"
        try:
            available = headers.is_file() or bool(re.search(
                r"^\s*Candidate:\s+(?!\(none\))\S+", runner("apt-cache", "policy", "linux-headers-" + host["kernel"]), re.M))
        except (OSError, ValueError, subprocess.SubprocessError):
            available = False
        check("kernel_headers", available, "需要已安装或 APT 索引中可取得的当前内核 headers；索引为空时先更新索引再检查。")
    check("root", (os.geteuid() if euid is None else euid) == 0, "需要 root 读取完整 VPD 并检查安装权限。")
    check("python", sys.version_info >= (3, 11), "需要 Python 3.11+；安装后的运行时使用 Debian Python 3.13。")
    check("systemd", (root / "run/systemd/system").is_dir() and _text(root / "proc/1/comm") == "systemd", "需要 systemd 作为 PID 1；容器不能用于硬件安装。")
    variables = list((root / "sys/firmware/efi/efivars").glob("SecureBoot-*"))
    try:
        secure_boot_ok = not (root / "sys/firmware/efi").exists() or (
            len(variables) == 1 and len(variables[0].read_bytes()) >= 5 and variables[0].read_bytes()[4] == 0)
    except OSError:
        secure_boot_ok = False
    check("secure_boot", secure_boot_ok, "自动安装需要确认 Secure Boot 已关闭；EFI 变量不可读时拒绝安装。")
    try:
        inventory_report = inventory(sysfs=root / "sys", os_release=root / "etc/os-release")
        boards = inventory_report["devices"]
        board_ok = len(boards) == 1 and boards[0]["identity_matched"] and boards[0]["bdf"] == BDF
        result["profile"] = inventory_report["profile"] if board_ok else None
        result["board"] = boards[0] if len(boards) == 1 else {"count": len(boards)}
        result["driver_version"] = inventory_report["driver_version"]
        driver_ok = inventory_report["checks"]["driver_version"] and inventory_report["checks"]["uio_bound"]
        result["driver_install_required"] = not driver_ok
        check("board_identity", board_ok, f"需要唯一的 Silicom PE31625G24DiRA，BDF {BDF}，完整且校验通过的 VPD，已知 B0/A11 修订。")
        check("pci_apertures", board_ok and required_pci_apertures(root / f"sys/bus/pci/devices/{BDF}"),
              "配套驱动需要已分配的 PCI BAR0（至少 1 MiB）和 BAR4；缺失时不能映射寄存器或绑定 UIO。")
        current_driver = boards[0]["driver"] if len(boards) == 1 else None
        check("driver_owner", current_driver in (None, "fm10k"), "板卡不能绑定 VFIO、其他驱动或被虚拟机直通。")
        if upgrading:
            check("driver_runtime", driver_ok, "升级必须保留已运行的匹配驱动和 UIO；不会在线更换内核驱动。")
        other_fm10k = [path for path in (root / "sys/bus/pci/drivers/fm10k").glob("????:??:??.?") if path.name != BDF]
        check("driver_exclusive", not other_fm10k, "fm10k 驱动不能同时绑定其他 PCI function。")
        uios = list((root / "sys/class/uio").glob("uio*"))
        check("uio_mapping", (not uios and not upgrading) or len(uios) == 1 and uios[0].name == "uio0" and
              (uios[0] / "device").resolve() == (root / f"sys/bus/pci/devices/{BDF}").resolve(), "原生运行时要求 /dev/uio0 唯一映射到目标板卡。")
    except (OSError, ValueError) as error:
        check("board_identity", False, "无法验证 PCI/VPD：" + str(error))
    try:
        sdk_report = inspect_sdk(sdk, source / "hardware/sdk-inputs.json")
        check("sdk", sdk_report["valid"], "需要与发布版本匹配的 IES 4.3.2 头文件和两份 ELF64 运行库。")
    except (OSError, ValueError, KeyError):
        check("sdk", False, "SDK 缺失或格式无效。")
    profile = PROFILES.get(result["profile"])
    try:
        platform_ok = bool(profile and not platform_file.is_symlink() and sha256(platform_file) == profile.sha256)
    except OSError:
        platform_ok = False
    check("platform", platform_ok, "原厂平台文件必须匹配当前板卡修订和锁定 SHA-256；B0 与 A11 不可互换。")
    if eye_firmware is not None:
        try:
            firmware = json.loads((source / "hardware/eye-firmware.json").read_text())
            valid = (not eye_firmware.is_symlink() and eye_firmware.stat().st_size == firmware["binary_bytes"]
                     and sha256(eye_firmware) == firmware["binary_sha256"])
        except (OSError, ValueError, KeyError):
            valid = False
        check("eye_firmware", valid, "可选眼图微码必须匹配本版本锁定的二进制大小与 SHA-256。")
    try:
        ip = ipaddress.ip_address(management_ip)
        valid_interface = bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", interface))
        if not valid_interface or ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
            raise ValueError("invalid management address/interface")
        addresses = json.loads(runner("ip", "-j", "address", "show", "dev", interface))
        assigned = {entry["local"] for item in addresses for entry in item.get("addr_info", [])}
        asic_net = root / f"sys/bus/pci/devices/{BDF}/net"
        asic_interfaces = {path.name for path in asic_net.iterdir()} if asic_net.exists() else set()
        dependencies = network_dependencies(root, interface)
        independent = not (dependencies & asic_interfaces) and all(
            (root / "sys/class/net" / name / "device").resolve() != asic_net.parent.resolve()
            for name in dependencies)
        check("management", str(ip) in assigned and independent, "管理地址必须已经配置在独立管理网卡上，且 VLAN/bridge/bond 不能依赖 ASIC 网卡；脚本不会配置 IP、路由或防火墙。")
        if not upgrading:
            for netdev in asic_interfaces:
                asic_addresses = json.loads(runner("ip", "-j", "address", "show", "dev", netdev))
                active = [entry for item in asic_addresses for entry in item.get("addr_info", []) if entry.get("scope") != "link"]
                netpath = root / "sys/class/net" / netdev
                attached = (netpath / "master").exists() or any(netpath.glob("upper_*"))
                check("asic_not_management_" + netdev, not active and not attached, "ASIC CPU 网卡不能承载已有 IP，也不能加入 bridge/bond/VLAN。")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        check("management", False, "无法确认独立管理网卡及已配置地址。")
    try:
        legacy = runner("systemctl", "show", *LEGACY_UNITS, "--property=LoadState,ActiveState")
        check("legacy_owner", "LoadState=loaded" not in legacy and "ActiveState=active" not in legacy, "检测到旧交换栈时拒绝安装；应先单独完成迁移。")
    except (OSError, ValueError, subprocess.SubprocessError):
        check("legacy_owner", False, "无法确认旧服务状态。")
    if not upgrading:
        occupied = any((root / path).exists() for path in (
            "opt/fm10k-controlpanel/native", "var/lib/fm10k-controlpanel-native",
            "etc/fm10k-controlpanel/native.env", "var/lib/fm10k-controlpanel/accounts.json",
            "var/lib/fm10k-controlpanel-updates/installation.json", "etc/fm10k-controlpanel/tls",
            "etc/systemd/system/fm10k-switch.target", "etc/systemd/system/fm10k-switchd.service",
            "etc/nginx/sites-available/fm10k-controlpanel", "etc/nginx/sites-enabled/fm10k-controlpanel"))
        check("fresh_install", not occupied, "首次安装只接受空白环境；已有安装必须使用配套升级流程。")
        if not prepared_libyang:
            check("dependency_prefix", not (root / "opt/netlab-deps/libyang2").exists(), "首次安装不能覆盖已有 libyang 目录。")
        if result["driver_install_required"]:
            check("driver_source", not (root / "usr/src/fm10k-uio-6.12.101-ies2").exists(), "不能覆盖已有 DKMS 驱动源码；需先单独检查。")
        try:
            owners = []
            for process in (root / "proc").iterdir():
                if not process.name.isdecimal():
                    continue
                cmdline = _text(process / "comm")
                if cmdline in {"switchd", "TestPoint", "testpoint", "rrcd", "netfabagent", "hmonagent"}:
                    owners.append(process.name)
                try:
                    maps = (process / "maps").read_text()
                except (FileNotFoundError, ProcessLookupError):
                    maps = ""
                try:
                    descriptors = "\n".join(os.readlink(fd) for fd in (process / "fd").iterdir())
                except (FileNotFoundError, ProcessLookupError):
                    descriptors = ""
                mappings = maps + "\n" + descriptors
                if "/dev/uio0" in mappings or f"/{BDF}/resource" in mappings or "libFocalpointSDK.so" in mappings:
                    owners.append(process.name)
            check("asic_owner", not owners, "首次安装前不能有进程映射 ASIC、UIO 或 SDK。")
        except OSError:
            check("asic_owner", False, "无法确认已有 ASIC 使用者。")
    for mount in ("opt", "var"):
        path = root / mount
        while not path.exists():
            path = path.parent
        check("disk_" + mount, shutil.disk_usage(path).free >= MIN_FREE, f"/{mount} 所在文件系统至少需要 4 GiB 可用空间。")
    memory = re.search(r"^MemTotal:\s+(\d+)\s+kB", _text(root / "proc/meminfo"), re.M)
    check("memory", bool(memory and int(memory[1]) >= 512 * 1024), "至少需要 512 MiB 内存；构建使用单进程以适应板载 CPU。")
    result["passed"] = all(item["passed"] for item in result["checks"])
    result["next_action"] = "可以显式执行 install" if result["passed"] else "修复未通过项后重新检查；没有更改系统或板卡"
    return result
