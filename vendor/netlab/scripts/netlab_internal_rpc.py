#!/usr/bin/env python3.11
"""Invoke the release-owned sealed INTERNAL RPC authority."""

from __future__ import annotations

import os
import stat
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path


HELPER_NAME = "netlab-internal-rpc"
PRODUCTION_RELEASES_ROOT = Path("/opt/netlab-runtime/releases")
MAX_PAYLOAD = 256 * 1024
ENVELOPE_MAGIC = 0x4E4C4952
ENVELOPE_VERSION = 1
ENVELOPE = struct.Struct(">IHiI")
SERVICE_BINARIES = {
    2: "configd",
    4: "rpd",
    7: "switchd",
    14: "l2d",
}


class InternalRpcError(RuntimeError):
    """Raised when the sealed helper or its transport fails."""


@dataclass(frozen=True)
class InternalRpcResponse:
    error_code: int
    payload: bytes


@dataclass(frozen=True)
class _PathIdentity:
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class _SocketIdentity:
    kernel_inode: str
    path_identity: _PathIdentity


@dataclass(frozen=True)
class _ListenerIdentity:
    pid: int
    euid: int
    egid: int
    executable: Path
    executable_identity: _PathIdentity


@dataclass(frozen=True)
class _LiveHelperResolution:
    socket: _SocketIdentity
    listener: _ListenerIdentity
    helper: Path
    helper_identity: _PathIdentity


def _identity_from_stat(result: os.stat_result) -> _PathIdentity:
    return _PathIdentity(
        device=result.st_dev,
        inode=result.st_ino,
        uid=result.st_uid,
        gid=result.st_gid,
        mode=result.st_mode,
        size=result.st_size,
        mtime_ns=result.st_mtime_ns,
        ctime_ns=result.st_ctime_ns,
    )


def _secure_directory(path: Path, label: str) -> _PathIdentity:
    try:
        result = path.lstat()
    except OSError as exc:
        raise InternalRpcError(f"cannot inspect {label} {path}: {exc}") from exc
    if (
        not stat.S_ISDIR(result.st_mode)
        or result.st_uid != 0
        or result.st_gid != 0
        or result.st_mode & 0o022
    ):
        raise InternalRpcError(
            f"{label} must be a root-owned, non-group/other-writable "
            f"real directory: {path}"
        )
    return _identity_from_stat(result)


def _secure_executable(path: Path, label: str) -> _PathIdentity:
    try:
        result = path.lstat()
    except OSError as exc:
        raise InternalRpcError(f"cannot inspect {label} {path}: {exc}") from exc
    if (
        not stat.S_ISREG(result.st_mode)
        or result.st_uid != 0
        or result.st_gid != 0
        or result.st_mode & 0o022
        or result.st_mode & 0o111 == 0
    ):
        raise InternalRpcError(
            f"{label} must be a root-owned, non-group/other-writable "
            f"regular executable: {path}"
        )
    return _identity_from_stat(result)


def _validate_directory_chain(anchor: Path, leaf: Path, label: str) -> None:
    try:
        relative = leaf.relative_to(anchor)
    except ValueError as exc:
        raise InternalRpcError(f"{label} is outside trusted root {anchor}") from exc
    current = anchor
    _secure_directory(current, f"{label} trusted root")
    for component in relative.parts:
        if component in ("", ".", ".."):
            raise InternalRpcError(f"{label} contains an unsafe component: {leaf}")
        current /= component
        _secure_directory(current, f"{label} path")


def _validate_release_executable(
    executable: Path,
    expected_binary: str,
    trusted_root: Path,
) -> _PathIdentity:
    if not executable.is_absolute() or not trusted_root.is_absolute():
        raise InternalRpcError("live release paths must be absolute")
    try:
        relative = executable.relative_to(trusted_root)
    except ValueError as exc:
        raise InternalRpcError(
            f"listener executable is outside trusted release root "
            f"{trusted_root}: {executable}"
        ) from exc
    if (
        len(relative.parts) != 3
        or relative.parts[1] != "build"
        or relative.parts[2] != expected_binary
        or any(part in ("", ".", "..") for part in relative.parts)
    ):
        raise InternalRpcError(
            "listener executable does not have sealed release layout "
            f"<trusted-root>/<release>/build/{expected_binary}: {executable}"
        )
    if trusted_root == PRODUCTION_RELEASES_ROOT:
        _validate_directory_chain(
            Path("/"), trusted_root, "production release root"
        )
    _validate_directory_chain(
        trusted_root, executable.parent, "listener release"
    )
    return _secure_executable(executable, "listener executable")


def _listener_inode(socket_path: Path) -> _SocketIdentity:
    try:
        socket_stat = socket_path.lstat()
    except OSError as exc:
        raise InternalRpcError(
            f"cannot inspect INTERNAL RPC socket {socket_path}: {exc}"
        ) from exc
    if (
        not stat.S_ISSOCK(socket_stat.st_mode)
        or socket_stat.st_uid != 0
        or socket_stat.st_mode & 0o007
    ):
        raise InternalRpcError(
            "INTERNAL RPC path must be a root-owned socket without "
            f"world permissions: {socket_path}"
        )
    _secure_directory(socket_path.parent, "INTERNAL RPC socket parent")

    matches: set[str] = set()
    try:
        lines = Path("/proc/net/unix").read_text(
            encoding="utf-8"
        ).splitlines()
    except OSError as exc:
        raise InternalRpcError(
            f"cannot inspect UNIX listeners for {socket_path}: {exc}"
        ) from exc
    for line in lines:
        fields = line.split()
        if (
            len(fields) >= 8
            and fields[3] == "00010000"
            and fields[4] == "0005"
            and fields[5] == "01"
            and fields[-1] == str(socket_path)
        ):
            matches.add(fields[6])
    if len(matches) != 1:
        raise InternalRpcError(
            "INTERNAL RPC socket must resolve to exactly one listening "
            f"SOCK_SEQPACKET inode: path={socket_path} inodes={sorted(matches)}"
        )
    return _SocketIdentity(
        next(iter(matches)), _identity_from_stat(socket_stat)
    )


def _effective_ids(pid: int) -> tuple[int, int]:
    euid: int | None = None
    egid: int | None = None

    try:
        lines = Path(f"/proc/{pid}/status").read_text(
            encoding="ascii"
        ).splitlines()
    except OSError as exc:
        raise InternalRpcError(
            f"cannot inspect INTERNAL RPC listener credentials pid={pid}: {exc}"
        ) from exc
    for line in lines:
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "Uid:":
            euid = int(fields[2])
        elif len(fields) >= 3 and fields[0] == "Gid:":
            egid = int(fields[2])
    if euid is None or egid is None:
        raise InternalRpcError(
            f"cannot parse INTERNAL RPC listener credentials pid={pid}"
        )
    return euid, egid


def _listener_owner(
    inode: str, expected_binary: str, trusted_root: Path
) -> _ListenerIdentity:
    expected = f"socket:[{inode}]"
    owners: set[int] = set()

    try:
        process_entries = list(Path("/proc").iterdir())
    except OSError as exc:
        raise InternalRpcError(
            f"cannot inspect processes for listener inode {inode}: {exc}"
        ) from exc
    for process_entry in process_entries:
        if not process_entry.name.isdecimal():
            continue
        try:
            descriptors = list((process_entry / "fd").iterdir())
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                if os.readlink(descriptor) == expected:
                    owners.add(int(process_entry.name))
                    break
            except OSError:
                continue
    if len(owners) != 1:
        raise InternalRpcError(
            "INTERNAL RPC listener must have exactly one process owner: "
            f"inode={inode} owners={sorted(owners)}"
        )

    pid = next(iter(owners))
    euid, egid = _effective_ids(pid)
    if euid != 0 or egid != 0:
        raise InternalRpcError(
            "INTERNAL RPC listener must run with effective UID/GID 0: "
            f"pid={pid} euid={euid} egid={egid}"
        )
    try:
        executable_text = os.readlink(f"/proc/{pid}/exe")
        running_stat = os.stat(f"/proc/{pid}/exe")
    except OSError as exc:
        raise InternalRpcError(
            f"cannot resolve INTERNAL RPC listener executable pid={pid}: {exc}"
        ) from exc
    if executable_text.endswith(" (deleted)"):
        raise InternalRpcError(
            f"INTERNAL RPC listener executable is deleted: {executable_text}"
        )
    executable = Path(executable_text)
    if not executable.is_absolute():
        raise InternalRpcError(
            "INTERNAL RPC listener executable is not absolute: "
            f"{executable}"
        )
    if executable.name != expected_binary:
        raise InternalRpcError(
            "INTERNAL RPC service does not match listener executable: "
            f"expected={expected_binary} actual={executable.name}"
        )
    executable_identity = _validate_release_executable(
        executable, expected_binary, trusted_root
    )
    if (
        executable_identity.device != running_stat.st_dev
        or executable_identity.inode != running_stat.st_ino
    ):
        raise InternalRpcError(
            "INTERNAL RPC listener executable path no longer names the "
            f"running inode: pid={pid} executable={executable}"
        )
    return _ListenerIdentity(
        pid, euid, egid, executable, executable_identity
    )


def _observe_live_release(
    service: int, socket_path: Path, trusted_root: Path
) -> _LiveHelperResolution:
    expected_binary = SERVICE_BINARIES.get(service)
    if expected_binary is None:
        raise InternalRpcError(
            f"service {service} has no sealed INTERNAL RPC endpoint"
        )

    socket_identity = _listener_inode(socket_path)
    listener = _listener_owner(
        socket_identity.kernel_inode, expected_binary, trusted_root
    )
    helper = listener.executable.with_name(HELPER_NAME)
    helper_identity = _secure_executable(
        helper, "same-release sealed helper"
    )
    return _LiveHelperResolution(
        socket_identity, listener, helper, helper_identity
    )


def _live_release_resolution(
    service: int,
    socket_path: Path,
    *,
    _trusted_root: Path = PRODUCTION_RELEASES_ROOT,
) -> _LiveHelperResolution:
    first = _observe_live_release(service, socket_path, _trusted_root)
    second = _observe_live_release(service, socket_path, _trusted_root)
    if first != second:
        raise InternalRpcError(
            "INTERNAL RPC listener or helper identity changed during resolution"
        )
    return second


def _live_release_helper(
    service: int,
    socket_path: Path,
    *,
    _trusted_root: Path = PRODUCTION_RELEASES_ROOT,
) -> Path:
    return _live_release_resolution(
        service, socket_path, _trusted_root=_trusted_root
    ).helper


def _helper_for(
    release_root: str | os.PathLike[str] | None,
    helper_path: str | os.PathLike[str] | None,
    *,
    service: int | None = None,
    socket_path: str | os.PathLike[str] | None = None,
) -> Path:
    if release_root is not None and helper_path is not None:
        raise ValueError("release_root and helper_path are mutually exclusive")
    if helper_path is not None:
        return Path(helper_path).resolve()
    if release_root is not None:
        return Path(release_root).resolve() / "build" / HELPER_NAME
    if service is None or socket_path is None:
        raise InternalRpcError(
            "service and socket_path are required to resolve the live helper"
        )
    return _live_release_helper(service, Path(socket_path))


def _decode_envelope(raw: bytes) -> InternalRpcResponse:
    if len(raw) < ENVELOPE.size:
        raise InternalRpcError("sealed helper returned a short envelope")
    magic, version, error_code, payload_len = ENVELOPE.unpack_from(raw)
    if magic != ENVELOPE_MAGIC:
        raise InternalRpcError("sealed helper returned bad envelope magic")
    if version != ENVELOPE_VERSION:
        raise InternalRpcError(
            f"sealed helper returned unsupported envelope version {version}"
        )
    if payload_len > MAX_PAYLOAD:
        raise InternalRpcError("sealed helper envelope exceeds IPC maximum")
    if len(raw) != ENVELOPE.size + payload_len:
        raise InternalRpcError("sealed helper envelope length mismatch")
    return InternalRpcResponse(error_code, raw[ENVELOPE.size:])


def _execute_helper(
    command: list[str], payload: bytes, timeout_seconds: float
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
        close_fds=True,
    )


def _call_internal_rpc(
    service: int,
    method: int,
    *,
    socket_path: str | os.PathLike[str],
    payload: bytes = b"",
    tx_id: int = 0,
    timeout_ms: int = 5000,
    release_root: str | os.PathLike[str] | None = None,
    helper_path: str | os.PathLike[str] | None = None,
    _trusted_live_root: Path,
) -> InternalRpcResponse:
    if isinstance(service, bool) or not isinstance(service, int):
        raise ValueError("service must be an integer")
    if isinstance(method, bool) or not isinstance(method, int):
        raise ValueError("method must be an integer")
    if not 0 <= service <= 0xFFFF:
        raise ValueError("service must be between 0 and 65535")
    if not 0 <= method <= 0xFFFF:
        raise ValueError("method must be between 0 and 65535")
    if isinstance(tx_id, bool) or not isinstance(tx_id, int):
        raise ValueError("tx_id must be an integer")
    if not 0 <= tx_id <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("tx_id must be between 0 and 18446744073709551615")
    if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int):
        raise ValueError("timeout_ms must be an integer")
    if not 1 <= timeout_ms <= 0x7FFFFFFF:
        raise ValueError("timeout_ms must be between 1 and 2147483647")
    if not isinstance(payload, bytes):
        raise ValueError("payload must be bytes")
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload exceeds NETLAB_MAX_MSG")
    socket_text = os.fspath(socket_path)
    if not isinstance(socket_text, str) or not socket_text:
        raise ValueError("socket_path must be a nonempty filesystem path")

    live_resolution: _LiveHelperResolution | None = None
    if release_root is None and helper_path is None:
        live_resolution = _live_release_resolution(
            service,
            Path(socket_text),
            _trusted_root=_trusted_live_root,
        )
        helper = live_resolution.helper
    else:
        helper = _helper_for(release_root, helper_path)
    command = [
        str(helper),
        "--service",
        str(service),
        "--method",
        str(method),
        "--tx-id",
        str(tx_id),
        "--timeout",
        str(timeout_ms),
        "--socket",
        socket_text,
    ]
    try:
        completed = _execute_helper(
            command, payload, (timeout_ms / 1000.0) + 5.0
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        if live_resolution is not None:
            current = _live_release_resolution(
                service,
                Path(socket_text),
                _trusted_root=_trusted_live_root,
            )
            if current != live_resolution:
                raise InternalRpcError(
                    "INTERNAL RPC listener or helper identity changed "
                    "during execution"
                ) from exc
        raise InternalRpcError(f"sealed helper execution failed: {exc}") from exc
    if live_resolution is not None:
        current = _live_release_resolution(
            service,
            Path(socket_text),
            _trusted_root=_trusted_live_root,
        )
        if current != live_resolution:
            raise InternalRpcError(
                "INTERNAL RPC listener or helper identity changed "
                "during execution"
            )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        if not detail:
            detail = f"exit status {completed.returncode}"
        raise InternalRpcError(f"sealed helper failed: {detail}")
    return _decode_envelope(completed.stdout)


def call_internal_rpc(
    service: int,
    method: int,
    *,
    socket_path: str | os.PathLike[str],
    payload: bytes = b"",
    tx_id: int = 0,
    timeout_ms: int = 5000,
    release_root: str | os.PathLike[str] | None = None,
    helper_path: str | os.PathLike[str] | None = None,
) -> InternalRpcResponse:
    """Call one contract-approved INTERNAL method through the sealed helper."""

    return _call_internal_rpc(
        service,
        method,
        socket_path=socket_path,
        payload=payload,
        tx_id=tx_id,
        timeout_ms=timeout_ms,
        release_root=release_root,
        helper_path=helper_path,
        _trusted_live_root=PRODUCTION_RELEASES_ROOT,
    )


__all__ = [
    "InternalRpcError",
    "InternalRpcResponse",
    "call_internal_rpc",
]
