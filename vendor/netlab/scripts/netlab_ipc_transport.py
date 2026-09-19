#!/usr/bin/env python3.11
"""Authenticated AF_UNIX SOCK_SEQPACKET transport shared by Python IPC peers.

The handshake mirrors libipc exactly.  Authentication binds the connection to
the credentials captured by SO_PEERCRED, while ``recv_peer_record`` requires
SCM_CREDENTIALS on every subsequently consumed application record.  Callers
must use ``recv_peer_record`` instead of ``socket.recv``/``socket.recvmsg`` for
all records received after a successful handshake.
"""
from __future__ import annotations

import errno
import os
import secrets
import socket
import struct
from dataclasses import dataclass


AUTH_MAGIC = 0x4E4C4155
AUTH_VERSION = 1
AUTH_CHALLENGE = 1
AUTH_RESPONSE = 2
AUTH_NONCE_SIZE = 32
AUTH_TIMEOUT_SECONDS = 5.0

_AUTH_RECORD = struct.Struct(">IHH32s")
_UCRED = struct.Struct("3i")
_FD = struct.Struct("i")
_SCM_MAX_FD = 253
_ANCILLARY_CAPACITY = (
    socket.CMSG_SPACE(_UCRED.size)
    + socket.CMSG_SPACE(_SCM_MAX_FD * _FD.size)
)


class IpcTransportError(OSError):
    """The peer violated the authenticated IPC transport contract."""


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    """Stable credentials captured from the connected UNIX peer."""

    pid: int
    uid: int
    gid: int


def _protocol_error(message: str) -> IpcTransportError:
    return IpcTransportError(errno.EPROTO, message)


def _permission_error(message: str) -> IpcTransportError:
    return IpcTransportError(errno.EPERM, message)


def _capture_peer_credentials(sock: socket.socket) -> PeerCredentials:
    if not hasattr(socket, "SO_PEERCRED"):
        raise _protocol_error("SO_PEERCRED is unavailable")
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
    if len(raw) != _UCRED.size:
        raise _protocol_error("invalid SO_PEERCRED record")
    pid, uid, gid = _UCRED.unpack(raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise _protocol_error("invalid UNIX peer credentials")
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def _enable_peer_credentials(sock: socket.socket) -> None:
    if not hasattr(socket, "SO_PASSCRED") or not hasattr(
        socket, "SCM_CREDENTIALS"
    ):
        raise _protocol_error("SCM_CREDENTIALS is unavailable")
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)


def prepare_client_socket(sock: socket.socket) -> None:
    """Enable credential delivery before connect, closing on any failure."""

    try:
        _enable_peer_credentials(sock)
    except BaseException:
        try:
            sock.close()
        finally:
            raise


def recv_peer_record(
    sock: socket.socket,
    peer: PeerCredentials,
    capacity: int,
    flags: int = 0,
) -> bytes:
    """Receive one record and require its sender to match ``peer`` exactly."""

    if capacity <= 0:
        raise ValueError("record capacity must be positive")
    if not hasattr(socket, "MSG_CMSG_CLOEXEC"):
        raise _protocol_error("MSG_CMSG_CLOEXEC is unavailable")
    data, ancillary, message_flags, _address = sock.recvmsg(
        capacity, _ANCILLARY_CAPACITY, flags | socket.MSG_CMSG_CLOEXEC
    )

    credentials: list[PeerCredentials] = []
    received_rights = False
    received_unknown = False
    malformed_credentials = False
    for level, kind, raw in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            received_rights = True
            complete = len(raw) - (len(raw) % _FD.size)
            for (received_fd,) in struct.iter_unpack(
                _FD.format, raw[:complete]
            ):
                try:
                    os.close(received_fd)
                except OSError:
                    pass
            continue
        if level != socket.SOL_SOCKET or kind != socket.SCM_CREDENTIALS:
            received_unknown = True
            continue
        if len(raw) != _UCRED.size:
            malformed_credentials = True
            continue
        pid, uid, gid = _UCRED.unpack(raw)
        credentials.append(PeerCredentials(pid=pid, uid=uid, gid=gid))

    truncation_flags = getattr(socket, "MSG_CTRUNC", 0) | getattr(
        socket, "MSG_TRUNC", 0
    )
    if message_flags & truncation_flags:
        raise _protocol_error("truncated authenticated IPC record")
    if received_rights:
        raise _protocol_error("SCM_RIGHTS forbidden on authenticated IPC")
    if received_unknown:
        raise _protocol_error("unknown authenticated IPC ancillary data")
    if malformed_credentials:
        raise _protocol_error("invalid SCM_CREDENTIALS record")
    if len(credentials) != 1:
        raise _permission_error(
            "authenticated IPC record has no unique sender credentials"
        )
    if credentials[0] != peer:
        raise _permission_error(
            "authenticated IPC record sender changed after connect"
        )
    return data


def _send_record(sock: socket.socket, record: bytes) -> None:
    sent = sock.send(record)
    if sent != len(record):
        raise _protocol_error("short authenticated IPC record send")


def _unpack_auth_record(
    record: bytes, expected_type: int, expected_nonce: bytes | None = None
) -> bytes:
    if len(record) != _AUTH_RECORD.size:
        raise _protocol_error("invalid IPC authentication record length")
    magic, version, record_type, nonce = _AUTH_RECORD.unpack(record)
    if (
        magic != AUTH_MAGIC
        or version != AUTH_VERSION
        or record_type != expected_type
    ):
        raise _protocol_error("invalid IPC authentication record identity")
    if expected_nonce is not None and not secrets.compare_digest(
        nonce, expected_nonce
    ):
        raise _permission_error("IPC authentication nonce mismatch")
    return nonce


def _run_authentication(
    sock: socket.socket,
    exchange,
    timeout: float = AUTH_TIMEOUT_SECONDS,
) -> PeerCredentials:
    """Run a bounded exchange, restore timeout on success, close on failure."""

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout <= 0
    ):
        raise ValueError("authentication timeout must be positive")
    bounded_timeout = min(float(timeout), AUTH_TIMEOUT_SECONDS)
    try:
        previous_timeout = sock.gettimeout()
        peer = _capture_peer_credentials(sock)
        _enable_peer_credentials(sock)
        sock.settimeout(bounded_timeout)
        exchange(peer)
        sock.settimeout(previous_timeout)
        return peer
    except BaseException:
        try:
            sock.close()
        finally:
            raise


def client_authenticate(
    sock: socket.socket,
    *,
    timeout: float = AUTH_TIMEOUT_SECONDS,
) -> PeerCredentials:
    """Authenticate a connected Python client to a libipc/Python server."""

    def exchange(peer: PeerCredentials) -> None:
        challenge = recv_peer_record(sock, peer, _AUTH_RECORD.size)
        nonce = _unpack_auth_record(challenge, AUTH_CHALLENGE)
        _send_record(
            sock,
            _AUTH_RECORD.pack(
                AUTH_MAGIC, AUTH_VERSION, AUTH_RESPONSE, nonce
            ),
        )

    return _run_authentication(sock, exchange, timeout)


def server_authenticate(
    sock: socket.socket,
    *,
    timeout: float = AUTH_TIMEOUT_SECONDS,
) -> PeerCredentials:
    """Authenticate an accepted Python server connection to its client."""

    def exchange(peer: PeerCredentials) -> None:
        nonce = secrets.token_bytes(AUTH_NONCE_SIZE)
        _send_record(
            sock,
            _AUTH_RECORD.pack(
                AUTH_MAGIC, AUTH_VERSION, AUTH_CHALLENGE, nonce
            ),
        )
        response = recv_peer_record(sock, peer, _AUTH_RECORD.size)
        _unpack_auth_record(response, AUTH_RESPONSE, nonce)

    return _run_authentication(sock, exchange, timeout)
