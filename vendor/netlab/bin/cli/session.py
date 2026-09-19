"""
CLI session — connects to mgmtd.sock (single unified entry point).
Sends nl_msg_hdr binary messages and receives responses.
"""
import os
import sys

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

import socket
import struct
from pathlib import Path
from typing import Tuple

_PROJECT_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(_PROJECT_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_PROJECT_SCRIPTS))

from netlab_ipc_transport import (  # noqa: E402
    IpcTransportError as _IpcTransportError,
    PeerCredentials as _PeerCredentials,
    client_authenticate as _client_authenticate,
    prepare_client_socket as _prepare_client_socket,
    recv_peer_record as _recv_peer_record,
)

MGMTD_SOCK = "/var/run/netlab/mgmtd.sock"

HDR_FMT = "<IHHQQHHIiII"  # little-endian, packed (magic,schema,type,req,tx,daemon,method,flags,error,timeout,plen)
HDR_SIZE = struct.calcsize(HDR_FMT)  # 44 bytes
MAGIC = 0x4E454C42  # "NELB"
MAX_PAYLOAD = 256 * 1024
SCHEMA_V1 = 1
SCHEMA_V2 = 2
CURRENT_SCHEMA = SCHEMA_V2

CHUNK_HDR_FMT = "<III"  # total payload, offset, data length
CHUNK_HDR_SIZE = struct.calcsize(CHUNK_HDR_FMT)
CHUNK_DATA_MAX = 64 * 1024

FLAG_CHUNKED = 0x80000000
FLAG_CHUNK_FIRST = 0x40000000
FLAG_CHUNK_LAST = 0x20000000
FLAG_TRANSPORT_MASK = FLAG_CHUNKED | FLAG_CHUNK_FIRST | FLAG_CHUNK_LAST

MSG_REQUEST  = 0
MSG_RESPONSE = 1
MSG_EVENT    = 2
MSG_ERROR    = 3


class _IpcProtocolError(RuntimeError):
    pass

# Daemon IDs
DAEMON_MGMTD   = 1
DAEMON_CONFIGD = 2
DAEMON_IFD     = 3
DAEMON_RPD     = 4
DAEMON_CHASSISD= 5
DAEMON_XCVRD   = 6
DAEMON_SWITCHD = 7
DAEMON_PACKETD = 8
DAEMON_LLDPD   = 10
DAEMON_LACPD   = 11
DAEMON_LINKMOND= 13
DAEMON_L2D     = 14
DAEMON_STATSD  = 15
DAEMON_STPD    = 16


def _socket_path_safe(path) -> bool:
    if not path or len(path.encode("utf-8")) >= 108:
        return False
    return all(c.isalnum() or c in "/._-:" for c in path)


def mgmtd_socket_path() -> str:
    path = os.environ.get("NETLAB_MGMTD_SOCKET")
    if _socket_path_safe(path):
        return path
    return MGMTD_SOCK


class CliSession:
    """Manages connection to mgmtd.sock."""

    def __init__(self):
        self.sock = None  # type: socket.socket | None
        self._peer = None  # type: _PeerCredentials | None
        self._test_record_receiver = None
        self.request_id = 0

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            self._test_record_receiver = None
            _prepare_client_socket(self.sock)
            self.sock.connect(mgmtd_socket_path())
            self._peer = _client_authenticate(self.sock)
            self.sock.settimeout(10.0)
            return True
        except (FileNotFoundError, ConnectionRefusedError, OSError) as e:
            print(f"error: cannot connect to mgmtd: {e}")
            if self.sock:
                self.sock.close()
            self.sock = None
            self._peer = None
            self._test_record_receiver = None
            return False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            self._peer = None
            self._test_record_receiver = None

    def _attach_test_transport(self, transport) -> None:
        """Attach an in-memory framing fixture without opening a live socket."""

        self.sock = transport
        self._peer = None
        self._test_record_receiver = transport.recv

    def _next_request_id(self) -> int:
        self.request_id += 1
        return self.request_id

    def send_request(self, daemon_id: int, method: int,
                     payload: bytes = b"",
                     timeout_ms: int = 0,
                     tx_id: int = 0) -> Tuple[int, int, bytes]:
        """
        Send a request via mgmtd, return (error_code, payload_len, payload).
        """
        if not self.sock:
            return (-1, 0, b"")
        if len(payload) > MAX_PAYLOAD:
            return (-1, 0, b"request payload too large")
        if timeout_ms < 0 or timeout_ms > 0xFFFFFFFF:
            return (-1, 0, b"invalid request timeout")
        if (isinstance(tx_id, bool) or not isinstance(tx_id, int) or
                tx_id < 0 or tx_id > 0xFFFFFFFFFFFFFFFF):
            return (-1, 0, b"invalid transaction ID")

        req_id = self._next_request_id()
        old_timeout = None
        try:
            if timeout_ms > 0:
                old_timeout = self.sock.gettimeout()
                self.sock.settimeout((timeout_ms / 1000.0) + 5.0)
            self._send_message(
                MSG_REQUEST, req_id, tx_id, daemon_id, method, 0,
                timeout_ms, payload)
            fields, payload_data = self._recv_message(req_id)
            return (fields[8], len(payload_data), payload_data)
        except socket.timeout:
            return (-1, 0, b"error: request timed out")
        except _IpcProtocolError as exc:
            return (-1, 0, f"error: {exc}".encode())
        except (BrokenPipeError, OSError):
            return (-1, 0, b"")
        finally:
            if old_timeout is not None and self.sock:
                self.sock.settimeout(old_timeout)

    def _send_packet(self, packet: bytes) -> None:
        if hasattr(self.sock, "send"):
            sent = self.sock.send(packet)
            if sent != len(packet):
                raise _IpcProtocolError("short request frame send")
            return
        self.sock.sendall(packet)

    def _send_message(self, msg_type: int, request_id: int, tx_id: int,
                      daemon_id: int, method: int, error_code: int,
                      timeout_ms: int, payload: bytes) -> None:
        if len(payload) <= CHUNK_DATA_MAX:
            header = struct.pack(
                HDR_FMT, MAGIC, CURRENT_SCHEMA, msg_type, request_id,
                tx_id, daemon_id, method, 0, error_code, timeout_ms,
                len(payload))
            self._send_packet(header + payload)
            return

        offset = 0
        while offset < len(payload):
            data = payload[offset:offset + CHUNK_DATA_MAX]
            flags = FLAG_CHUNKED
            if offset == 0:
                flags |= FLAG_CHUNK_FIRST
            if offset + len(data) == len(payload):
                flags |= FLAG_CHUNK_LAST
            chunk_header = struct.pack(
                CHUNK_HDR_FMT, len(payload), offset, len(data))
            header = struct.pack(
                HDR_FMT, MAGIC, CURRENT_SCHEMA, msg_type, request_id,
                tx_id, daemon_id, method, flags, error_code, timeout_ms,
                len(chunk_header) + len(data))
            self._send_packet(header + chunk_header + data)
            offset += len(data)

    def _recv_packet(self):
        if self._peer is not None:
            try:
                full_msg = _recv_peer_record(
                    self.sock, self._peer, HDR_SIZE + MAX_PAYLOAD
                )
            except _IpcTransportError as exc:
                raise _IpcProtocolError(
                    f"response sender authentication failed: {exc}"
                ) from exc
        elif self._test_record_receiver is not None:
            full_msg = self._test_record_receiver(HDR_SIZE + MAX_PAYLOAD)
        else:
            raise _IpcProtocolError(
                "response received on unauthenticated IPC socket"
            )

        if len(full_msg) < HDR_SIZE:
            raise _IpcProtocolError("short response header")
        fields = struct.unpack(HDR_FMT, full_msg[:HDR_SIZE])
        if fields[0] != MAGIC:
            raise _IpcProtocolError("bad response magic")
        if fields[1] not in (0, SCHEMA_V1, SCHEMA_V2):
            raise _IpcProtocolError("unsupported response schema")
        if fields[2] not in (MSG_REQUEST, MSG_RESPONSE, MSG_EVENT, MSG_ERROR):
            raise _IpcProtocolError("invalid response type")
        payload_len = fields[10]
        if payload_len > MAX_PAYLOAD:
            raise _IpcProtocolError("response too large")
        transport_flags = fields[7] & FLAG_TRANSPORT_MASK
        if (fields[1] == SCHEMA_V2 and transport_flags == 0 and
                payload_len > CHUNK_DATA_MAX):
            raise _IpcProtocolError("non-canonical schema 2 response frame")
        if (fields[7] & FLAG_CHUNKED and
                payload_len > CHUNK_HDR_SIZE + CHUNK_DATA_MAX):
            raise _IpcProtocolError("response chunk too large")
        total = HDR_SIZE + payload_len
        if len(full_msg) != total:
            raise _IpcProtocolError("response frame length mismatch")
        return fields, full_msg[HDR_SIZE:]

    @staticmethod
    def _decode_chunk(fields, payload: bytes):
        flags = fields[7]
        if fields[1] != SCHEMA_V2 or not (flags & FLAG_CHUNKED):
            raise _IpcProtocolError("invalid chunk schema or flags")
        if len(payload) < CHUNK_HDR_SIZE:
            raise _IpcProtocolError("short chunk header")
        total, offset, data_len = struct.unpack(
            CHUNK_HDR_FMT, payload[:CHUNK_HDR_SIZE])
        if total <= CHUNK_DATA_MAX or total > MAX_PAYLOAD:
            raise _IpcProtocolError("invalid chunk total")
        if data_len <= 0 or data_len > CHUNK_DATA_MAX:
            raise _IpcProtocolError("invalid chunk data length")
        if len(payload) != CHUNK_HDR_SIZE + data_len:
            raise _IpcProtocolError("chunk length mismatch")
        if offset > total or data_len > total - offset:
            raise _IpcProtocolError("chunk range exceeds payload")
        if offset + data_len < total and data_len != CHUNK_DATA_MAX:
            raise _IpcProtocolError("non-final chunk is not canonical")
        return total, offset, payload[CHUNK_HDR_SIZE:]

    @staticmethod
    def _logical_headers_match(first, current) -> bool:
        stable_fields = (0, 1, 2, 3, 4, 5, 6, 8, 9)
        return (
            all(first[index] == current[index] for index in stable_fields) and
            (first[7] & ~FLAG_TRANSPORT_MASK) ==
            (current[7] & ~FLAG_TRANSPORT_MASK)
        )

    def _recv_message(self, request_id: int):
        first, payload = self._recv_packet()
        if first[2] not in (MSG_RESPONSE, MSG_ERROR):
            raise _IpcProtocolError("unexpected response type")
        if first[3] != request_id:
            raise _IpcProtocolError("response request id mismatch")
        transport_flags = first[7] & FLAG_TRANSPORT_MASK
        if transport_flags == 0:
            return first, payload
        if (not (transport_flags & FLAG_CHUNKED) or
                not (transport_flags & FLAG_CHUNK_FIRST) or
                (transport_flags & FLAG_CHUNK_LAST)):
            raise _IpcProtocolError("invalid first response chunk")

        total, offset, data = self._decode_chunk(first, payload)
        if offset != 0:
            raise _IpcProtocolError("first response chunk offset is not zero")
        result = bytearray(total)
        result[:len(data)] = data
        received = len(data)
        while received < total:
            current, current_payload = self._recv_packet()
            if not self._logical_headers_match(first, current):
                raise _IpcProtocolError("response chunk metadata mismatch")
            current_flags = current[7] & FLAG_TRANSPORT_MASK
            if (not (current_flags & FLAG_CHUNKED) or
                    (current_flags & FLAG_CHUNK_FIRST)):
                raise _IpcProtocolError("invalid response chunk sequence")
            chunk_total, chunk_offset, chunk_data = self._decode_chunk(
                current, current_payload)
            if chunk_total != total or chunk_offset != received:
                raise _IpcProtocolError("response chunk offset mismatch")
            final = received + len(chunk_data) == total
            if bool(current_flags & FLAG_CHUNK_LAST) != final:
                raise _IpcProtocolError("invalid final response chunk marker")
            result[received:received + len(chunk_data)] = chunk_data
            received += len(chunk_data)

        fields = list(first)
        fields[7] &= ~FLAG_TRANSPORT_MASK
        fields[10] = total
        return tuple(fields), bytes(result)
