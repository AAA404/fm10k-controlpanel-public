#!/usr/bin/env python3.11
"""IPC schema V2 framing, compatibility, and fail-closed contracts."""

import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from collections import deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "bin" / "cli"))

from netlab_ipc_transport import (  # noqa: E402
    IpcTransportError,
    PeerCredentials,
    client_authenticate,
    prepare_client_socket,
    recv_peer_record,
    server_authenticate,
)
from session import (  # noqa: E402
    CHUNK_DATA_MAX,
    CHUNK_HDR_FMT,
    CHUNK_HDR_SIZE,
    CURRENT_SCHEMA,
    DAEMON_MGMTD,
    FLAG_CHUNKED,
    FLAG_CHUNK_FIRST,
    FLAG_CHUNK_LAST,
    FLAG_TRANSPORT_MASK,
    HDR_FMT,
    HDR_SIZE,
    MAGIC,
    MAX_PAYLOAD,
    MSG_RESPONSE,
    CliSession,
)


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f": {name}")
    if not condition and detail:
        print(detail)
    return 0 if condition else 1


def response_frames(payload, *, request_id=1, method=1,
                    final_marker=True):
    frames = []
    if len(payload) <= CHUNK_DATA_MAX:
        header = struct.pack(
            HDR_FMT, MAGIC, CURRENT_SCHEMA, MSG_RESPONSE, request_id, 0,
            DAEMON_MGMTD, method, 0, 0, 0, len(payload))
        return [header + payload]

    offset = 0
    while offset < len(payload):
        data = payload[offset:offset + CHUNK_DATA_MAX]
        flags = FLAG_CHUNKED
        if offset == 0:
            flags |= FLAG_CHUNK_FIRST
        if offset + len(data) == len(payload) and final_marker:
            flags |= FLAG_CHUNK_LAST
        chunk = struct.pack(CHUNK_HDR_FMT, len(payload), offset, len(data))
        header = struct.pack(
            HDR_FMT, MAGIC, CURRENT_SCHEMA, MSG_RESPONSE, request_id, 0,
            DAEMON_MGMTD, method, flags, 0, 0, len(chunk) + len(data))
        frames.append(header + chunk + data)
        offset += len(data)
    return frames


class PacketQueue:
    def __init__(self, packets):
        self.packets = deque(packets)
        self.sent = []
        self.timeout = 10.0

    def send(self, packet):
        self.sent.append(bytes(packet))
        return len(packet)

    def recv(self, size, flags=0):
        if not self.packets:
            raise OSError("no queued packet")
        packet = self.packets[0]
        if not flags & socket.MSG_PEEK:
            self.packets.popleft()
        return packet[:size]

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value


def decode_sent_chunks(frames):
    result = bytearray()
    expected_offset = 0
    for index, frame in enumerate(frames):
        fields = struct.unpack(HDR_FMT, frame[:HDR_SIZE])
        payload = frame[HDR_SIZE:]
        total, offset, data_len = struct.unpack(
            CHUNK_HDR_FMT, payload[:CHUNK_HDR_SIZE])
        flags = fields[7] & FLAG_TRANSPORT_MASK
        if fields[1] != CURRENT_SCHEMA or not flags & FLAG_CHUNKED:
            raise AssertionError("request did not use schema V2 chunks")
        if bool(flags & FLAG_CHUNK_FIRST) != (index == 0):
            raise AssertionError("request first marker mismatch")
        if bool(flags & FLAG_CHUNK_LAST) != (index == len(frames) - 1):
            raise AssertionError("request last marker mismatch")
        if offset != expected_offset or data_len != len(payload) - CHUNK_HDR_SIZE:
            raise AssertionError("request chunk range mismatch")
        if total != MAX_PAYLOAD:
            raise AssertionError("request chunk total mismatch")
        result.extend(payload[CHUNK_HDR_SIZE:])
        expected_offset += data_len
    return bytes(result)


def test_python_max_response():
    payload = bytes(index % 251 for index in range(MAX_PAYLOAD))
    fake = PacketQueue(response_frames(payload))
    session = CliSession()
    session._attach_test_transport(fake)
    error, length, received = session.send_request(DAEMON_MGMTD, 1)
    return check(
        "Python client reassembles a 256 KiB schema V2 response",
        error == 0 and length == MAX_PAYLOAD and received == payload and
        len(fake.sent) == 1,
        f"error={error} length={length} sent={len(fake.sent)}")


def test_python_max_request():
    payload = bytes(index % 239 for index in range(MAX_PAYLOAD))
    fake = PacketQueue(response_frames(b""))
    session = CliSession()
    session._attach_test_transport(fake)
    error, length, received = session.send_request(
        DAEMON_MGMTD, 1, payload)
    try:
        reconstructed = decode_sent_chunks(fake.sent)
    except AssertionError as exc:
        reconstructed = b""
        detail = str(exc)
    else:
        detail = ""
    return check(
        "Python client emits four canonical chunks for a 256 KiB request",
        error == 0 and length == 0 and received == b"" and
        len(fake.sent) == 4 and reconstructed == payload,
        detail or f"error={error} length={length} frames={len(fake.sent)}")


def test_python_transaction_id():
    tx_id = 0x1020304050607080
    fake = PacketQueue(response_frames(b""))
    session = CliSession()
    session._attach_test_transport(fake)
    error, length, received = session.send_request(
        DAEMON_MGMTD, 1, tx_id=tx_id)
    fields = struct.unpack(HDR_FMT, fake.sent[0][:HDR_SIZE])
    failed = check(
        "Python client writes the caller-selected transaction ID",
        error == 0 and length == 0 and received == b"" and
        fields[4] == tx_id,
        f"error={error} length={length} tx-id={fields[4]}")

    invalid = (-1, 0x10000000000000000, True, "1")
    for value in invalid:
        fake = PacketQueue(response_frames(b""))
        session = CliSession()
        session._attach_test_transport(fake)
        error, _length, detail = session.send_request(
            DAEMON_MGMTD, 1, tx_id=value)
        failed += check(
            f"Python client rejects out-of-range transaction ID {value}",
            error == -1 and b"transaction ID" in detail and not fake.sent,
            f"error={error} detail={detail!r} sent={len(fake.sent)}")
    return failed


def test_python_rejects_malformed_sequences():
    failed = 0
    payload = b"x" * (CHUNK_DATA_MAX + 1)

    frames = response_frames(payload, final_marker=False)
    fake = PacketQueue(frames)
    session = CliSession()
    session._attach_test_transport(fake)
    error, _length, detail = session.send_request(DAEMON_MGMTD, 1)
    failed += check(
        "Python client rejects a missing final marker",
        error == -1 and b"final" in detail, detail.decode(errors="replace"))

    offset_payload = b"y" * (2 * CHUNK_DATA_MAX + 1)
    frames = response_frames(offset_payload)
    fields = list(struct.unpack(HDR_FMT, frames[1][:HDR_SIZE]))
    chunk_payload = bytearray(frames[1][HDR_SIZE:])
    total, _offset, data_len = struct.unpack(
        CHUNK_HDR_FMT, chunk_payload[:CHUNK_HDR_SIZE])
    chunk_payload[:CHUNK_HDR_SIZE] = struct.pack(
        CHUNK_HDR_FMT, total, 0, data_len)
    frames[1] = struct.pack(HDR_FMT, *fields) + chunk_payload
    fake = PacketQueue(frames)
    session = CliSession()
    session._attach_test_transport(fake)
    error, _length, detail = session.send_request(DAEMON_MGMTD, 1)
    failed += check(
        "Python client rejects an out-of-order chunk offset",
        error == -1 and b"offset" in detail, detail.decode(errors="replace"))

    direct = struct.pack(
        HDR_FMT, MAGIC, CURRENT_SCHEMA, MSG_RESPONSE, 1, 0,
        DAEMON_MGMTD, 1, 0, 0, 0, CHUNK_DATA_MAX + 1)
    fake = PacketQueue([direct + b"x" * (CHUNK_DATA_MAX + 1)])
    session = CliSession()
    session._attach_test_transport(fake)
    error, _length, detail = session.send_request(DAEMON_MGMTD, 1)
    failed += check(
        "Python client rejects non-canonical direct schema V2 frames",
        error == -1 and b"non-canonical" in detail,
        detail.decode(errors="replace"))
    return failed


def test_python_real_seqpacket():
    payload = bytes(index % 227 for index in range(MAX_PAYLOAD))
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.settimeout(1.75)
    server.settimeout(2.25)
    server_error = []
    restored_server_timeouts = []

    def serve():
        try:
            peer = server_authenticate(server)
            restored_server_timeouts.append(server.gettimeout())
            request = recv_peer_record(
                server, peer, HDR_SIZE + CHUNK_DATA_MAX
            )
            if len(request) != HDR_SIZE:
                raise RuntimeError(f"unexpected request size {len(request)}")
            for frame in response_frames(payload):
                if server.send(frame) != len(frame):
                    raise RuntimeError("short response send")
        except Exception as exc:  # pragma: no cover - surfaced below
            server_error.append(str(exc))
        finally:
            server.close()

    worker = threading.Thread(target=serve, daemon=True)
    prepare_client_socket(client)
    worker.start()
    session = CliSession()
    session.sock = client
    session._peer = client_authenticate(client)
    restored_client_timeout = client.gettimeout()
    error, length, received = session.send_request(DAEMON_MGMTD, 1)
    worker.join(timeout=5)
    client.close()
    return check(
        "Python schema V2 works over a real AF_UNIX SOCK_SEQPACKET pair",
        error == 0 and length == MAX_PAYLOAD and received == payload and
        restored_client_timeout == 1.75 and
        restored_server_timeouts == [2.25] and
        not worker.is_alive() and not server_error,
        (
            f"error={error} length={length} server={server_error} "
            f"timeouts={restored_client_timeout}/"
            f"{restored_server_timeouts}"
        ))


def test_python_ancillary_fail_closed():
    class InjectedRightsRecord:
        def __init__(self, source_fd):
            self.source_fd = source_fd
            self.received_fd = -1
            self.flags = 0
            self.ancillary_capacity = 0

        def recvmsg(self, _capacity, ancillary_capacity, flags):
            self.flags = flags
            self.ancillary_capacity = ancillary_capacity
            self.received_fd = os.dup(self.source_fd)
            return (
                b"x",
                [
                    (
                        socket.SOL_SOCKET,
                        socket.SCM_RIGHTS,
                        struct.pack("i", self.received_fd),
                    )
                ],
                0,
                None,
            )

    read_fd, write_fd = os.pipe()
    injected = InjectedRightsRecord(read_fd)
    peer = PeerCredentials(os.getpid(), os.geteuid(), os.getegid())
    rejected = False
    try:
        recv_peer_record(injected, peer, 64)
    except IpcTransportError as exc:
        rejected = "SCM_RIGHTS" in str(exc)
    finally:
        os.close(read_fd)
        os.close(write_fd)
    try:
        os.fstat(injected.received_fd)
        received_fd_closed = False
        os.close(injected.received_fd)
    except OSError:
        received_fd_closed = True

    cloexec = bool(
        injected.flags & getattr(socket, "MSG_CMSG_CLOEXEC", 0)
    )
    full_rights_capacity = (
        injected.ancillary_capacity
        >= socket.CMSG_SPACE(struct.calcsize("3i"))
        + socket.CMSG_SPACE(253 * struct.calcsize("i"))
    )
    failed = check(
        "Python authenticated receive rejects and closes SCM_RIGHTS",
        rejected and received_fd_closed and cloexec and full_rights_capacity,
        (
            f"rejected={rejected} closed={received_fd_closed} "
            f"flags={injected.flags} "
            f"ancillary-capacity={injected.ancillary_capacity}"
        ),
    )

    class InjectedUnknownRecord:
        def recvmsg(self, _capacity, _ancillary_capacity, _flags):
            return (
                b"x",
                [
                    (
                        socket.SOL_SOCKET,
                        socket.SCM_CREDENTIALS,
                        struct.pack("3i", peer.pid, peer.uid, peer.gid),
                    ),
                    (0x7FFF, 0x7FFF, b"unknown"),
                ],
                0,
                None,
            )

    try:
        recv_peer_record(InjectedUnknownRecord(), peer, 64)
        unknown_rejected = False
    except IpcTransportError as exc:
        unknown_rejected = "unknown" in str(exc)
    failed += check(
        "Python authenticated receive rejects unknown ancillary data",
        unknown_rejected,
    )

    session_source = (ROOT / "bin" / "cli" / "session.py").read_text(
        encoding="utf-8"
    )
    failed += check(
        "Python client enables credential delivery before connect",
        session_source.index("_prepare_client_socket(self.sock)")
        < session_source.index("self.sock.connect("),
    )
    return failed


def test_c_ipc_v2_contract():
    source = r'''
#include "netlab/ipc.h"
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define CHECK(name, expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", name); \
        return 1; \
    } \
} while (0)

typedef struct {
    nl_conn conn;
    nl_msg_hdr *msg;
    nl_status status;
} send_job;

static void *send_main(void *arg) {
    send_job *job = arg;
    job->status = nl_send(&job->conn, job->msg);
    return NULL;
}

static void fill_payload(nl_msg_hdr *msg) {
    u32 i;
    for (i = 0; i < msg->payload_len; i++)
        msg->payload[i] = (u8)(i % 251U);
}

static int payload_matches(const nl_msg_hdr *msg) {
    u32 i;
    for (i = 0; i < msg->payload_len; i++) {
        if (msg->payload[i] != (u8)(i % 251U))
            return 0;
    }
    return 1;
}

static int payload_roundtrip(u32 payload_len) {
    int sv[2];
    pthread_t thread;
    send_job job = {0};
    nl_conn receiver = {0};
    nl_msg_hdr *received = NULL;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0)
        return 0;
    job.conn.fd = sv[0];
    receiver.fd = sv[1];
    job.msg = nl_msg_alloc(payload_len);
    if (!job.msg)
        return 0;
    job.msg->type = NL_MSG_RESPONSE;
    job.msg->request_id = 77;
    fill_payload(job.msg);
    if (job.msg->payload[job.msg->payload_len] != '\0')
        return 0;
    if (pthread_create(&thread, NULL, send_main, &job) != 0)
        return 0;
    if (nl_recv(&receiver, &received) != NL_OK || !received)
        return 0;
    pthread_join(thread, NULL);
    if (job.status != NL_OK ||
        received->schema_version != NETLAB_IPC_SCHEMA_V2 ||
        received->payload_len != payload_len ||
        (received->flags & NL_MSG_F_TRANSPORT_MASK) != 0 ||
        !receiver.peer_schema_known ||
        receiver.peer_schema_version != NETLAB_IPC_SCHEMA_V2 ||
        received->payload[received->payload_len] != '\0' ||
        !payload_matches(received))
        return 0;
    nl_msg_free(received);
    nl_msg_free(job.msg);
    close(sv[0]);
    close(sv[1]);
    return 1;
}

static int inspect_max_frames(void) {
    int sv[2];
    pthread_t thread;
    send_job job = {0};
    u32 expected_offset = 0;
    int frame_count = 0;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0)
        return 0;
    job.conn.fd = sv[0];
    job.msg = nl_msg_alloc(NETLAB_MAX_MSG);
    if (!job.msg)
        return 0;
    job.msg->type = NL_MSG_RESPONSE;
    job.msg->request_id = 88;
    fill_payload(job.msg);
    if (pthread_create(&thread, NULL, send_main, &job) != 0)
        return 0;

    while (expected_offset < NETLAB_MAX_MSG) {
        u8 frame[NETLAB_IPC_MAX_FRAME];
        nl_msg_hdr *header;
        nl_ipc_chunk_hdr chunk;
        ssize_t len = recv(sv[1], frame, sizeof(frame), 0);
        if (len <= (ssize_t)(NL_HDR_SIZE + NL_IPC_CHUNK_HDR_SIZE))
            return 0;
        header = (nl_msg_hdr *)frame;
        memcpy(&chunk, header->payload, sizeof(chunk));
        if ((size_t)len > NETLAB_IPC_MAX_FRAME ||
            header->schema_version != NETLAB_IPC_SCHEMA_V2 ||
            header->payload_len != NL_IPC_CHUNK_HDR_SIZE + chunk.data_len ||
            chunk.total_payload_len != NETLAB_MAX_MSG ||
            chunk.offset != expected_offset ||
            chunk.data_len == 0 ||
            chunk.data_len > NETLAB_IPC_CHUNK_DATA_MAX ||
            (header->flags & NL_MSG_F_CHUNKED) == 0 ||
            (((header->flags & NL_MSG_F_CHUNK_FIRST) != 0) !=
             (expected_offset == 0)) ||
            (((header->flags & NL_MSG_F_CHUNK_LAST) != 0) !=
             (expected_offset + chunk.data_len == NETLAB_MAX_MSG)))
            return 0;
        expected_offset += chunk.data_len;
        frame_count++;
    }
    pthread_join(thread, NULL);
    nl_msg_free(job.msg);
    close(sv[0]);
    close(sv[1]);
    return job.status == NL_OK && frame_count == 4;
}

static int legacy_downgrade(void) {
    int sv[2];
    nl_conn sender = {0};
    nl_msg_hdr *msg;
    u8 frame[NL_HDR_SIZE + 16];
    nl_msg_hdr *wire = (nl_msg_hdr *)frame;
    ssize_t len;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0)
        return 0;
    sender.fd = sv[0];
    sender.peer_schema_known = true;
    sender.peer_schema_version = NETLAB_IPC_SCHEMA_V1;
    msg = nl_msg_alloc(16);
    if (!msg)
        return 0;
    msg->type = NL_MSG_RESPONSE;
    memset(msg->payload, 'x', msg->payload_len);
    if (nl_send(&sender, msg) != NL_OK)
        return 0;
    len = recv(sv[1], frame, sizeof(frame), 0);
    nl_msg_free(msg);
    close(sv[0]);
    close(sv[1]);
    return len == (ssize_t)sizeof(frame) &&
           wire->schema_version == NETLAB_IPC_SCHEMA_V1 &&
           (wire->flags & NL_MSG_F_TRANSPORT_MASK) == 0;
}

static int raw_chunk(int fd, u32 total, u32 offset, u32 data_len,
                     u32 flags, u64 request_id) {
    size_t len = NL_HDR_SIZE + NL_IPC_CHUNK_HDR_SIZE + data_len;
    nl_msg_hdr *header = calloc(1, len);
    nl_ipc_chunk_hdr chunk = {
        .total_payload_len = total,
        .offset = offset,
        .data_len = data_len,
    };
    ssize_t sent;

    if (!header)
        return 0;
    header->magic = NETLAB_MAGIC;
    header->schema_version = NETLAB_IPC_SCHEMA_V2;
    header->type = NL_MSG_RESPONSE;
    header->request_id = request_id;
    header->flags = flags;
    header->payload_len = (u32)NL_IPC_CHUNK_HDR_SIZE + data_len;
    memcpy(header->payload, &chunk, sizeof(chunk));
    memset(header->payload + sizeof(chunk), 'z', data_len);
    sent = send(fd, header, len, 0);
    free(header);
    return sent == (ssize_t)len;
}

static int malformed_sequences_rejected(void) {
    int sv[2];
    nl_conn receiver = {0};
    nl_msg_hdr *msg = NULL;
    nl_msg_hdr *direct;
    size_t direct_len = NL_HDR_SIZE + NETLAB_IPC_CHUNK_DATA_MAX + 1U;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0)
        return 0;
    receiver.fd = sv[1];
    direct = calloc(1, direct_len);
    if (!direct)
        return 0;
    direct->magic = NETLAB_MAGIC;
    direct->schema_version = NETLAB_IPC_SCHEMA_V2;
    direct->type = NL_MSG_RESPONSE;
    direct->payload_len = NETLAB_IPC_CHUNK_DATA_MAX + 1U;
    if (send(sv[0], direct, direct_len, 0) != (ssize_t)direct_len)
        return 0;
    free(direct);
    if (nl_recv(&receiver, &msg) != NL_ERR || msg != NULL)
        return 0;
    close(sv[0]);
    close(sv[1]);

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0)
        return 0;
    receiver.fd = sv[1];
    if (!raw_chunk(sv[0], NETLAB_IPC_CHUNK_DATA_MAX + 1U, 0,
                   NETLAB_IPC_CHUNK_DATA_MAX,
                   NL_MSG_F_CHUNKED | NL_MSG_F_CHUNK_FIRST, 1) ||
        !raw_chunk(sv[0], NETLAB_IPC_CHUNK_DATA_MAX + 1U, 1, 1,
                   NL_MSG_F_CHUNKED | NL_MSG_F_CHUNK_LAST, 1))
        return 0;
    if (nl_recv(&receiver, &msg) != NL_ERR || msg != NULL)
        return 0;
    close(sv[0]);
    close(sv[1]);

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0)
        return 0;
    receiver.fd = sv[1];
    if (!raw_chunk(sv[0], NETLAB_IPC_CHUNK_DATA_MAX + 1U, 0,
                   NETLAB_IPC_CHUNK_DATA_MAX,
                   NL_MSG_F_CHUNKED | NL_MSG_F_CHUNK_FIRST, 1) ||
        !raw_chunk(sv[0], NETLAB_IPC_CHUNK_DATA_MAX + 1U,
                   NETLAB_IPC_CHUNK_DATA_MAX, 1,
                   NL_MSG_F_CHUNKED | NL_MSG_F_CHUNK_LAST, 2))
        return 0;
    if (nl_recv(&receiver, &msg) != NL_ERR || msg != NULL)
        return 0;
    close(sv[0]);
    close(sv[1]);
    return 1;
}

static int count_open_fds(void) {
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    int count = 0;

    if (!directory)
        return -1;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            count++;
    }
    closedir(directory);
    return count;
}

static int authenticated_receive_rejects_rights(void) {
    int sv[2];
    int pipe_fds[2];
    int enabled = 1;
    int before;
    int after;
    int receive_errno;
    char byte = 'x';
    char received;
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec iov = {
        .iov_base = &byte,
        .iov_len = sizeof(byte),
    };
    struct msghdr message = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    nl_conn receiver = {0};
    ssize_t result;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0 ||
        pipe(pipe_fds) != 0)
        return 0;
    if (setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED,
                   &enabled, sizeof(enabled)) != 0)
        return 0;
    receiver.fd = sv[1];
    if (nl_get_peer_cred(
            receiver.fd, &receiver.peer_uid, &receiver.peer_gid,
            &receiver.peer_pid) != NL_OK)
        return 0;
    receiver.peer_credentials_enabled = true;
    receiver.peer_authenticated = true;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &pipe_fds[0], sizeof(int));
    before = count_open_fds();
    if (before < 0 ||
        sendmsg(sv[0], &message, 0) != (ssize_t)sizeof(byte))
        return 0;
    errno = 0;
    result = nl_recv_peer_record(
        &receiver, &received, sizeof(received), 0);
    receive_errno = errno;
    after = count_open_fds();
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    close(sv[0]);
    close(sv[1]);
    return result < 0 && receive_errno == EPROTO && after == before;
}

int main(void) {
    static const u32 payload_lengths[] = {
        0U, 255U, 256U, 4096U, NETLAB_MAX_MSG,
    };
    nl_msg_hdr *msg = nl_msg_alloc(0);
    CHECK("allocator uses current schema",
          msg && msg->schema_version == NETLAB_IPC_SCHEMA_CURRENT &&
          msg->payload[msg->payload_len] == '\0');
    nl_msg_free(msg);
    for (size_t i = 0; i < sizeof(payload_lengths) /
                           sizeof(payload_lengths[0]); i++) {
        CHECK("payload roundtrip preserves trailing sentinel",
              payload_roundtrip(payload_lengths[i]));
    }
    CHECK("max payload uses four bounded frames", inspect_max_frames());
    CHECK("legacy response downgrade", legacy_downgrade());
    CHECK("malformed chunk sequences rejected", malformed_sequences_rejected());
    CHECK("authenticated receive closes and rejects SCM_RIGHTS",
          authenticated_receive_rejects_rights());
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as directory:
        source_path = Path(directory) / "ipc_v2.c"
        executable = Path(directory) / "ipc_v2"
        source_path.write_text(source, encoding="utf-8")
        build = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                "-pedantic", "-D_GNU_SOURCE", "-I", str(ROOT / "include"),
                str(ROOT / "lib" / "libipc" / "ipc.c"),
                str(ROOT / "lib" / "libipc" / "daemon_identity.c"),
                str(ROOT / "lib" / "liblog" / "log.c"),
                str(source_path), "-lpthread", "-o", str(executable),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if build.returncode != 0:
            return check("C IPC V2 contract builds", False, build.stdout)
        run = subprocess.run(
            [str(executable)],
            cwd=ROOT,
            env={**os.environ, "LC_ALL": "C"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=15,
        )
        return check(
            "C IPC V2 framing and fail-closed contracts hold",
            run.returncode == 0,
            run.stdout,
        )


def test_mgmtd_observability_contract():
    header = (ROOT / "sbin" / "mgmtd" / "mgmtd.h").read_text(
        encoding="utf-8")
    main_source = (ROOT / "sbin" / "mgmtd" / "main.c").read_text(
        encoding="utf-8")
    session_source = (ROOT / "sbin" / "mgmtd" / "session.c").read_text(
        encoding="utf-8")
    return check(
        "mgmtd exposes negotiated IPC schema and framing limits",
        "u16 schema_version;" in header and
        "ipc-schema-current" in main_source and
        "ipc-chunk-data-max" in main_source and
        "conn->peer_schema_version" in session_source,
    )


def main():
    failed = 0
    failed += test_python_max_response()
    failed += test_python_max_request()
    failed += test_python_transaction_id()
    failed += test_python_rejects_malformed_sequences()
    failed += test_python_real_seqpacket()
    failed += test_python_ancillary_fail_closed()
    failed += test_c_ipc_v2_contract()
    failed += test_mgmtd_observability_contract()
    print(f"\nResults: {'all passed' if failed == 0 else str(failed) + ' failed'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
