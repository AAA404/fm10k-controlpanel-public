#!/usr/bin/env python3.11
"""Offline contracts for IPC hardening and config persistence."""
import os
import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bin" / "cli"))

from session import (  # noqa: E402
    CliSession,
    DAEMON_CONFIGD,
    DAEMON_IFD,
    DAEMON_MGMTD,
    DAEMON_SWITCHD,
    HDR_FMT,
    HDR_SIZE,
    MAGIC,
    MAX_PAYLOAD,
    MSG_RESPONSE,
)


def check(name, condition, detail=""):
    print(("PASS" if condition else "FAIL") + f": {name}")
    if not condition and detail:
        print(detail)
    return 0 if condition else 1


def test_switchd_policy_contract():
    source = r'''
#include "netlab/ipc.h"
#include <stdio.h>

#define CHECK(name, expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", name); \
        return 1; \
    } \
} while (0)

static int requires_txid(nl_rpc_method method) {
    const nl_rpc_contract *contract =
        nl_rpc_contract_lookup(NL_DAEMON_SWITCHD, method);
    return contract &&
        (contract->flags & NL_RPC_CONTRACT_TX_ID_REQUIRED) != 0;
}

static int caller_allowed(nl_rpc_method method, nl_daemon_id caller) {
    return nl_rpc_contract_caller_allowed(
        nl_rpc_contract_lookup(NL_DAEMON_SWITCHD, method), caller);
}

int main(void) {
    CHECK("QoS queue profile apply requires txid",
          requires_txid(
              NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_APPLY));
    CHECK("QoS queue profile rollback requires txid",
          requires_txid(
              NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_ROLLBACK));
    CHECK("QoS watermark apply requires txid",
          requires_txid(
              NL_SWITCHD_QOS_WATERMARK_OWNER_APPLY));
    CHECK("QoS watermark rollback requires txid",
          requires_txid(
              NL_SWITCHD_QOS_WATERMARK_OWNER_ROLLBACK));
    CHECK("QoS queue profile readback does not require txid",
          !requires_txid(
              NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_READBACK));
    CHECK("hidden QoS profile owner is internal only",
          caller_allowed(NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_APPLY,
                         NL_DAEMON_INTERNAL) &&
          !caller_allowed(NL_SWITCHD_QOS_QUEUE_PROFILE_OWNER_APPLY,
                          NL_DAEMON_SWITCHD));
    CHECK("hidden QoS watermark owner is internal only",
          caller_allowed(NL_SWITCHD_QOS_WATERMARK_OWNER_APPLY,
                         NL_DAEMON_INTERNAL) &&
          !caller_allowed(NL_SWITCHD_QOS_WATERMARK_OWNER_APPLY,
                          NL_DAEMON_SWITCHD));
    CHECK("sealed L3 dry-run authority is explicit",
          caller_allowed(NL_SWITCHD_L3_TX_DRY_RUN, NL_DAEMON_INTERNAL));
    CHECK("normal RPD transaction methods do not gain INTERNAL",
          !caller_allowed(NL_SWITCHD_L3_TX_APPLY, NL_DAEMON_INTERNAL) &&
          !caller_allowed(NL_SWITCHD_L3_TX_READBACK, NL_DAEMON_INTERNAL) &&
          !caller_allowed(NL_SWITCHD_L3_TX_ROLLBACK, NL_DAEMON_INTERNAL));
    CHECK("public and cache-only reads do not gain INTERNAL",
          !caller_allowed(NL_SWITCHD_OPTICS_MUX_PROBE, NL_DAEMON_INTERNAL) &&
          !caller_allowed(NL_SWITCHD_PORT_SNAPSHOT_GET,
                          NL_DAEMON_INTERNAL));
    CHECK("unknown switchd method is fail closed",
          !caller_allowed(65000, NL_DAEMON_SWITCHD));
    CHECK("public switchd view remains allowed",
          caller_allowed(NL_SWITCHD_COS_GET, NL_DAEMON_SWITCHD));
    CHECK("ifd readback uses explicit daemon identity",
          caller_allowed(NL_SWITCHD_PORT_GET_STATE, NL_DAEMON_IFD) &&
          caller_allowed(NL_SWITCHD_PORT_GET_INVENTORY, NL_DAEMON_IFD));
    CHECK("coherent snapshot is limited to cache owners",
          caller_allowed(NL_SWITCHD_PORT_SNAPSHOT_GET, NL_DAEMON_IFD) &&
          caller_allowed(NL_SWITCHD_PORT_SNAPSHOT_GET, NL_DAEMON_STATSD) &&
          !caller_allowed(NL_SWITCHD_PORT_SNAPSHOT_GET,
                          NL_DAEMON_CONFIGD) &&
          !caller_allowed(NL_SWITCHD_PORT_SNAPSHOT_GET,
                          NL_DAEMON_LINKMOND) &&
          !caller_allowed(NL_SWITCHD_PORT_SNAPSHOT_GET,
                          NL_DAEMON_SWITCHD));
    CHECK("l2d inventory readback is authorized",
          caller_allowed(NL_SWITCHD_PORT_GET_INVENTORY, NL_DAEMON_L2D));
    CHECK("retired L3 daemon identity has no switchd authority",
          !caller_allowed(NL_SWITCHD_L3_TX_APPLY, NL_DAEMON_L3D));
    CHECK("MGMTD can proxy public switchd view",
          caller_allowed(NL_SWITCHD_COS_GET, NL_DAEMON_MGMTD));
	    return 0;
	}
'''
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "policy_contract.c"
        exe = Path(td) / "policy_contract"
        src.write_text(source, encoding="utf-8")
        proc = subprocess.run(
            [
                "gcc",
                "-std=c99",
                "-Wall",
                "-Werror",
                "-I",
                str(ROOT / "include"),
                str(ROOT / "lib" / "libipc" / "ipc_contract.c"),
                str(src),
                "-o",
                str(exe),
            ],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        if proc.returncode != 0:
            return check("switchd policy contract builds", False, proc.stdout)
        proc = subprocess.run(
            [str(exe)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        return check("switchd policy contract holds",
                     proc.returncode == 0, proc.stdout)


class FakeSeqpacket:
    def __init__(self, packet):
        self.packet = packet
        self.timeout = 10.0
        self.recv_sizes = []
        self.sent = b""

    def sendall(self, msg):
        self.sent += msg

    def recv(self, size, flags=0):
        self.recv_sizes.append(size)
        if flags & socket.MSG_PEEK:
            return self.packet[:size]
        return self.packet[:size]

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value


def response_packet(payload_len, error_code=0):
    payload = b"x" * payload_len
    header = struct.pack(
        HDR_FMT,
        MAGIC,
        1,
        MSG_RESPONSE,
        1,
        0,
        DAEMON_MGMTD,
        1,
        0,
        error_code,
        0,
        payload_len,
    )
    return header + payload


def test_cli_max_payload_response():
    packet = response_packet(MAX_PAYLOAD)
    fake = FakeSeqpacket(packet)
    sess = CliSession()
    sess._attach_test_transport(fake)
    ec, plen, payload = sess.send_request(DAEMON_MGMTD, 1, b"")
    return check(
        "Python client reads max payload plus header",
        ec == 0 and plen == MAX_PAYLOAD and len(payload) == MAX_PAYLOAD and
        (HDR_SIZE + MAX_PAYLOAD) in fake.recv_sizes,
        f"ec={ec} plen={plen} payload={len(payload)} recv_sizes={fake.recv_sizes}",
    )


def test_cli_oversize_response_rejected():
    packet = response_packet(MAX_PAYLOAD + 1)
    fake = FakeSeqpacket(packet)
    sess = CliSession()
    sess._attach_test_transport(fake)
    ec, plen, payload = sess.send_request(DAEMON_MGMTD, 1, b"")
    return check(
        "Python client rejects oversized payload",
        ec == -1 and plen == 0 and b"too large" in payload,
        f"ec={ec} plen={plen} payload={payload!r}",
    )


def test_cli_oversize_request_rejected():
    fake = FakeSeqpacket(response_packet(0))
    sess = CliSession()
    sess._attach_test_transport(fake)
    ec, plen, payload = sess.send_request(
        DAEMON_MGMTD, 1, b"x" * (MAX_PAYLOAD + 1))
    return check(
        "Python client rejects oversized request before send",
        ec == -1 and plen == 0 and b"too large" in payload and
        fake.sent == b"",
        f"ec={ec} plen={plen} payload={payload!r} sent={len(fake.sent)}",
    )


def test_c_ipc_hardening_contract():
    source = r'''
#include "netlab/ipc.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(name, expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", name); \
        return 1; \
    } \
} while (0)

static int path_is_regular(const char *path) {
    struct stat st;

    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int main(void) {
    const char *dir = getenv("TEST_IPC_DIR");
    nl_msg_hdr *msg;
    char path[256];
    char sock[256];
    char bad_suffix[256];
    char bad_dot[256];
    char bad_dotdot[256];
    char resp[8];
    int fd;
    int listen_fd = -1;
    struct stat st;

    if (!dir || !dir[0])
        return 1;

    CHECK("oversize IPC alloc rejected",
          nl_msg_alloc(NETLAB_MAX_MSG + 1) == NULL);
    msg = nl_msg_alloc(NETLAB_MAX_MSG);
    CHECK("max IPC alloc accepted", msg != NULL);
    nl_msg_free(msg);

    CHECK("negative RPC payload rejected before connect",
          nl_rpc_call_ex("/tmp/netlab-missing.sock", NL_DAEMON_INTERNAL,
                         NL_DAEMON_MGMTD, NL_MGMTD_SHOW_STATUS, 0,
                         (const u8 *)"x", -1, (u8 *)resp, sizeof(resp),
                         1000, NULL) < 0);
    CHECK("NULL RPC payload with positive length rejected",
          nl_rpc_call_ex("/tmp/netlab-missing.sock", NL_DAEMON_INTERNAL,
                         NL_DAEMON_MGMTD, NL_MGMTD_SHOW_STATUS, 0,
                         NULL, 1, (u8 *)resp, sizeof(resp),
                         1000, NULL) < 0);

    snprintf(path, sizeof(path), "%s/not-a-socket.sock", dir);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK("ordinary IPC placeholder created", fd >= 0);
    CHECK("ordinary IPC placeholder written", write(fd, "x", 1) == 1);
    close(fd);
    CHECK("server listen refuses non-socket placeholder",
          nl_server_listen(path, &listen_fd) != NL_OK);
    CHECK("server listen did not unlink ordinary file", path_is_regular(path));

    snprintf(bad_suffix, sizeof(bad_suffix), "%s/not-a-socket.txt", dir);
    CHECK("server listen rejects non-sock suffix",
          nl_server_listen(bad_suffix, &listen_fd) != NL_OK);
    snprintf(bad_dot, sizeof(bad_dot), "%s/.", dir);
    CHECK("server listen rejects trailing dot segment",
          nl_server_listen(bad_dot, &listen_fd) != NL_OK);
    snprintf(bad_dotdot, sizeof(bad_dotdot), "%s/..", dir);
    CHECK("server listen rejects trailing parent segment",
          nl_server_listen(bad_dotdot, &listen_fd) != NL_OK);

    snprintf(sock, sizeof(sock), "%s/service.sock", dir);
    CHECK("server listen accepts safe socket path",
          nl_server_listen(sock, &listen_fd) == NL_OK);
    close(listen_fd);
    CHECK("safe IPC unlink removes socket",
          nl_ipc_unlink_socket(sock) == NL_OK &&
          lstat(sock, &st) != 0 && errno == ENOENT);
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "ipc_hardening.c"
        exe = Path(td) / "ipc_hardening"
        src.write_text(source, encoding="utf-8")
        proc = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                "-pedantic", "-D_GNU_SOURCE",
                "-I", str(ROOT / "include"),
                str(ROOT / "lib" / "libipc" / "ipc.c"),
                str(ROOT / "lib" / "libipc" / "daemon_identity.c"),
                str(ROOT / "lib" / "libipc" / "rpc_client.c"),
                str(ROOT / "lib" / "libipc" / "ipc_contract.c"),
                str(ROOT / "lib" / "liblog" / "log.c"),
                str(src),
                "-lpthread",
                "-o", str(exe),
            ],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        if proc.returncode != 0:
            return check("C IPC hardening contract builds", False, proc.stdout)
        env = os.environ.copy()
        env["TEST_IPC_DIR"] = td
        proc = subprocess.run(
            [str(exe)],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        return check("C IPC hardening contract holds",
                     proc.returncode == 0, proc.stdout)


def test_c_ipc_frame_fuzz_contract():
    source = r'''
#include "netlab/ipc.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(name, expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", name); \
        return 1; \
    } \
} while (0)

static int recv_status_for_frame(const void *frame, size_t frame_len) {
    int sv[2];
    nl_conn conn = {0};
    nl_msg_hdr *msg = NULL;
    nl_status st;

    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0)
        return 99;
    conn.fd = sv[1];
    if (send(sv[0], frame, frame_len, 0) != (ssize_t)frame_len) {
        close(sv[0]);
        close(sv[1]);
        return 98;
    }
    st = nl_recv(&conn, &msg);
    nl_msg_free(msg);
    close(sv[0]);
    close(sv[1]);
    return st == NL_OK ? 0 : 1;
}

int main(void) {
    nl_msg_hdr hdr;
    unsigned char short_header[1] = {0};
    unsigned char truncated[NL_HDR_SIZE + 2];

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = NETLAB_MAGIC;
    hdr.payload_len = 0;
    CHECK("valid zero-payload frame accepted",
          recv_status_for_frame(&hdr, NL_HDR_SIZE) == 0);

    CHECK("short IPC header rejected",
          recv_status_for_frame(short_header, sizeof(short_header)) == 1);

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = 0xdeadbeefU;
    hdr.payload_len = 0;
    CHECK("bad IPC magic rejected",
          recv_status_for_frame(&hdr, NL_HDR_SIZE) == 1);

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = NETLAB_MAGIC;
    hdr.payload_len = NETLAB_MAX_MSG + 1;
    CHECK("oversized IPC payload header rejected",
          recv_status_for_frame(&hdr, NL_HDR_SIZE) == 1);

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = NETLAB_MAGIC;
    hdr.payload_len = 4;
    memcpy(truncated, &hdr, NL_HDR_SIZE);
    truncated[NL_HDR_SIZE] = 'x';
    truncated[NL_HDR_SIZE + 1] = 'y';
    CHECK("truncated IPC payload rejected",
          recv_status_for_frame(truncated, sizeof(truncated)) == 1);

    return 0;
}
'''
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "ipc_frame_fuzz.c"
        exe = Path(td) / "ipc_frame_fuzz"
        src.write_text(source, encoding="utf-8")
        proc = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                "-pedantic", "-D_GNU_SOURCE",
                "-I", str(ROOT / "include"),
                str(ROOT / "lib" / "libipc" / "ipc.c"),
                str(ROOT / "lib" / "libipc" / "daemon_identity.c"),
                str(ROOT / "lib" / "liblog" / "log.c"),
                str(src),
                "-lpthread",
                "-o", str(exe),
            ],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        if proc.returncode != 0:
            return check("C IPC frame fuzz contract builds", False,
                         proc.stdout)
        proc = subprocess.run(
            [str(exe)],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        return check("C IPC frame fuzz contract holds",
                     proc.returncode == 0, proc.stdout)


def test_c_ipc_expected_disconnect_logging():
    source = r'''
#include "netlab/ipc.h"
#include "netlab/log.h"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <syslog.h>
#include <unistd.h>

#define CHECK(name, expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", name); \
        return 1; \
    } \
} while (0)

int main(void) {
    struct timeval timeout = {0, 20000};
    nl_conn conn = {0};
    nl_msg_hdr *msg = NULL;
    int sv[2];

    signal(SIGPIPE, SIG_IGN);
    nl_log_init("ipc-expected-errors", LOG_USER, NL_LOG_INFO);

    CHECK("timeout socketpair created",
          socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
    CHECK("receive timeout configured",
          setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO,
                     &timeout, sizeof(timeout)) == 0);
    conn.fd = sv[0];
    CHECK("receive timeout is returned to caller",
          nl_recv(&conn, &msg) == NL_ERR && msg == NULL);
    close(sv[0]);
    close(sv[1]);

    CHECK("peer-close socketpair created",
          socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
    conn.fd = sv[0];
    close(sv[1]);
    msg = nl_msg_alloc(0);
    CHECK("message allocated", msg != NULL);
    CHECK("peer close is returned to caller", nl_send(&conn, msg) == NL_ERR);
    close(sv[0]);

    conn.fd = -1;
    CHECK("unexpected descriptor error is returned to caller",
          nl_send(&conn, msg) == NL_ERR);
    nl_msg_free(msg);
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "ipc_expected_errors.c"
        exe = Path(td) / "ipc_expected_errors"
        src.write_text(source, encoding="utf-8")
        proc = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                "-pedantic", "-D_GNU_SOURCE",
                "-I", str(ROOT / "include"),
                str(ROOT / "lib" / "libipc" / "ipc.c"),
                str(ROOT / "lib" / "libipc" / "daemon_identity.c"),
                str(ROOT / "lib" / "liblog" / "log.c"),
                str(src),
                "-lpthread",
                "-o", str(exe),
            ],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        if proc.returncode != 0:
            return check("C IPC expected-error logging builds",
                         False, proc.stdout)
        proc = subprocess.run(
            [str(exe)],
            cwd=str(ROOT),
            env={**os.environ, "LC_ALL": "C"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        error_lines = [line for line in proc.stdout.splitlines()
                       if " ERR " in line]
        return check(
            "C IPC hides expected timeout/peer-close noise but keeps real errors",
            proc.returncode == 0 and len(error_lines) == 1 and
            "Bad file descriptor" in error_lines[0] and
            "Resource temporarily unavailable" not in proc.stdout and
            "Broken pipe" not in proc.stdout,
            proc.stdout)


def test_mgmtd_lab_only_access_contract():
    source = r'''
#include "mgmtd.h"
#include <stdio.h>
#include <stdlib.h>

#define CHECK(name, expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s\n", name); \
        return 1; \
    } \
} while (0)

int main(void) {
    nl_conn user = {0};
    nl_conn root = {0};
    mgmtd_route xcvrd_info;
    mgmtd_route xcvrd_alias;

    user.peer_uid = 1000;
    root.peer_uid = 0;
    unsetenv("NETLAB_MGMTD_ALLOW_UNPRIVILEGED_WRITE");
    unsetenv("NETLAB_LAB_ONLY_MGMTD_ALLOW_UNPRIVILEGED_WRITE");

    CHECK("view access remains public",
          mgmtd_access_allowed(&user, MGMTD_ACCESS_VIEW));
    CHECK("root write access remains allowed",
          mgmtd_access_allowed(&root, MGMTD_ACCESS_CONFIG));
    CHECK("non-root write access denied by default",
          !mgmtd_access_allowed(&user, MGMTD_ACCESS_CONFIG));

    setenv("NETLAB_MGMTD_ALLOW_UNPRIVILEGED_WRITE", "1", 1);
    CHECK("legacy unprivileged write env no longer grants access",
          !mgmtd_access_allowed(&user, MGMTD_ACCESS_CONFIG));

    setenv("NETLAB_LAB_ONLY_MGMTD_ALLOW_UNPRIVILEGED_WRITE", "1", 1);
    CHECK("explicit lab-only unprivileged write env grants access",
          mgmtd_access_allowed(&user, MGMTD_ACCESS_CONFIG));

    xcvrd_info = mgmtd_lookup_route(NL_DAEMON_XCVRD,
                                    NL_SWITCHD_XCVR_INFO_GET);
    xcvrd_alias = mgmtd_lookup_route(NL_DAEMON_XCVRD,
                                     NL_SWITCHD_PFE_STATUS_GET);
    CHECK("xcvrd virtual route exposes transceiver readback only",
          xcvrd_info.ok && !xcvrd_alias.ok);
    return 0;
}
'''
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "mgmtd_access.c"
        exe = Path(td) / "mgmtd_access"
        src.write_text(source, encoding="utf-8")
        proc = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                "-pedantic", "-D_GNU_SOURCE",
                "-I", str(ROOT / "include"),
                "-I", str(ROOT / "sbin" / "mgmtd"),
                str(ROOT / "sbin" / "mgmtd" / "routes.c"),
                str(ROOT / "lib" / "libipc" / "ipc.c"),
                str(ROOT / "lib" / "libipc" / "daemon_identity.c"),
                str(ROOT / "lib" / "libipc" / "ipc_contract.c"),
                str(ROOT / "lib" / "liblog" / "log.c"),
                str(src),
                "-lpthread",
                "-o", str(exe),
            ],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        if proc.returncode != 0:
            return check("mgmtd lab-only access contract builds",
                         False, proc.stdout)
        proc = subprocess.run(
            [str(exe)],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            check=False,
        )
        return check("mgmtd lab-only access contract holds",
                     proc.returncode == 0, proc.stdout)


def test_source_contracts():
    failed = 0
    configd = (ROOT / "sbin" / "configd" / "main.c").read_text(
        encoding="utf-8")
    ipc = (ROOT / "lib" / "libipc" / "ipc.c").read_text(encoding="utf-8")
    lldpd = (ROOT / "sbin" / "lldpd" / "main.c").read_text(
        encoding="utf-8")
    linkmond = (ROOT / "sbin" / "linkmond" / "main.c").read_text(
        encoding="utf-8")
    ifd = (ROOT / "sbin" / "ifd" / "main.c").read_text(encoding="utf-8")
    l2_hw_probe = (ROOT / "sbin" / "l2d" / "l2_hw_probe.c").read_text(
        encoding="utf-8")

    failed += check(
        "configd derives configuration emptiness from the schema tree",
        "static bool tree_has_configuration" in configd and
        "return tree && lyd_child(tree) != NULL;" in configd and
        "parse_config_xml_data" in configd)
    failed += check(
        "configd has no fixed top-level XML tag emptiness allowlist",
        'strstr(xml, "<snmp")' not in configd and
        'strstr(xml, "<chassis")' not in configd)
    failed += check("configd active persistence uses atomic rename",
                    "mkstemp(tmpl)" in configd and
                    "rename(tmpl, path)" in configd and
                    "fsync_parent_dir(path)" in configd)
    failed += check("configd no longer truncates destination in persist_xml_file",
                    'fopen(path, "w")' not in configd)
    failed += check("C IPC rejects short headers before parsing",
                    "ret < (ssize_t)NL_HDR_SIZE" in ipc and
                    "short header" in ipc)
    failed += check("C IPC requires peer credentials",
                    "nl_get_peer_cred(conn->fd" in ipc and
                    "!= NL_OK" in ipc)
    failed += check("C IPC listen unlinks sockets only after lstat",
                    "lstat(path, &st)" in ipc and
                    "S_ISSOCK(st.st_mode)" in ipc and
                    "refusing to unlink non-socket" in ipc)
    failed += check("C IPC alloc enforces NETLAB_MAX_MSG",
                    "payload_len > NETLAB_MAX_MSG" in ipc and
                    "return NULL" in ipc)
    failed += check("lldpd sets daemon identity for switchd reads",
                    "NL_DAEMON_LLDPD" in lldpd and
                    "NL_DAEMON_SWITCHD, method" in lldpd)
    failed += check("linkmond sets daemon identity for switchd reads",
                    linkmond.count(
                        "nl_rpc_call_ex(switchd_socket_path(), "
                        "NL_DAEMON_LINKMOND") >= 2 and
                    "nl_rpc_call_ex(statsd_socket_path(), "
                    "NL_DAEMON_LINKMOND" in linkmond)
    failed += check("ifd switchd reads use explicit daemon identity",
                    "SW_SOCKET, NL_DAEMON_IFD, NL_DAEMON_SWITCHD" in ifd and
                    "NL_SWITCHD_PORT_SNAPSHOT_GET" in ifd and
                    '(const u8 *)"counters=0"' in ifd)
    failed += check("l2d hardware probes use l2d identity for switchd reads",
                    "NL_DAEMON_CONFIGD" not in l2_hw_probe and
                    "nl_rpc_call_ex(SWITCHD_SOCKET, NL_DAEMON_L2D" in
                    l2_hw_probe)
    failed += check("l2d accepts switchd reserved port zero inventory entry",
                    'id < 0' in l2_hw_probe and
                    'if (id > 0)' in l2_hw_probe)
    failed += check("required l2d hardware probes fail closed",
                    "l2_hw_probe_begin(require_hw)" in
                    (ROOT / "sbin" / "l2d" / "l2_plan.c").read_text(
                        encoding="utf-8") and
                    "hardware read-back failed" in l2_hw_probe and
                    "L2_HW_RPC_OR_RETURN" in l2_hw_probe)
    return failed


def main():
    failed = 0
    failed += test_switchd_policy_contract()
    failed += test_cli_max_payload_response()
    failed += test_cli_oversize_response_rejected()
    failed += test_cli_oversize_request_rejected()
    failed += test_c_ipc_hardening_contract()
    failed += test_c_ipc_frame_fuzz_contract()
    failed += test_c_ipc_expected_disconnect_logging()
    failed += test_mgmtd_lab_only_access_contract()
    failed += test_source_contracts()
    print(f"\nResults: {failed == 0 and 'all passed' or str(failed) + ' failed'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
