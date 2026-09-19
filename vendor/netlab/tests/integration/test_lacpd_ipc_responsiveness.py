#!/usr/bin/env python3.11
# Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json.
"""Isolated contracts for lacpd IPC responsiveness and idle polling."""

from __future__ import annotations

import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from netlab_ipc_transport import (  # noqa: E402
    client_authenticate,
    prepare_client_socket,
    recv_peer_record,
    server_authenticate,
)

LACPD = ROOT / "build" / "lacpd"
MGMTD = ROOT / "build" / "mgmtd"
PROFILE = ROOT / "config" / "platform" / "default.profile"
HDR_FMT = "<IHHQQHHIiII"
HDR_SIZE = struct.calcsize(HDR_FMT)
MAGIC = 0x4E454C42

EMPTY_CONFIG = b'<netlab-config xmlns="urn:netlab:config"/>'
LACP_CONFIG = b"""<netlab-config xmlns="urn:netlab:config">
  <interfaces>
    <interface>
      <name>ae0</name>
      <aggregated-ether-options>
        <lacp><mode>passive</mode></lacp>
      </aggregated-ether-options>
    </interface>
    <interface>
      <name>et-0/0/0</name>
      <ether-options><ieee8023ad>ae0</ieee8023ad></ether-options>
    </interface>
  </interfaces>
</netlab-config>"""


def check(name: str, condition: bool, detail: str = "") -> int:
    print(("PASS" if condition else "FAIL") + f": {name}")
    if not condition and detail:
        print(detail)
    return 0 if condition else 1


class SwitchdStub:
    def __init__(self, path: Path, delays: dict[int, float] | None = None):
        self.path = path
        self.delays = delays or {}
        self.counts: defaultdict[int, int] = defaultdict(int)
        self.condition = threading.Condition()
        self.stop_event = threading.Event()
        self.sock: socket.socket | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.sock.settimeout(0.2)
        self.sock.bind(str(self.path))
        self.sock.listen(16)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as wake:
                wake.connect(str(self.path))
        except OSError:
            pass
        if self.thread:
            self.thread.join(timeout=4)
        if self.sock:
            self.sock.close()

    def count(self, method: int) -> int:
        with self.condition:
            return self.counts[method]

    def wait_count(self, method: int, expected: int,
                   timeout: float = 8.0) -> bool:
        deadline = time.monotonic() + timeout
        with self.condition:
            while self.counts[method] < expected:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self.condition.wait(remaining)
            return True

    def _serve(self) -> None:
        assert self.sock is not None
        while not self.stop_event.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                try:
                    peer = server_authenticate(conn)
                    packet = recv_peer_record(conn, peer, 262144)
                except OSError:
                    continue
                if len(packet) < HDR_SIZE:
                    continue
                fields = struct.unpack(HDR_FMT, packet[:HDR_SIZE])
                method = fields[6]
                with self.condition:
                    self.counts[method] += 1
                    self.condition.notify_all()
                delay = self.delays.get(method, 0.0)
                if delay:
                    time.sleep(delay)
                if method == 73:
                    body = (b'<lags native-generation="0000000000000001"><lag ae="0" id="1" logical-port="100">'
                            b'<member port="1"/></lag></lags>')
                elif method == 2:
                    body = b"port=1 link=UP"
                else:
                    body = b"ok"
                response = struct.pack(
                    HDR_FMT, MAGIC, 1, 1, fields[3], fields[4], 7, method,
                    0, 0, 0, len(body)) + body
                try:
                    conn.sendall(response)
                except (BrokenPipeError, ConnectionResetError):
                    pass


def wait_socket(path: Path, proc: subprocess.Popen[str],
                timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        if path.exists():
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                probe.connect(str(path))
                return True
            except OSError:
                pass
            finally:
                probe.close()
        time.sleep(0.05)
    return False


def rpc(path: Path, method: int = 1,
        timeout: float = 0.75) -> tuple[str, float]:
    request = struct.pack(
        HDR_FMT, MAGIC, 1, 0, 1, 0, 11, method, 0, 0,
        int(timeout * 1000), 0)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.settimeout(timeout)
    started = time.monotonic()
    try:
        prepare_client_socket(client)
        client.connect(str(path))
        peer = client_authenticate(client)
        client.sendall(request)
        response = recv_peer_record(client, peer, 262144)
    finally:
        client.close()
    elapsed = time.monotonic() - started
    fields = struct.unpack(HDR_FMT, response[:HDR_SIZE])
    length = fields[10]
    return response[HDR_SIZE:HDR_SIZE + length].decode(errors="replace"), elapsed


def stop_process(proc: subprocess.Popen[str]) -> str:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
    try:
        output, _ = proc.communicate(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill()
        output, _ = proc.communicate(timeout=4)
    return output


def daemon_env(temp: Path, config_dir: Path,
               lacpd_socket: Path, switchd_socket: Path) -> dict[str, str]:
    return {
        **os.environ,
        "NETLAB_ROOT": str(ROOT),
        "NETLAB_CONFIG_DIR": str(config_dir),
        "NETLAB_PLATFORM_PROFILE": str(PROFILE),
        "NETLAB_LACPD_SOCKET": str(lacpd_socket),
        "NETLAB_SWITCHD_SOCKET": str(switchd_socket),
        "NETLAB_PACKETD_SOCKET": str(temp / "missing-packetd.sock"),
    }


def responsiveness_contract(temp: Path) -> tuple[bool, str]:
    config_dir = temp / "configured"
    config_dir.mkdir()
    (config_dir / "active.conf").write_bytes(LACP_CONFIG)
    lacpd_socket = temp / "lacpd-configured.sock"
    mgmtd_socket = temp / "mgmtd-configured.sock"
    switchd_socket = temp / "switchd-configured.sock"
    stub = SwitchdStub(switchd_socket, {73: 1.25, 2: 1.25, 72: 1.25})
    stub.start()
    proc = subprocess.Popen(
        [str(LACPD)], cwd=ROOT,
        env=daemon_env(temp, config_dir, lacpd_socket, switchd_socket),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    details: list[str] = []
    ok = True
    gateway: subprocess.Popen[str] | None = None
    try:
        if not wait_socket(lacpd_socket, proc):
            return False, "lacpd socket did not appear"
        gateway_env = daemon_env(
            temp, config_dir, lacpd_socket, switchd_socket)
        gateway_env["NETLAB_MGMTD_SOCKET"] = str(mgmtd_socket)
        gateway = subprocess.Popen(
            [str(MGMTD)], cwd=ROOT, env=gateway_env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if not wait_socket(mgmtd_socket, gateway):
            return False, "mgmtd gateway socket did not appear"
        for method, count, label in (
                (73, 2, "LAG read-back"),
                (2, 1, "port link read-back"),
                (72, 1, "member detach")):
            if not stub.wait_count(method, count):
                ok = False
                details.append(f"{label} method={method} did not start")
                continue
            try:
                body, elapsed = rpc(mgmtd_socket)
            except (OSError, struct.error) as exc:
                ok = False
                details.append(f"{label} show RPC failed: {exc}")
                continue
            if "<lags>" not in body or elapsed >= 0.5:
                ok = False
                details.append(
                    f"{label} blocked show RPC: elapsed={elapsed:.3f}s "
                    f"body={body!r}")
        if stub.wait_count(73, 3):
            try:
                body, elapsed = rpc(mgmtd_socket, method=2)
            except (OSError, struct.error) as exc:
                ok = False
                details.append(f"reload RPC failed during read-back: {exc}")
            else:
                if body != "lacpd reload complete" or elapsed >= 0.5:
                    ok = False
                    details.append(
                        f"reload RPC blocked on hardware: elapsed={elapsed:.3f}s "
                        f"body={body!r}")
        else:
            ok = False
            details.append("third LAG read-back did not start")
    finally:
        gateway_output = stop_process(gateway) if gateway else ""
        output = stop_process(proc)
        stub.stop()
    if not ok:
        details.extend((gateway_output, output))
    return ok, "\n".join(details)


def empty_config_contract(temp: Path) -> tuple[bool, str]:
    config_dir = temp / "empty"
    config_dir.mkdir()
    (config_dir / "active.conf").write_bytes(EMPTY_CONFIG)
    lacpd_socket = temp / "lacpd-empty.sock"
    switchd_socket = temp / "switchd-empty.sock"
    stub = SwitchdStub(switchd_socket)
    stub.start()
    proc = subprocess.Popen(
        [str(LACPD)], cwd=ROOT,
        env=daemon_env(temp, config_dir, lacpd_socket, switchd_socket),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        if not wait_socket(lacpd_socket, proc):
            return False, "lacpd socket did not appear"
        time.sleep(2.2)
        polls = stub.count(73)
    finally:
        output = stop_process(proc)
        stub.stop()
    return polls == 0, f"hardware-readback-calls={polls}\n{output}"


def main() -> int:
    failed = 0
    build = subprocess.run(
        ["make", "lacpd", "mgmtd"], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    failed += check("lacpd builds", build.returncode == 0, build.stdout)
    if build.returncode:
        return failed

    with tempfile.TemporaryDirectory(prefix="netlab-lacpd-ipc-") as td:
        temp = Path(td)
        ok, detail = responsiveness_contract(temp)
        failed += check(
            "lacpd show/reload RPCs remain responsive during slow hardware calls",
            ok, detail)
        ok, detail = empty_config_contract(temp)
        failed += check("lacpd skips LAG hardware polling without LAG config",
                        ok, detail)
    return failed


if __name__ == "__main__":
    raise SystemExit(main())
