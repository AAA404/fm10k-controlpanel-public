"""Root-owned socket helper: only inspect or configure/retry systemd-timesyncd.

The Web process has no CAP_SYS_TIME, sudo permission or arbitrary command API.
systemd owns the listening socket and runs one bounded instance per connection.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import socket
import struct
import subprocess
import time

from .time_sync import TimeSyncError, TimeSyncRequest, receive_json

CONFIG = Path("/etc/systemd/timesyncd.conf.d/99-fm10k-panel.conf")
MARKER = Path("/run/systemd/timesync/synchronized")
LOCK = Path("/run/fm10k-time/operation.lock")


def run(*args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=6,
                                env={"PATH": "/usr/bin:/usr/sbin", "LC_ALL": "C"})
    except subprocess.TimeoutExpired as error:
        raise TimeSyncError("时间服务响应超时，请刷新状态后重试。") from error
    if result.returncode:
        raise TimeSyncError(f"时间服务操作失败：{result.stderr.strip()[:400] or result.stdout.strip()[:400]}")
    return result.stdout


def properties(text):
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


class TimeManager:
    def __init__(self, config=CONFIG, marker=MARKER, runner=run):
        self.config, self.marker, self.run = config, marker, runner

    def status(self):
        clock = properties(self.run("/usr/bin/timedatectl", "show", "-p", "Timezone", "-p", "NTP", "-p", "NTPSynchronized"))
        unit = properties(self.run("/usr/bin/systemctl", "show", "systemd-timesyncd.service", "-p", "LoadState", "-p", "ActiveState", "-p", "StatusText"))
        enabled = clock.get("NTP") == "yes"
        available = unit.get("LoadState") == "loaded"
        active = unit.get("ActiveState") == "active"
        ntp = properties(self.run("/usr/bin/timedatectl", "show-timesync", "--all")) if available and active else {}
        # Kernel synchronization alone may survive a daemon restart. Require a
        # successful NTP message in this daemon instance as well.
        message = ntp.get("NTPMessage", "")
        count = re.search(r"PacketCount=(\d+)", message)
        synchronized = active and enabled and clock.get("NTPSynchronized") == "yes" and bool(
            count and int(count[1]) > 0 and "Ignored=no" in message)
        servers = ntp.get("SystemNTPServers", "").split()
        # Retain configured servers when the service is disabled or stopped.
        if self.config.exists() and not active:
            for line in self.config.read_text().splitlines():
                if line.startswith("NTP="):
                    servers = line[4:].split()
        state = "unavailable" if not available else "synchronized" if synchronized else "disabled" if not enabled else "waiting" if active else "service-error"
        explanation = {"unavailable": "未安装 systemd-timesyncd。", "disabled": "尚未开启自动时间同步。",
                       "synchronized": "已收到时间服务器响应，系统时钟已同步。",
                       "waiting": "尚未确认同步；请检查 DNS、管理网络及到时间服务器的 UDP 123 连通性。",
                       "service-error": "时间同步服务未运行，请重试或检查服务日志。"}[state]
        return {"available": available, "provider": "systemd-timesyncd", "state": state,
                "enabled": enabled, "synchronized": synchronized, "server_time": time.time(),
                "timezone": clock.get("Timezone", "UTC"), "servers": servers,
                "fallback_servers": ntp.get("FallbackNTPServers", "").split(),
                "network_servers": ntp.get("LinkNTPServers", "").split(),
                "runtime_servers": ntp.get("RuntimeNTPServers", "").split(),
                "selected_server": ntp.get("ServerName") or None, "server_address": ntp.get("ServerAddress") or None,
                "last_synchronized_at": self.marker.stat().st_mtime if self.marker.exists() else None,
                "service_status": unit.get("StatusText", ""), "message": explanation}

    def write_config(self, data):
        temporary = self.config.with_suffix(".new")
        with temporary.open("wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.config)

    def sync(self, servers):
        servers = TimeSyncRequest(servers=servers).servers
        before = self.status()
        if not before["available"]:
            raise TimeSyncError("未安装 systemd-timesyncd，无法启动在线校时。")
        for name in ("chrony.service", "ntpsec.service", "ntp.service"):
            other = properties(self.run("/usr/bin/systemctl", "show", name, "-p", "ActiveState"))
            if other.get("ActiveState") in {"active", "activating"}:
                raise TimeSyncError("已有其他 NTP 服务运行，请先统一时间服务配置。")
        old = self.config.read_bytes() if self.config.exists() else None
        try:
            if servers is not None:
                self.write_config(("# Managed by FM10K Control Panel\n[Time]\nNTP=\nNTP=" + " ".join(servers) + "\nFallbackNTP=\n").encode())
            self.run("/usr/bin/timedatectl", "set-ntp", "true")
            self.run("/usr/bin/systemctl", "restart", "systemd-timesyncd.service")
            current = self.status()
            if servers is not None and current["servers"] != servers:
                raise TimeSyncError("时间服务器回读不一致，可能存在优先级更高的系统配置。")
            # An accepted request is not a successful exchange with an NTP server.
            return {**current, "message": "已发起同步，正在等待时间服务器响应。" if not current["synchronized"] else current["message"]}
        except Exception as error:
            try:
                if servers is not None:
                    if old is None:
                        self.config.unlink(missing_ok=True)
                    else:
                        self.write_config(old)
                if before["enabled"]:
                    self.run("/usr/bin/systemctl", "restart", "systemd-timesyncd.service")
                else:
                    self.run("/usr/bin/timedatectl", "set-ntp", "false")
            except Exception as recovery:
                raise TimeSyncError(f"同步操作失败，恢复旧设置也未完成：{recovery}") from error
            raise TimeSyncError(f"同步操作失败，已恢复原设置：{error}") from error


def handle(request, manager):
    if set(request) - {"action", "servers"} or request.get("action") not in {"status", "sync"}:
        raise TimeSyncError("不支持的时间请求")
    settings = TimeSyncRequest(servers=request.get("servers"))
    return manager.status() if request["action"] == "status" else manager.sync(settings.servers)


def main():
    if os.geteuid() != 0:
        raise SystemExit("the time helper must be socket-activated as root")
    with socket.socket(fileno=0) as connection:
        connection.settimeout(25)
        _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid not in {0, pwd.getpwnam("fm10k-web").pw_uid}:
            raise SystemExit("unauthorized time helper peer")
        try:
            request = receive_json(connection)
            with open(LOCK, "a", opener=lambda path, flags: os.open(path, flags, 0o600)) as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise TimeSyncError("另一项时间操作正在进行，请稍后刷新。") from error
                response = {"ok": True, "data": handle(request, TimeManager())}
        except Exception as error:
            response = {"ok": False, "error": str(error)[:800]}
        connection.sendall(json.dumps(response, ensure_ascii=False).encode() + b"\n")
    return 0
