"""NTP settings and the unprivileged client of the fixed-action time helper."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import time

from pydantic import Field, field_validator
from .models import Model
from .storage import atomic_json, read_json

DEFAULT_SERVERS = ["ntp.aliyun.com", "ntp.tencent.com"]
SOCKET_PATH = "/run/fm10k-time/control.sock"
MAX_MESSAGE = 16384


class TimeSyncRequest(Model):
    # None means retry with the existing system configuration.
    servers: list[str] | None = Field(default=None, min_length=1, max_length=4)

    @field_validator("servers")
    @classmethod
    def validate_servers(cls, values):
        if values is None:
            return values
        result = []
        for value in values:
            value = value.strip().lower()
            if not value or len(value) > 253 or any(c.isspace() for c in value):
                raise ValueError("时间服务器需为 IP 或主机名，不包含空格、URL 或端口")
            try:
                address = ipaddress.ip_address(value)
                if address.is_multicast or address.is_unspecified or "%" in value:
                    raise ValueError("无效的时间服务器地址")
                value = str(address)
            except ValueError as error:
                if ":" in value or re.fullmatch(r"[\d.]+", value) or not all(
                    re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in value.rstrip(".").split(".")
                ):
                    raise ValueError("时间服务器需为有效 IP 或主机名，不包含 URL、端口或配置指令") from error
            if value not in result:
                result.append(value)
        return result


class TimeSyncError(RuntimeError):
    pass


def receive_json(connection):
    data = bytearray()
    while b"\n" not in data and len(data) <= MAX_MESSAGE:
        block = connection.recv(min(4096, MAX_MESSAGE + 1 - len(data)))
        if not block:
            break
        data.extend(block)
    if len(data) > MAX_MESSAGE or not data.endswith(b"\n") or data.count(b"\n") != 1:
        raise TimeSyncError("时间服务返回了无效消息")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise TimeSyncError("时间服务消息必须为对象")
    return value


class TimeSyncClient:
    def __init__(self, mode, directory, socket_path=SOCKET_PATH):
        self.mode, self.path, self.socket_path = mode, directory / "time-sync-simulated.json", socket_path

    def request(self, action, servers=None):
        if action not in {"status", "sync"}:
            raise TimeSyncError("未知的时间操作")
        settings = TimeSyncRequest(servers=servers)
        if self.mode == "mock":
            state = read_json(self.path) or {"servers": DEFAULT_SERVERS, "enabled": False}
            if action == "sync":
                state.update(enabled=True, servers=settings.servers or state["servers"])
                atomic_json(self.path, state)
            return {**state, "available": True, "provider": "simulated", "state": "simulated",
                    "synchronized": False, "server_time": time.time(), "timezone": "UTC",
                    "selected_server": None, "server_address": None, "last_synchronized_at": None,
                    "message": "模拟模式仅保存测试设置，不修改电脑时间或连接时间服务器。"}
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(25)
                connection.connect(self.socket_path)
                connection.sendall(json.dumps({"action": action, "servers": settings.servers}).encode() + b"\n")
                result = receive_json(connection)
            if not result.get("ok"):
                raise TimeSyncError(result.get("error", "时间操作失败"))
            return result["data"]
        except (OSError, ValueError, KeyError) as error:
            raise TimeSyncError("时间服务不可用，请检查 fm10k-time.socket 与 systemd-timesyncd。") from error
