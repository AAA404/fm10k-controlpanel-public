"""Bounded retrieval and validation of native two-dimensional sampler scans."""
from __future__ import annotations

import copy
import csv
import io
import math
import re
import uuid
from typing import Literal

from pydantic import Field, StrictInt, field_validator

from .board import HardwareError
from .models import Model, PHYSICAL

ACTIVE = {"preparing", "running", "cancelling", "reading"}
ERRORS = {
    "eye_busy": "已有眼图正在采集，请等待完成或取消当前采集。",
    "configuration_busy": "配置正在变更，请完成配置事务后再采集。",
    "no_signal": "当前 Lane 未检测到可采样的 RX 信号。",
    "signal_lost": "采集过程中 RX 信号丢失，已停止采集。",
    "port_disabled": "当前端口未启用或无法读取端口状态。",
    "unsupported_speed": "眼图采集支持每 Lane 10G / 25G。",
    "unsupported_firmware": "当前 SerDes 固件不支持此眼图协议。",
    "firmware_probe_failed": "无法读取 SerDes 眼图能力。",
    "restore_failed": "采集后状态恢复未通过校验；需恢复原生服务后才能继续。",
    "job_expired": "此采集结果已被新的任务替换。",
    "column_timeout": "采样列超时，未读取的采样点保持为空。",
    "dfe_timeout": "均衡器暂停超时，已停止采集。",
    "dfe_pause_failed": "无法暂停均衡器，已停止采集。",
    "configuration_changed": "配置发生变更，采集已取消。",
    "user_cancelled": "采集已取消。",
    "service_stopping": "原生服务正在停止，采集已取消。",
    "sample_timeout": "固件报告采样点超时，已停止采集；超时点不计为测量数据。",
    "loopback_requires_link_down": "内部回环自检仅支持 Link Down 的端口。",
    "loopback_already_configured": "当前 Lane 已设置回环或测试码型，请先恢复正常模式。",
    "loopback_setup_failed": "内部回环准备失败，已尝试恢复原状态。",
    "loopback_probe_failed": "无法读取当前 Lane 的回环或发送源状态。",
    "serdes_not_ready": "当前 Lane 的 RX / TX 尚未就绪。",
    "master_requires_offline_board": "此板仅支持离线眼图：所有数据口须 Link Down。",
    "master_firmware_unavailable": "缺少已校验的离线眼图微码，请按原生部署说明安装。",
    "master_firmware_setup_failed": "临时采集微码未通过校验，已尝试恢复原主控微码。",
}


class EyeRequest(Model):
    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex, pattern=r"^[0-9a-f]{32}$")
    lane: StrictInt = Field(ge=0, le=3)
    signal_source: Literal["external", "internal_loopback"] = "external"
    x_resolution: StrictInt = 64
    y_step: StrictInt = 2
    dwell_bits: StrictInt = 1_000_000

    @field_validator("x_resolution", "y_step", "dwell_bits")
    @classmethod
    def allowed(cls, value, info):
        allowed = {"x_resolution": {16, 32, 64}, "y_step": {1, 2, 4, 8},
                   "dwell_bits": {100_000, 1_000_000, 10_000_000}}
        if value not in allowed[info.field_name]:
            raise ValueError("不支持的眼图采样参数")
        return value


def validate_chunk(value):
    if not isinstance(value, dict):
        raise HardwareError("眼图响应格式无效")
    if value.get("error") and not value.get("id"):
        raise HardwareError(ERRORS.get(value["error"], "眼图采集失败：" + str(value["error"])))
    if value.get("state") == "idle":
        return value
    if not re.fullmatch(r"[0-9a-f]{32}", str(value.get("id", ""))) or value.get("state") not in {
            "preparing", "running", "cancelling", "complete", "cancelled", "failed"}:
        raise HardwareError("眼图任务标识或状态无效")
    limits = {"port": (1, 24), "lane": (0, 3), "x_resolution": (16, 64), "x_points": (33, 129),
              "y_points": (32, 256), "y_step": (1, 8), "dwell_bits": (100000, 10000000),
              "columns_done": (0, 129), "column_offset": (0, 129)}
    for name, (low, high) in limits.items():
        if type(value.get(name)) is not int or not low <= value[name] <= high:
            raise HardwareError("眼图采样参数无效：" + name)
    if (value["x_resolution"] not in {16,32,64} or value["y_step"] not in {1,2,4,8} or
            value["x_points"] != 2 * value["x_resolution"] + 1 or
            value["y_points"] != 256 // value["y_step"] or value.get("y_min") != -128 or
            value["dwell_bits"] % 20 or value["epl"] != tuple(PHYSICAL)[(value["port"]-1)//4] or
            not 0 <= value["column_offset"] <= value["columns_done"] <= value["x_points"] or
            value.get("source") not in {"serdes-hardware", "simulator"} or
            value.get("signal_source") not in {"external", "internal_prbs31_loopback"} or
            value.get("measurement") != "offset-sampler-xor" or value.get("vertical_unit") != "DAC"):
        raise HardwareError("眼图坐标、端口或来源不一致")
    rows = value.get("errors")
    if not isinstance(rows, list) or len(rows) > 4 or value["column_offset"] + len(rows) > value["columns_done"]:
        raise HardwareError("眼图数据分页无效")
    if any(not isinstance(row, list) or len(row) != value["y_points"] or
           any(type(n) is not int or not 0 <= n <= 134201344 for n in row) for row in rows):
        raise HardwareError("眼图采样计数无效")
    if not isinstance(value.get("started_at"), (int, float)) or not math.isfinite(value["started_at"]):
        raise HardwareError("眼图采样时间无效")
    if value["state"] == "complete" and (value["columns_done"] != value["x_points"] or
            value.get("restored") is not True or value.get("restore_failed")):
        raise HardwareError("眼图尚未完整采集或恢复，不能标为完成")
    return value


def merge_chunk(previous, chunk):
    validate_chunk(chunk)
    if chunk["state"] == "idle":
        return copy.deepcopy(chunk)
    previous = previous or {}
    points = copy.deepcopy(previous.get("errors", []))
    if previous:
        for name in ("id", "port", "epl", "lane", "source", "signal_source", "speed_mbps",
                     "x_points", "y_points", "x_resolution", "x_step", "y_step", "y_min",
                     "dwell_bits", "dwell_scale", "rx_clock_divider", "started_at",
                     "firmware", "master_firmware", "sampling_master_firmware",
                     "temporary_master", "phase_multiplier", "compare_mode_before"):
            if previous.get(name) != chunk.get(name):
                raise HardwareError("眼图分页属于不同采集任务")
        if chunk["columns_done"] < previous.get("columns_done", 0):
            raise HardwareError("眼图进度发生倒退")
    offset = chunk["column_offset"]
    if offset > len(points):
        raise HardwareError("眼图数据分页缺失")
    for index, row in enumerate(chunk["errors"], offset):
        if index < len(points):
            if points[index] != row:
                raise HardwareError("已完成的眼图采样计数发生变化")
        else:
            points.append(row.copy())
    value = {**previous, **chunk, "errors": points, "native_state": chunk["state"], "column_offset": 0}
    if value["state"] == "complete" and len(points) != value["x_points"]:
        value["state"] = "reading"
    value["received_columns"] = len(points)
    value["progress"] = value["columns_done"] / value["x_points"]
    value["message"] = ERRORS.get(value.get("error"), value.get("error", ""))
    value["metrics"] = metrics(value)
    return value


def metrics(value):
    if value.get("state") != "complete" or len(value.get("errors", [])) != value.get("x_points"):
        return None
    data, bits = value["errors"], value["dwell_bits"]
    x0, y0 = value["x_resolution"], 128 // value["y_step"]
    threshold = 1e-4
    center = data[x0][y0]
    result = {"threshold": threshold, "center_errors": center, "sampled_bits": bits,
              "center_error_ratio": center / bits, "detection_floor": 1 / bits,
              "eye_width_ui": None, "eye_height_dac": None}
    if center / bits > threshold:
        return result
    left = right = x0
    bottom = top = y0
    while left > 0 and data[left-1][y0] / bits <= threshold: left -= 1
    while right+1 < len(data) and data[right+1][y0] / bits <= threshold: right += 1
    while bottom > 0 and data[x0][bottom-1] / bits <= threshold: bottom -= 1
    while top+1 < len(data[x0]) and data[x0][top+1] / bits <= threshold: top += 1
    result.update(eye_width_ui=(right-left)/value["x_resolution"],
                  eye_height_dac=(top-bottom)*value["y_step"],
                  width_clipped=left==0 or right==len(data)-1,
                  height_clipped=bottom==0 or top==len(data[x0])-1)
    return result


def export_csv(value):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(["scan_id", "source", "port", "epl", "lane", "phase_ui", "threshold_dac", "errors", "sampled_bits", "xor_error_ratio", "signal_source",
                     "state", "restored", "columns_done", "x_points", "y_points", "started_at"])
    for x, row in enumerate(value.get("errors", [])):
        for y, errors in enumerate(row):
            writer.writerow([value["id"], value["source"], value["port"], value["epl"], value["lane"],
                             (x-value["x_resolution"])/value["x_resolution"], -128+y*value["y_step"],
                             errors, value["dwell_bits"], errors/value["dwell_bits"], value["signal_source"],
                             value["state"], value.get("restored") is True, value["columns_done"],
                             value["x_points"], value["y_points"], value["started_at"]])
    return stream.getvalue()
