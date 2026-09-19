"""Decode the existing fixed, read-only FM10K PHY snapshot.

Register bit positions and DFE enums are from the pinned IES 4.3.2 headers.
Optical power uses the board cache; explicit eye acquisitions use eye.py.
"""
from __future__ import annotations

import math

from .models import PHYSICAL, PortGroup
from .netlab_codec import parse_xml

PHY_REFRESH_SECONDS = 5
PHY_STALE_SECONDS = 15
ETHERNET_MODES = {"40g": 0x70005, "100g": 0xB0000}


class PhyModeChanged(ValueError):
    pass


def diagnostic_shell(epl: int, mode=None, profile=None, revision=None):
    physical = PHYSICAL[epl]
    return {
        "epl": epl, "mpo": physical["mpo"], "owner_port": physical["base"],
        "mode": mode, "profile": profile, "revision": revision,
        "refresh_seconds": PHY_REFRESH_SECONDS, "stale_after_seconds": PHY_STALE_SECONDS,
        "capabilities": {
            "tx_power": "not_exposed", "rx_power": "unqualified",
            "eye_diagram": "on_demand_sampler", "eye_metrics": "not_exposed",
            "ber": "not_exposed", "phy": "aggregate_only",
        },
        "phy": {"quality": "pending", "sampled_at": None, "lanes": [], "pcs": None},
    }


def decode_phy(payload: bytes, group: PortGroup, *, wall: float, monotonic_ms: float):
    root = parse_xml(payload)
    physical = PHYSICAL[group.epl]
    if root.tag != "fm10k-phy" or int(root.get("port", "0")) != physical["base"] or int(root.get("epl", "-1")) != group.epl:
        raise ValueError("PHY 快照端口或 EPL 不匹配")
    if group.mode not in ETHERNET_MODES or int(root.get("ethernet-mode-raw", "0")) != ETHERNET_MODES[group.mode]:
        raise PhyModeChanged("PHY 缓存尚未切换到当前端口模式")
    sampled_ms = int(root.attrib["sampled-monotonic-ms"])
    if not math.isfinite(wall) or not math.isfinite(monotonic_ms) or sampled_ms < 0 or sampled_ms > monotonic_ms + 1:
        raise ValueError("PHY 采样时钟无效")
    age = max(0.0, (monotonic_ms - sampled_ms) / 1000)
    errors = {}

    def fields(node, prefix, names):
        found = {}
        for item in node.findall("field"):
            name = item.get("name")
            if name not in names:
                continue
            if name in found:
                raise ValueError("PHY 字段重复")
            status = int(item.attrib["status"])
            if status:
                found[name] = None
                errors[prefix + name] = status
            else:
                value = int(item.attrib["value"])
                if not -(1 << 31) <= value < (1 << 31):
                    raise ValueError("PHY 字段超出范围")
                found[name] = value
        for name in names - found.keys():
            found[name] = None
            errors[prefix + name] = "missing"
        return found

    def bit(value, shift):
        return None if value is None else bool(value & (1 << shift))

    shared = fields(root, "", {"pcs_ml_baser_cfg", "pcs_ml_baser_rx_status", "speed_mbps"})
    pcs = shared["pcs_ml_baser_rx_status"]
    pcs_status = {
        "block_lock": [bit(pcs, 8 + lane) for lane in range(4)],
        "am_lock": [bit(pcs, 22 + lane) for lane in range(4)],
        "aligned": bit(pcs, 21), "high_ber": bit(pcs, 20),
        "raw": None if pcs is None else f"0x{pcs & 0xffffffff:08x}",
    }
    lanes = []
    seen = set()
    for node in root.findall("lane"):
        lane = int(node.attrib["id"])
        if lane not in range(4) or lane in seen:
            raise ValueError("PHY Lane 编号无效或重复")
        seen.add(lane)
        values = fields(node, f"lane{lane}.", {
            "lane_serdes_status", "tx_pre", "tx_cursor", "tx_post", "rx_polarity", "tx_polarity",
            "rx_termination", "dfe_mode", "coarse_dfe", "fine_dfe", "signal_transition_threshold",
        })
        status = values.pop("lane_serdes_status")
        lanes.append({
            "lane": lane, "tx_ready": bit(status, 25), "rx_ready": bit(status, 24),
            "rx_idle": bit(status, 26), "rx_activity": bit(status, 27),
            "tx_power_dbm": None, "rx_power_dbm": None,
            "eye_height_mv": None, "eye_width_ui": None,
            "serdes_raw": None if status is None else f"0x{status & 0xffffffff:08x}", **values,
        })
    if seen != set(range(4)):
        raise ValueError("PHY 快照缺少 Lane")
    return {"quality": "stale" if age > PHY_STALE_SECONDS else "partial" if errors else "valid",
            "sampled_at": wall - age, "source": "switchd-phy", "pcs": pcs_status,
            "lanes": sorted(lanes, key=lambda value: value["lane"]), "errors": errors}


def power_for_epl(module, epl, now):
    """Map CXP channel numbering to the four EPL lanes, retaining freshness."""
    module = module or {}
    quality = module.get("rx_power_quality", "unavailable")
    sampled = module.get("rx_power_sampled_at")
    result = {"quality": quality, "sampled_at": sampled, "source": module.get("power_source"),
              "tx_quality": module.get("tx_power_quality", "not_exposed"), "channels": []}
    channels = module.get("rx_power")
    if not isinstance(channels, list): return result
    if module.get("mpo") != PHYSICAL[epl]["mpo"] or module.get("power_source") != "cxp-rx-page1" or len(channels) != 12:
        result["quality"] = "unqualified"
        return result
    values = {}
    for value in channels:
        if (not isinstance(value, dict) or type(value.get("channel")) is not int or
                value["channel"] not in range(12) or value["channel"] in values or
                type(value.get("raw")) is not int or not 0 <= value["raw"] <= 65535):
            result["quality"] = "unavailable"
            return result
        values[value["channel"]] = value["raw"]
    if quality == "valid" and (not isinstance(sampled, (int,float)) or not math.isfinite(sampled) or
                               sampled > now+1 or now-sampled > PHY_STALE_SECONDS):
        result["quality"] = "stale"
    first = PHYSICAL[epl]["position"]*4
    for lane in range(4):
        raw = values[first+lane]
        result["channels"].append({"lane":lane,"module_channel":first+lane,"raw":raw,
                                   "microwatts":raw/10,"dbm":10*math.log10(raw/10000) if raw else None})
    return result
