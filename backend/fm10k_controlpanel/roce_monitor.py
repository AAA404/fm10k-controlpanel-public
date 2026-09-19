"""Bounded observation history; sampled pauses never authorize a recovery write."""
from collections import deque
import copy


class RoceMonitor:
    interval_seconds = 10

    def __init__(self):
        self.last_read = None
        self.revision = None
        self.generation = None
        self.previous = {}
        self.history = deque(maxlen=180)
        self.events = deque(maxlen=64)
        self.peaks = {}

    def gap(self):
        self.previous.clear()
        self.generation = None

    def observe(self, sample, monotonic_now):
        revision, generation = sample.get("revision"), sample.get("sample_generation")
        if revision != self.revision:
            self.gap()
            self.peaks.clear()
            self.history.clear()
            self.revision = revision
        elapsed = monotonic_now - self.last_read if self.last_read is not None else None
        continuous = elapsed is not None and 0 < elapsed <= 3 * self.interval_seconds and (
            type(generation) is int and type(self.generation) is int and generation > self.generation)
        if not continuous:
            self.previous.clear()
        rows = []
        for p in sample.get("ports", []):
            if not p.get("selected"):
                continue
            port = p["port"]
            pause, usage = p.get("pause", {}), p.get("tc3_usage_bytes")
            valid = sample.get("quality") == "valid" and sample.get("configuration_applied") is True and p.get("link") == "up" and p.get("quality") == "valid" and pause.get("quality") == "valid"
            mask = pause.get("paused_class_mask")
            paused = bool(mask & 8) if type(mask) is int and pause.get("quality") == "valid" else None
            tx_bytes = p.get("counters", {}).get("tx_bytes")
            prior = self.previous.get(port, {})
            stalled = valid and paused and type(usage) is int and usage > 0 and type(tx_bytes) is int
            same = stalled and prior.get("stalled") and tx_bytes == prior.get("tx_bytes")
            observed = prior.get("observed_seconds", 0) + elapsed if same and continuous else 0
            alarm = bool(stalled and observed >= 30)
            if alarm and not prior.get("alarm"):
                self.events.append({"time": sample.get("sampled_at"), "revision": revision, "port": port,
                    "kind": "pause-stall-suspected", "message": "连续采样发现优先级 3 暂停、队列非空且出口字节未增长；需检查对端。", "automatic_action": False})
            if prior.get("alarm") and valid and not alarm:
                self.events.append({"time": sample.get("sampled_at"), "revision": revision, "port": port,
                    "kind": "pause-stall-cleared", "message": "后续采样不再满足暂停停滞条件。", "automatic_action": False})
            self.previous[port] = {"stalled": stalled, "observed_seconds": observed, "alarm": alarm, "tx_bytes": tx_bytes}
            if type(usage) is int and usage >= 0:
                self.peaks[port] = max(self.peaks.get(port, 0), usage)
            rows.append({"port": port, "pause_observed": paused, "observed_stall_seconds": observed,
                         "suspected_stall": alarm, "tc3_usage_bytes": usage,
                         "tc3_peak_bytes": self.peaks.get(port), "quality": "valid" if valid else "unavailable"})
        self.last_read, self.generation = monotonic_now, generation
        self.history.append({"time": sample.get("sampled_at"), "revision": revision, "ports": copy.deepcopy(rows)})
        return {"interval_seconds": self.interval_seconds, "persistent": False, "automatic_recovery": False,
                "observation": "采样只能证明各采样时刻的暂停；可能遗漏间隔内恢复，不作为连续暂停时长或死锁证明。",
                "ports": rows, "history": list(self.history), "events": list(self.events)}
