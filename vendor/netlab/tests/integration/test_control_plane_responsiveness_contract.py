#!/usr/bin/env python3.11
"""Validate Control-Plane Responsiveness V1 source and formatter contracts."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def check(name: str, condition: bool, detail: str = "") -> int:
    print(("PASS" if condition else "FAIL") + ": " + name)
    if not condition and detail:
        print(detail)
    return 0 if condition else 1


def main() -> int:
    failed = 0
    hal = (ROOT / "include/netlab/hal.h").read_text(encoding="utf-8")
    executor = (ROOT / "sbin/switchd/sdk_executor.c").read_text(
        encoding="utf-8")
    rpc = (ROOT / "sbin/switchd/rpc_server.c").read_text(encoding="utf-8")
    contracts = (ROOT / "lib/libipc/ipc_contract.c").read_text(
        encoding="utf-8")
    ifd = (ROOT / "sbin/ifd/main.c").read_text(encoding="utf-8")
    statsd = (ROOT / "sbin/statsd/main.c").read_text(encoding="utf-8")
    l2d = (ROOT / "sbin/l2d/main.c").read_text(encoding="utf-8")
    chassis = (ROOT / "sbin/chassisd/main.c").read_text(encoding="utf-8")
    rpd = (ROOT / "sbin/rpd/main.c").read_text(encoding="utf-8")
    l3_owner = (ROOT / "lib/libl3owner/l3_owner.c").read_text(
        encoding="utf-8")
    frr = (ROOT / "sbin/rpd/frr_runtime.c").read_text(encoding="utf-8")
    port_state_sources = "\n".join(
        (ROOT / path).read_text(encoding="utf-8")
        for path in (
            "sbin/switchd/sdk_executor.c",
            "sbin/switchd/sdk_init.c",
            "sbin/switchd/read_back_verifier.c",
            "sbin/switchd/hal_packet.c",
            "sbin/switchd/hal_config.c",
            "sbin/switchd/hal_port.c",
        )
    )

    failed += check(
        "executor exposes bounded queues, latency metrics, and shutdown",
        all(token in hal + executor for token in (
            "SDK_EXEC_AGING_NS", "wait_p95_us", "exec_p95_us",
            "queue_high_watermark", "sdk_executor_stats_snapshot",
            "sdk_executor_shutdown")) and
        "for (int priority = SDK_PRIO_CONTROL_PACKET;" in executor and
        "CLOCK_MONOTONIC" in executor and "CLOCK_REALTIME" not in
        executor[executor.index("int sdk_exec_with_prio"):],
        executor,
    )
    failed += check(
        "switchd provides one coherent state/counter snapshot RPC",
        "SDK_OP_GET_PORT_SNAPSHOT" in hal and
        "NL_SWITCHD_PORT_SNAPSHOT_GET" in contracts and
        "msg->method == NL_SWITCHD_PORT_SNAPSHOT_GET" in rpc and
        "<port-snapshot" in rpc and 'counters=\\\"%s\\\"' in rpc,
        "missing SDK_OP_GET_PORT_SNAPSHOT, method 120 policy/dispatch, "
        "or snapshot XML contract",
    )
    failed += check(
        "slow sensor collection yields between individual SDK samples",
        "op.args.switch_sensors.count = 1" in rpc and
        "hal_get_switch_digital_sensors_range" in executor and
        "NETLAB_SWITCH_SENSOR_MAX; sensor++" in rpc,
        "switch sensor polling must not monopolize the SDK executor",
    )
    failed += check(
        "FM SDK port-state reads provide the implementation's eight slots",
        "NETLAB_PORT_STATE_INFO_SLOTS 8" in hal and
        "info[4]" not in port_state_sources and
        "fm_int state, info;" not in port_state_sources,
        "fmGetPortState writes eight entries in this frozen SDK release",
    )
    failed += check(
        "transitional FM port states remain unknown instead of hard down",
        "port_link_state_name" in rpc and
        'default:\n        return "unknown";' in rpc,
        "BIST, partially-up, and DFE tuning are transitional states",
    )
    failed += check(
        "ifd and statsd consume one bounded snapshot call",
        "NL_DAEMON_IFD, NL_DAEMON_SWITCHD" in ifd and
        "NL_SWITCHD_PORT_SNAPSHOT_GET" in ifd and
        "NL_DAEMON_STATSD, NL_DAEMON_SWITCHD" in statsd and
        "NL_SWITCHD_PORT_SNAPSHOT_GET" in statsd and
        "NL_SWITCHD_PORT_COUNTERS_GET" not in statsd and
        "collect_port_snapshot" in ifd,
        ifd + "\n--- statsd ---\n" + statsd,
    )
    failed += check(
        "slow cache owners use workers instead of daemon idle callbacks",
        ".on_idle" not in ifd and ".on_idle" not in l2d and
        ".on_idle" not in chassis and ".on_idle" not in rpd and
        all(token in ifd + l2d + chassis + rpd for token in (
            "ifd_refresh_main", "l2d_refresh_main",
            "chassisd_poll_main", "rpd_maintenance_main")),
        ifd + l2d + chassis + rpd,
    )
    failed += check(
        "configd post-commit L2 refresh waits for the cache worker",
        "if (msg->payload_len == 0)" in l2d and
        "if (!l2d_request_refresh(true))" in l2d and
        "configd_l2_refresh_cache();" in
        (ROOT / "sbin/configd/main.c").read_text(encoding="utf-8"),
        "successful commits must provide immediate read-your-writes to "
        "l2d show and clear RPCs",
    )
    append_start = frr.index("int rpd_frr_runtime_append_xml")
    append_body = frr[append_start:]
    failed += check(
        "rpd show formats cached FRR telemetry without vtysh execution",
        "rpd_frr_runtime_collect_observation" in frr and
        "rpd_frr_runtime_merge_observation" in frr and
        "refresh_vtysh_state(rt)" not in append_body and
        "<maintenance worker=" in rpd,
        append_body[:5000],
    )
    failed += check(
        "instanceable L3 owner caches its profile-backed resource model",
        "resource_model_lock" in l3_owner and
        "resource_model_cached" in l3_owner and
        "l3_resource_model_build_uncached" in l3_owner and
        "*model = owner->resource_model_cache" in l3_owner and
        "cacheable && model->profile_loaded" in l3_owner,
        "periodic rpd read-back must not reload the global interface "
        "resolver, while failed initial loads remain retryable",
    )
    failed += check(
        "port recovery exposes attempts and operator escalation",
        "sdk_port_recovery_stats_snapshot" in hal + executor + rpc and
        'full-pfe-escalation=\\\"operator-required\\\"' in
        (ROOT / "sbin/switchd/hal_sdk_runtime.c").read_text(
            encoding="utf-8"),
        "missing recovery metrics API or explicit operator escalation",
    )

    if failed:
        print(f"FAILED: {failed} control-plane responsiveness checks")
        return 1
    print("OK: control-plane responsiveness contracts passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
