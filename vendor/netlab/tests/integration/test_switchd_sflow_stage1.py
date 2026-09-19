#!/usr/bin/env python3.11
"""Build and run the switchd sFlow Stage1 ownership regression fixture."""

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VENDOR_ROOT = Path(os.environ.get("NETLAB_VENDOR_ROOT", "/opt/netlab-vendor"))
SDK_TREE = os.environ.get(
    "NETLAB_SDK_TREE",
    "IES_SDK-4.3.2-20160607_6ports_15032017_14i_LINK_OPT_EEE_VRM",
)
IES_SDK = Path(os.environ.get("IES_SDK", VENDOR_ROOT / SDK_TREE / "ies"))
SOURCE = ROOT / "tests" / "integration" / "switchd_sflow_stage1_test.c"
BINARY = ROOT / "build" / "switchd_sflow_stage1_test"
SDK_INIT = ROOT / "sbin" / "switchd" / "sdk_init.c"
SDK_EVENT_HANDLER = ROOT / "sbin" / "switchd" / "sdk_event_handler.c"
RPC_SERVER = ROOT / "sbin" / "switchd" / "rpc_server.c"


def check_source_routing() -> bool:
    sdk_init = SDK_INIT.read_text(encoding="utf-8")
    generic_events = SDK_EVENT_HANDLER.read_text(encoding="utf-8")
    rpc_server = RPC_SERVER.read_text(encoding="utf-8")

    handler_start = sdk_init.find("static void event_handler(")
    handler_end = sdk_init.find(
        "static bool inventory_has_port(", handler_start
    )
    if handler_start < 0 or handler_end < 0:
        print("FAIL: locate switchd SDK event handler")
        return False
    handler = sdk_init[handler_start:handler_end]

    route = handler.find("if (event == FM_EVENT_SFLOW_PKT_RECV)")
    generic_init = handler.find("init_sdk_event(&evt, event, sw)")
    if route < 0 or generic_init < 0 or route >= generic_init:
        print("FAIL: sFlow callback bypasses generic event initialization")
        return False
    fast_path = handler[route:generic_init]
    if (
        "sflow_capture_handle_event" not in fast_path
        or "return;" not in fast_path
        or "sdk_event_queue_push" in fast_path
    ):
        print("FAIL: sFlow callback has a dedicated terminal capture path")
        return False
    if "case FM_EVENT_SFLOW_PKT_RECV" in handler:
        print("FAIL: sFlow callback is absent from the generic switch path")
        return False
    sentinel = handler.find("sdk_event_barrier_handle")
    if sentinel < 0 or sentinel >= generic_init:
        print("FAIL: SDK software sentinel bypasses generic event publication")
        return False
    if "FM_EVENT_SFLOW_PKT_RECV" in generic_events:
        print("FAIL: sFlow callback is absent from the generic event queue")
        return False

    bringup_start = sdk_init.find("int sdk_bringup(")
    cleanup_start = sdk_init.find(
        "static int sdk_context_cleanup_resources(", bringup_start
    )
    shutdown_start = sdk_init.find("int sdk_shutdown(", cleanup_start)
    if bringup_start < 0 or cleanup_start < 0 or shutdown_start < 0:
        print("FAIL: locate switchd SDK lifecycle")
        return False
    bringup = sdk_init[bringup_start:cleanup_start]
    capture_init = bringup.find("sflow_capture_init()")
    sdk_initialize = bringup.find("fmInitialize(event_handler)")
    fifo_calls = []
    fifo_cursor = 0
    while True:
        fifo_cursor = bringup.find(
            "configure_event_delivery_properties()", fifo_cursor)
        if fifo_cursor < 0:
            break
        fifo_calls.append(fifo_cursor)
        fifo_cursor += 1
    fail_label = bringup.rfind("\nfail:")
    if (
        capture_init < 0
        or sdk_initialize < 0
        or fail_label < 0
        or capture_init >= sdk_initialize
        or len(fifo_calls) != 2
        or not (fifo_calls[0] < sdk_initialize < fifo_calls[1])
    ):
        print(
            "FAIL: packet FIFO is pinned around SDK property-file loading")
        return False
    if "return -1;" in bringup[capture_init:fail_label]:
        print("FAIL: acquired SDK resources bypass the common unwind path")
        return False
    if (
        "FM_AAK_API_PACKET_RX_DIRECT_ENQUEUEING" not in sdk_init
        or "observed != FALSE" not in sdk_init
        or "ctx->event_delivery_started = true" not in bringup
        or (
            bringup.find("ctx->event_delivery_started = true") >=
            fifo_calls[1]
        )
        or "cleanup_unproven = true;" not in bringup[
            bringup.find("st = fmOSInitialize()"):
            bringup.find("configure_mac_event_properties()")
        ]
        or "ctx->switch_state_touched = true" not in bringup
        or "ctx->switch_up = true" not in bringup
        or "ctx->raw_socket_started = true" not in bringup
        or "goto fail;" not in bringup
        or "sdk_context_cleanup_resources(ctx)" not in bringup
        or (
            "if (ctx->raw_socket_started)\n"
            "        cleanup_unproven = true;" not in bringup
        )
    ):
        print("FAIL: SDK bringup records and unwinds each owned resource")
        return False

    cleanup = sdk_init[cleanup_start:shutdown_start]
    executor_shutdown = cleanup.find("sdk_executor_shutdown")
    capture_shutdown_begin = cleanup.find(
        "sflow_capture_shutdown_begin()")
    event_barrier = cleanup.find("sdk_event_barrier_drain")
    capture_shutdown_wait = cleanup.find(
        "sflow_capture_shutdown_wait()")
    event_stop = cleanup.find("sdk_event_barrier_stop()")
    raw_socket_destroy = cleanup.find("fmRawPacketSocketDestroy")
    switch_down = cleanup.find("fmSetSwitchState(ctx->sw, FALSE)")
    if (
        executor_shutdown < 0
        or capture_shutdown_begin < 0
        or event_barrier < 0
        or capture_shutdown_wait < 0
        or event_stop < 0
        or raw_socket_destroy < 0
        or switch_down < 0
        or not (
            executor_shutdown < capture_shutdown_begin <
            event_barrier < capture_shutdown_wait <
            event_stop < raw_socket_destroy < switch_down
        )
        or "if (!ctx->initialized)" in cleanup
        or "sflow_capture_shutdown_cancel()" not in cleanup
        or "ctx->switch_state_touched" not in cleanup
        or "sdk_event_barrier_drain(ctx->sw, ctx->switch_up)" not in cleanup
    ):
        print(
            "FAIL: sFlow shutdown crosses the SDK FIFO barrier and exact-free "
            "capture barrier before milestone-owned teardown"
        )
        return False

    parser_start = rpc_server.find(
        "static bool parse_sflow_live_probe_payload(")
    parser_end = rpc_server.find(
        "static bool parse_payload_int_range(", parser_start)
    if parser_start < 0 or parser_end < 0:
        print("FAIL: locate strict sFlow live-probe payload parser")
        return False
    parser = rpc_server[parser_start:parser_end]
    if (
        '"ack=" NL_SFLOW_V1_PROBE_ACK "\\nport="' not in parser
        or "memcmp(payload, prefix" not in parser
        or "end[-1] != '\\n'" not in parser
        or "strstr(" in parser
    ):
        print("FAIL: sFlow probe requires the exact canonical ack payload")
        return False

    dispatch_start = rpc_server.find(
        "if (msg->method == NL_SWITCHD_SFLOW_LIVE_PROBE)")
    dispatch_end = rpc_server.find(
        "if (msg->method == NL_SWITCHD_L3_RIF_LIVE_PROBE)",
        dispatch_start,
    )
    if dispatch_start < 0 or dispatch_end < 0:
        print("FAIL: locate sFlow live-probe RPC dispatch")
        return False
    dispatch = rpc_server[dispatch_start:dispatch_end]
    if (
        "op.args.sflow_probe.tx_id = msg->tx_id" not in dispatch
        or 'tx-id=\\"%llu\\"' not in dispatch
    ):
        print("FAIL: sFlow probe preserves its required transaction identity")
        return False

    print("PASS: sFlow callback bypasses generic events with lifecycle hooks")
    return True


def main() -> int:
    include_dirs = [
        ROOT / "include",
        IES_SDK / "include",
        IES_SDK / "include" / "platforms",
        IES_SDK / "include" / "alos",
        IES_SDK / "include" / "alos" / "linux",
        IES_SDK / "include" / "common",
        IES_SDK / "include" / "api",
        IES_SDK / "include" / "std" / "intel",
        IES_SDK / "include" / "platforms" / "libertyTrail",
        IES_SDK / "include" / "platforms" / "common",
        IES_SDK / "include" / "platforms" / "util" / "boardManager",
    ]
    if not IES_SDK.is_dir():
        print(f"FAIL: SDK include tree is missing: {IES_SDK}")
        return 1
    if not check_source_routing():
        return 1

    BINARY.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "cc",
        "-std=c99",
        "-D_GNU_SOURCE",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-ffunction-sections",
        "-Wl,--gc-sections",
    ]
    for include_dir in include_dirs:
        command.extend(("-I", str(include_dir)))
    command.extend(("-o", str(BINARY), str(SOURCE)))

    build = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if build.returncode != 0:
        print("FAIL: switchd sFlow Stage1 fixture builds")
        print(build.stdout)
        return 1
    print("PASS: switchd sFlow Stage1 fixture builds")

    run = subprocess.run(
        [str(BINARY)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    print(run.stdout, end="")
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())
