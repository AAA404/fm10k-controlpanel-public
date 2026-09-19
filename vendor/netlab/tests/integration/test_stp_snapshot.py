#!/usr/bin/env python3.11
"""Versioned, paged STP snapshot boundary and drift tests."""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


C_TEST = r'''
#include "netlab/stp_snapshot.h"
#include "netlab/ipc.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int make_snapshot(uint32_t count, nl_stp_snapshot *snapshot) {
    if (!snapshot || count > NL_STP_SNAPSHOT_MAX_ENTRIES)
        return -1;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->entries = calloc(count ? count : 1U,
                               sizeof(*snapshot->entries));
    if (!snapshot->entries)
        return -1;
    snapshot->n_entries = count;
    snapshot->total_entries = count;
    for (uint32_t i = 0; i < count; i++) {
        snapshot->entries[i].vlan = (uint16_t)(i / 24U + 1U);
        snapshot->entries[i].port = (uint16_t)(i % 24U + 1U);
        snapshot->entries[i].state = (uint8_t)(i % 5U);
    }
    return nl_stp_snapshot_finalize(snapshot);
}

static int roundtrip(uint32_t count) {
    nl_stp_snapshot source = {0};
    nl_stp_snapshot assembled = {0};
    unsigned char *wire = malloc(NETLAB_MAX_MSG);
    uint32_t offset = 0;
    unsigned int pages = 0;
    int rc = 10;

    if (!wire || make_snapshot(count, &source) != 0)
        goto done;
    do {
        nl_stp_snapshot_page page = {0};
        int encoded = nl_stp_snapshot_page_encode(
            &source, offset, wire, NETLAB_MAX_MSG);

        if (encoded <= 0 ||
            nl_stp_snapshot_page_decode(wire, (size_t)encoded, &page) != 0 ||
            page.offset != offset ||
            nl_stp_snapshot_append_page(&assembled, &page) != 0) {
            nl_stp_snapshot_page_reset(&page);
            goto done;
        }
        offset = page.next_offset;
        pages++;
        nl_stp_snapshot_page_reset(&page);
    } while (!assembled.complete);
    if (assembled.n_entries != count || assembled.total_entries != count ||
        assembled.generation != source.generation ||
        (count > 0 &&
         (!nl_stp_snapshot_has_member(&assembled, 1, 1) ||
          !nl_stp_snapshot_has_member(
              &assembled, (int)((count - 1U) / 24U + 1U),
              (int)((count - 1U) % 24U + 1U)))))
        goto done;
    if ((count <= NL_STP_SNAPSHOT_PAGE_ENTRIES && pages != 1U) ||
        (count == NL_STP_SNAPSHOT_MAX_ENTRIES && pages != 3U))
        goto done;
    rc = 0;

done:
    free(wire);
    nl_stp_snapshot_reset(&source);
    nl_stp_snapshot_reset(&assembled);
    return rc;
}

static int malformed_tests(void) {
    nl_stp_snapshot source = {0};
    nl_stp_snapshot duplicate = {0};
    nl_stp_snapshot_page page = {0};
    nl_stp_snapshot_page_request request = {0};
    nl_stp_snapshot_page_request decoded_request = {0};
    unsigned char *wire = malloc(NETLAB_MAX_MSG);
    unsigned char request_wire[20];
    int encoded;
    int rc = 20;

    if (!wire || make_snapshot(257, &source) != 0)
        goto done;
    request.generation = 0;
    request.offset = 0;
    if (nl_stp_snapshot_page_request_encode(
            &request, request_wire, sizeof(request_wire)) != 20 ||
        nl_stp_snapshot_page_request_decode(
            request_wire, sizeof(request_wire), &decoded_request) != 0 ||
        decoded_request.generation != 0 || decoded_request.offset != 0)
        goto done;
    request.generation = source.generation;
    request.offset = 0;
    if (nl_stp_snapshot_page_request_encode(
            &request, request_wire, sizeof(request_wire)) >= 0)
        goto done;
    request.offset = 1;
    if (nl_stp_snapshot_page_request_encode(
            &request, request_wire, sizeof(request_wire)) != 20)
        goto done;

    encoded = nl_stp_snapshot_page_encode(
        &source, 0, wire, NETLAB_MAX_MSG);
    if (encoded <= 0 ||
        nl_stp_snapshot_page_decode(wire, (size_t)encoded - 1U, &page) == 0)
        goto done;
    ((unsigned char *)wire)[0] ^= 0xffU;
    if (nl_stp_snapshot_page_decode(wire, (size_t)encoded, &page) == 0)
        goto done;

    duplicate.entries = calloc(2, sizeof(*duplicate.entries));
    if (!duplicate.entries)
        goto done;
    duplicate.n_entries = duplicate.total_entries = 2;
    duplicate.entries[0].vlan = duplicate.entries[1].vlan = 1;
    duplicate.entries[0].port = duplicate.entries[1].port = 1;
    duplicate.entries[0].state = duplicate.entries[1].state = 3;
    if (nl_stp_snapshot_finalize(&duplicate) == 0 || duplicate.complete ||
        duplicate.generation != 0)
        goto done;
    rc = 0;

done:
    nl_stp_snapshot_page_reset(&page);
    nl_stp_snapshot_reset(&source);
    nl_stp_snapshot_reset(&duplicate);
    free(wire);
    return rc;
}

static int drift_test(void) {
    const uint32_t count = NL_STP_SNAPSHOT_PAGE_ENTRIES + 1U;
    nl_stp_snapshot first = {0};
    nl_stp_snapshot changed = {0};
    nl_stp_snapshot assembled = {0};
    nl_stp_snapshot_page page = {0};
    unsigned char *wire = malloc(NETLAB_MAX_MSG);
    int encoded;
    int rc = 30;

    if (!wire || make_snapshot(count, &first) != 0 ||
        make_snapshot(count, &changed) != 0)
        goto done;
    changed.entries[count - 1U].state =
        (uint8_t)((changed.entries[count - 1U].state + 1U) % 5U);
    if (nl_stp_snapshot_finalize(&changed) != 0 ||
        changed.generation == first.generation)
        goto done;
    encoded = nl_stp_snapshot_page_encode(
        &first, 0, wire, NETLAB_MAX_MSG);
    if (encoded <= 0 ||
        nl_stp_snapshot_page_decode(wire, (size_t)encoded, &page) != 0 ||
        nl_stp_snapshot_append_page(&assembled, &page) != 0)
        goto done;
    nl_stp_snapshot_page_reset(&page);
    encoded = nl_stp_snapshot_page_encode(
        &changed, NL_STP_SNAPSHOT_PAGE_ENTRIES, wire, NETLAB_MAX_MSG);
    if (encoded <= 0 ||
        nl_stp_snapshot_page_decode(wire, (size_t)encoded, &page) != 0 ||
        nl_stp_snapshot_append_page(&assembled, &page) == 0 ||
        assembled.complete)
        goto done;
    rc = 0;

done:
    nl_stp_snapshot_page_reset(&page);
    nl_stp_snapshot_reset(&first);
    nl_stp_snapshot_reset(&changed);
    nl_stp_snapshot_reset(&assembled);
    free(wire);
    return rc;
}

int main(void) {
    static const uint32_t counts[] = {
        0, 255, 256, 257, 2048, NL_STP_SNAPSHOT_MAX_ENTRIES
    };

    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        int rc = roundtrip(counts[i]);
        if (rc != 0)
            return rc;
    }
    if (malformed_tests() != 0)
        return 20;
    if (drift_test() != 0)
        return 30;
    return 0;
}
'''


C_HAL_TEST = r'''
#include "netlab/hal.h"

#include <fm_sdk.h>
#include <api/fm_api_vlan.h>
#include <stdint.h>
#include <string.h>

static uint32_t g_count;
static uint32_t g_ports_per_vlan = 24;
static int64_t g_fail_index = -1;
static int g_hidden_port;

bool nl_ifid_is_user_port(int logical_port) {
    return logical_port > 0 && logical_port != g_hidden_port;
}

static uint32_t vlan_count(void) {
    return g_count == 0 ? 0 :
        (g_count + g_ports_per_vlan - 1U) / g_ports_per_vlan;
}

static uint32_t ports_in_vlan(uint32_t vlan) {
    uint32_t first = (vlan - 1U) * g_ports_per_vlan;
    uint32_t remaining = g_count - first;
    return remaining < g_ports_per_vlan ? remaining : g_ports_per_vlan;
}

fm_status fmGetVlanFirst(fm_int sw, fm_int *first_id) {
    (void)sw;
    *first_id = g_count ? 1 : 0;
    return FM_OK;
}

fm_status fmGetVlanNext(fm_int sw, fm_int start_id, fm_int *next_id) {
    (void)sw;
    *next_id = (uint32_t)start_id < vlan_count() ? start_id + 1 : 0;
    return FM_OK;
}

fm_status fmGetVlanPortFirst(fm_int sw, fm_int vlan_id,
                             fm_int *first_port) {
    (void)sw;
    if (vlan_id < 1 || (uint32_t)vlan_id > vlan_count())
        return FM_ERR_INVALID_VLAN;
    *first_port = 1;
    return FM_OK;
}

fm_status fmGetVlanPortNext(fm_int sw, fm_int vlan_id,
                            fm_int start_port, fm_int *next_port) {
    (void)sw;
    *next_port = (uint32_t)start_port < ports_in_vlan((uint32_t)vlan_id) ?
        start_port + 1 : 0;
    return FM_OK;
}

fm_status fmGetVlanPortState(fm_int sw, fm_uint16 vlan_id,
                             fm_int port, fm_int *state) {
    uint32_t index;
    (void)sw;
    index = ((uint32_t)vlan_id - 1U) * g_ports_per_vlan +
        (uint32_t)port - 1U;
    if ((int64_t)index == g_fail_index)
        return FM_ERR_INVALID_PORT;
    *state = (fm_int)(index % 5U);
    return FM_OK;
}

static int run_count(uint32_t count) {
    struct sdk_result result;
    int rc;

    memset(&result, 0, sizeof(result));
    g_count = count;
    g_ports_per_vlan = 24;
    g_fail_index = -1;
    g_hidden_port = 0;
    rc = hal_get_stp_table(0, &result);
    if (rc != 0 || !result.data.stp_table.complete ||
        result.data.stp_table.n_entries != count ||
        result.data.stp_table.total_entries != count)
        return 40;
    if (count > 0 &&
        (result.data.stp_table.entries[count - 1U].vlan !=
             (uint16_t)((count - 1U) / 24U + 1U) ||
         result.data.stp_table.entries[count - 1U].port !=
             (uint16_t)((count - 1U) % 24U + 1U)))
        return 41;
    nl_stp_snapshot_reset(&result.data.stp_table);
    return 0;
}

int main(void) {
    static const uint32_t counts[] = {
        0, 255, 256, 257, 2048, NL_STP_SNAPSHOT_MAX_ENTRIES
    };
    struct sdk_result result;

    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
        int rc = run_count(counts[i]);
        if (rc != 0)
            return rc;
    }

    memset(&result, 0, sizeof(result));
    g_count = 257;
    g_ports_per_vlan = 24;
    g_fail_index = 256;
    if (hal_get_stp_table(0, &result) == 0 ||
        result.data.stp_table.complete ||
        result.data.stp_table.entries != NULL)
        return 42;

    memset(&result, 0, sizeof(result));
    g_count = 25;
    g_ports_per_vlan = 25;
    g_fail_index = -1;
    g_hidden_port = 25;
    if (hal_get_stp_table(0, &result) != 0 ||
        !result.data.stp_table.complete ||
        result.data.stp_table.n_entries != 24)
        return 43;
    nl_stp_snapshot_reset(&result.data.stp_table);

    memset(&result, 0, sizeof(result));
    g_hidden_port = 0;
    if (hal_get_stp_table(0, &result) == 0 ||
        result.data.stp_table.complete ||
        result.data.stp_table.entries != NULL)
        return 44;
    return 0;
}
'''


C_CLIENT_TEST = r'''
#include "stp_switchd.h"
#include "netlab/ipc.h"

#include <stdlib.h>
#include <string.h>

static nl_stp_snapshot g_source;
static nl_stp_snapshot g_changed;
static int g_pages;
static int g_drift;

static int make_snapshot(nl_stp_snapshot *snapshot) {
    const uint32_t count = NL_STP_SNAPSHOT_MAX_ENTRIES;

    snapshot->entries = calloc(count, sizeof(*snapshot->entries));
    if (!snapshot->entries)
        return -1;
    snapshot->n_entries = snapshot->total_entries = count;
    for (uint32_t i = 0; i < count; i++) {
        snapshot->entries[i].vlan = (uint16_t)(i / 24U + 1U);
        snapshot->entries[i].port = (uint16_t)(i % 24U + 1U);
        snapshot->entries[i].state = (uint8_t)(i % 5U);
    }
    return nl_stp_snapshot_finalize(snapshot);
}

int nl_rpc_call_alloc_ex(const char *socket_path, nl_daemon_id caller,
                         nl_daemon_id service, nl_rpc_method method,
                         u64 tx_id, const u8 *payload, int payload_len,
                         int timeout_ms, nl_rpc_response *response) {
    nl_stp_snapshot_page_request request = {0};
    const nl_stp_snapshot *selected;
    int encoded;

    (void)tx_id;
    if (!socket_path || caller != NL_DAEMON_STPD ||
        service != NL_DAEMON_SWITCHD ||
        method != NL_SWITCHD_STP_SNAPSHOT_PAGE_GET || timeout_ms <= 0 ||
        nl_stp_snapshot_page_request_decode(
            payload, (size_t)payload_len, &request) != 0)
        return -1;
    selected = g_drift && request.offset > 0 ? &g_changed : &g_source;
    response->payload = malloc(NETLAB_MAX_MSG);
    if (!response->payload)
        return -1;
    encoded = nl_stp_snapshot_page_encode(
        selected, request.offset, response->payload, NETLAB_MAX_MSG);
    if (encoded <= 0) {
        free(response->payload);
        memset(response, 0, sizeof(*response));
        return -1;
    }
    response->payload_len = (u32)encoded;
    response->error_code = 0;
    g_pages++;
    return encoded;
}

void nl_rpc_response_free(nl_rpc_response *response) {
    if (!response)
        return;
    free(response->payload);
    memset(response, 0, sizeof(*response));
}

int main(void) {
    int vlans[NL_STP_SNAPSHOT_MAX_VLANS];
    int rc;

    if (make_snapshot(&g_source) != 0 || make_snapshot(&g_changed) != 0)
        return 50;
    g_changed.entries[g_changed.n_entries - 1U].state =
        (uint8_t)((g_changed.entries[g_changed.n_entries - 1U].state + 1U) %
                  5U);
    if (nl_stp_snapshot_finalize(&g_changed) != 0 ||
        g_changed.generation == g_source.generation)
        return 51;

    g_pages = 0;
    rc = stp_switchd_collect_hardware_port_vlans(
        "/mock/switchd.sock", 24, vlans, NL_STP_SNAPSHOT_MAX_VLANS);
    if (rc != (int)NL_STP_SNAPSHOT_MAX_VLANS || g_pages != 3 ||
        vlans[0] != 1 ||
        vlans[NL_STP_SNAPSHOT_MAX_VLANS - 1U] != 4094)
        return 52;

    g_pages = 0;
    rc = stp_switchd_collect_hardware_port_vlans(
        "/mock/switchd.sock", 24, vlans, 256);
    if (rc != -1 || g_pages != 3)
        return 53;

    g_pages = 0;
    g_drift = 1;
    rc = stp_switchd_collect_hardware_port_vlans(
        "/mock/switchd.sock", 24, vlans, NL_STP_SNAPSHOT_MAX_VLANS);
    if (rc != -1 || g_pages != 2)
        return 54;

    nl_stp_snapshot_reset(&g_source);
    nl_stp_snapshot_reset(&g_changed);
    return 0;
}
'''


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="netlab-stp-snapshot-") as td:
        binary = Path(td) / "stp-snapshot-test"
        compiled = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                "-ffunction-sections", "-fdata-sections",
                "-Wl,--gc-sections", "-D_GNU_SOURCE",
                "-I", str(ROOT / "include"),
                "-x", "c", "-",
                str(ROOT / "lib" / "libipc" / "stp_snapshot.c"),
                "-o", str(binary),
            ],
            input=C_TEST,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=ROOT,
            env={**os.environ, "LC_ALL": "C"},
            check=False,
        )
        if compiled.returncode != 0:
            print(compiled.stdout)
            return 1
        ran = subprocess.run(
            [str(binary)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, check=False,
        )
        if ran.returncode != 0:
            print(ran.stdout)
            print(f"STP snapshot fixture failed rc={ran.returncode}")
            return 1
        ies = (Path("/opt/netlab-vendor") /
               "IES_SDK-4.3.2-20160607_6ports_15032017_14i_LINK_OPT_EEE_VRM" /
               "ies")
        hal_binary = Path(td) / "stp-hal-test"
        include_dirs = [
            ies / "include", ies / "include/platforms",
            ies / "include/alos", ies / "include/alos/linux",
            ies / "include/common", ies / "include/api",
            ies / "include/std/intel",
            ies / "include/platforms/libertyTrail",
            ies / "include/platforms/common",
            ies / "include/platforms/util/boardManager",
        ]
        hal_compiled = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                "-ffunction-sections", "-fdata-sections",
                "-Wl,--gc-sections", "-D_GNU_SOURCE",
                "-I", str(ROOT / "include"),
                *[item for path in include_dirs for item in ("-I", str(path))],
                "-x", "c", "-",
                str(ROOT / "sbin" / "switchd" / "hal_vlan.c"),
                str(ROOT / "lib" / "libipc" / "stp_snapshot.c"),
                "-o", str(hal_binary),
            ],
            input=C_HAL_TEST,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=ROOT,
            env={**os.environ, "LC_ALL": "C"},
            check=False,
        )
        if hal_compiled.returncode != 0:
            print(hal_compiled.stdout)
            return 1
        hal_ran = subprocess.run(
            [str(hal_binary)], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, check=False,
        )
        if hal_ran.returncode != 0:
            print(hal_ran.stdout)
            print(f"STP HAL fixture failed rc={hal_ran.returncode}")
            return 1
        client_binary = Path(td) / "stp-client-test"
        client_compiled = subprocess.run(
            [
                "gcc", "-std=c11", "-Wall", "-Werror", "-Wextra",
                "-ffunction-sections", "-fdata-sections",
                "-Wl,--gc-sections", "-D_GNU_SOURCE",
                "-I", str(ROOT / "include"),
                "-I", str(ROOT / "sbin" / "stpd"),
                "-x", "c", "-",
                str(ROOT / "sbin" / "stpd" / "stp_switchd.c"),
                str(ROOT / "lib" / "libipc" / "stp_snapshot.c"),
                "-o", str(client_binary),
            ],
            input=C_CLIENT_TEST,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=ROOT,
            env={**os.environ, "LC_ALL": "C"},
            check=False,
        )
        if client_compiled.returncode != 0:
            print(client_compiled.stdout)
            return 1
        client_ran = subprocess.run(
            [str(client_binary)], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, check=False,
        )
        if client_ran.returncode != 0:
            print(client_ran.stdout)
            print(f"STP client fixture failed rc={client_ran.returncode}")
            return 1
    print("OK: STP snapshot is exact through 4094 VLAN x 24 ports")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
