#!/usr/bin/env python3.11
"""Keep public persistent L3 and dynamic RIB capacities explicit."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
YANG = ROOT / "include" / "netlab" / "netlab.yang"


def check(name: str, condition: bool, detail: str = "") -> int:
    print(("PASS" if condition else "FAIL") + f": {name}")
    if not condition and detail:
        print(detail)
    return 0 if condition else 1


def yanglint_path() -> str | None:
    return shutil.which("yanglint")


def validate(binary: str, xml: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory(prefix="netlab-l3-capacity-") as td:
        data = Path(td) / "config.xml"
        data.write_text(xml, encoding="utf-8")
        proc = subprocess.run(
            [binary, "-t", "data", str(YANG), str(data)],
            cwd=ROOT,
            env=os.environ.copy(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        return proc.returncode, proc.stdout


def wrap(body: str) -> str:
    return ("<netlab-config xmlns=\"urn:netlab:config\">" + body +
            "</netlab-config>")


def route_with_nexthops(count: int) -> str:
    nexthops = "".join(
        f"<next-hop-address>192.0.2.{index}</next-hop-address>"
        for index in range(1, count + 1)
    )
    return wrap(
        "<routing-options><static><route>"
        "<prefix>203.0.113.0/24</prefix>" + nexthops +
        "</route></static></routing-options>"
    )


def routed_interfaces(count: int) -> str:
    entries = "".join(
        "<interface>"
        f"<name>irb.{index + 1}</name>"
        f"<address>10.{index // 256}.{index % 256}.1/24</address>"
        "</interface>"
        for index in range(count)
    )
    return wrap("<interfaces-routing>" + entries + "</interfaces-routing>")


def static_routes(count: int) -> str:
    entries = "".join(
        "<route>"
        f"<prefix>10.{index // 256}.{index % 256}.0/24</prefix>"
        "<next-hop-id>1</next-hop-id>"
        "</route>"
        for index in range(count)
    )
    return wrap("<routing-options><static>" + entries +
                "</static></routing-options>")


def split_scope_arps(global_count: int, vrf_count: int) -> str:
    def entries(start: int, count: int) -> str:
        return "".join(
            "<arp>"
            f"<ip>10.{index // 256}.{index % 256}.2</ip>"
            "<mac>02:00:00:00:00:01</mac><interface>irb.1</interface>"
            "</arp>"
            for index in range(start, start + count)
        )

    return wrap(
        "<routing-options><static>" + entries(0, global_count) +
        "</static></routing-options>"
        "<routing-instances><instance><name>blue</name>"
        "<instance-type>vrf</instance-type><routing-options><static>" +
        entries(global_count, vrf_count) +
        "</static></routing-options></instance></routing-instances>"
    )


def main() -> int:
    failed = 0
    yang = YANG.read_text(encoding="utf-8")
    configd = (ROOT / "sbin" / "configd" / "l3_client.c").read_text()
    switchd = (ROOT / "sbin" / "switchd" /
               "l3_plan_parser.c").read_text()
    hal = (ROOT / "sbin" / "switchd" / "hal_l3.c").read_text()
    capacity = (ROOT / "include" / "netlab" /
                "l3_capacity.h").read_text()
    rib_h = (ROOT / "sbin" / "rpd" / "rib.h").read_text()
    rib_c = (ROOT / "sbin" / "rpd" / "rib.c").read_text()
    rpd_main = (ROOT / "sbin" / "rpd" / "main.c").read_text()
    fpm_h = (ROOT / "sbin" / "rpd" / "fpm.h").read_text()

    failed += check(
        "public persistent capacities match the switchd owner",
        all(token in yang for token in (
            "max-elements 64;", "max-elements 256;",
            "max-elements 128;", "max-elements 32;",
            "max-elements 1024;", "max-elements 16;",
            "persistent L3 ARP entries across inet.0 and VRF V1",
            "persistent L3 routes across inet.0 and VRF V1",
        )) and
        all(token in capacity for token in (
            "NL_L3_PERSISTENT_MAX_RIFS 64",
            "NL_L3_PERSISTENT_MAX_ARP 256",
            "NL_L3_PERSISTENT_MAX_NEXTHOPS 256",
            "NL_L3_PERSISTENT_MAX_ECMP 128",
            "NL_L3_PERSISTENT_MAX_ROUTES 1024",
            "NL_L3_PERSISTENT_MAX_ECMP_MEMBERS 32",
        )) and
        all(token in configd and token in switchd and token in hal
            for token in (
                "NL_L3_PERSISTENT_MAX_RIFS",
                "NL_L3_PERSISTENT_MAX_ARP",
                "NL_L3_PERSISTENT_MAX_NEXTHOPS",
                "NL_L3_PERSISTENT_MAX_ECMP",
                "NL_L3_PERSISTENT_MAX_ROUTES",
                "NL_L3_PERSISTENT_MAX_ECMP_MEMBERS",
            )) and
        not any(token in configd + switchd + hal for token in (
            "#define L3_PERSISTENT_MAX_",
            "#define L3_TX_MAX_",
            "#define HAL_L3_PERSISTENT_MAX_RIFS",
            "#define HAL_L3_PERSISTENT_MAX_ARP",
            "#define HAL_L3_PERSISTENT_MAX_NEXTHOPS",
            "#define HAL_L3_PERSISTENT_MAX_ECMP ",
            "#define HAL_L3_PERSISTENT_MAX_ROUTES",
        )),
    )
    failed += check(
        "dynamic RIB capacity remains explicit and fail closed",
        all(token in rib_h for token in (
            "RPD_RIB_MAX_ROUTES 4096", "RPD_RIB_MAX_ARP 1024",
            "RPD_RIB_MAX_NEXTHOPS 16",
        )) and
        all(token in capacity for token in (
            "NL_L3_DYNAMIC_MAX_ROUTES 4096",
            "NL_L3_DYNAMIC_MAX_NEXTHOPS 16",
            "NL_L3_DYNAMIC_MAX_UNIQUE_NEXTHOPS",
        )) and
        all(token in switchd and token in hal for token in (
            "NL_L3_DYNAMIC_MAX_ROUTES",
            "NL_L3_DYNAMIC_MAX_NEXTHOPS",
        )) and
        "RIB route capacity exceeded" in rib_c and
        "too many nexthops" in rib_c,
    )
    failed += check(
        "RPD FPM capacities use the shared L3 owner contract",
        "#define RPD_FPM_RIF_MAP_MAX NL_L3_PERSISTENT_MAX_RIFS" in
        rpd_main and
        "RPD_FPM_RIF_MAP_TEXT_MAX" in rpd_main and
        "char buf[512]" not in rpd_main and
        "#define RPD_FPM_NH_CACHE_MAX "
        "NL_L3_DYNAMIC_MAX_UNIQUE_NEXTHOPS" in fpm_h and
        "#define RPD_FPM_NH_CACHE_MAX 256" not in fpm_h,
    )

    binary = yanglint_path()
    if not binary:
        print("SKIP: yanglint unavailable")
        return 1 if failed else 0
    rc, out = validate(binary, route_with_nexthops(16))
    failed += check("16 static route nexthops validate", rc == 0, out)
    rc, out = validate(binary, route_with_nexthops(17))
    failed += check("17 static route nexthops reject explicitly", rc != 0,
                    out)
    rc, out = validate(binary, routed_interfaces(65))
    failed += check("65th routed interface rejects explicitly", rc != 0,
                    out)
    rc, out = validate(binary, static_routes(1025))
    failed += check("1025th persistent route rejects explicitly", rc != 0,
                    out)
    rc, out = validate(binary, split_scope_arps(129, 128))
    failed += check("257th cross-scope ARP rejects explicitly", rc != 0,
                    out)

    if failed:
        print(f"FAILED: {failed} L3 capacity checks failed")
    else:
        print("OK: L3 capacity contracts are explicit")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
