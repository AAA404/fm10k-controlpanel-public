#!/usr/bin/env python3.11
"""Keep the switchd RPD FIB transaction metadata out of fixed BSS."""

import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "sbin" / "switchd" / "l3_plan_parser.c"
MAX_STACK_FRAME_BYTES = 131_072


def check(name: str, condition: bool, detail: str = "") -> int:
    print(("PASS" if condition else "FAIL") + f": {name}")
    if not condition and detail:
        print(detail)
    return 0 if condition else 1


def symbol_sizes(obj: Path) -> dict[str, int]:
    result = subprocess.run(
        ["nm", "-S", "--defined-only", str(obj)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout)
    sizes: dict[str, int] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 4:
            sizes[fields[3]] = int(fields[1], 16)
    return sizes


def stack_frames(path: Path) -> dict[str, int]:
    frames: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        location = fields[0]
        try:
            size = int(fields[1])
        except ValueError:
            continue
        function = location.rsplit(":", 1)[-1]
        frames[function] = size
    return frames


def main() -> int:
    failed = 0
    with tempfile.TemporaryDirectory(prefix="netlab-l3-owner-") as tmp:
        obj = Path(tmp) / "l3_plan_parser.o"
        stack_usage = obj.with_suffix(".su")
        build = subprocess.run(
            [
                "cc", "-std=c99", "-D_GNU_SOURCE", "-Wall", "-Wextra",
                "-Werror", f"-Wframe-larger-than={MAX_STACK_FRAME_BYTES}",
                "-fstack-usage", "-Iinclude", "-c", str(SOURCE),
                "-o", str(obj),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        failed += check("L3 owner storage probe builds",
                        build.returncode == 0, build.stdout)
        if build.returncode != 0:
            return 1
        try:
            sizes = symbol_sizes(obj)
        except RuntimeError as exc:
            return check("L3 owner storage symbols are readable", False,
                         str(exc))

        owner_size = sizes.get("g_l3_fib_owner", -1)
        snapshot_size = sizes.get("g_l3_fib_snapshot", -1)
        tx_owner_size = sizes.get("g_l3_tx_owner", -1)
        failed += check(
            "RPD FIB owner keeps only pointer-sized transaction metadata",
            0 < owner_size <= 128,
            f"g_l3_fib_owner={owner_size} bytes",
        )
        failed += check(
            "typed snapshot staging keeps payloads on the heap",
            0 < snapshot_size <= 512,
            f"g_l3_fib_snapshot={snapshot_size} bytes",
        )
        failed += check(
            "persistent transaction owner keeps current/pre on the heap",
            0 < tx_owner_size <= 128,
            f"g_l3_tx_owner={tx_owner_size} bytes",
        )
        failed += check(
            "all parser L3 owner metadata stays below 1 KiB",
            owner_size > 0 and snapshot_size > 0 and tx_owner_size > 0 and
            owner_size + snapshot_size + tx_owner_size <= 1024,
            f"combined={owner_size + snapshot_size + tx_owner_size} bytes",
        )
        frames = stack_frames(stack_usage)
        largest_name, largest_size = max(frames.items(), key=lambda item: item[1])
        failed += check(
            "all L3 parser stack frames stay below the bounded budget",
            largest_size <= MAX_STACK_FRAME_BYTES,
            f"largest={largest_name}:{largest_size} bytes; "
            f"limit={MAX_STACK_FRAME_BYTES} bytes",
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
