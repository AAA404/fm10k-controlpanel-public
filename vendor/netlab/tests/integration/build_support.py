"""Portable compiler and runtime flags for public integration fixtures."""
from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path


def libyang_flags() -> tuple[list[str], list[str], Path | None]:
    """Return libyang 2.x compiler/linker flags without host-specific paths."""
    prefix_value = os.environ.get("NETLAB_LIBYANG_PREFIX")
    if prefix_value:
        prefix = Path(prefix_value)
        include_dir = prefix / "include"
        library_dir = prefix / "lib64"
        if not library_dir.is_dir():
            library_dir = prefix / "lib"
        header = include_dir / "libyang" / "libyang.h"
        if not header.is_file() or not library_dir.is_dir():
            raise RuntimeError(
                f"invalid NETLAB_LIBYANG_PREFIX: {prefix}"
            )
        return (["-I", str(include_dir)],
                ["-L", str(library_dir), "-lyang"], library_dir)

    exists = subprocess.run(
        ["pkg-config", "--exists", "libyang >= 2.0"], check=False
    )
    if exists.returncode != 0:
        raise RuntimeError(
            "libyang >= 2.0 is unavailable; install libyang2-dev or set "
            "NETLAB_LIBYANG_PREFIX"
        )

    def query(option: str) -> list[str]:
        result = subprocess.run(
            ["pkg-config", option, "libyang"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "pkg-config failed")
        return shlex.split(result.stdout)

    return query("--cflags"), query("--libs"), None


def runtime_environment(library_dir: Path | None) -> dict[str, str]:
    environment = {**os.environ, "LC_ALL": "C"}
    if library_dir is not None:
        previous = environment.get("LD_LIBRARY_PATH")
        environment["LD_LIBRARY_PATH"] = (
            str(library_dir) + (":" + previous if previous else "")
        )
    return environment
