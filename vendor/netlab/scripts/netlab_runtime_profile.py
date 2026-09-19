"""Runtime platform profile helpers for operator scripts."""
import os
from pathlib import Path


def default_profile_path(root=None):
    env = os.environ.get("NETLAB_PLATFORM_PROFILE")
    if env:
        return Path(env)

    root_path = Path(root) if root is not None else Path(
        os.environ.get("NETLAB_ROOT", Path(__file__).resolve().parents[1]))
    for path in (
        Path("/var/lib/netlab/platform.profile"),
        Path("/etc/netlab/platform.profile"),
        root_path / "config" / "platform" / "default.profile",
    ):
        if path.exists():
            return path
    return Path("/var/lib/netlab/platform.profile")
