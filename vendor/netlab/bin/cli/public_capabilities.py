"""CLI compatibility import for the shared public capability authority."""

import os
import sys
from pathlib import Path

ROOT = Path(os.environ.get("NETLAB_ROOT", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(ROOT / "scripts"))
from netlab_public_capabilities import (  # noqa: E402,F401
    GENERAL_ACL_INDEPENDENT,
    MANAGEMENT_SERVICES,
    public_capability_authority,
    public_capability_enabled,
)
