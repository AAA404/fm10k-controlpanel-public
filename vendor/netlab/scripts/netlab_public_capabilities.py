"""Read immutable public capability bits and their sealed source identity."""

import hashlib
import os
import re
from functools import lru_cache
from pathlib import Path


GENERAL_ACL_INDEPENDENT = "general-acl-independent"
MANAGEMENT_SERVICES = "management-services"

_MACROS = {
    GENERAL_ACL_INDEPENDENT: "NETLAB_PUBLIC_GENERAL_ACL_INDEPENDENT",
    MANAGEMENT_SERVICES: "NETLAB_PUBLIC_MANAGEMENT_SERVICES",
}


def _default_root():
    return Path(os.environ.get(
        "NETLAB_ROOT", Path(__file__).resolve().parents[1]))


@lru_cache(maxsize=8)
def _authority(root_text):
    path = Path(root_text) / "include" / "netlab" / "public_capabilities.h"
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    values = {}
    for capability, macro in _MACROS.items():
        matches = re.findall(
            rf"(?m)^#define[ \t]+{re.escape(macro)}[ \t]+([01])[ \t]*$",
            source,
        )
        if len(matches) != 1:
            return {}
        values[capability] = matches[0] == "1"
    return values


def public_capability_enabled(capability, root=None):
    """Return false for unknown, missing, duplicated, or malformed authority."""
    if capability not in _MACROS:
        return False
    authority_root = Path(root) if root is not None else _default_root()
    return _authority(str(authority_root.resolve())).get(capability, False)


def public_capability_authority(capability, root=None):
    """Return the sealed source identity used for a public capability."""
    authority_root = Path(root) if root is not None else _default_root()
    authority_root = authority_root.resolve()
    path = authority_root / "include" / "netlab" / "public_capabilities.h"
    macro = _MACROS.get(capability)
    try:
        source_bytes = path.read_bytes()
    except OSError:
        source_bytes = b""
    values = _authority(str(authority_root))
    valid = bool(macro and source_bytes and capability in values)
    return {
        "capability-id": capability,
        "macro": macro or "",
        "enabled": values.get(capability, False) if valid else False,
        "valid": valid,
        "path": str(path),
        "sha256": hashlib.sha256(source_bytes).hexdigest()
        if source_bytes else "",
    }
