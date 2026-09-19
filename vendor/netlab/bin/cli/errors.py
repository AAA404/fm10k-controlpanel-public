"""
CLI error formatting — Junos-style error messages.
Maps nl_error_code to user-readable error strings with hints.
"""

ERROR_MAP = {
    # CONFIG_ERROR
    1001: ("invalid configuration path", None),
    1002: ("invalid value for this configuration key", None),
    1003: ("VLAN is not defined",
          'configure it with "set vlans <name> vlan-id <1-4094>"'),
    1004: ("vlan-id already used by another VLAN", None),
    1005: ("interface not found",
          'run "show interfaces terse" to list available interfaces'),
    1006: ("invalid interface-mode (must be access or trunk)", None),
    1007: ("access interface requires exactly one VLAN member", None),
    1008: ("native-vlan-id must be included in trunk vlan members", None),
    1009: ("VLAN is still referenced by interfaces",
          "remove interface memberships before deleting this VLAN"),
    1010: ("feature is not supported in this build",
          "this feature is outside the current hardware-backed command set"),
    1011: ("vlan-id must be in range 1..4094", None),
    1012: ("invalid VLAN name", None),
    1013: ("cannot delete default VLAN", None),
    1014: ("trunk interface has no VLAN members", None),

    # PFE_ERROR
    2001: ("commit rejected: PFE is down",
          'run "show chassis forwarding" for PFE status details'),
    2002: ("PFE capability insufficient for this commit", None),
    2003: ("forwarding runtime initialization failed", None),
    2004: ("forwarding runtime operation failed", None),
    2005: ("forwarding runtime operation timed out", None),
    2006: ("hardware read-back verification failed", None),
    2007: ("hardware state is out of sync",
          'run "show system alarms" and "request system reconcile"'),

    # RPC_ERROR
    3001: ("daemon RPC timed out", None),
    3002: ("daemon is unreachable", None),
    3003: ("permission denied", None),
    3004: ("transaction ID is required for this operation", None),
    3005: ("idempotency conflict: parameters differ from cached result", None),
    3006: ("malformed request", None),

    # ROLLBACK_ERROR
    4001: ("rollback failed", None),
    4002: ("pre-state missing for rollback", None),
    4003: ("hardware verification failed after rollback", None),

    # COMMIT_ERROR
    5001: ("active configuration has been modified",
          "update candidate configuration before commit"),
    5002: ("commit lock is held by another session", None),
    5003: ("commit journal is corrupt", None),
}


def format_error(code: int, detail: str = "", hint: str = "") -> str:
    """Format an error code into a Junos-style error message."""
    # If daemon already sent a fully formatted message, return it directly
    if detail and ("error:" in detail or "commit rejected" in detail.lower()
                   or detail.startswith("commit")):
        return detail
    entry = ERROR_MAP.get(code)
    if not entry:
        return f"error: unknown error (code={code})"
    msg, default_hint = entry
    lines = [f"error: {msg}"]
    if detail:
        lines.append(f"reason: {detail}")
    h = hint or default_hint
    if h:
        lines.append(f"hint: {h}")
    return "\n".join(lines)
