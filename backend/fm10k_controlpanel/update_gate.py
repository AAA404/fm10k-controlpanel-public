"""Block native startup after an interrupted upgrade until its worker recovers."""
from contextlib import contextmanager
import json
import os
from pathlib import Path

TERMINAL_PHASES = {"committed", "rolled_back", "aborted"}


def process_identity(root, pid):
    # comm may contain spaces or parentheses; fields after its final ')' start
    # at field 3, so starttime (field 22) has index 19 here.
    fields = (root / f"proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    if fields[0] in {"Z", "X"}:
        raise ValueError("update worker is no longer running")
    return {"pid": pid, "start_ticks": fields[19],
            "boot_id": (root / "proc/sys/kernel/random/boot_id").read_text().strip()}


@contextmanager
def startup_permission(paths):
    from .installation import save
    path = paths.root / "run/fm10k-update/startup-permission.json"
    save(path, process_identity(paths.root, os.getpid()))
    try:
        yield
    finally:
        path.unlink(missing_ok=True)


def verify_update_gate(root=Path("/"), reader=None):
    journal = root / "var/lib/fm10k-controlpanel-updates/transaction.json"
    if not journal.exists():
        return
    if reader is None:
        from .native_guard import trusted_file
        reader = trusted_file
    transaction = json.loads(reader(journal))
    if transaction.get("schema") != 1:
        raise ValueError("unknown update recovery journal")
    if transaction.get("phase") in TERMINAL_PHASES:
        return
    try:
        permission = json.loads(reader(root / "run/fm10k-update/startup-permission.json"))
        pid = permission["pid"]
        if type(pid) is not int or pid <= 1 or permission != process_identity(root, pid):
            raise ValueError("update worker identity changed")
    except (OSError, ValueError, KeyError, IndexError):
        raise ValueError("an interrupted update must be recovered by fm10k-update-worker before native startup") from None
