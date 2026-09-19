"""Dynamic completion candidates loaded from runtime state."""
import os
import stat
import xml.etree.ElementTree as ET

from platform_profile import (aggregate_names, interface_names_with_flag,
                              physical_interface_names)

COMPLETION_RPC_TIMEOUT_MS = 750


def _completion_rpc_timeout_ms():
    value = os.environ.get("NETLAB_CLI_COMPLETION_TIMEOUT_MS", "")
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        return COMPLETION_RPC_TIMEOUT_MS
    if timeout < 100:
        return 100
    if timeout > 5000:
        return 5000
    return timeout


def dynamic_candidates(dyn_type, partial):
    """Best-effort dynamic completions from mgmtd with static fallbacks."""
    if dyn_type == "aggregates":
        return [
            {"word": name, "help": "aggregated interface"}
            for name in aggregate_names()
            if name.startswith(partial)
        ]
    if dyn_type == "rollback":
        return _rollback_candidates(partial)
    if dyn_type == "rollback-numbers":
        return _rollback_candidates(partial, include_rescue=False)
    if dyn_type not in (
        "interfaces", "config-interfaces", "operational-interfaces",
        "physical-interfaces", "rstp-interfaces", "lldp-interfaces", "vlans",
    ):
        return []
    try:
        if dyn_type in (
            "interfaces", "config-interfaces", "operational-interfaces",
            "physical-interfaces", "rstp-interfaces", "lldp-interfaces",
        ):
            words = _interface_words_for_completion(dyn_type)
        else:
            words = _vlan_words_for_completion()
        return [{"word": w, "help": dyn_type[:-1]} for w in words
                if w and w.startswith(partial)]
    except Exception:
        return []


def _interface_words_for_completion(dyn_type):
    runtime_words = _ifd_interface_words()

    if dyn_type == "operational-interfaces":
        return runtime_words

    if dyn_type == "physical-interfaces":
        words = [w for w in runtime_words if not w.startswith("ae")]
        return words or physical_interface_names()

    if dyn_type == "rstp-interfaces":
        return interface_names_with_flag("rstp")

    if dyn_type == "lldp-interfaces":
        return interface_names_with_flag("lldp")

    words = []
    for name in physical_interface_names() + runtime_words + aggregate_names():
        if name and name not in words:
            words.append(name)
    return words


def _ifd_interface_words():
    try:
        from session import (CliSession, DAEMON_IFD, mgmtd_socket_path)
        if not os.path.exists(mgmtd_socket_path()):
            return []
        sess = CliSession()
        if not sess.connect():
            return []
        try:
            ec, _, resp = sess.send_request(
                DAEMON_IFD, 1, b"terse",
                timeout_ms=_completion_rpc_timeout_ms())
        finally:
            sess.close()
        if ec != 0:
            return []
        root = ET.fromstring(resp.decode(errors="replace"))
        return [_text(x, "name") for x in root.findall("interface")
                if _text(x, "name")]
    except Exception:
        return []


def _vlan_words_for_completion():
    try:
        from session import (CliSession, DAEMON_L2D, mgmtd_socket_path)
        if not os.path.exists(mgmtd_socket_path()):
            return []
        sess = CliSession()
        if not sess.connect():
            return []
        try:
            ec, _, resp = sess.send_request(
                DAEMON_L2D, 1, b"",
                timeout_ms=_completion_rpc_timeout_ms())
        finally:
            sess.close()
        if ec != 0:
            return []
        root = ET.fromstring(resp.decode(errors="replace"))
        return [_text(x, "name") for x in root.findall("vlan")
                if _text(x, "name")]
    except Exception:
        return []


def _rollback_candidates(partial, include_rescue=True):
    candidates = []
    if include_rescue and _rescue_config_present() and "rescue".startswith(partial):
        candidates.append({
            "word": "rescue",
            "help": "load saved rescue configuration into candidate",
        })
    try:
        from session import (CliSession, DAEMON_CONFIGD, mgmtd_socket_path)
        if not os.path.exists(mgmtd_socket_path()):
            return candidates
        sess = CliSession()
        if not sess.connect():
            return candidates
        try:
            ec, _, resp = sess.send_request(
                DAEMON_CONFIGD, 11, b"",
                timeout_ms=_completion_rpc_timeout_ms())
        finally:
            sess.close()
        if ec != 0:
            return candidates
        for line in resp.decode(errors="replace").splitlines():
            if not line.strip():
                continue
            if "\t" in line:
                word, help_text = line.split("\t", 1)
            else:
                parts = line.split(None, 1)
                word = parts[0]
                help_text = parts[1] if len(parts) > 1 else ""
            if word.startswith(partial):
                candidates.append({"word": word, "help": help_text})
        return candidates
    except Exception:
        return candidates


def _rescue_config_present():
    store = os.environ.get("NETLAB_CONFIG_STORE_DIR",
                           "/var/lib/netlab/config")
    try:
        st = os.lstat(os.path.join(store, "rescue.conf"))
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode)


def _text(elem, tag):
    child = elem.find(tag)
    return child.text.strip() if child is not None and child.text else ""
