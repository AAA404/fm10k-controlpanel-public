#!/usr/bin/env python3
"""
NetLab CLI — Junos-like operational and configuration mode.
prompt_toolkit for input, custom completion engine for Tab/? context help.
"""
import os
import sys
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

import hashlib
import difflib
import json
import re
import shlex
import shutil
import stat as stat_module
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Optional, List

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.application import run_in_terminal
from prompt_toolkit.shortcuts.prompt import CompleteStyle

from session import (CliSession, DAEMON_MGMTD, DAEMON_CONFIGD, DAEMON_IFD,
                     DAEMON_RPD, DAEMON_CHASSISD,
                     DAEMON_SWITCHD, DAEMON_PACKETD, DAEMON_L2D, DAEMON_STATSD,
                     DAEMON_LLDPD, DAEMON_LACPD, DAEMON_STPD)
from errors import format_error
from pipe import apply_pipe
from cli_helpers import ifname_to_hw_port, xml_child_text, xml_local_name
from config_paths import (cli_to_delete_path, cli_to_path,
                          unsupported_config_delete_leaf,
                          unsupported_config_leaf)
from platform_profile import load_profile, physical_interface_names, port_to_ifname
from port_mode import PortModeError, start_background_action
from output_format import (format_interfaces_terse, format_interface_detail,
                           format_vlans, format_eth_sw_interfaces,
                           format_interface_statistics,
                           format_pfe_resources,
                           format_class_of_service_flow_control,
                           format_class_of_service_forwarding,
                           format_class_of_service_interfaces,
                           format_class_of_service_capabilities,
                           format_class_of_service_ets,
                           format_class_of_service_queues,
                           format_class_of_service_scheduler,
                           format_class_of_service_watermarks,
                           format_control_plane_protection,
                           format_forwarding_runtime,
                           format_sdk_runtime, format_switch_config,
                           format_mgmtd_status,
                           format_lldp_neighbors, format_lldp_statistics,
                           format_lldp_neighbors_detail,
                           format_lldp_interfaces, format_lldp_local,
                           format_mac_snapshot, format_mac_move,
                           format_ingress_rate_limit,
                           format_egress_rate_limit,
                           format_l3_ecmp_table,
                           format_l3_interface_table,
                           format_l3_next_hop_table,
                           format_l3_resource_table,
                           format_l3_route_summary,
                           format_l3_route_table,
                           format_rpd_forwarding_table,
                           format_rpd_arp_table,
                           format_rpd_route_summary,
                           format_rpd_route_table,
                           format_rpd_state,
                           format_l3_shadow_state,
                           format_l3_state,
                           format_secure_access_port, format_storm_control,
                           format_dhcp_snooping, format_arp_inspection,
                           format_ethernet_switching_acl_capabilities,
                           format_acl_policer, format_acl_summary,
                           format_egress_acl, format_ingress_acl,
                           format_ingress_ipv4_acl,
                           format_user_filter,
                           format_spanning_tree,
                           format_spanning_tree_capabilities,
                           format_spanning_tree_state,
                           format_stp_monitor,
                           format_config_hierarchy,
                           format_config_as_set,
                           format_pfe_status,
                           format_chassis_alarms,
                           format_chassis_hardware,
                           format_chassis_optics_mux,
                           format_chassis_port_mode,
                           format_interface_optics_mux_calibration_check,
                           format_interface_optics_mux_calibration,
                           format_interface_optics_mux_mapping,
                           format_interface_optics_mux,
                           format_lacp, format_port_mirroring)
from output_igmp import format_igmp_snooping
from completion_engine import (get_context_candidates, parse_context,
                               common_prefix)

STYLE = Style.from_dict({"prompt": "bold ansigreen"})

OPTICS_UNAVAILABLE_REASON = (
    "platform DOM telemetry is unavailable in the active chassis mode"
)
OPTICS_MUX_RPC_PAYLOAD = b"bus=0 mux=0x58"
OPTICS_MUX_RPC_TIMEOUT_MS = 5000
OPTICS_MUX_RPC_RETRIES = 2
OPTICS_MUX_RPC_RETRY_DELAY_SEC = 0.2
PUBLIC_RUNTIME_RPC_TIMEOUT_MS = 2000
CONFIG_READ_RPC_TIMEOUT_MS = 2000
CONFIG_WRITE_RPC_TIMEOUT_MS = 5000
CONFIG_COMMIT_RPC_TIMEOUT_MS = 45000
CONFIG_AUTHORITY_TOKEN_VARIABLE = "NETLAB_CONFIG_AUTHORITY_TOKEN"
CONFIG_AUTHORITY_ENVELOPE = b"netlab-config-authority-v1 "
CONFIGD_MUTATION_METHODS = frozenset((1, 2, 3, 4, 7, 10, 12))


def _optics_mux_rpc_timeout_ms():
    value = os.environ.get("NETLAB_CLI_OPTICS_TIMEOUT_MS", "")
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        return OPTICS_MUX_RPC_TIMEOUT_MS
    if timeout < 250:
        return 250
    if timeout > 10000:
        return 10000
    return timeout


def _public_runtime_rpc_timeout_ms():
    value = os.environ.get("NETLAB_CLI_RUNTIME_TIMEOUT_MS", "")
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        return PUBLIC_RUNTIME_RPC_TIMEOUT_MS
    if timeout < 250:
        return 250
    if timeout > 10000:
        return 10000
    return timeout


def _config_read_rpc_timeout_ms():
    value = os.environ.get("NETLAB_CLI_CONFIG_READ_TIMEOUT_MS", "")
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        return CONFIG_READ_RPC_TIMEOUT_MS
    if timeout < 250:
        return 250
    if timeout > 10000:
        return 10000
    return timeout


def _config_write_rpc_timeout_ms():
    value = os.environ.get("NETLAB_CLI_CONFIG_WRITE_TIMEOUT_MS", "")
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        return CONFIG_WRITE_RPC_TIMEOUT_MS
    if timeout < 250:
        return 250
    if timeout > 60000:
        return 60000
    return timeout


def _config_commit_rpc_timeout_ms():
    value = os.environ.get("NETLAB_CLI_CONFIG_COMMIT_TIMEOUT_MS", "")
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        return CONFIG_COMMIT_RPC_TIMEOUT_MS
    if timeout < 250:
        return 250
    if timeout > 300000:
        return 300000
    return timeout


def _plain_prompt(cli):
    return "".join(text for _, text in cli.get_prompt()).lstrip("\n")


def _format_context_help(cli, command_text, candidates, marker=""):
    lines = [_plain_prompt(cli) + command_text + marker]
    if not candidates:
        lines.append("  No completions available")
    else:
        lines.append("Possible completions:")
        for c in candidates:
            lines.append(f"  {c['word']:<28} {c.get('help', '')}")
    return "\n".join(lines) + "\n"


# ===== Key bindings for Tab and ? =====
def _build_keybindings(cli):
    kb = KeyBindings()

    @kb.add("?")
    def show_help(event):
        """Print context-sensitive help without consuming '?'."""
        text = event.current_buffer.document.text_before_cursor
        candidates = get_context_candidates(text, cli.mode, cli.edit_path)

        def print_help():
            sys.stdout.write("\n")
            sys.stdout.write(_format_context_help(cli, text, candidates, "?"))
            sys.stdout.write("\n")
            sys.stdout.flush()

        run_in_terminal(print_help)

    @kb.add("tab")
    def tab_complete(event):
        """Junos-like Tab completion."""
        buffer = event.current_buffer
        text = buffer.document.text_before_cursor

        consumed, partial = parse_context(text)
        candidates = get_context_candidates(text, cli.mode, cli.edit_path)
        # Strip "|" prefix for pipe context matching
        match_partial = partial[1:] if partial.startswith("|") else partial

        # Filter out special keys
        real_candidates = [c for c in candidates
                          if not c['word'].startswith("<")]
        words = [c["word"] for c in real_candidates]

        if not match_partial:
            def print_all():
                sys.stdout.write("\n")
                sys.stdout.write(_format_context_help(cli, text, candidates))
                sys.stdout.write("\n")
                sys.stdout.flush()
            run_in_terminal(print_all)
            return

        matched = [w for w in words if w.startswith(match_partial)]

        if len(matched) == 1:
            # Single match: complete and append space
            word = matched[0]
            suffix = word[len(match_partial):]
            buffer.insert_text(suffix + " ")
            return

        if len(matched) > 1:
            prefix = common_prefix(matched)
            if prefix and len(prefix) > len(match_partial):
                buffer.insert_text(prefix[len(match_partial):])
                return

            def print_list():
                sys.stdout.write("\n")
                matches = [c for c in real_candidates
                           if c['word'].startswith(match_partial)]
                sys.stdout.write(_format_context_help(cli, text, matches))
                sys.stdout.write("\n")
                sys.stdout.flush()
            run_in_terminal(print_list)
            return

    return kb


# ===== CLI class =====
class NetLabCLI:
    def __init__(self):
        self.mode = "operational"
        self.edit_path: List[str] = []
        self.hostname = "netlab"
        self.config_session_mode = "shared"
        self.config_lock_token = f"{os.getpid()}:{id(self)}"

    def get_prompt(self):
        edit = " ".join(self.edit_path)
        if self.mode == "config":
            if edit:
                return [("class:prompt", f"\n[edit {edit}]\n{self.hostname}# ")]
            return [("class:prompt", f"\n[edit]\n{self.hostname}# ")]
        return [("class:prompt", f"\n{self.hostname}> ")]

    def run(self):
        s = CliSession()
        if not s.connect():
            print("error: mgmtd not running")
            sys.exit(1)
        s.close()

        kb = _build_keybindings(self)
        session = PromptSession(
            history=FileHistory("/tmp/netlab_cli_history"),
            complete_while_typing=False,
            complete_style=CompleteStyle.READLINE_LIKE,
            key_bindings=kb,
            style=STYLE,
            multiline=False,
        )

        print("NetLab CLI — connected to mgmtd")
        print("Tab=complete  ?=help  Ctrl+C=abort  Ctrl+D=quit\n")
        while True:
            try:
                text = session.prompt(self.get_prompt())
            except KeyboardInterrupt:
                print("^C")
                continue
            except EOFError:
                print()
                break

            line = text.strip()
            if not line:
                continue
            if line == "?":
                # Standalone ? → show top-level help
                candidates = get_context_candidates("", self.mode, self.edit_path)
                print(_format_context_help(self, "", candidates, "?"), end="")
                print()
                continue
            if line in ("quit", "exit"):
                if self.mode == "config":
                    self._release_config_lock()
                    self.mode = "operational"
                    self.edit_path = []
                    self.config_session_mode = "shared"
                    continue
                break

            result = self.dispatch(line)
            if result is not None:
                print(result)

    def dispatch(self, line: str) -> Optional[str]:
        # Handle pipe: split on "|" that has spaces around it
        if " | " in line or " |" in line or "| " in line:
            parts = line.split("|", 1)
            cmd_part = parts[0].strip()
            pipe_part = parts[1].strip() if len(parts) > 1 else ""
            try:
                cmd_tokens = shlex.split(cmd_part) if cmd_part else []
            except ValueError as e:
                return f"error: {e}"
            pipe_tokens = pipe_part.split()
            # Route "show | compare" / "show | display" to config diff handler
            if (self.mode == "config" and cmd_tokens and
                    cmd_tokens[0] == "show" and pipe_tokens and
                    pipe_tokens[0] in ("display", "compare", "com")):
                return self._pipe_show(pipe_tokens,
                                       active=False,
                                       path_tokens=cmd_tokens[1:])
            if cmd_tokens == ["show"] and (pipe_part.startswith("compare") or
                                           pipe_part.startswith("display") or
                                           pipe_part.startswith("com")):
                return self._pipe_show(pipe_tokens, active=False)
            if cmd_tokens == ["show", "configuration"] and (
                    pipe_part.startswith("display") or
                    pipe_part.startswith("compare")):
                return self._pipe_show(pipe_tokens, active=True)
            result = self._dispatch_cmd(cmd_part)
            if result and pipe_part:
                return apply_pipe(result, pipe_part)
            return result
        return self._dispatch_cmd(line)

    def _dispatch_cmd(self, line: str) -> Optional[str]:
        try:
            tokens = shlex.split(line)
        except ValueError as e:
            return f"error: {e}"
        if not tokens:
            return None
        cmd = tokens[0].lower()

        if cmd == "configure":
            return self._configure(tokens[1:])
        elif cmd == "exit":
            if len(tokens) != 1:
                return f"error: unknown exit option: {' '.join(tokens[1:])}"
            if self.mode == "config":
                self._release_config_lock()
                self.mode = "operational"
                self.edit_path = []
                self.config_session_mode = "shared"
            return None
        elif cmd == "quit":
            if len(tokens) != 1:
                return f"error: unknown quit option: {' '.join(tokens[1:])}"
            if self.mode == "config":
                self._release_config_lock()
                self.mode = "operational"
                self.edit_path = []
                self.config_session_mode = "shared"
            return None

        if self.mode == "operational":
            return self._handle_op(tokens)
        return self._handle_cfg(tokens)

    def _handle_op(self, tokens):
        cmd = tokens[0]
        if cmd == "show":
            return self._show(tokens[1:])
        if cmd == "request":
            return self._request(tokens[1:])
        if cmd == "clear":
            return self._clear(tokens[1:])
        if cmd == "file":
            return self._file(tokens[1:])
        if cmd == "ping":
            return self._ping(tokens[1:])
        if cmd == "traceroute":
            return self._traceroute(tokens[1:])
        return f"error: unknown command: {cmd}"

    def _ping(self, tokens):
        if not tokens:
            return "error: usage: ping <host> [count <1-20>]"
        target = tokens[0]
        error = self._validate_host_target(target, "ping")
        if error:
            return error
        count = 5
        seen = set()
        i = 1
        while i < len(tokens):
            if tokens[i] != "count":
                return f"error: unknown ping option: {' '.join(tokens[i:])}"
            if "count" in seen:
                return "error: duplicate ping count option"
            if i + 1 >= len(tokens):
                return "error: missing ping count value"
            try:
                count = int(tokens[i + 1], 10)
            except ValueError:
                return f"error: invalid ping count: {tokens[i + 1]}"
            if count < 1 or count > 20:
                return "error: ping count must be 1..20"
            seen.add("count")
            i += 2
        output = self._run_local_command(
            ["ping", "-c", str(count), "-W", "2", target],
            timeout=max(5, count * 3),
        )
        return "\n".join([
            "Host reachability test:",
            f"  target : {target}",
            f"  count  : {count}",
            "",
            output,
        ]).rstrip("\n")

    def _traceroute(self, tokens):
        if not tokens:
            return "error: usage: traceroute <host>"
        target = tokens[0]
        error = self._validate_host_target(target, "traceroute")
        if error:
            return error
        if len(tokens) > 1:
            return f"error: unknown traceroute option: {' '.join(tokens[1:])}"
        output = self._run_local_command(
            ["traceroute", "-n", "-w", "2", "-q", "1", target],
            timeout=30,
        )
        return "\n".join([
            "Path trace:",
            f"  target : {target}",
            "",
            output,
        ]).rstrip("\n")

    def _validate_host_target(self, target, command):
        if not target:
            return f"error: missing {command} target"
        if target.startswith("-"):
            return f"error: invalid {command} target: {target}"
        if not re.match(r"^[A-Za-z0-9_.:-]+$", target):
            return f"error: invalid {command} target: {target}"
        return None

    def _configure(self, tokens):
        if self.mode == "config":
            if tokens:
                return f"error: already in configuration mode: {' '.join(tokens)}"
            return None
        if not tokens:
            lock_error = self._config_writable_error()
            if lock_error:
                return lock_error
            self.config_session_mode = "shared"
            self.mode = "config"
            return None
        if tokens == ["exclusive"]:
            error = self._acquire_config_lock("exclusive")
            if error:
                return error
            self.config_session_mode = "exclusive"
            self.mode = "config"
            return "Entering configuration mode (exclusive)"
        if tokens == ["private"]:
            return ("error: configure private requires per-session candidate "
                    "support; use configure exclusive or configure")
        return f"error: unknown configure option: {' '.join(tokens)}"

    def _config_lock_path(self):
        lab_path = os.environ.get("NETLAB_LAB_ONLY_CONFIG_LOCK_PATH")
        if lab_path and self._path_under_roots(
                lab_path, ("/tmp", "/var/tmp", "/var/run/netlab",
                           "/run/netlab")):
            return os.path.abspath(os.path.expanduser(lab_path))
        return "/var/run/netlab/cli-config.lock"

    def _path_under_roots(self, path, roots):
        try:
            real_path = os.path.realpath(os.path.abspath(
                os.path.expanduser(path)))
            for root in roots:
                real_root = os.path.realpath(os.path.abspath(root))
                if os.path.commonpath([real_path, real_root]) == real_root:
                    return True
        except (OSError, ValueError):
            return False
        return False

    def _mutable_file_roots(self):
        return (
            "/tmp",
            "/var/tmp",
            "/run/netlab",
            "/var/run/netlab",
            "/var/lib/netlab",
            "/var/log/netlab",
            "/opt/netlab-artifacts",
        )

    def _mutable_path_error(self, path, role):
        if self._path_under_roots(path, self._mutable_file_roots()):
            return None
        return f"error: {role} is outside allowed mutable paths: {path}"

    def _regular_file_error(self, path, role, missing_error=True):
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            if missing_error:
                return f"error: file not found: {path}"
            return None
        except OSError as exc:
            return f"error: cannot inspect {role}: {exc}"
        if stat_module.S_ISLNK(st.st_mode):
            return f"error: cannot use symbolic link as {role}: {path}"
        if stat_module.S_ISDIR(st.st_mode):
            return f"error: cannot use directory as {role}: {path}"
        if not stat_module.S_ISREG(st.st_mode):
            return f"error: cannot use non-regular file as {role}: {path}"
        return None

    def _destination_parent_error(self, path):
        parent = os.path.dirname(path)
        if not parent:
            return None
        parent_mutable = self._mutable_path_error(parent, "destination parent")
        if parent_mutable:
            return parent_mutable
        try:
            st = os.lstat(parent)
        except FileNotFoundError:
            return f"error: destination directory not found: {parent}"
        except OSError as exc:
            return f"error: cannot inspect destination parent: {exc}"
        if stat_module.S_ISLNK(st.st_mode):
            return f"error: destination parent is a symbolic link: {parent}"
        if not stat_module.S_ISDIR(st.st_mode):
            return f"error: destination parent is not a directory: {parent}"
        return None

    def _unlink_config_lock(self, path):
        if self._mutable_path_error(path, "configuration lock"):
            return
        if self._regular_file_error(path, "configuration lock",
                                    missing_error=False):
            return
        try:
            os.unlink(path)
        except OSError:
            pass

    def _config_lock_owner(self):
        path = self._config_lock_path()
        if self._regular_file_error(path, "configuration lock",
                                    missing_error=False):
            return {
                "path": path,
                "pid": 0,
                "token": "",
                "mode": "unknown",
                "user": "unknown",
                "started": 0,
            }
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            with os.fdopen(fd, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError):
            return {
                "path": path,
                "pid": 0,
                "token": "",
                "mode": "unknown",
                "user": "unknown",
                "started": 0,
            }
        pid = int(data.get("pid") or 0)
        if pid > 0 and not self._pid_alive(pid):
            self._unlink_config_lock(path)
            return None
        return data

    def _pid_alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False

    def _format_config_lock_error(self, owner):
        if not owner:
            return None
        if owner.get("token") == self.config_lock_token:
            return None
        pid = owner.get("pid", "?")
        user = owner.get("user") or "unknown"
        mode = owner.get("mode") or "unknown"
        started = owner.get("started") or 0
        if started:
            start_text = time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(int(started)))
        else:
            start_text = "unknown"
        return ("error: configuration database is locked\n"
                f"  mode    : {mode}\n"
                f"  user    : {user}\n"
                f"  pid     : {pid}\n"
                f"  started : {start_text}")

    def _config_writable_error(self):
        return self._format_config_lock_error(self._config_lock_owner())

    def _acquire_config_lock(self, mode):
        path = self._config_lock_path()
        owner = self._config_lock_owner()
        error = self._format_config_lock_error(owner)
        if error:
            return error
        if owner and owner.get("token") == self.config_lock_token:
            return None
        data = {
            "pid": os.getpid(),
            "token": self.config_lock_token,
            "mode": mode,
            "user": os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown",
            "started": int(time.time()),
        }
        try:
            os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
            flags = (os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                     getattr(os, "O_NOFOLLOW", 0))
            fd = os.open(path, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, sort_keys=True)
                handle.write("\n")
        except FileExistsError:
            return self._config_writable_error()
        except OSError as exc:
            return f"error: cannot acquire configuration lock: {exc}"
        return None

    def _release_config_lock(self):
        owner = self._config_lock_owner()
        if not owner or owner.get("token") != self.config_lock_token:
            return
        self._unlink_config_lock(self._config_lock_path())

    def _file(self, tokens):
        if not tokens:
            return "error: incomplete file command"
        if tokens[0] == "compare":
            return self._file_compare(tokens[1:])
        if tokens[0] == "copy":
            if len(tokens) != 3:
                return "error: usage: file copy <source> <destination>"
            return self._file_copy(tokens[1], tokens[2])
        if tokens[0] == "checksum":
            if len(tokens) != 3:
                return "error: usage: file checksum md5|sha1|sha256 <path>"
            return self._file_checksum(tokens[1], tokens[2])
        if tokens[0] == "delete":
            if len(tokens) != 2:
                return "error: usage: file delete <path>"
            return self._file_delete(tokens[1])
        if tokens[0] == "rename":
            if len(tokens) != 3:
                return "error: usage: file rename <source> <destination>"
            return self._file_rename(tokens[1], tokens[2])
        if tokens[0] == "list":
            if len(tokens) > 2:
                return "error: usage: file list [path]"
            path = tokens[1] if len(tokens) == 2 else "."
            return self._file_list(path)
        if tokens[0] == "show":
            if len(tokens) != 2:
                return "error: usage: file show <path>"
            return self._file_show(tokens[1])
        return f"error: unknown file command: {' '.join(tokens)}"

    def _file_compare(self, tokens):
        if len(tokens) < 3 or tokens[0] != "files":
            return ("error: usage: file compare files <file1> <file2> "
                    "[context|unified] [ignore-white-space]")
        if len(tokens) > 5:
            return ("error: usage: file compare files <file1> <file2> "
                    "[context|unified] [ignore-white-space]")
        left_path = os.path.expanduser(tokens[1])
        right_path = os.path.expanduser(tokens[2])
        style = "default"
        ignore_white_space = False
        for option in tokens[3:]:
            if option in ("context", "unified"):
                if style != "default":
                    return f"error: duplicate file compare output style: {option}"
                style = option
            elif option == "ignore-white-space":
                ignore_white_space = True
            else:
                return f"error: unknown file compare option: {option}"

        left_lines, error = self._read_compare_lines(left_path)
        if error:
            return error
        right_lines, error = self._read_compare_lines(right_path)
        if error:
            return error
        if ignore_white_space:
            left_lines = self._normalize_compare_whitespace(left_lines)
            right_lines = self._normalize_compare_whitespace(right_lines)

        if left_lines == right_lines:
            return "Files are identical"
        if style == "unified":
            diff = difflib.unified_diff(
                left_lines, right_lines,
                fromfile=left_path, tofile=right_path,
                lineterm="")
        elif style == "context":
            diff = difflib.context_diff(
                left_lines, right_lines,
                fromfile=left_path, tofile=right_path,
                lineterm="")
        else:
            diff = difflib.ndiff(left_lines, right_lines)
        return "\n".join(diff)

    def _read_compare_lines(self, path):
        max_bytes = 10 * 1024 * 1024
        try:
            stat = os.stat(path)
        except FileNotFoundError:
            return None, f"error: file not found: {path}"
        except OSError as exc:
            return None, f"error: cannot access file: {exc}"
        if os.path.isdir(path):
            return None, f"error: cannot compare directory: {path}"
        if stat.st_size > max_bytes:
            return None, (
                f"error: file too large for CLI compare: {path} "
                f"({stat.st_size} bytes; max {max_bytes})")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read().splitlines(), None
        except OSError as exc:
            return None, f"error: cannot read file: {exc}"

    def _normalize_compare_whitespace(self, lines):
        return [" ".join(line.split()) for line in lines]

    def _file_list(self, path):
        path = os.path.expanduser(path)
        try:
            stat = os.stat(path)
        except FileNotFoundError:
            return f"error: file not found: {path}"
        except OSError as exc:
            return f"error: cannot access file: {exc}"
        if not os.path.isdir(path):
            return self._format_file_entry(os.path.basename(path), path, stat)
        try:
            names = sorted(os.listdir(path))
        except OSError as exc:
            return f"error: cannot list directory: {exc}"
        lines = [f"Directory: {path}"]
        for name in names[:200]:
            item = os.path.join(path, name)
            try:
                item_stat = os.stat(item)
            except OSError:
                continue
            lines.append(self._format_file_entry(name, item, item_stat))
        if len(names) > 200:
            lines.append(f"... {len(names) - 200} entries omitted")
        return "\n".join(lines)

    def _format_file_entry(self, name, path, stat):
        suffix = "/" if os.path.isdir(path) else ""
        stamp = time.strftime("%Y-%m-%d %H:%M:%S",
                              time.localtime(stat.st_mtime))
        return f"{name + suffix:<32} {stat.st_size:>10} bytes  {stamp}"

    def _file_show(self, path):
        path = os.path.expanduser(path)
        if os.path.isdir(path):
            return f"error: cannot show directory: {path}"
        text, error, truncated = self._read_text_file(path, max_bytes=1048576)
        if error:
            return error
        header = f"File: {path}"
        if truncated:
            header += "\nNote: output truncated to first 1048576 bytes"
        return header + "\n" + text.rstrip("\n")

    def _file_checksum(self, algorithm, path):
        algorithm = algorithm.lower()
        path, _stat, checksum, error = self._file_digest(algorithm, path)
        if error:
            kind, detail = error
            if kind == "unsupported":
                return f"error: unsupported checksum algorithm: {detail}"
            if kind == "directory":
                return f"error: cannot checksum directory: {path}"
            if kind == "not-found":
                return f"error: file not found: {path}"
            return f"error: cannot checksum file: {detail}"
        return "\n".join([
            "File checksum:",
            f"  file      : {path}",
            f"  algorithm : {algorithm}",
            f"  checksum  : {checksum}",
        ])

    def _file_digest(self, algorithm, path):
        algorithm = algorithm.lower()
        if algorithm not in ("md5", "sha1", "sha256"):
            return path, None, "", ("unsupported", algorithm)
        path = os.path.expanduser(path)
        try:
            stat = os.stat(path)
        except FileNotFoundError:
            return path, None, "", ("not-found", path)
        except OSError as exc:
            return path, None, "", ("read", exc)
        if os.path.isdir(path):
            return path, stat, "", ("directory", path)
        digest = hashlib.new(algorithm)
        try:
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    if not chunk:
                        break
                    digest.update(chunk)
        except OSError as exc:
            return path, stat, "", ("read", exc)
        return path, stat, digest.hexdigest(), None

    def _file_copy(self, source, destination):
        source = os.path.expanduser(source)
        destination = os.path.expanduser(destination)
        error = self._mutable_path_error(source, "source")
        if error:
            return error
        if os.path.isdir(source) and not os.path.islink(source):
            return f"error: cannot copy directory: {source}"
        error = self._regular_file_error(source, "source")
        if error:
            return error
        if os.path.isdir(destination):
            destination = os.path.join(destination, os.path.basename(source))
        error = self._mutable_path_error(destination, "destination")
        if error:
            return error
        error = self._destination_parent_error(destination)
        if error:
            return error
        error = self._regular_file_error(destination, "destination",
                                         missing_error=False)
        if error:
            return error
        try:
            shutil.copy2(source, destination)
        except OSError as exc:
            return f"error: cannot copy file: {exc}"
        return "\n".join([
            "file copied",
            f"  source      : {source}",
            f"  destination : {destination}",
        ])

    def _file_delete(self, path):
        path = os.path.expanduser(path)
        error = self._mutable_path_error(path, "file")
        if error:
            return error
        if os.path.isdir(path) and not os.path.islink(path):
            return f"error: cannot delete directory: {path}"
        error = self._regular_file_error(path, "file")
        if error:
            return error
        try:
            os.unlink(path)
        except FileNotFoundError:
            return f"error: file not found: {path}"
        except OSError as exc:
            return f"error: cannot delete file: {exc}"
        return "\n".join([
            "file deleted",
            f"  file : {path}",
        ])

    def _file_rename(self, source, destination):
        source = os.path.expanduser(source)
        destination = os.path.expanduser(destination)
        error = self._mutable_path_error(source, "source")
        if error:
            return error
        if os.path.isdir(source) and not os.path.islink(source):
            return f"error: cannot rename directory: {source}"
        error = self._regular_file_error(source, "source")
        if error:
            return error
        if os.path.isdir(destination):
            destination = os.path.join(destination, os.path.basename(source))
        error = self._mutable_path_error(destination, "destination")
        if error:
            return error
        error = self._destination_parent_error(destination)
        if error:
            return error
        error = self._regular_file_error(destination, "destination",
                                         missing_error=False)
        if error:
            return error
        try:
            os.rename(source, destination)
        except OSError as exc:
            return f"error: cannot rename file: {exc}"
        return "\n".join([
            "file renamed",
            f"  source      : {source}",
            f"  destination : {destination}",
        ])

    def _read_text_file(self, path, max_bytes=None, tail_lines=None):
        try:
            with open(path, "rb") as handle:
                if tail_lines is not None:
                    data = handle.read()
                    truncated = False
                elif max_bytes is not None:
                    data = handle.read(max_bytes + 1)
                    truncated = len(data) > max_bytes
                    data = data[:max_bytes]
                else:
                    data = handle.read()
                    truncated = False
        except FileNotFoundError:
            return "", f"error: file not found: {path}", False
        except OSError as exc:
            return "", f"error: cannot read file: {exc}", False
        text = data.decode("utf-8", errors="replace")
        if tail_lines is not None:
            lines = text.splitlines()
            if len(lines) > tail_lines:
                text = "\n".join(lines[-tail_lines:]) + "\n"
                truncated = True
            else:
                truncated = False
        return text, None, truncated

    def _request(self, tokens):
        if tokens == ["support", "information"]:
            return self._request_support_information()
        if tokens == ["system", "reconcile"]:
            resp = self._configd_commit_rpc(12, b"")
            text, error = self._configd_action_text(resp)
            return error or text
        if (len(tokens) >= 2 and tokens[0] == "system" and
                tokens[1] in ("reboot", "halt", "power-off")):
            return self._request_system_power_action(tokens[1], tokens[2:])
        if (len(tokens) >= 2 and tokens[0] == "system" and
                tokens[1] == "snapshot"):
            return self._request_system_snapshot(tokens[2:])
        if (len(tokens) >= 2 and tokens[0] == "system" and
                tokens[1] == "zeroize"):
            return self._request_system_zeroize(tokens[2:])
        if (len(tokens) >= 2 and tokens[0] == "system" and
                tokens[1] == "storage"):
            return self._request_system_storage(tokens[2:])
        if (len(tokens) >= 2 and tokens[0] == "system" and
                tokens[1] == "services"):
            return self._request_system_services(tokens[2:])
        if (len(tokens) >= 2 and tokens[0] == "system" and
                tokens[1] == "core-dumps"):
            return self._request_system_core_dumps(tokens[2:])
        if (len(tokens) >= 2 and tokens[0] == "system" and
                tokens[1] == "configuration"):
            return self._request_system_configuration(tokens[2:])
        if (len(tokens) >= 2 and tokens[0] == "system" and
                tokens[1] == "software"):
            return self._request_system_software(tokens[2:])
        if tokens == ["chassis", "port-mode", "apply"]:
            return self._request_chassis_port_mode("apply")
        if tokens == ["chassis", "port-mode", "rollback"]:
            return self._request_chassis_port_mode("rollback")
        if not tokens:
            return "error: incomplete request command"
        return f"error: unknown request target: {' '.join(tokens)}"

    def _request_system_power_action(self, action, tokens):
        if tokens:
            return f"error: unknown system {action} option: {' '.join(tokens)}"
        display = {
            "reboot": "reboot",
            "halt": "halt",
            "power-off": "power-off",
        }[action]
        return "\n".join([
            f"System {display} request:",
            f"  action       : {display}",
            "  schedule     : immediate",
            "  confirmation : not available",
            "  execution    : blocked (system supervisor gate not configured)",
            "  state        : no changes made",
        ])

    def _request_system_snapshot(self, tokens):
        if tokens:
            return f"error: unknown system snapshot option: {' '.join(tokens)}"
        return "\n".join([
            "System snapshot request:",
            "  action       : snapshot",
            "  target       : recovery media",
            "  execution    : blocked (snapshot backend not configured)",
            "  state        : no changes made",
        ])

    def _request_system_zeroize(self, tokens):
        if tokens:
            return f"error: unknown system zeroize option: {' '.join(tokens)}"
        return "\n".join([
            "System zeroize request:",
            "  action       : zeroize",
            "  confirmation : not available",
            "  execution    : blocked (factory reset gate not configured)",
            "  state        : no changes made",
        ])

    def _system_service_names(self):
        return ("ssh", "netconf", "restconf", "gnmi", "snmp")

    def _request_system_services(self, tokens):
        if not tokens:
            return "error: incomplete request system services command"
        if tokens[0] != "restart":
            return f"error: unknown system services target: {' '.join(tokens)}"
        if len(tokens) < 2:
            return "error: missing service name for request system services restart"
        if len(tokens) > 2:
            return f"error: unknown system services restart option: {' '.join(tokens[2:])}"
        service = tokens[1]
        if service not in self._system_service_names():
            return f"error: unknown system service: {service}"
        return "\n".join([
            "System service restart:",
            f"  service      : {service}",
            "  action       : restart",
            "  execution    : blocked (service supervisor gate not configured)",
            "  state        : no changes made",
        ])

    def _request_system_core_dumps(self, tokens):
        if not tokens:
            return "error: incomplete request system core-dumps command"
        if tokens[0] != "delete":
            return f"error: unknown system core-dumps target: {' '.join(tokens)}"
        if len(tokens) < 2:
            return "error: missing core dump file name or all"
        if len(tokens) > 2:
            return f"error: unknown system core-dumps delete option: {' '.join(tokens[2:])}"
        target = tokens[1]
        if target != "all" and os.path.basename(target) != target:
            return "error: core dump file must be a basename"
        entries = self._core_dump_entries()
        matches = entries if target == "all" else [
            entry for entry in entries
            if os.path.basename(entry["path"]) == target
        ]
        lines = [
            "System core dump delete:",
            f"  target       : {target}",
            f"  matched files: {len(matches)}",
        ]
        for entry in matches[:20]:
            lines.append(f"    {entry['path']}")
        if len(matches) > 20:
            lines.append("    ... output truncated to 20 files")
        lines.extend([
            "  execution    : blocked (core dump retention policy not configured)",
            "  state        : no changes made",
        ])
        return "\n".join(lines)

    def _request_system_storage(self, tokens):
        if tokens != ["cleanup"]:
            if not tokens:
                return "error: incomplete request system storage command"
            return f"error: unknown system storage target: {' '.join(tokens)}"
        cleanup_paths = [
            os.environ.get("NETLAB_SUPPORT_DIR", "/var/tmp/netlab-support"),
            self._config_archive_dir(),
            "/tmp",
        ]
        lines = [
            "System storage cleanup:",
            "  action       : cleanup",
            "  candidate paths:",
        ]
        for path in cleanup_paths:
            lines.append(f"    {path}")
        lines.extend([
            "  execution    : blocked (cleanup policy not configured)",
            "  state        : no changes made",
        ])
        return "\n".join(lines)

    def _request_system_configuration(self, tokens):
        if tokens == ["rescue", "save"]:
            path = self._rescue_config_path()
            regular_error = self._rescue_regular_file_error(path)
            if regular_error and regular_error != "missing":
                return regular_error
            try:
                text = self._active_config_as_set()
            except RuntimeError as exc:
                return f"error: {exc}"
            return self._write_config_file(path, text, "rescue configuration saved")
        if tokens == ["rescue", "delete"]:
            path = self._rescue_config_path()
            regular_error = self._rescue_regular_file_error(path)
            if regular_error:
                if regular_error == "missing":
                    return "rescue configuration not present"
                return regular_error
            try:
                os.unlink(path)
            except FileNotFoundError:
                return "rescue configuration not present"
            except OSError as exc:
                return f"error: cannot delete rescue configuration: {exc}"
            return "rescue configuration deleted"
        if tokens == ["archive"]:
            try:
                text = self._active_config_as_set()
            except RuntimeError as exc:
                return f"error: {exc}"
            path = self._next_config_archive_path()
            return self._write_config_file(path, text,
                                           "configuration archived")
        if len(tokens) == 3 and tokens[0] == "archive" and tokens[1] == "delete":
            path, error = self._archive_config_path(tokens[2])
            if error:
                return error
            regular_error = self._archive_regular_file_error(path, tokens[2])
            if regular_error:
                if regular_error == "missing":
                    return f"configuration archive not present: {tokens[2]}"
                return regular_error
            try:
                os.unlink(path)
            except FileNotFoundError:
                return f"configuration archive not present: {tokens[2]}"
            except OSError as exc:
                return f"error: cannot delete configuration archive: {exc}"
            return "configuration archive deleted"
        if not tokens:
            return "error: incomplete request system configuration command"
        return f"error: unknown system configuration target: {' '.join(tokens)}"

    def _request_system_software(self, tokens):
        if len(tokens) == 2 and tokens[0] == "validate":
            return self._request_system_software_validate(tokens[1])
        if tokens and tokens[0] == "add":
            return self._request_system_software_add(tokens[1:])
        if tokens and tokens[0] == "rollback":
            return self._request_system_software_rollback(tokens[1:])
        if not tokens:
            return "error: incomplete request system software command"
        return f"error: unknown system software target: {' '.join(tokens)}"

    def _request_system_software_validate(self, image_path):
        image, error = self._software_image_metadata(image_path)
        if error:
            return error
        return "\n".join([
            "Software image validation:",
            f"  image        : {image['path']}",
            f"  size         : {image['size']} bytes",
            f"  sha256       : {image['sha256']}",
            f"  signature    : {image['signature']}",
            "  verification : not performed (trust anchor not configured)",
            "  install      : not requested",
        ])

    def _request_system_software_add(self, tokens):
        if not tokens:
            return ("error: usage: request system software add <image-file> "
                    "[validate|no-validate] [no-copy] [reboot]")
        image_path = tokens[0]
        options = tokens[1:]
        allowed = {"validate", "no-validate", "no-copy", "reboot"}
        seen = set()
        for option in options:
            if option not in allowed:
                return f"error: unknown system software add option: {option}"
            if option in seen:
                return f"error: duplicate system software add option: {option}"
            seen.add(option)
        if "validate" in seen and "no-validate" in seen:
            return "error: validate and no-validate cannot be used together"

        image, error = self._software_image_metadata(image_path)
        if error:
            return error
        option_text = " ".join(options) if options else "validate"
        validation_text = (
            "blocked (trust anchor not configured)"
            if "no-validate" not in seen
            else "not requested (no-validate)")
        reboot_text = "blocked" if "reboot" in seen else "not requested"
        return "\n".join([
            "Software image add:",
            f"  image        : {image['path']}",
            f"  size         : {image['size']} bytes",
            f"  sha256       : {image['sha256']}",
            f"  signature    : {image['signature']}",
            f"  options      : {option_text}",
            f"  verification : {validation_text}",
            "  install      : blocked (image signing and A/B upgrade not configured)",
            f"  reboot       : {reboot_text}",
            "  state        : no changes made",
        ])

    def _request_system_software_rollback(self, tokens):
        target = "last successfully installed image"
        old_snapshot = "not requested"
        remaining = list(tokens)
        if remaining and remaining[0] != "with-old-snapshot-config":
            target = remaining.pop(0)
        for option in remaining:
            if option == "with-old-snapshot-config":
                if old_snapshot == "requested":
                    return "error: duplicate system software rollback option: with-old-snapshot-config"
                old_snapshot = "requested"
            else:
                return f"error: unknown system software rollback option: {option}"
        return "\n".join([
            "Software rollback:",
            f"  target              : {target}",
            f"  old snapshot config : {old_snapshot}",
            "  rollback image      : unavailable",
            "  A/B upgrade         : not configured",
            "  action              : blocked",
            "  state               : no changes made",
        ])

    def _software_image_metadata(self, image_path):
        path, stat, checksum, error = self._file_digest("sha256", image_path)
        if error:
            kind, detail = error
            if kind == "directory":
                return None, f"error: software image must be a regular file: {path}"
            if kind == "not-found":
                return None, f"error: file not found: {path}"
            return None, f"error: cannot read software image: {detail}"

        signature_path = path + ".sig"
        signature = "missing"
        try:
            sig_stat = os.stat(signature_path)
            if os.path.isdir(signature_path):
                signature = "present but not a regular file"
            else:
                signature = f"present ({sig_stat.st_size} bytes)"
        except FileNotFoundError:
            pass
        except OSError as exc:
            signature = f"unreadable ({exc})"
        return {
            "path": path,
            "size": stat.st_size,
            "sha256": checksum,
            "signature": signature,
        }, None

    def _config_store_dir(self):
        return os.environ.get("NETLAB_CONFIG_STORE_DIR",
                              "/var/lib/netlab/config")

    def _rescue_config_path(self):
        return os.path.join(self._config_store_dir(), "rescue.conf")

    def _rescue_regular_file_error(self, path=None):
        path = path or self._rescue_config_path()
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return "missing"
        except OSError as exc:
            return f"error: cannot access rescue configuration: {exc}"
        if not stat_module.S_ISREG(st.st_mode):
            return "error: rescue configuration must be a regular file"
        return None

    def _config_archive_dir(self):
        return os.path.join(self._config_store_dir(), "archive")

    def _archive_config_path(self, name):
        if not name or os.path.basename(name) != name or "/" in name:
            return None, "error: archive file must be a file name"
        if not name.endswith(".set"):
            return None, "error: archive file must end with .set"
        return os.path.join(self._config_archive_dir(), name), None

    def _archive_regular_file_error(self, path, name):
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return "missing"
        except OSError as exc:
            return f"error: cannot access configuration archive: {exc}"
        if not stat_module.S_ISREG(st.st_mode):
            return f"error: configuration archive must be a regular file: {name}"
        return None

    def _next_config_archive_path(self):
        return self._next_timestamped_file_path(
            self._config_archive_dir(), "configuration", ".set")

    def _next_timestamped_file_path(self, directory, prefix, suffix):
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        base = os.path.join(directory, f"{prefix}-{stamp}{suffix}")
        if not os.path.exists(base):
            return base
        for index in range(1, 1000):
            candidate = os.path.join(
                directory, f"{prefix}-{stamp}-{index:02d}{suffix}")
            if not os.path.exists(candidate):
                return candidate
        return os.path.join(
            directory, f"{prefix}-{stamp}-{os.getpid()}{suffix}")

    def _active_config_as_set(self):
        xml = self._get_config_xml(active=True).lstrip()
        if not xml.startswith("<"):
            if xml.startswith("error: "):
                xml = xml[7:]
            raise RuntimeError(xml if xml else "cannot read active configuration")
        return format_config_as_set(xml)

    def _write_config_file(self, path, text, success):
        try:
            os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
            tmp = f"{path}.tmp.{os.getpid()}"
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write(text)
                if text and not text.endswith("\n"):
                    handle.write("\n")
            os.replace(tmp, path)
        except OSError as exc:
            return f"error: cannot write configuration file: {exc}"
        statements = sum(1 for line in text.splitlines()
                         if line.strip().startswith("set "))
        return "\n".join([
            success,
            f"  file       : {path}",
            f"  statements : {statements}",
        ])

    def _request_chassis_port_mode(self, action):
        try:
            pid, log_path = start_background_action(action)
            return (
                "port-mode %s started in background\n"
                "  pid : %s\n"
                "  log : %s\n"
                "Reconnect after the switch stack restarts, then run "
                "\"show chassis port-mode\"."
            ) % (action, pid, log_path)
        except (OSError, subprocess.SubprocessError, PortModeError) as exc:
            return "error: failed to start port-mode %s: %s" % (action, exc)

    def _show(self, tokens):
        if not tokens:
            return "error: incomplete command"
        sub = tokens[0]
        if sub == "interfaces":
            return self._show_interfaces(tokens[1:])
        if sub == "vlans":
            return self._show_vlans(tokens[1:])
        if sub == "ethernet-switching":
            return self._show_eth_sw(tokens[1:])
        if sub == "firewall":
            return self._show_firewall(tokens[1:])
        if sub == "diagnostics":
            return self._show_diagnostics(tokens[1:])
        if sub == "log":
            return self._show_log(tokens[1:])
        if sub == "version":
            return self._show_version(tokens[1:])
        if sub == "configuration":
            return self._show_config(tokens[1:])
        if sub == "system":
            return self._show_system(tokens[1:])
        if sub == "ntp":
            return self._show_ntp(tokens[1:])
        if sub == "snmp":
            return self._show_snmp(tokens[1:])
        if sub == "chassis":
            return self._show_chassis(tokens[1:])
        if sub == "control-plane":
            return self._show_control_plane(tokens[1:])
        if sub == "class-of-service":
            return self._show_class_of_service(tokens[1:])
        if sub == "forwarding-options":
            return self._show_forwarding_options(tokens[1:])
        if sub == "igmp-snooping":
            return self._show_igmp_snooping(tokens[1:])
        if sub == "lldp":
            return self._show_lldp(tokens[1:])
        if sub == "lacp":
            return self._show_lacp(tokens[1:])
        if sub == "route":
            return self._show_route(tokens[1:])
        if sub == "arp":
            return self._show_arp(tokens[1:])
        if sub == "rpd":
            return self._show_rpd(tokens[1:])
        if sub == "ospf":
            return self._show_ospf(tokens[1:])
        if sub == "bgp":
            return self._show_bgp(tokens[1:])
        if sub == "spanning-tree":
            return self._show_spanning_tree(tokens[1:])
        return f"error: unknown show target: {sub}"

    def _show_firewall(self, tokens):
        if not tokens:
            resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
            text, unavailable = self._public_runtime_text("Firewall filters",
                                                          resp)
            if unavailable:
                return unavailable
            return format_acl_summary(text)
        if len(tokens) == 2 and tokens[0] == "family":
            if tokens[1] == "ethernet-switching":
                resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
                text, unavailable = self._public_runtime_text(
                    "Firewall ethernet-switching filters", resp)
                if unavailable:
                    return unavailable
                return format_ingress_acl(text)
            if tokens[1] == "inet":
                resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
                text, unavailable = self._public_runtime_text(
                    "Firewall inet filters", resp)
                if unavailable:
                    return unavailable
                return format_ingress_ipv4_acl(text)
        return f"error: unknown firewall target: {' '.join(tokens)}"

    def _show_diagnostics(self, tokens):
        if not tokens:
            return "error: incomplete diagnostics command"
        if tokens[0] == "forwarding":
            if len(tokens) == 1:
                return "error: incomplete diagnostics forwarding command"
            if len(tokens) >= 2 and tokens[1] == "runtime":
                if len(tokens) != 2:
                    return ("error: unknown diagnostics forwarding runtime "
                            f"target: {' '.join(tokens[2:])}")
                resp = self._public_runtime_rpc(DAEMON_SWITCHD, 66, b"")
                text, unavailable = self._public_runtime_text(
                    "Forwarding runtime", resp)
                if unavailable:
                    return unavailable
                return format_forwarding_runtime(text)
            if len(tokens) >= 2 and tokens[1] == "sdk":
                if len(tokens) != 2:
                    return ("error: unknown diagnostics forwarding runtime "
                            f"target: {' '.join(tokens[2:])}")
                return self._diagnostics_redirect(
                    "show diagnostics forwarding sdk",
                    "show diagnostics forwarding runtime")
            return self._show_chassis(["forwarding"] + tokens[1:],
                                      diagnostics=True)
        if tokens[0] == "l3":
            if len(tokens) == 1:
                return "error: incomplete diagnostics l3 command"
            return self._show_route(tokens[1:], diagnostics=True)
        if tokens[0] == "ethernet-switching":
            if len(tokens) == 1:
                return "error: incomplete diagnostics ethernet-switching command"
            return self._show_eth_sw(tokens[1:], diagnostics=True)
        if tokens[0] == "class-of-service":
            if len(tokens) == 1:
                return "error: incomplete diagnostics class-of-service command"
            return self._show_class_of_service(tokens[1:],
                                               diagnostics=True)
        return f"error: unknown diagnostics target: {' '.join(tokens)}"

    def _show_system(self, tokens):
        if tokens and tokens[0] == "management":
            return self._show_system_management(tokens[1:])
        if tokens and tokens[0] == "alarms":
            return self._show_system_alarms(tokens[1:])
        if tokens and tokens[0] == "uptime":
            return self._show_system_uptime(tokens[1:])
        if tokens and tokens[0] == "boot-messages":
            return self._show_system_boot_messages(tokens[1:])
        if tokens and tokens[0] == "memory":
            return self._show_system_memory(tokens[1:])
        if tokens and tokens[0] == "buffers":
            return self._show_system_buffers(tokens[1:])
        if tokens and tokens[0] == "queues":
            return self._show_system_queues(tokens[1:])
        if tokens and tokens[0] == "virtual-memory":
            return self._show_system_virtual_memory(tokens[1:])
        if tokens and tokens[0] == "processes":
            return self._show_system_processes(tokens[1:])
        if tokens and tokens[0] == "connections":
            return self._show_system_connections(tokens[1:])
        if tokens and tokens[0] == "statistics":
            return self._show_system_statistics(tokens[1:])
        if tokens and tokens[0] == "storage":
            return self._show_system_storage(tokens[1:])
        if tokens and tokens[0] == "core-dumps":
            return self._show_system_core_dumps(tokens[1:])
        if tokens and tokens[0] == "users":
            return self._show_system_users(tokens[1:])
        if tokens and tokens[0] == "login":
            return self._show_system_login(tokens[1:])
        if tokens and tokens[0] == "authentication":
            return self._show_system_authentication(tokens[1:])
        if tokens and tokens[0] == "radius-server":
            return self._show_system_auth_servers("radius-server", tokens[1:])
        if tokens and tokens[0] == "tacplus-server":
            return self._show_system_auth_servers("tacplus-server", tokens[1:])
        if tokens and tokens[0] == "accounting":
            return self._show_system_accounting(tokens[1:])
        if tokens and tokens[0] == "ntp":
            return self._show_system_ntp(tokens[1:])
        if tokens and tokens[0] == "syslog":
            return self._show_system_syslog(tokens[1:])
        if tokens and tokens[0] == "software":
            return self._show_system_software(tokens[1:])
        if tokens and tokens[0] == "license":
            return self._show_system_license(tokens[1:])
        if tokens and tokens[0] == "commit":
            return self._show_system_commit(tokens[1:])
        if tokens and tokens[0] == "rollback":
            return self._show_system_rollback(tokens[1:])
        if tokens and tokens[0] == "configuration":
            return self._show_system_configuration(tokens[1:])
        if tokens and tokens[0] == "services":
            return self._show_system_services(tokens[1:])
        if tokens:
            return f"error: unknown system target: {' '.join(tokens)}"
        return self._show_system_information()

    def _active_config_root(self):
        text = self._get_config_xml(active=True).lstrip()
        if not text.startswith("<"):
            return None, text if text else "error: cannot read active configuration"
        try:
            return ET.fromstring(text), None
        except ET.ParseError as exc:
            return None, f"error: cannot parse active configuration: {exc}"

    def _xml_child(self, elem, tag):
        if elem is None:
            return None
        for item in list(elem):
            if xml_local_name(item.tag) == tag:
                return item
        return None

    def _xml_children(self, elem, tag):
        if elem is None:
            return []
        return [item for item in list(elem) if xml_local_name(item.tag) == tag]

    def _show_system_management(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system management target: {' '.join(tokens)}"
        resp = self._public_runtime_rpc(DAEMON_MGMTD, 1, b"")
        text, unavailable = self._public_runtime_text("System management",
                                                      resp)
        if unavailable:
            return unavailable
        capability_resp = self._public_runtime_rpc(
            DAEMON_CONFIGD, 18, b"")
        capability_text, capability_unavailable = self._public_runtime_text(
            "Configuration authority", capability_resp)
        return format_mgmtd_status(
            text, capability_unavailable or capability_text)

    def _show_system_login(self, tokens=None):
        tokens = tokens or []
        user_filter = None
        if tokens:
            if len(tokens) == 2 and tokens[0] == "user":
                user_filter = tokens[1]
            else:
                return f"error: unknown system login target: {' '.join(tokens)}"
        root, error = self._active_config_root()
        if error:
            return error
        system = self._xml_child(root, "system")
        login = self._xml_child(system, "login")
        users = self._xml_children(login, "user")
        rows = []
        for user in users:
            name = xml_child_text(user, "name")
            if not name or (user_filter and name != user_filter):
                continue
            auth = self._xml_child(user, "authentication")
            methods = []
            if auth is not None and xml_child_text(auth, "encrypted-password"):
                methods.append("encrypted-password")
            if auth is not None and xml_child_text(auth, "ssh-rsa"):
                methods.append("ssh-rsa")
            rows.append((name, xml_child_text(user, "class") or "-",
                         ", ".join(methods) if methods else "-"))
        if user_filter and not rows:
            return f"System login: user {user_filter} not configured"
        if not rows:
            return "System login: no local users configured"
        lines = [
            "System login:",
            "  User             Class         Authentication",
        ]
        for name, login_class, auth_text in rows:
            lines.append(f"  {name:<16} {login_class:<13} {auth_text}")
        return "\n".join(lines)

    def _auth_method_list(self, system):
        order = self._xml_child(system, "authentication-order")
        methods = []
        for method in self._xml_children(order, "method"):
            name = xml_child_text(method, "name")
            if name:
                methods.append(name)
        return methods

    def _auth_server_rows(self, system, server_type):
        rows = []
        default_port = "1812" if server_type == "radius-server" else "49"
        for server in self._xml_children(system, server_type):
            address = xml_child_text(server, "address")
            if not address:
                continue
            rows.append({
                "address": address,
                "port": xml_child_text(server, "port") or default_port,
                "source": xml_child_text(server, "source-address") or "-",
                "timeout": xml_child_text(server, "timeout") or "-",
                "retry": xml_child_text(server, "retry") or "-",
                "secret": "configured" if xml_child_text(server, "secret")
                else "missing",
                "single": "yes" if xml_child_text(
                    server, "single-connection") == "true" else "no",
            })
        return rows

    def _show_system_authentication(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system authentication target: {' '.join(tokens)}"
        root, error = self._active_config_root()
        if error:
            return error
        system = self._xml_child(root, "system")
        methods = self._auth_method_list(system)
        radius = self._auth_server_rows(system, "radius-server")
        tacplus = self._auth_server_rows(system, "tacplus-server")
        order = " ".join(methods) if methods else "password (default)"
        return "\n".join([
            "System authentication:",
            f"  Authentication order : {order}",
            f"  Local users          : {len(self._xml_children(self._xml_child(system, 'login'), 'user'))}",
            f"  RADIUS servers       : {len(radius)}",
            f"  TACACS+ servers      : {len(tacplus)}",
            "  Runtime AAA          : local password only",
            "  Remote AAA state     : configuration intent only",
        ])

    def _show_system_auth_servers(self, server_type, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system {server_type} target: {' '.join(tokens)}"
        root, error = self._active_config_root()
        if error:
            return error
        system = self._xml_child(root, "system")
        rows = self._auth_server_rows(system, server_type)
        title = "RADIUS" if server_type == "radius-server" else "TACACS+"
        if not rows:
            return f"System {title} servers: not configured"
        lines = [
            f"System {title} servers:",
            "  Address          Port   Source address   Timeout Retry  Secret      Single",
        ]
        for row in rows:
            retry = row["retry"] if server_type == "radius-server" else "-"
            single = row["single"] if server_type == "tacplus-server" else "-"
            lines.append(
                f"  {row['address']:<16} {row['port']:<6} "
                f"{row['source']:<16} {row['timeout']:<7} "
                f"{retry:<6} {row['secret']:<11} {single}"
            )
        lines.extend([
            "",
            "State: configuration intent only; remote AAA runtime integration is pending.",
        ])
        return "\n".join(lines)

    def _show_system_accounting(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system accounting target: {' '.join(tokens)}"
        root, error = self._active_config_root()
        if error:
            return error
        system = self._xml_child(root, "system")
        accounting = self._xml_child(system, "accounting")
        events_node = self._xml_child(accounting, "events")
        events = []
        for event in self._xml_children(events_node, "event"):
            name = xml_child_text(event, "name")
            if name:
                events.append(name)
        events_text = " ".join(events) if events else "not configured"
        login_state = "intent configured" if "login" in events else "not configured"
        change_state = ("intent configured; see show system commit"
                        if "change-log" in events else "not configured")
        command_state = ("intent configured; local command log gate pending"
                         if "interactive-commands" in events
                         else "not configured")
        return "\n".join([
            "System accounting:",
            f"  Events            : {events_text}",
            f"  Login audit       : {login_state}",
            f"  Change audit      : {change_state}",
            f"  Command audit     : {command_state}",
            "  Remote accounting : not configured",
            "  State             : local audit intent only",
        ])

    def _show_system_ntp(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system ntp target: {' '.join(tokens)}"
        rows, error = self._ntp_server_rows()
        if error:
            return error
        if not rows:
            return "\n".join([
                "System NTP: not configured",
                "Runtime NTP state: configuration intent only",
            ])
        lines = [
            "System NTP:",
            "  Server           Prefer",
        ]
        for address, prefer in rows:
            lines.append(f"  {address:<16} {prefer}")
        lines.extend([
            "",
            "Runtime NTP state: configuration intent only; daemon sync is "
            "not reported here.",
        ])
        return "\n".join(lines)

    def _ntp_server_rows(self):
        root, error = self._active_config_root()
        if error:
            return [], error
        system = self._xml_child(root, "system")
        ntp = self._xml_child(system, "ntp")
        servers = self._xml_children(ntp, "server")
        rows = []
        for server in servers:
            address = xml_child_text(server, "address")
            if address:
                prefer = ("yes" if xml_child_text(server, "prefer") == "true"
                          else "no")
                rows.append((address, prefer))
        return rows, None

    def _show_ntp(self, tokens=None):
        tokens = tokens or []
        if not tokens:
            return self._show_system_ntp([])
        if len(tokens) != 1 or tokens[0] not in ("associations", "status"):
            return f"error: unknown ntp target: {' '.join(tokens)}"
        rows, error = self._ntp_server_rows()
        if error:
            return error
        if tokens[0] == "associations":
            if not rows:
                return "\n".join([
                    "NTP associations: not configured",
                    "Runtime NTP state: configuration intent only",
                ])
            lines = [
                "NTP associations:",
                "  Server           Prefer  Reach  Delay  Offset  Jitter",
            ]
            for address, prefer in rows:
                lines.append(f"  {address:<16} {prefer:<6} -      -      -       -")
            lines.extend([
                "",
                "Runtime NTP state: configuration intent only; daemon peer "
                "state is not reported here.",
            ])
            return "\n".join(lines)

        if not rows:
            return "\n".join([
                "NTP status: not configured",
                "Runtime NTP state: configuration intent only",
            ])
        preferred = ", ".join(address for address, prefer in rows
                              if prefer == "yes") or "-"
        lines = [
            "NTP status:",
            "  Synchronization : not reported",
            f"  Configured peers: {len(rows)}",
            f"  Preferred peers : {preferred}",
            "  Runtime state   : configuration intent only",
        ]
        return "\n".join(lines)

    def _snmp_summary(self):
        root, error = self._active_config_root()
        if error:
            return None, [], [], error
        snmp = self._xml_child(root, "snmp")
        communities = self._xml_children(snmp, "community")
        trap_groups = self._xml_children(snmp, "trap-group")
        return snmp, communities, trap_groups, None

    def _show_snmp(self, tokens=None):
        tokens = tokens or []
        if tokens and not (tokens == ["statistics"] or
                           tokens == ["statistics", "subagents"]):
            return f"error: unknown snmp target: {' '.join(tokens)}"
        snmp, communities, trap_groups, error = self._snmp_summary()
        if error:
            return error
        contact = xml_child_text(snmp, "contact") if snmp is not None else ""
        location = xml_child_text(snmp, "location") if snmp is not None else ""
        configured = bool(
            contact or location or communities or trap_groups
        )
        if tokens:
            lines = [
                "SNMP statistics:",
                "  Input packets   : not reported",
                "  Output packets  : not reported",
                "  Silent drops    : not reported",
                f"  Communities     : {len(communities)}",
                f"  Trap groups     : {len(trap_groups)}",
            ]
            if tokens == ["statistics", "subagents"]:
                lines.append("  Subagents       : not reported")
            lines.extend([
                "",
                "Runtime SNMP state: configuration intent only; packet "
                "counters are not reported here.",
            ])
            return "\n".join(lines)
        lines = [
            "SNMP:",
            f"  State       : {'configured/not-implemented' if configured else 'disabled'}",
            f"  Contact     : {contact or '-'}",
            f"  Location    : {location or '-'}",
            f"  Communities : {len(communities)}",
            f"  Trap groups : {len(trap_groups)}",
        ]
        if communities:
            lines.append("")
            lines.append("  Community         Authorization  Clients")
            for community in communities:
                clients = ", ".join(
                    xml_child_text(client, "address") or "-"
                    for client in self._xml_children(community, "clients"))
                lines.append(
                    f"  {xml_child_text(community, 'name') or '-':<17} "
                    f"{xml_child_text(community, 'authorization') or '-':<14} "
                    f"{clients or '-'}")
        if trap_groups:
            lines.append("")
            lines.append("  Trap group        Version  Targets")
            for group in trap_groups:
                targets = ", ".join(
                    xml_child_text(target, "address") or "-"
                    for target in self._xml_children(group, "targets"))
                lines.append(
                    f"  {xml_child_text(group, 'name') or '-':<17} "
                    f"{xml_child_text(group, 'version') or '-':<8} "
                    f"{targets or '-'}")
        lines.extend([
            "",
            "Runtime SNMP state: configuration intent only; use "
            "'show snmp statistics' for the packet-counter boundary.",
        ])
        return "\n".join(lines)

    def _show_system_syslog(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system syslog target: {' '.join(tokens)}"
        root, error = self._active_config_root()
        if error:
            return error
        system = self._xml_child(root, "system")
        syslog = self._xml_child(system, "syslog")
        rows = []
        for kind in ("host", "file"):
            for entry in self._xml_children(syslog, kind):
                target = xml_child_text(entry, "name")
                if target:
                    rows.append(
                        (kind, target, xml_child_text(entry, "any") or "-"))
        if not rows:
            return "\n".join([
                "System syslog: not configured",
                "Runtime syslog state: configuration intent only",
            ])
        lines = [
            "System syslog:",
            "  Type   Target             Any",
        ]
        for kind, target, level in rows:
            lines.append(f"  {kind:<6} {target:<18} {level}")
        lines.extend([
            "",
            "Runtime syslog state: configuration intent only; delivery "
            "status is not reported here.",
        ])
        return "\n".join(lines)

    def _show_system_users(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system users target: {' '.join(tokens)}"
        rows = []
        result = self._run_local_command(["who", "-u"], timeout=3)
        if not result.startswith("error:"):
            for raw in result.splitlines():
                parts = raw.split()
                if len(parts) < 3:
                    continue
                user = parts[0]
                line = parts[1]
                login_time = " ".join(parts[2:4]) if len(parts) >= 4 else parts[2]
                idle = parts[4] if len(parts) >= 5 else "-"
                pid = parts[5] if len(parts) >= 6 else "-"
                remote = parts[6].strip("()") if len(parts) >= 7 else "-"
                rows.append((user, line, remote, login_time, idle, pid))
        if not rows:
            user = (os.environ.get("USER") or os.environ.get("LOGNAME") or
                    "unknown")
            remote = os.environ.get("SSH_CONNECTION", "").split(" ", 1)[0]
            rows.append((user, os.environ.get("SSH_TTY", "-"),
                         remote or "local",
                         time.strftime("%Y-%m-%d %H:%M",
                                       time.localtime()), "-", str(os.getpid())))
        lines = [
            "System users:",
            "  User       Terminal     From             Login time        Idle   PID",
        ]
        for user, line, remote, login_time, idle, pid in rows:
            lines.append(
                f"  {user:<10} {line:<12} {remote:<16} "
                f"{login_time:<17} {idle:<6} {pid}"
            )
        return "\n".join(lines)

    def _show_system_services(self, tokens=None):
        tokens = tokens or []
        text = self._get_config_xml(active=True).lstrip()
        if not text.startswith("<"):
            return text if text else "error: cannot read active configuration"
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            return f"error: cannot parse active configuration: {exc}"

        def child(elem, tag):
            if elem is None:
                return None
            for item in list(elem):
                if xml_local_name(item.tag) == tag:
                    return item
            return None

        def child_text(elem, tag):
            item = child(elem, tag)
            if item is None or item.text is None:
                return ""
            return item.text.strip()

        def list_count(elem, tag):
            if elem is None:
                return 0
            return sum(1 for item in list(elem)
                       if xml_local_name(item.tag) == tag)

        def children(elem, tag):
            if elem is None:
                return []
            return [item for item in list(elem) if xml_local_name(item.tag) == tag]

        system = child(root, "system")
        services = child(system, "services")
        snmp = child(root, "snmp")

        ssh = child(services, "ssh")
        ssh_enabled = child_text(ssh, "enable") == "true"
        ssh_root_login = child_text(ssh, "root-login")
        netconf = child(services, "netconf")
        restconf = child(services, "restconf")
        gnmi = child(services, "gnmi")
        gnmi_grpc = child_text(gnmi, "grpc") == "true"
        gnmi_port = child_text(gnmi, "port")

        snmp_configured = False
        if snmp is not None:
            snmp_configured = bool(
                child_text(snmp, "contact") or
                child_text(snmp, "location") or
                list_count(snmp, "community") or
                list_count(snmp, "trap-group")
            )

        ssh_configured = bool(ssh_enabled or ssh_root_login)
        netconf_configured = child_text(netconf, "ssh") == "true"
        restconf_configured = child_text(restconf, "https") == "true"
        gnmi_configured = bool(gnmi_grpc or gnmi_port)

        def intent_state(configured):
            return "configured/not-implemented" if configured else "disabled"

        rows = [
            ("ssh", intent_state(ssh_configured),
             f"root-login={ssh_root_login or '-'}"),
            ("netconf", intent_state(netconf_configured), "transport=ssh"),
            ("restconf", intent_state(restconf_configured), "transport=https"),
            ("gnmi", intent_state(gnmi_configured),
             f"transport=grpc port={gnmi_port or '57400'}"),
            ("snmp", intent_state(snmp_configured),
             f"communities={list_count(snmp, 'community')} "
             f"trap-groups={list_count(snmp, 'trap-group')}"),
        ]
        if tokens:
            if len(tokens) != 1:
                return f"error: unknown system services target: {' '.join(tokens)}"
            service = tokens[0]
            states = {name: (state, detail) for name, state, detail in rows}
            if service not in states:
                return f"error: unknown system services target: {service}"
            state, detail = states[service]
            lines = [
                f"System service: {service}",
                f"  State  : {state}",
                f"  Detail : {detail}",
            ]
            if service == "ssh":
                lines.extend([
                    f"  Configured : {'yes' if ssh_configured else 'no'}",
                    f"  Root login : {ssh_root_login or '-'}",
                ])
            elif service == "netconf":
                lines.append(
                    f"  SSH intent    : {'configured' if netconf_configured else 'disabled'}")
            elif service == "restconf":
                lines.append(
                    f"  HTTPS intent  : {'configured' if restconf_configured else 'disabled'}")
            elif service == "gnmi":
                lines.extend([
                    f"  gRPC intent    : {'configured' if gnmi_grpc else 'disabled'}",
                    f"  TCP port       : {gnmi_port or '57400'}",
                ])
            elif service == "snmp":
                contact = child_text(snmp, "contact") or "-"
                location = child_text(snmp, "location") or "-"
                lines.extend([
                    f"  Contact     : {contact}",
                    f"  Location    : {location}",
                    f"  Communities : {list_count(snmp, 'community')}",
                    f"  Trap groups : {list_count(snmp, 'trap-group')}",
                ])
                communities = children(snmp, "community")
                if communities:
                    lines.append("")
                    lines.append("  Community         Authorization  Clients")
                    for community in communities:
                        clients = ", ".join(
                            child_text(client, "address") or "-"
                            for client in children(community, "clients"))
                        lines.append(
                            f"  {child_text(community, 'name') or '-':<17} "
                            f"{child_text(community, 'authorization') or '-':<14} "
                            f"{clients or '-'}")
                trap_groups = children(snmp, "trap-group")
                if trap_groups:
                    lines.append("")
                    lines.append("  Trap group        Version  Targets")
                    for group in trap_groups:
                        targets = ", ".join(
                            child_text(target, "address") or "-"
                            for target in children(group, "targets"))
                        lines.append(
                            f"  {child_text(group, 'name') or '-':<17} "
                            f"{child_text(group, 'version') or '-':<8} "
                            f"{targets or '-'}")
            lines.append("")
            lines.append("Runtime owner: not implemented; configuration intent is "
                         "not an enabled listener.")
            return "\n".join(lines)

        lines = [
            "System services:",
            "  Service    State       Detail",
        ]
        for service, state, detail in rows:
            lines.append(f"  {service:<10} {state:<11} {detail}")
        lines.append("")
        lines.append("Runtime owner: not implemented; configured intent does not "
                     "mean that a listener is enabled.")
        return "\n".join(lines)

    def _show_system_software(self, tokens):
        if tokens:
            return f"error: unknown system software target: {' '.join(tokens)}"
        profile = {}
        try:
            profile = load_profile().get("platform", {})
        except Exception:
            profile = {}
        runtime = []
        if profile.get("chassis-name"):
            runtime.append(profile.get("chassis-name"))
        if profile.get("port-mode"):
            runtime.append(profile.get("port-mode"))
        if profile.get("network-services"):
            runtime.append(profile.get("network-services"))
        runtime_text = " / ".join(runtime) if runtime else "-"
        return "\n".join([
            "System software:",
            "  Package          : NetLab Switch OS",
            f"  Version          : {os.environ.get('NETLAB_VERSION', 'development')}",
            f"  Build revision   : {self._git_revision()}",
            f"  Kernel           : {self._kernel_version()}",
            f"  Host platform    : {self._host_platform()}",
            f"  Runtime mode     : {runtime_text}",
            "  Install state    : read-only inventory",
            "  Image validation : request system software validate <image-file>",
            "  Image install    : request system software add <image-file> (blocked)",
            "  Image signing    : trust anchor not configured",
            "  A/B upgrade      : not configured",
            "  Rollback image   : unavailable",
            "  Rollback command : request system software rollback (blocked)",
        ])

    def _show_system_license(self, tokens):
        if tokens:
            return f"error: unknown system license target: {' '.join(tokens)}"
        return "\n".join([
            "System license:",
            "  State            : not configured",
            "  License store    : unavailable",
            "  Enforcement      : not active",
            "  Managed features : base switching/routing mode",
            "  Expiration       : not applicable",
            "  Runtime boundary : features are governed by build/platform gates",
            "  Install command  : not available",
        ])

    def _show_version(self, tokens):
        if tokens:
            return f"error: unknown version target: {' '.join(tokens)}"
        profile = {}
        try:
            profile = load_profile().get("platform", {})
        except Exception:
            profile = {}
        return "\n".join([
            "NetLab Switch OS",
            f"  Software version : {os.environ.get('NETLAB_VERSION', 'development')}",
            f"  Build revision   : {self._git_revision()}",
            f"  Kernel           : {self._kernel_version()}",
            f"  Host platform    : {self._host_platform()}",
            f"  Chassis mode     : {profile.get('chassis-name') or '-'}",
            f"  Port mode        : {profile.get('port-mode') or '-'}",
            f"  Network services : {profile.get('network-services') or '-'}",
        ])

    def _repo_root(self):
        return os.environ.get(
            "NETLAB_ROOT",
            os.path.abspath(os.path.join(os.path.dirname(__file__),
                                         "..", "..")),
        )

    def _git_revision(self):
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "--short=12", "HEAD"],
                cwd=self._repo_root(),
                stderr=subprocess.DEVNULL,
                universal_newlines=True,
                timeout=2,
            ).strip()
        except Exception:
            return "unknown"

    def _kernel_version(self):
        try:
            uname = os.uname()
            return f"{uname.sysname} {uname.release} {uname.machine}"
        except Exception:
            return "unknown"

    def _host_platform(self):
        try:
            return os.uname().nodename
        except Exception:
            return "unknown"

    def _show_system_alarms(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system alarms target: {' '.join(tokens)}"
        return "\n".join([
            "System alarms:",
            "  No active system alarms",
            "",
            "State: read-only system alarm facade; use 'show chassis alarms' "
            "for chassis sensor alarms.",
        ])

    def _show_system_uptime(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system uptime target: {' '.join(tokens)}"
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as handle:
                uptime_seconds = int(float(handle.read().split()[0]))
        except Exception:
            uptime_seconds = 0
        now = int(time.time())
        booted = now - uptime_seconds if uptime_seconds else 0
        lines = [
            "System uptime:",
            "  Current time : %s" % time.strftime(
                "%Y-%m-%d %H:%M:%S %Z", time.localtime(now)),
        ]
        if booted:
            lines.extend([
                "  System booted: %s" % time.strftime(
                    "%Y-%m-%d %H:%M:%S %Z", time.localtime(booted)),
                f"  Uptime       : {self._format_duration(uptime_seconds)}",
            ])
        else:
            lines.append("  Uptime       : unknown")
        lines.extend([
            "",
            "State: host uptime inventory only; no configuration or hardware "
            "state is changed.",
        ])
        return "\n".join(lines)

    def _show_system_boot_messages(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system boot-messages target: {' '.join(tokens)}"
        source, rows = self._host_boot_message_rows()
        lines = [
            "System boot messages:",
            f"  Source: {source}",
        ]
        if rows:
            lines.append("")
            lines.extend(f"  {row}" for row in rows)
        else:
            lines.extend([
                "  boot message inventory unavailable",
            ])
        lines.extend([
            "",
            "State: read-only boot message inventory; no configuration or "
            "hardware state is changed.",
        ])
        return "\n".join(lines)

    def _host_boot_message_rows(self, limit=80):
        for path in self._boot_message_files():
            rows = self._head_text_file(path, limit)
            if rows:
                return path, rows
        result = self._run_local_command(["dmesg", "--ctime"], timeout=5)
        if result and not result.startswith("error:"):
            lowered = result.lower()
            if ("operation not permitted" not in lowered and
                    "read kernel buffer failed" not in lowered):
                rows = [line.rstrip() for line in result.splitlines()
                        if line.strip()]
                if rows:
                    return "dmesg --ctime", rows[:limit]
        return "unavailable", []

    def _boot_message_files(self):
        paths = []
        env = os.environ.get("NETLAB_BOOT_MESSAGES_FILE")
        if env:
            paths.append(env)
        for path in ("/var/log/dmesg", "/var/log/boot.log"):
            if path not in paths:
                paths.append(path)
        return paths

    def _head_text_file(self, path, limit):
        if not path:
            return []
        try:
            if not os.path.isfile(path):
                return []
            rows = []
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    text = line.rstrip("\n")
                    if not text.strip():
                        continue
                    rows.append(text)
                    if len(rows) >= limit:
                        break
            return rows
        except OSError:
            return []

    def _format_duration(self, seconds):
        seconds = max(0, int(seconds))
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, secs = divmod(rem, 60)
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours or parts:
            parts.append(f"{hours}h")
        if minutes or parts:
            parts.append(f"{minutes}m")
        parts.append(f"{secs}s")
        return " ".join(parts)

    def _show_system_memory(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system memory target: {' '.join(tokens)}"
        meminfo = self._proc_meminfo()
        lines = [
            "System memory:",
        ]
        if not meminfo:
            lines.extend([
                "  memory inventory unavailable",
                "",
                "State: host memory inventory only; no configuration or "
                "hardware state is changed.",
            ])
            return "\n".join(lines)
        total = meminfo.get("MemTotal", 0)
        free = meminfo.get("MemFree", 0)
        available = meminfo.get("MemAvailable", free)
        buffers = meminfo.get("Buffers", 0)
        cached = meminfo.get("Cached", 0)
        slab = meminfo.get("Slab", 0)
        used = max(0, total - available) if total else 0
        swap_total = meminfo.get("SwapTotal", 0)
        swap_free = meminfo.get("SwapFree", 0)
        swap_used = max(0, swap_total - swap_free) if swap_total else 0
        lines.extend([
            f"  Total        : {self._human_bytes(total)}",
            f"  Used         : {self._human_bytes(used)}",
            f"  Available    : {self._human_bytes(available)}",
            f"  Free         : {self._human_bytes(free)}",
            f"  Buffers      : {self._human_bytes(buffers)}",
            f"  Cached       : {self._human_bytes(cached)}",
            f"  Slab         : {self._human_bytes(slab)}",
            f"  Swap total   : {self._human_bytes(swap_total)}",
            f"  Swap used    : {self._human_bytes(swap_used)}",
            "  Source       : host /proc/meminfo",
            "",
            "State: host memory inventory only; no configuration or "
            "hardware state is changed.",
        ])
        return "\n".join(lines)

    def _show_system_virtual_memory(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system virtual-memory target: {' '.join(tokens)}"
        meminfo = self._proc_meminfo()
        vmstat = self._proc_vmstat()
        lines = [
            "System virtual memory:",
            "  Memory:",
        ]
        if meminfo:
            total = meminfo.get("MemTotal", 0)
            free = meminfo.get("MemFree", 0)
            available = meminfo.get("MemAvailable", free)
            lines.extend([
                f"    Total      : {self._human_bytes(total)}",
                f"    Free       : {self._human_bytes(free)}",
                f"    Available  : {self._human_bytes(available)}",
                f"    Dirty      : {self._human_bytes(meminfo.get('Dirty', 0))}",
                f"    Writeback  : {self._human_bytes(meminfo.get('Writeback', 0))}",
                f"    Swap total : {self._human_bytes(meminfo.get('SwapTotal', 0))}",
                f"    Swap free  : {self._human_bytes(meminfo.get('SwapFree', 0))}",
                f"    Swap cached: {self._human_bytes(meminfo.get('SwapCached', 0))}",
            ])
        else:
            lines.append("    unavailable")
        lines.append("  VM counters:")
        wanted = [
            ("pgfault", "Page faults"),
            ("pgmajfault", "Major faults"),
            ("pgpgin", "Page in"),
            ("pgpgout", "Page out"),
            ("pswpin", "Swap in"),
            ("pswpout", "Swap out"),
            ("pgalloc_normal", "Page alloc normal"),
            ("pgfree", "Page free"),
        ]
        found = False
        for key, label in wanted:
            if key not in vmstat:
                continue
            found = True
            lines.append(f"    {label:<17}: {vmstat[key]}")
        if not found:
            lines.append("    unavailable")
        lines.extend([
            "  Source       : host /proc/meminfo and /proc/vmstat",
            "",
            "State: host virtual memory counters only; no configuration or "
            "hardware state is changed.",
        ])
        return "\n".join(lines)

    def _show_system_buffers(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system buffers target: {' '.join(tokens)}"
        meminfo = self._proc_meminfo()
        sockstat = self._proc_sockstat("/proc/net/sockstat")
        sockstat6 = self._proc_sockstat("/proc/net/sockstat6")
        lines = [
            "System buffers:",
            "  Memory buffers:",
        ]
        if meminfo:
            memory_items = [
                ("Buffers", "Buffers"),
                ("Cached", "Cached"),
                ("SwapCached", "Swap cached"),
                ("Active(file)", "Active file"),
                ("Inactive(file)", "Inactive file"),
                ("Shmem", "Shared memory"),
                ("Slab", "Slab"),
                ("SReclaimable", "Reclaimable slab"),
                ("SUnreclaim", "Unreclaimable slab"),
            ]
            for key, label in memory_items:
                if key in meminfo:
                    lines.append(
                        f"    {label:<18}: {self._human_bytes(meminfo[key])}")
        else:
            lines.append("    unavailable")
        lines.append("  Socket buffers:")
        socket_rows = self._socket_buffer_rows(sockstat, sockstat6)
        if socket_rows:
            lines.extend(socket_rows)
        else:
            lines.append("    unavailable")
        lines.extend([
            "  Source       : host /proc/meminfo and /proc/net/sockstat",
            "",
            "State: host buffer counters only; no configuration or hardware "
            "state is changed.",
        ])
        return "\n".join(lines)

    def _socket_buffer_rows(self, sockstat, sockstat6):
        rows = []
        for label, stats in (("IPv4", sockstat), ("IPv6", sockstat6)):
            for proto in sorted(stats):
                values = stats.get(proto) or {}
                if not values:
                    continue
                summary = " ".join(
                    f"{key}={values[key]}" for key in sorted(values))
                rows.append(f"    {label:<4} {proto:<8}: {summary}")
        return rows[:20]

    def _show_system_queues(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system queues target: {' '.join(tokens)}"
        sysv_rows, sysv_available = self._sysvipc_msg_rows()
        posix_rows, posix_available = self._posix_mqueue_rows()
        lines = [
            "System queues:",
            "  System V message queues:",
        ]
        if not sysv_available:
            lines.append("    unavailable")
        elif not sysv_rows:
            lines.append("    none")
        else:
            lines.append("    Queue ID     Bytes      Messages   UID     Last send   Last receive")
            for row in sysv_rows[:20]:
                lines.append(
                    f"    {row.get('msqid', '-'):<12} "
                    f"{row.get('cbytes', '-'):<10} "
                    f"{row.get('qnum', '-'):<10} "
                    f"{row.get('uid', '-'):<7} "
                    f"{self._format_epoch(row.get('stime')):<11} "
                    f"{self._format_epoch(row.get('rtime'))}"
                )
            if len(sysv_rows) > 20:
                lines.append("    ... output truncated to 20 queues")
        lines.append("  POSIX message queues:")
        if not posix_available:
            lines.append("    unavailable")
        elif not posix_rows:
            lines.append("    none")
        else:
            for name, detail in posix_rows[:20]:
                lines.append(f"    {name:<24} {detail}")
            if len(posix_rows) > 20:
                lines.append("    ... output truncated to 20 queues")
        lines.extend([
            "  Source       : host /proc/sysvipc/msg and /dev/mqueue",
            "",
            "State: host queue inventory only; no configuration or hardware "
            "state is changed.",
        ])
        return "\n".join(lines)

    def _sysvipc_msg_rows(self, path="/proc/sysvipc/msg"):
        rows = []
        try:
            with open(path, "r", encoding="utf-8") as handle:
                header = None
                for line in handle:
                    parts = line.split()
                    if not parts:
                        continue
                    if header is None:
                        header = parts
                        continue
                    rows.append(dict(zip(header, parts)))
        except OSError:
            return [], False
        return rows, True

    def _posix_mqueue_rows(self, root="/dev/mqueue"):
        if not os.path.isdir(root):
            return [], False
        rows = []
        try:
            names = sorted(os.listdir(root))
        except OSError:
            return [], False
        for name in names:
            path = os.path.join(root, name)
            if not os.path.isfile(path):
                continue
            detail = "-"
            try:
                with open(path, "r", encoding="utf-8",
                          errors="replace") as handle:
                    detail = (handle.readline() or "").strip() or "-"
            except OSError:
                detail = "unreadable"
            rows.append((name, detail))
        return rows, True

    def _format_epoch(self, raw):
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return "-"
        if value <= 0:
            return "-"
        return time.strftime("%H:%M:%S", time.localtime(value))

    def _proc_meminfo(self):
        meminfo = {}
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as handle:
                for line in handle:
                    if ":" not in line:
                        continue
                    key, raw_value = line.split(":", 1)
                    parts = raw_value.split()
                    if not parts:
                        continue
                    try:
                        value = int(parts[0])
                    except ValueError:
                        continue
                    unit = parts[1].lower() if len(parts) > 1 else "b"
                    multiplier = 1024 if unit == "kb" else 1
                    meminfo[key] = value * multiplier
        except OSError:
            return {}
        return meminfo

    def _proc_vmstat(self):
        stats = {}
        try:
            with open("/proc/vmstat", "r", encoding="utf-8") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) != 2:
                        continue
                    try:
                        stats[parts[0]] = int(parts[1])
                    except ValueError:
                        continue
        except OSError:
            return {}
        return stats

    def _proc_sockstat(self, path):
        stats = {}
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    if ":" not in line:
                        continue
                    proto, raw_values = line.split(":", 1)
                    parts = raw_values.split()
                    values = {}
                    for index in range(0, len(parts) - 1, 2):
                        try:
                            values[parts[index]] = int(parts[index + 1])
                        except ValueError:
                            continue
                    stats[proto] = values
        except OSError:
            return {}
        return stats

    def _show_system_processes(self, tokens=None):
        tokens = tokens or []
        extensive = False
        if tokens:
            if len(tokens) == 1 and tokens[0] == "extensive":
                extensive = True
            else:
                return f"error: unknown system processes target: {' '.join(tokens)}"
        fields = "pid,ppid,stat,etime,comm,args"
        if extensive:
            fields = "pid,ppid,user,stat,pcpu,pmem,vsz,rss,etime,comm,args"
        result = self._run_local_command(
            ["ps", "-eo", fields],
            timeout=5,
        )
        if result.startswith("error:"):
            return result
        rows = [line.rstrip() for line in result.splitlines() if line.strip()]
        lines = ["System processes:"]
        if extensive:
            lines.append("View: extensive")
        lines.extend(rows[:80])
        if len(rows) > 80:
            lines.append("... output truncated to 80 lines")
        lines.extend([
            "",
            "State: host process inventory only; no configuration or hardware "
            "state is changed.",
        ])
        return "\n".join(lines)

    def _show_system_connections(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system connections target: {' '.join(tokens)}"
        lines = ["System connections:"]
        for command in (["ss", "-tunap"], ["netstat", "-an"]):
            result = self._run_local_command(command, timeout=5)
            if result and not result.startswith("error:"):
                rows = [line.rstrip() for line in result.splitlines()
                        if line.strip()]
                if rows:
                    lines.extend(rows[:80])
                    if len(rows) > 80:
                        lines.append("... output truncated to 80 lines")
                    lines.extend([
                        "",
                        "State: host socket inventory only; no configuration or "
                        "hardware state is changed.",
                    ])
                    return "\n".join(lines)
        lines.extend([
            "  connection table unavailable",
            "",
            "State: host socket inventory only; no configuration or hardware "
            "state is changed.",
        ])
        return "\n".join(lines)

    def _show_system_statistics(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system statistics target: {' '.join(tokens)}"
        stats = self._proc_net_snmp_stats()
        lines = [
            "System statistics:",
            "  Protocol  Metric             Value",
        ]
        if not stats:
            lines.append("  -         unavailable        -")
        wanted = {
            "Ip": ("InReceives", "OutRequests", "InDiscards", "OutDiscards"),
            "Icmp": ("InMsgs", "OutMsgs", "InErrors", "OutErrors"),
            "Tcp": ("ActiveOpens", "PassiveOpens", "InSegs", "OutSegs"),
            "Udp": ("InDatagrams", "OutDatagrams", "InErrors", "NoPorts"),
        }
        for proto, metrics in wanted.items():
            values = stats.get(proto, {})
            for metric in metrics:
                if metric in values:
                    lines.append(
                        f"  {proto:<8} {metric:<18} {values[metric]}")
        lines.extend([
            "",
            "State: host kernel counters only; no configuration or hardware "
            "state is changed.",
        ])
        return "\n".join(lines)

    def _proc_net_snmp_stats(self):
        try:
            with open("/proc/net/snmp", "r", encoding="utf-8") as handle:
                raw_lines = [line.strip() for line in handle if line.strip()]
        except OSError:
            return {}
        stats = {}
        i = 0
        while i + 1 < len(raw_lines):
            header = raw_lines[i].split()
            values = raw_lines[i + 1].split()
            i += 2
            if not header or not values:
                continue
            proto = header[0].rstrip(":")
            if proto != values[0].rstrip(":"):
                continue
            keys = [item.rstrip(":") for item in header[1:]]
            stats[proto] = dict(zip(keys, values[1:]))
        return stats

    def _show_system_storage(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system storage target: {' '.join(tokens)}"
        paths = []
        for path in ("/", "/var", "/tmp", self._config_store_dir()):
            if path not in paths:
                paths.append(path)
        lines = [
            "System storage:",
            "  Filesystem                 Size       Used      Avail     Use%",
        ]
        for path in paths:
            probe = path
            while probe and not os.path.exists(probe):
                parent = os.path.dirname(probe)
                if parent == probe:
                    break
                probe = parent
            try:
                usage = shutil.disk_usage(probe or path)
            except OSError as exc:
                lines.append(f"  {path:<24s} unavailable: {exc}")
                continue
            used = usage.total - usage.free
            pct = int(round((used / usage.total) * 100)) if usage.total else 0
            lines.append(
                f"  {path:<24s} {self._human_bytes(usage.total):>8s} "
                f"{self._human_bytes(used):>8s} "
                f"{self._human_bytes(usage.free):>8s} {pct:>7d}%"
            )
        lines.extend([
            "",
            "State: host filesystem usage only; no configuration or hardware "
            "state is changed.",
        ])
        return "\n".join(lines)

    def _core_dump_dirs(self):
        env = os.environ.get("NETLAB_CORE_DUMP_DIR")
        raw_paths = env.split(os.pathsep) if env else [
            "/var/crash",
            "/var/tmp",
            "/var/core",
        ]
        paths = []
        for path in raw_paths:
            if path and path not in paths:
                paths.append(path)
        return paths

    def _is_core_dump_name(self, name):
        lowered = name.lower()
        return (
            lowered == "core" or
            lowered.startswith("core.") or
            lowered.startswith("core-") or
            lowered.endswith(".core") or
            ".core." in lowered
        )

    def _core_dump_entries(self):
        entries = []
        seen = set()
        for directory in self._core_dump_dirs():
            try:
                names = os.listdir(directory)
            except OSError:
                continue
            for name in names:
                if not self._is_core_dump_name(name):
                    continue
                path = os.path.join(directory, name)
                if path in seen:
                    continue
                try:
                    stat = os.stat(path)
                except OSError:
                    continue
                if not os.path.isfile(path):
                    continue
                seen.add(path)
                entries.append({
                    "path": path,
                    "size": stat.st_size,
                    "mtime": stat.st_mtime,
                })
        entries.sort(key=lambda item: (-item["mtime"], item["path"]))
        return entries

    def _show_system_core_dumps(self, tokens=None):
        tokens = tokens or []
        if tokens:
            return f"error: unknown system core-dumps target: {' '.join(tokens)}"
        lines = [
            "System core dumps:",
            "  File                                     Size      Modified",
        ]
        entries = self._core_dump_entries()
        if not entries:
            lines.append("  No core dumps found")
        for entry in entries[:80]:
            modified = time.strftime("%Y-%m-%d %H:%M:%S",
                                     time.localtime(entry["mtime"]))
            lines.append(
                f"  {entry['path']:<40.40s} "
                f"{self._human_bytes(entry['size']):>8s} {modified}"
            )
        if len(entries) > 80:
            lines.append("  ... output truncated to 80 files")
        lines.extend([
            "",
            "State: read-only core file inventory; no files are removed.",
        ])
        return "\n".join(lines)

    def _human_bytes(self, value):
        value = float(value)
        for unit in ("B", "K", "M", "G", "T"):
            if value < 1024 or unit == "T":
                if unit == "B":
                    return f"{int(value)}{unit}"
                return f"{value:.1f}{unit}"
            value /= 1024
        return f"{int(value)}B"

    def _run_local_command(self, args, timeout=10):
        try:
            proc = subprocess.run(args, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  universal_newlines=True,
                                  timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return f"error: cannot run {' '.join(args)}: {exc}"
        text = proc.stdout
        if proc.returncode != 0 and proc.stderr:
            text += proc.stderr
        return text.rstrip("\n")

    def _request_support_information(self):
        support_dir = os.environ.get("NETLAB_SUPPORT_DIR",
                                     "/var/tmp/netlab-support")
        path = self._next_timestamped_file_path(
            support_dir, "support-info", ".txt")
        commands = [
            "show version",
            "show system",
            "show system alarms",
            "show system uptime",
            "show system boot-messages",
            "show system memory",
            "show system buffers",
            "show system queues",
            "show system virtual-memory",
            "show system storage",
            "show system core-dumps",
            "show system software",
            "show system license",
            "show system users",
            "show system login",
            "show system connections",
            "show system statistics",
            "show system authentication",
            "show system radius-server",
            "show system tacplus-server",
            "show system accounting",
            "show system ntp",
            "show system syslog",
            "show ntp associations",
            "show snmp statistics",
            "show system processes",
            "show system processes extensive",
            "show system commit",
            "show system commit confirmed",
            "show system rollback",
            "show system configuration",
            "show chassis hardware",
            "show chassis alarms",
            "show chassis environment",
            "show chassis routing-engine",
            "show chassis port-mode",
            "show interfaces terse",
            "show route summary",
            "show log",
            "show configuration | display set",
        ]
        lines = [
            "NetLab support information",
            "Generated: %s" % time.strftime("%Y-%m-%d %H:%M:%S %Z",
                                            time.localtime()),
            "",
        ]
        for command in commands:
            lines.extend([f"## {command}", ""])
            try:
                output = self.dispatch(command)
            except Exception as exc:
                output = f"error: {exc}"
            lines.append((output or "").rstrip("\n"))
            lines.append("")
        try:
            os.makedirs(support_dir, mode=0o750, exist_ok=True)
            tmp = f"{path}.tmp.{os.getpid()}"
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines).rstrip("\n") + "\n")
            os.replace(tmp, path)
        except OSError as exc:
            return f"error: cannot write support information: {exc}"
        return "\n".join([
            "Support information written",
            f"  file : {path}",
            f"  commands : {len(commands)}",
        ])

    def _known_log_files(self):
        system_dir = os.environ.get("NETLAB_SYSTEM_LOG_DIR", "/var/log")
        netlab_dir = os.environ.get("NETLAB_LOG_DIR", "/var/log/netlab")
        logs = {
            "messages": os.path.join(system_dir, "messages"),
            "secure": os.path.join(system_dir, "secure"),
            "boot": os.path.join(system_dir, "boot.log"),
        }
        for name in (
                "mgmtd", "configd", "ifd", "l2d", "rpd",
                "switchd", "packetd", "stpd", "lldpd", "lacpd",
                "chassisd", "statsd", "linkmond", "supervisor"):
            logs[name] = os.path.join(netlab_dir, f"{name}.log")
        return logs

    def _show_log(self, tokens):
        logs = self._known_log_files()
        if not tokens:
            lines = ["Log files:"]
            for name in sorted(logs):
                path = logs[name]
                try:
                    stat = os.stat(path)
                    status = "%8d bytes  %s" % (
                        stat.st_size,
                        time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(stat.st_mtime)),
                    )
                except FileNotFoundError:
                    status = "not present"
                except OSError as exc:
                    status = f"unavailable: {exc}"
                lines.append(f"  {name:<12} {status}  {path}")
            return "\n".join(lines)
        if len(tokens) != 1:
            return "error: usage: show log [log-name]"
        name = tokens[0]
        if name.endswith(".log"):
            name = name[:-4]
        path = logs.get(name)
        if not path:
            return f"error: unknown log file: {tokens[0]}"
        text, error, truncated = self._read_text_file(path, tail_lines=100)
        if error:
            return f"Log file: {name}\nPath: {path}\n{error}"
        header = f"Log file: {name}\nPath: {path}\nLast 100 lines:"
        if truncated:
            header += "\nNote: earlier lines omitted"
        return header + "\n" + self._public_safe_log_text(text).rstrip("\n")

    def _public_safe_log_text(self, text):
        replacements = {
            "hidden": "diagnostic",
            "ies-sdk": "forwarding-plane",
            "sdk": "forwarding runtime",
            "owner": "role",
            "ownership": "assignment",
        }

        def replace(match):
            return replacements[match.group(0).lower()]

        return re.sub(r"\b(ies-sdk|ownership|owner|sdk|hidden)\b",
                      replace, text, flags=re.IGNORECASE)

    def _show_system_information(self):
        hostname = "netlab"
        try:
            xml = self._get_config_xml(active=True)
            root = ET.fromstring(xml)
            for child in root.iter():
                if xml_local_name(child.tag) != "host-name":
                    continue
                if child.text and child.text.strip():
                    hostname = child.text.strip()
                    break
        except Exception:
            pass
        return "\n".join([
            "NetLab Switch OS",
            f"Hostname: {hostname}",
            "Mode: hardware-backed L2",
        ])

    def _show_system_commit(self, tokens):
        if tokens == ["confirmed"]:
            text = self._configd_read_text(13, what="commit confirmation state")
            if text.startswith("error:"):
                return text
            return text.rstrip("\n")
        if tokens:
            return f"error: unknown system commit target: {' '.join(tokens)}"
        text = self._configd_read_text(11, what="commit history")
        if text.startswith("error:"):
            return text
        return self._format_commit_history(text)

    def _show_system_rollback(self, tokens):
        if len(tokens) == 3 and tokens[1] == "compare":
            return self._show_system_rollback_compare(tokens[0], tokens[2])
        if len(tokens) == 2 and tokens[1] == "compare":
            return ("error: usage: show system rollback <rollback-number> "
                    "compare <rollback-number>")
        if len(tokens) == 1:
            return self._show_system_rollback_config(tokens[0])
        if len(tokens) > 1:
            return f"error: unknown system rollback target: {' '.join(tokens)}"
        text = self._configd_read_text(11, what="rollback history")
        if text.startswith("error:"):
            return text
        return self._format_rollback_history(text)

    def _show_system_rollback_config(self, generation_text):
        xml, error = self._rollback_config_xml(generation_text)
        if error:
            return error
        return self._format_rollback_config(generation_text, xml)

    def _show_system_rollback_compare(self, left_generation, right_generation):
        left_xml, error = self._rollback_config_xml(left_generation)
        if error:
            return error
        right_xml, error = self._rollback_config_xml(right_generation)
        if error:
            return error
        return self._format_config_set_compare(
            left_xml, right_xml,
            f"No differences between rollback {left_generation} "
            f"and rollback {right_generation}")

    def _rollback_config_xml(self, generation_text):
        if not generation_text.isdigit():
            return None, "error: rollback number must be a non-negative integer"
        generation = int(generation_text, 10)
        if generation == 0:
            xml = self._get_config_xml(active=True).lstrip()
            if not xml.startswith("<"):
                return None, xml if xml else "error: cannot read active configuration"
            return xml, None

        ids = self._rollback_snapshot_ids()
        if len(ids) <= generation:
            return None, (
                f"error: rollback {generation} unavailable\n"
                f"reason: only {len(ids)} committed configuration "
                f"snapshot{' is' if len(ids) == 1 else 's are'} available"
            )
        commit_id = ids[len(ids) - generation - 1]
        path = self._rollback_snapshot_path(commit_id)
        text, read_error, _ = self._read_text_file(path)
        if read_error:
            return None, (f"error: rollback {generation} unavailable\n"
                          f"reason: cannot read {path}")
        if not text.lstrip().startswith("<"):
            return None, (f"error: rollback {generation} failed\n"
                          "reason: invalid rollback snapshot")
        return text, None

    def _rollback_snapshot_dir(self):
        return os.path.join(self._config_store_dir(), "rollback")

    def _rollback_snapshot_path(self, commit_id):
        return os.path.join(self._rollback_snapshot_dir(),
                            f"{commit_id:016x}.conf")

    def _rollback_snapshot_ids(self):
        try:
            names = os.listdir(self._rollback_snapshot_dir())
        except FileNotFoundError:
            return []
        except OSError:
            return []
        ids = []
        for name in names:
            if not name.endswith(".conf"):
                continue
            hex_id = name[:-5]
            try:
                commit_id = int(hex_id, 16)
            except ValueError:
                continue
            if commit_id > 0:
                ids.append(commit_id)
        return sorted(ids)

    def _format_rollback_config(self, generation, xml):
        body = format_config_hierarchy(xml)
        return f"Rollback configuration {generation}:\n{body}"

    def _config_set_lines(self, xml, path_tokens=None):
        text = format_config_as_set(xml, path_tokens=path_tokens)
        return [line for line in text.splitlines()
                if line.strip().startswith("set ")]

    def _format_config_hierarchy_compare(self, source_xml, compare_xml,
                                         no_changes_text, path_tokens=None):
        source_lines = self._config_set_lines(source_xml, path_tokens)
        compare_lines = self._config_set_lines(compare_xml, path_tokens)
        source_set = set(source_lines)
        compare_set = set(compare_lines)

        changes = []
        for line in compare_lines:
            if line not in source_set:
                changes.append(("-", line))
        for line in source_lines:
            if line not in compare_set:
                changes.append(("+", line))
        if not changes:
            return no_changes_text

        lines = []
        last_edit = None
        for sign, set_line in changes:
            edit_path, leaf = self._set_line_to_compare_edit(set_line)
            if edit_path != last_edit:
                lines.append(f"[edit {edit_path}]" if edit_path else "[edit]")
                last_edit = edit_path
            lines.append(f"{sign}   {leaf};")
        return "\n".join(lines)

    def _set_line_to_compare_edit(self, set_line):
        line = set_line.strip()
        if not line.startswith("set "):
            return "", line
        tokens = line.split()[1:]
        if not tokens:
            return "", ""

        try:
            _, value = cli_to_path(tokens)
        except Exception:
            value = ""

        if value == "true":
            return " ".join(tokens[:-1]), tokens[-1]

        value_tokens = value.split() if value else []
        if (value_tokens and len(tokens) > len(value_tokens) and
                tokens[-len(value_tokens):] == value_tokens):
            leaf_index = len(tokens) - len(value_tokens) - 1
            if leaf_index >= 0:
                return (" ".join(tokens[:leaf_index]),
                        " ".join(tokens[leaf_index:]))

        if len(tokens) >= 2:
            return " ".join(tokens[:-2]), " ".join(tokens[-2:])
        return "", tokens[0]

    def _format_config_set_compare(self, source_xml, compare_xml,
                                   no_changes_text, path_tokens=None):
        source_lines = self._config_set_lines(source_xml, path_tokens)
        compare_lines = self._config_set_lines(compare_xml, path_tokens)
        source_set = set(source_lines)
        compare_set = set(compare_lines)

        lines = ["[edit]"]
        for line in compare_lines:
            if line not in source_set:
                lines.append(f"-   {line}")
        for line in source_lines:
            if line not in compare_set:
                lines.append(f"+   {line}")
        if len(lines) == 1:
            return no_changes_text
        return "\n".join(lines)

    def _parse_rollback_history_rows(self, text):
        rows = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if "\t" in line:
                revision, detail = line.split("\t", 1)
            else:
                parts = line.split(None, 1)
                revision = parts[0]
                detail = parts[1] if len(parts) > 1 else ""
            rows.append((revision, detail))
        return rows

    def _format_commit_history(self, text):
        rows = self._parse_rollback_history_rows(text)
        if not rows:
            return "Commit history: empty"
        lines = ["Commit history:", "Revision  Details"]
        for revision, detail in rows:
            lines.append(f"{revision:<8}  {detail}")
        return "\n".join(lines)

    def _format_rollback_history(self, text):
        rows = self._parse_rollback_history_rows(text)
        if not rows:
            return "Rollback history: empty"
        lines = ["Rollback history:", "Rollback  Details"]
        for revision, detail in rows:
            lines.append(f"{revision:<8}  {detail}")
        return "\n".join(lines)

    def _show_system_configuration(self, tokens):
        if tokens == ["rescue"]:
            regular_error = self._rescue_regular_file_error()
            if regular_error:
                if regular_error == "missing":
                    return "rescue configuration not present"
                return regular_error
            return self._format_config_file_contents(
                "Rescue configuration", self._rescue_config_path(),
                "rescue configuration not present")
        if tokens == ["archive"]:
            archive_dir = self._config_archive_dir()
            try:
                entries = [
                    os.path.join(archive_dir, name)
                    for name in os.listdir(archive_dir)
                    if name.endswith(".set") and
                    os.path.isfile(os.path.join(archive_dir, name)) and
                    not os.path.islink(os.path.join(archive_dir, name))
                ]
            except FileNotFoundError:
                entries = []
            except OSError as exc:
                return f"error: cannot read configuration archive: {exc}"
            if not entries:
                return "Configuration archive: empty"
            entries.sort(key=lambda path: os.path.getmtime(path),
                         reverse=True)
            lines = ["Configuration archive:"]
            for path in entries[:20]:
                try:
                    stat = os.stat(path)
                except OSError:
                    continue
                lines.append(
                    "  %-32s %8d bytes  %s" % (
                        os.path.basename(path),
                        stat.st_size,
                        time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(stat.st_mtime)),
                    )
                )
            return "\n".join(lines)
        if len(tokens) == 2 and tokens[0] == "archive":
            path, error = self._archive_config_path(tokens[1])
            if error:
                return error
            regular_error = self._archive_regular_file_error(path, tokens[1])
            if regular_error:
                if regular_error == "missing":
                    return f"configuration archive not present: {tokens[1]}"
                return regular_error
            text, read_error, truncated = self._read_text_file(
                path, max_bytes=1048576)
            if read_error:
                if read_error.startswith("error: file not found:"):
                    return f"configuration archive not present: {tokens[1]}"
                return read_error
            header = f"Configuration archive: {tokens[1]}"
            if truncated:
                header += "\nNote: output truncated to first 1048576 bytes"
            return header + "\n" + text.rstrip("\n")
        if not tokens:
            rescue = self._format_config_file_status(
                "Rescue configuration", self._rescue_config_path())
            archive = self._show_system_configuration(["archive"])
            return rescue + "\n\n" + archive
        return f"error: unknown system configuration target: {' '.join(tokens)}"

    def _format_config_file_status(self, title, path):
        try:
            stat = os.lstat(path)
        except FileNotFoundError:
            return f"{title}: not present"
        except OSError as exc:
            return f"error: cannot read {title.lower()}: {exc}"
        if not stat_module.S_ISREG(stat.st_mode):
            return f"error: {title.lower()} must be a regular file"
        try:
            with open(path, "r", encoding="utf-8") as handle:
                statements = sum(1 for line in handle
                                 if line.strip().startswith("set "))
        except OSError:
            statements = 0
        return "\n".join([
            f"{title}: present",
            f"  file       : {path}",
            f"  size       : {stat.st_size} bytes",
            "  modified   : %s" % time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
            f"  statements : {statements}",
        ])

    def _format_config_file_contents(self, title, path, missing_text):
        text, read_error, truncated = self._read_text_file(
            path, max_bytes=1048576)
        if read_error:
            if read_error.startswith("error: file not found:"):
                return missing_text
            return read_error
        header = f"{title}:"
        if truncated:
            header += "\nNote: output truncated to first 1048576 bytes"
        body = text.rstrip("\n")
        if not body:
            return header
        return header + "\n" + body

    def _public_runtime_rpc(self, daemon, method, payload=b""):
        return self._rpc(daemon, method, payload,
                         timeout_ms=_public_runtime_rpc_timeout_ms())

    def _public_runtime_reason(self, text):
        reason = text[len("error:"):].strip() or "runtime unavailable"
        return (reason.replace("SDK", "forwarding runtime")
                  .replace("sdk", "forwarding runtime")
                  .replace("owner", "runtime state")
                  .replace("Owner", "Runtime state")
                  .replace("hidden", "diagnostic")
                  .replace("Hidden", "Diagnostic"))

    def _public_runtime_text(self, title, resp):
        text = resp.decode(errors='replace')
        if not text.startswith("error:"):
            return text, None
        reason = self._public_runtime_reason(text)
        return text, "\n".join([
            f"{title}: unavailable",
            f"  Reason : {reason}",
        ])

    def _public_action_rpc(self, daemon, method, payload=b""):
        return self._public_runtime_rpc(daemon, method, payload)

    def _public_action_text(self, title, resp):
        text = resp.decode(errors='replace')
        if not text.startswith("error:"):
            return text, None
        reason = self._public_runtime_reason(text)
        return text, "\n".join([
            f"{title}: failed",
            f"  Reason : {reason}",
        ])

    def _show_interfaces(self, tokens):
        tokens = tokens or []
        ifname = tokens[0] if tokens else None
        if ifname == "diagnostics":
            return self._show_interfaces_diagnostics(tokens[1:])
        if ifname == "statistics":
            if len(tokens) > 2:
                return f"error: unknown interfaces statistics target: {' '.join(tokens[1:])}"
            name = tokens[1] if len(tokens) == 2 else ""
            resp = self._public_runtime_rpc(
                DAEMON_STATSD, 1, name.encode() if name else b"")
            text, unavailable = self._public_runtime_text(
                "Interface statistics", resp)
            if unavailable:
                return unavailable
            return format_interface_statistics(text)
        if ifname == "descriptions":
            if len(tokens) > 1:
                return f"error: unknown interfaces descriptions target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_IFD, 1, b"terse")
            text, unavailable = self._public_runtime_text("Interfaces", resp)
            if unavailable:
                return unavailable
            return format_interfaces_terse(text)
        if ifname == "detail":
            if len(tokens) > 1:
                return f"error: unknown interfaces detail target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_IFD, 1, b"detail")
            text, unavailable = self._public_runtime_text("Interfaces", resp)
            if unavailable:
                return unavailable
            return format_interface_detail(text)
        if ifname == "extensive":
            if len(tokens) > 1:
                return f"error: unknown interfaces extensive target: {' '.join(tokens[1:])}"
            detail = self._public_runtime_rpc(DAEMON_IFD, 1, b"detail")
            detail_text, detail_unavailable = self._public_runtime_text(
                "Interfaces", detail)
            if detail_unavailable:
                return detail_unavailable
            stats = self._public_runtime_rpc(DAEMON_STATSD, 1, b"")
            stats_text, stats_unavailable = self._public_runtime_text(
                "Interface statistics", stats)
            return (format_interface_detail(detail_text) + "\n\n" +
                    (stats_unavailable if stats_unavailable else
                     format_interface_statistics(stats_text)))
        if ifname == "terse":
            if len(tokens) > 1:
                return f"error: unknown interfaces terse target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_IFD, 1, b"terse")
            text, unavailable = self._public_runtime_text("Interfaces", resp)
            if unavailable:
                return unavailable
            return format_interfaces_terse(text)
        if ifname and len(tokens) >= 2 and tokens[1] == "detail":
            if len(tokens) > 2:
                return f"error: unknown interface detail target: {' '.join(tokens[2:])}"
            resp = self._public_runtime_rpc(
                DAEMON_IFD, 1, f"detail name={ifname}".encode())
            text, unavailable = self._public_runtime_text(
                f"Interface {ifname}", resp)
            if unavailable:
                return unavailable
            return format_interface_detail(text)
        if ifname and len(tokens) >= 2 and tokens[1] == "extensive":
            if len(tokens) > 2:
                return f"error: unknown interface extensive target: {' '.join(tokens[2:])}"
            detail = self._public_runtime_rpc(
                DAEMON_IFD, 1, f"detail name={ifname}".encode())
            detail_text, detail_unavailable = self._public_runtime_text(
                f"Interface {ifname}", detail)
            if detail_unavailable:
                return detail_unavailable
            stats = self._public_runtime_rpc(DAEMON_STATSD, 1, ifname.encode())
            stats_text, stats_unavailable = self._public_runtime_text(
                "Interface statistics", stats)
            return (format_interface_detail(detail_text) + "\n\n" +
                    (stats_unavailable if stats_unavailable else
                     format_interface_statistics(stats_text)))
        if ifname and len(tokens) >= 2 and tokens[1] == "statistics":
            if len(tokens) > 2:
                return f"error: unknown interface statistics target: {' '.join(tokens[2:])}"
            resp = self._public_runtime_rpc(DAEMON_STATSD, 1, ifname.encode())
            text, unavailable = self._public_runtime_text(
                "Interface statistics", resp)
            if unavailable:
                return unavailable
            return format_interface_statistics(text)
        if len(tokens) > 1:
            return f"error: unknown interface target: {' '.join(tokens[1:])}"
        if ifname and ifname not in ("detail", "terse", "statistics"):
            resp = self._public_runtime_rpc(
                DAEMON_IFD, 1, f"detail name={ifname}".encode())
            text, unavailable = self._public_runtime_text(
                f"Interface {ifname}", resp)
            if unavailable:
                return unavailable
            return format_interface_detail(text)
        resp = self._public_runtime_rpc(DAEMON_IFD, 1, b"terse")
        text, unavailable = self._public_runtime_text("Interfaces", resp)
        if unavailable:
            return unavailable
        return format_interfaces_terse(text)

    def _show_interfaces_diagnostics(self, tokens):
        if not tokens:
            return "error: incomplete interfaces diagnostics command"
        if tokens[0] != "optics":
            return f"error: unknown interfaces diagnostics target: {' '.join(tokens)}"
        tokens = tokens[1:]
        if not tokens:
            return self._show_all_interface_optics()
        if tokens[0] == "calibration":
            if len(tokens) == 1:
                return self._show_interface_optics_calibration()
            if len(tokens) == 3 and tokens[1] == "check":
                if tokens[2] not in ("active", "full"):
                    return f"error: unknown optics calibration check scope: {tokens[2]}"
                return self._show_interface_optics_calibration_check(tokens[2])
            return f"error: unknown optics calibration option: {' '.join(tokens[1:])}"
        if tokens[0] == "mapping":
            if len(tokens) > 1:
                return f"error: unknown interfaces diagnostics optics mapping target: {' '.join(tokens[1:])}"
            return self._show_interface_optics_mapping()
        if len(tokens) > 1:
            return f"error: unknown interfaces diagnostics optics target: {' '.join(tokens)}"
        return self._show_interface_optics(tokens[0])

    def _show_vlans(self, tokens):
        style = "brief"
        vlan_filter = ""

        for tok in tokens:
            if tok in ("brief", "detail", "extensive"):
                style = tok
                continue
            if vlan_filter:
                return f"error: unsupported show vlans argument: {tok}"
            vlan_filter = tok
        resp = self._public_runtime_rpc(DAEMON_L2D, 1, b"")
        text, unavailable = self._public_runtime_text(
            "VLAN information", resp)
        if unavailable:
            return unavailable
        return format_vlans(text, style, vlan_filter)

    def _show_forwarding_options(self, tokens):
        if tokens != ["port-mirroring"]:
            return ("error: usage: show forwarding-options "
                    "port-mirroring")
        resp = self._public_runtime_rpc(DAEMON_L2D, 8, b"")
        text, unavailable = self._public_runtime_text(
            "Port mirroring", resp)
        if unavailable:
            return unavailable
        return format_port_mirroring(text)

    def _show_igmp_snooping(self, tokens):
        if tokens:
            return "error: usage: show igmp-snooping"
        resp = self._public_runtime_rpc(DAEMON_L2D, 9, b"")
        text, unavailable = self._public_runtime_text(
            "IGMP snooping", resp)
        if unavailable:
            return unavailable
        return format_igmp_snooping(text)

    def _diagnostics_redirect(self, old_path, new_path):
        return f"error: use '{new_path}'"

    def _show_eth_sw(self, tokens, diagnostics=False):
        if not tokens:
            resp = self._public_runtime_rpc(DAEMON_L2D, 2, b"")
            text, unavailable = self._public_runtime_text(
                "Ethernet switching interfaces", resp)
            if unavailable:
                return unavailable
            return format_eth_sw_interfaces(text)
        if tokens[0] == "interfaces":
            if len(tokens) > 1:
                return f"error: unknown ethernet-switching interfaces target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_L2D, 2, b"")
            text, unavailable = self._public_runtime_text(
                "Ethernet switching interfaces", resp)
            if unavailable:
                return unavailable
            return format_eth_sw_interfaces(text)
        if tokens[0] == "table":
            if len(tokens) > 1:
                return f"error: unknown ethernet-switching table target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 125, b"")
            if resp.startswith(b"error:"):
                _, unavailable = self._public_runtime_text(
                    "Ethernet switching table", resp)
                return unavailable
            return format_mac_snapshot(resp)
        if tokens[0] == "mac-move":
            if len(tokens) > 1:
                return f"error: unknown ethernet-switching mac-move target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
            text, unavailable = self._public_runtime_text(
                "Ethernet switching mac-move", resp)
            if unavailable:
                return unavailable
            return format_mac_move(text)
        if tokens[0] == "secure-access-port":
            if len(tokens) > 1:
                return f"error: unknown ethernet-switching secure-access-port target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
            text, unavailable = self._public_runtime_text(
                "Secure access port", resp)
            if unavailable:
                return unavailable
            return format_secure_access_port(text)
        if tokens[0] == "dhcp-snooping":
            if len(tokens) > 1:
                return f"error: unknown ethernet-switching dhcp-snooping target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
            text, unavailable = self._public_runtime_text(
                "DHCP snooping", resp)
            if unavailable:
                return unavailable
            return format_dhcp_snooping(text)
        if tokens[0] == "arp-inspection":
            if len(tokens) > 1:
                return f"error: unknown ethernet-switching arp-inspection target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
            text, unavailable = self._public_runtime_text(
                "ARP inspection", resp)
            if unavailable:
                return unavailable
            return format_arp_inspection(text)
        hidden = {
            "user-filter": "show diagnostics ethernet-switching user-filter",
            "ingress-acl": "show diagnostics ethernet-switching ingress-acl",
            "ingress-ipv4-acl": (
                "show diagnostics ethernet-switching ingress-ipv4-acl"),
            "acl-policer": "show diagnostics ethernet-switching acl-policer",
            "egress-acl": "show diagnostics ethernet-switching egress-acl",
            "acl-capabilities": (
                "show diagnostics ethernet-switching acl-capabilities"),
        }
        if tokens[0] in hidden and not diagnostics:
            if len(tokens) > 1:
                return f"error: unknown ethernet-switching {tokens[0]} target: {' '.join(tokens[1:])}"
            return self._diagnostics_redirect(
                "show ethernet-switching " + tokens[0], hidden[tokens[0]])
        if tokens[0] == "user-filter":
            if len(tokens) > 1:
                return f"error: unknown diagnostics ethernet-switching user-filter target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
            text, unavailable = self._public_runtime_text(
                "Ethernet switching user filter", resp)
            if unavailable:
                return unavailable
            return format_user_filter(text)
        if tokens[0] == "ingress-acl":
            if len(tokens) > 1:
                return f"error: unknown diagnostics ethernet-switching ingress-acl target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
            text, unavailable = self._public_runtime_text(
                "Ethernet switching ingress ACL", resp)
            if unavailable:
                return unavailable
            return format_ingress_acl(text)
        if tokens[0] == "ingress-ipv4-acl":
            if len(tokens) > 1:
                return f"error: unknown diagnostics ethernet-switching ingress-ipv4-acl target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
            text, unavailable = self._public_runtime_text(
                "Ethernet switching ingress IPv4 ACL", resp)
            if unavailable:
                return unavailable
            return format_ingress_ipv4_acl(text)
        if tokens[0] == "acl-policer":
            if len(tokens) > 1:
                return f"error: unknown diagnostics ethernet-switching acl-policer target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
            text, unavailable = self._public_runtime_text(
                "Ethernet switching ACL policer", resp)
            if unavailable:
                return unavailable
            return format_acl_policer(text)
        if tokens[0] == "egress-acl":
            if len(tokens) > 1:
                return f"error: unknown diagnostics ethernet-switching egress-acl target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
            text, unavailable = self._public_runtime_text(
                "Ethernet switching egress ACL", resp)
            if unavailable:
                return unavailable
            return format_egress_acl(text)
        if tokens[0] == "acl":
            if len(tokens) > 1:
                return f"error: unknown ethernet-switching acl target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_L2D, 4, b"")
            text, unavailable = self._public_runtime_text(
                "Ethernet switching ACL", resp)
            if unavailable:
                return unavailable
            return format_acl_summary(text)
        if tokens[0] == "acl-capabilities":
            if len(tokens) > 1:
                return f"error: unknown diagnostics ethernet-switching acl-capabilities target: {' '.join(tokens[1:])}"
            return format_ethernet_switching_acl_capabilities()
        if tokens[0] == "storm-control":
            if len(tokens) > 1:
                return f"error: unknown ethernet-switching storm-control target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 56, b"")
            text, unavailable = self._public_runtime_text(
                "Storm control", resp)
            if unavailable:
                return unavailable
            return format_storm_control(text)
        if tokens[0] == "ingress-rate-limit":
            if len(tokens) > 1:
                return f"error: unknown ethernet-switching ingress-rate-limit target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(
                DAEMON_SWITCHD, 56, b"ingress-rate-limit")
            text, unavailable = self._public_runtime_text(
                "Ingress rate limit", resp)
            if unavailable:
                return unavailable
            return format_ingress_rate_limit(text)
        if tokens[0] == "egress-rate-limit":
            if len(tokens) > 1:
                return f"error: unknown ethernet-switching egress-rate-limit target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(
                DAEMON_SWITCHD, 56, b"egress-rate-limit")
            text, unavailable = self._public_runtime_text(
                "Egress rate limit", resp)
            if unavailable:
                return unavailable
            return format_egress_rate_limit(text)
        return f"error: unknown ethernet-switching: {' '.join(tokens)}"

    def _show_class_of_service(self, tokens, diagnostics=False):
        if not tokens:
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 68, b"interfaces")
            text, unavailable = self._public_runtime_text(
                "Class of service interfaces", resp)
            if unavailable:
                return unavailable
            return format_class_of_service_interfaces(text)
        if tokens[0] == "interfaces":
            if len(tokens) > 1:
                return f"error: unknown class-of-service interfaces target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 68, b"interfaces")
            text, unavailable = self._public_runtime_text(
                "Class of service interfaces", resp)
            if unavailable:
                return unavailable
            return format_class_of_service_interfaces(text)
        if tokens[0] == "forwarding":
            if len(tokens) > 1:
                return f"error: unknown class-of-service forwarding target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 68, b"forwarding")
            text, unavailable = self._public_runtime_text(
                "Class of service forwarding", resp)
            if unavailable:
                return unavailable
            return format_class_of_service_forwarding(text)
        if tokens[0] == "flow-control":
            if len(tokens) > 1:
                return f"error: unknown class-of-service flow-control target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(
                DAEMON_SWITCHD, 68, b"flow-control")
            text, unavailable = self._public_runtime_text(
                "Class of service flow control", resp)
            if unavailable:
                return unavailable
            return format_class_of_service_flow_control(text)
        if tokens[0] == "scheduler":
            if len(tokens) > 1:
                return f"error: unknown class-of-service scheduler target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 68, b"scheduler")
            text, unavailable = self._public_runtime_text(
                "Class of service scheduler", resp)
            if unavailable:
                return unavailable
            return format_class_of_service_scheduler(text)
        hidden = {
            "ets": "show diagnostics class-of-service ets",
            "queues": "show diagnostics class-of-service queues",
            "watermarks": "show diagnostics class-of-service watermarks",
        }
        if tokens[0] in hidden and not diagnostics:
            if len(tokens) > 1:
                return f"error: unknown class-of-service {tokens[0]} target: {' '.join(tokens[1:])}"
            return self._diagnostics_redirect(
                "show class-of-service " + tokens[0], hidden[tokens[0]])
        if tokens[0] == "ets":
            if len(tokens) > 1:
                return f"error: unknown diagnostics class-of-service ets target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 68, b"scheduler")
            text, unavailable = self._public_runtime_text(
                "Class of service ETS", resp)
            if unavailable:
                return unavailable
            return format_class_of_service_ets(text)
        if tokens[0] == "queues":
            if len(tokens) > 1:
                return f"error: unknown diagnostics class-of-service queues target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 68, b"queues")
            text, unavailable = self._public_runtime_text(
                "Class of service queues", resp)
            if unavailable:
                return unavailable
            return format_class_of_service_queues(text)
        if tokens[0] == "watermarks":
            if len(tokens) > 1:
                return f"error: unknown diagnostics class-of-service watermarks target: {' '.join(tokens[1:])}"
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 68, b"watermarks")
            text, unavailable = self._public_runtime_text(
                "Class of service watermarks", resp)
            if unavailable:
                return unavailable
            return format_class_of_service_watermarks(text)
        if tokens[0] == "capabilities":
            if len(tokens) > 1:
                target = "diagnostics class-of-service" if diagnostics else "class-of-service"
                return f"error: unknown {target} capabilities target: {' '.join(tokens[1:])}"
            return format_class_of_service_capabilities(diagnostics=diagnostics)
        return f"error: unknown class-of-service: {' '.join(tokens)}"

    def _show_config(self, tokens):
        text = self._get_config_xml(active=True)
        if text.lstrip().startswith("<"):
            return format_config_hierarchy(text, tokens)
        return text

    def _get_config_xml(self, active: bool) -> str:
        label = "active configuration" if active else "candidate configuration"
        return self._configd_read_text(8 if active else 5, what=label)

    def _configd_read_text(self, method, payload=b"", what="configuration"):
        resp = self._rpc(
            DAEMON_CONFIGD, method, payload,
            timeout_ms=_config_read_rpc_timeout_ms())
        text = resp.decode(errors='replace')
        if text.startswith("error:"):
            detail = text[6:].strip() or "unknown error"
            return f"error: cannot read {what}: {detail}"
        return text

    def _configd_write_rpc(self, method, payload=b""):
        return self._configd_mutation_rpc(
            method, payload, timeout_ms=_config_write_rpc_timeout_ms())

    def _configd_commit_rpc(self, method, payload=b""):
        if method in CONFIGD_MUTATION_METHODS:
            return self._configd_mutation_rpc(
                method, payload, timeout_ms=_config_commit_rpc_timeout_ms())
        return self._rpc(
            DAEMON_CONFIGD, method, payload,
            timeout_ms=_config_commit_rpc_timeout_ms())

    def _configd_mutation_rpc(self, method, payload=b"", *, timeout_ms=None):
        if method not in CONFIGD_MUTATION_METHODS:
            raise ValueError(f"configd method {method} is not mutating")
        payload, error = self._configd_guarded_payload(payload)
        if error:
            return error.encode()
        if timeout_ms is None:
            timeout_ms = _config_commit_rpc_timeout_ms()
        return self._rpc(
            DAEMON_CONFIGD, method, payload, timeout_ms=timeout_ms)

    def _configd_guarded_payload(self, payload):
        token = os.environ.get(CONFIG_AUTHORITY_TOKEN_VARIABLE)
        if token is None:
            return payload, None
        if re.fullmatch(r"[0-9a-f]{64}", token) is None:
            return payload, "error: invalid production configuration authority token"
        return (CONFIG_AUTHORITY_ENVELOPE + token.encode("ascii") + b"\n" +
                payload), None

    def _configd_action_text(self, resp):
        text = resp.decode(errors='replace')
        if not text.startswith("error:"):
            return text, None
        return text, "error: " + self._public_runtime_reason(text)

    def _show_chassis(self, tokens, diagnostics=False):
        if tokens and tokens[0] == "forwarding":
            return self._show_chassis_forwarding(tokens[1:], diagnostics)
        if tokens and tokens[0] == "hardware":
            return self._show_chassis_hardware(tokens[1:])
        if tokens and tokens[0] == "environment":
            return self._show_chassis_environment(tokens[1:])
        if tokens and tokens[0] == "alarms":
            return self._show_chassis_alarms(tokens[1:])
        if tokens and tokens[0] == "routing-engine":
            return self._show_chassis_routing_engine(tokens[1:])
        if tokens and tokens[0] == "port-mode":
            if len(tokens) > 1:
                return f"error: unknown chassis port-mode target: {' '.join(tokens[1:])}"
            return format_chassis_port_mode()
        if tokens and tokens[0] == "optics":
            if len(tokens) >= 2 and tokens[1] == "mux":
                if len(tokens) >= 3 and (tokens[2] != "detail" or
                                         len(tokens) > 3):
                    return f"error: unknown chassis optics mux option: {' '.join(tokens[2:])}"
                resp = self._optics_mux_rpc()
                text = resp.decode(errors='replace')
                if text.startswith("error:"):
                    return ("Chassis optics mux: unavailable "
                            f"(status={text[6:].strip()})")
                return format_chassis_optics_mux(
                    text, detail=(len(tokens) >= 3 and tokens[2] == "detail"))
            return f"error: unknown chassis optics target: {' '.join(tokens[1:])}"
        return f"error: unknown chassis target: {' '.join(tokens)}"

    def _show_chassis_forwarding(self, tokens, diagnostics=False):
        tokens = tokens or []
        if not tokens:
            resp = self._rpc(
                DAEMON_SWITCHD, 34, b"pfe_status",
                timeout_ms=_public_runtime_rpc_timeout_ms())
            text = resp.decode(errors='replace')
            if text.startswith("error:"):
                return "\n".join([
                    "PFE capability status:",
                    "  PFE state      : unavailable",
                    "  Runtime init   : unavailable",
                    "  Switch enabled : unavailable",
                    f"  Reason         : {self._public_runtime_reason(text)}",
                ])
            return format_pfe_status(text)
        if len(tokens) != 1:
            return f"error: unknown chassis forwarding target: {' '.join(tokens)}"
        if tokens[0] in ("config", "sdk") and not diagnostics:
            return self._diagnostics_redirect(
                "show chassis forwarding " + tokens[0],
                "show diagnostics forwarding " +
                ("runtime" if tokens[0] == "sdk" else tokens[0]))
        if tokens[0] == "resources":
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 55, b"")
            text, unavailable = self._public_runtime_text(
                "PFE resources", resp)
            if unavailable:
                return unavailable
            return format_pfe_resources(text)
        if tokens[0] == "config":
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 64, b"")
            text, unavailable = self._public_runtime_text(
                "Forwarding configuration", resp)
            if unavailable:
                return unavailable
            return format_switch_config(text)
        if tokens[0] == "sdk":
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 66, b"")
            text, unavailable = self._public_runtime_text(
                "Forwarding runtime", resp)
            if unavailable:
                return unavailable
            return format_sdk_runtime(text)
        return f"error: unknown chassis forwarding target: {' '.join(tokens)}"

    def _show_chassis_hardware(self, tokens):
        tokens = tokens or []
        if tokens:
            return f"error: unknown chassis hardware target: {' '.join(tokens)}"
        resp = self._public_runtime_rpc(DAEMON_CHASSISD, 1, b"")
        text, unavailable = self._public_runtime_text("Chassis hardware", resp)
        if unavailable:
            return unavailable
        return format_chassis_hardware(text)

    def _show_chassis_environment(self, tokens):
        tokens = tokens or []
        if tokens:
            return f"error: unknown chassis environment target: {' '.join(tokens)}"
        resp = self._public_runtime_rpc(DAEMON_CHASSISD, 1, b"")
        raw, unavailable = self._public_runtime_text("Chassis environment",
                                                     resp)
        if unavailable:
            return unavailable
        text = format_chassis_hardware(raw)
        return text.replace("Chassis hardware:", "Chassis environment:", 1)

    def _show_chassis_routing_engine(self, tokens):
        if tokens:
            return f"error: unknown chassis routing-engine target: {' '.join(tokens)}"
        uname = os.uname()
        meminfo = self._proc_meminfo()
        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
        used = max(0, total - available) if total else 0
        loadavg = self._host_load_average()
        uptime = self._host_uptime_seconds()
        lines = [
            "Routing Engine status:",
            "  Slot          : 0",
            "  Current state : Master",
            f"  Model         : {self._host_cpu_model()}",
            f"  CPU cores     : {os.cpu_count() or 'unknown'}",
            f"  Kernel        : {uname.sysname} {uname.release} {uname.machine}",
            "  Uptime        : %s" % (
                self._format_duration(uptime) if uptime else "unknown"),
            f"  Load averages : {loadavg}",
            f"  Memory total  : {self._human_bytes(total)}",
            f"  Memory used   : {self._human_bytes(used)}",
            f"  Memory avail  : {self._human_bytes(available)}",
            "  Source        : host runtime inventory",
            "",
            "State: read-only routing-engine inventory; no configuration or "
            "hardware state is changed.",
        ]
        return "\n".join(lines)

    def _host_cpu_model(self):
        try:
            with open("/proc/cpuinfo", "r", encoding="utf-8") as handle:
                for line in handle:
                    if ":" not in line:
                        continue
                    key, value = [part.strip() for part in line.split(":", 1)]
                    if key in ("model name", "Hardware", "Processor"):
                        return value or "unknown"
        except OSError:
            pass
        return "unknown"

    def _host_load_average(self):
        try:
            with open("/proc/loadavg", "r", encoding="utf-8") as handle:
                values = handle.read().split()[:3]
        except OSError:
            values = []
        return " ".join(values) if values else "unknown"

    def _host_uptime_seconds(self):
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as handle:
                return int(float(handle.read().split()[0]))
        except Exception:
            return 0

    def _show_chassis_alarms(self, tokens):
        if tokens:
            return f"error: unknown chassis alarms target: {' '.join(tokens)}"
        resp = self._public_runtime_rpc(DAEMON_CHASSISD, 1, b"")
        raw, unavailable = self._public_runtime_text("Chassis alarms", resp)
        if unavailable:
            return unavailable
        return format_chassis_alarms(raw)

    def _show_control_plane(self, tokens):
        if tokens == ["protection"]:
            resp = self._rpc(
                DAEMON_SWITCHD, 65, b"",
                timeout_ms=_public_runtime_rpc_timeout_ms())
            punt = b""
            try:
                punt = self._rpc(
                    DAEMON_PACKETD, 1, b"",
                    timeout_ms=_public_runtime_rpc_timeout_ms())
            except RuntimeError:
                punt = b""
            text = resp.decode(errors='replace')
            if text.startswith("error:"):
                return "\n".join([
                    "Control-plane protection: unavailable",
                    "  Source : forwarding-plane",
                    f"  Reason : {self._public_runtime_reason(text)}",
                ])
            return format_control_plane_protection(
                text,
                punt.decode(errors='replace') if punt else "")
        return f"error: unknown control-plane target: {' '.join(tokens)}"

    def _show_lldp(self, tokens):
        if not tokens:
            return "error: incomplete lldp command"
        if tokens and tokens[0] == "interfaces":
            if len(tokens) > 1:
                return (f"error: unknown lldp interfaces target: "
                        f"{' '.join(tokens[1:])}")
            resp = self._public_runtime_rpc(DAEMON_LLDPD, 3, b"")
            text, unavailable = self._public_runtime_text(
                "LLDP interfaces", resp)
            if unavailable:
                return unavailable
            return format_lldp_interfaces(text)
        if tokens and tokens[0] == "local-information":
            if len(tokens) > 1:
                return (f"error: unknown lldp local-information target: "
                        f"{' '.join(tokens[1:])}")
            resp = self._public_runtime_rpc(DAEMON_LLDPD, 5, b"")
            text, unavailable = self._public_runtime_text(
                "LLDP local information", resp)
            if unavailable:
                return unavailable
            return format_lldp_local(text)
        if tokens and tokens[0] == "neighbors" and len(tokens) > 1:
            if tokens[1] == "detail":
                if len(tokens) > 2:
                    return (f"error: unknown lldp neighbors detail target: "
                            f"{' '.join(tokens[2:])}")
                resp = self._public_runtime_rpc(DAEMON_LLDPD, 4, b"")
                text, unavailable = self._public_runtime_text(
                    "LLDP neighbors", resp)
                if unavailable:
                    return unavailable
                return format_lldp_neighbors_detail(text)
            return f"error: unknown lldp neighbors target: {' '.join(tokens[1:])}"
        if tokens and tokens[0] == "statistics":
            if len(tokens) > 1:
                return (f"error: unknown lldp statistics target: "
                        f"{' '.join(tokens[1:])}")
            resp = self._public_runtime_rpc(DAEMON_LLDPD, 2, b"")
            text, unavailable = self._public_runtime_text(
                "LLDP statistics", resp)
            if unavailable:
                return unavailable
            return format_lldp_statistics(text)
        if tokens and tokens[0] != "neighbors":
            return f"error: unknown lldp target: {' '.join(tokens)}"
        resp = self._public_runtime_rpc(DAEMON_LLDPD, 1, b"")
        text, unavailable = self._public_runtime_text("LLDP neighbors", resp)
        if unavailable:
            return unavailable
        return format_lldp_neighbors(text)

    def _show_lacp(self, tokens):
        if not tokens:
            return "error: incomplete lacp command"
        if len(tokens) > 1 and tokens[0] == "interfaces":
            return (f"error: unknown lacp interfaces target: "
                    f"{' '.join(tokens[1:])}")
        if tokens and tokens[0] != "interfaces":
            return f"error: unknown lacp target: {' '.join(tokens)}"
        resp = self._public_runtime_rpc(DAEMON_LACPD, 1, b"")
        text, unavailable = self._public_runtime_text("LACP interfaces", resp)
        if unavailable:
            return unavailable
        return format_lacp(text)

    def _show_route(self, tokens, diagnostics=False):
        if not tokens:
            resp = self._public_runtime_rpc(DAEMON_RPD, 13, b"")
            text, unavailable = self._public_runtime_text("Route table", resp)
            if unavailable:
                return unavailable
            return format_rpd_route_table(text)
        target = "diagnostics l3" if diagnostics else "route"
        hidden = {
            "state": "show diagnostics l3 state",
            "next-hop": "show diagnostics l3 next-hop",
            "ecmp": "show diagnostics l3 ecmp",
            "resources": "show diagnostics l3 resources",
            "shadow": "show diagnostics l3 shadow",
        }
        if tokens[0] in hidden:
            if len(tokens) > 1:
                return (f"error: unknown {target} {tokens[0]} target: "
                        f"{' '.join(tokens[1:])}")
            if not diagnostics:
                return self._diagnostics_redirect(
                    "show route " + tokens[0], hidden[tokens[0]])
        if tokens[0] == "state":
            resp = self._public_runtime_rpc(DAEMON_RPD, 1, b"")
            text, unavailable = self._public_runtime_text(
                "Layer 3 control-plane state", resp)
            if unavailable:
                return unavailable
            return format_l3_state(text)
        if tokens[0] == "protocol":
            if len(tokens) < 2:
                return "error: incomplete route protocol command"
            if len(tokens) > 2:
                return (f"error: unknown route protocol {tokens[1]} target: "
                        f"{' '.join(tokens[2:])}")
            if tokens[1] not in ("ospf", "bgp", "static", "connected"):
                return f"error: unknown route protocol: {tokens[1]}"
            resp = self._public_runtime_rpc(DAEMON_RPD, 13, b"")
            text, unavailable = self._public_runtime_text(
                f"Route table protocol {tokens[1]}", resp)
            if unavailable:
                return unavailable
            return format_rpd_route_table(text, protocol=tokens[1])
        if tokens[0] == "table":
            if len(tokens) < 2:
                return "error: incomplete route table command"
            if len(tokens) > 2:
                return (f"error: unknown route table {tokens[1]} target: "
                        f"{' '.join(tokens[2:])}")
            if not tokens[1].endswith(".inet.0") and tokens[1] != "inet.0":
                return f"error: unknown IPv4 route table: {tokens[1]}"
            resp = self._public_runtime_rpc(DAEMON_RPD, 13, b"")
            text, unavailable = self._public_runtime_text(
                f"Route table {tokens[1]}", resp)
            if unavailable:
                return unavailable
            return format_rpd_route_table(text, table=tokens[1])
        if tokens[0] == "forwarding-table":
            if len(tokens) > 1:
                return (f"error: unknown {target} forwarding-table target: "
                        f"{' '.join(tokens[1:])}")
            resp = self._public_runtime_rpc(DAEMON_RPD, 13, b"")
            text, unavailable = self._public_runtime_text(
                "Route forwarding table", resp)
            if unavailable:
                return unavailable
            return format_rpd_forwarding_table(text)
        if tokens[0] == "summary":
            if len(tokens) > 1:
                return (f"error: unknown {target} summary target: "
                        f"{' '.join(tokens[1:])}")
            resp = self._public_runtime_rpc(DAEMON_RPD, 13, b"")
            text, unavailable = self._public_runtime_text(
                "Route summary", resp)
            if unavailable:
                return unavailable
            return format_rpd_route_summary(text)
        if tokens[0] == "interfaces":
            if len(tokens) > 1:
                return (f"error: unknown {target} interfaces target: "
                        f"{' '.join(tokens[1:])}")
            resp = self._public_runtime_rpc(DAEMON_RPD, 6, b"")
            text, unavailable = self._public_runtime_text(
                "Layer 3 interfaces", resp)
            if unavailable:
                return unavailable
            return format_l3_interface_table(text)
        if tokens[0] == "next-hop":
            resp = self._public_runtime_rpc(DAEMON_RPD, 6, b"")
            text, unavailable = self._public_runtime_text(
                "Layer 3 next hops", resp)
            if unavailable:
                return unavailable
            return format_l3_next_hop_table(text)
        if tokens[0] == "ecmp":
            resp = self._public_runtime_rpc(DAEMON_RPD, 6, b"")
            text, unavailable = self._public_runtime_text("Layer 3 ECMP", resp)
            if unavailable:
                return unavailable
            return format_l3_ecmp_table(text)
        if tokens[0] == "resources":
            resp = self._public_runtime_rpc(DAEMON_RPD, 6, b"")
            text, unavailable = self._public_runtime_text(
                "Layer 3 resources", resp)
            if unavailable:
                return unavailable
            return format_l3_resource_table(text)
        if tokens[0] == "shadow":
            resp = self._public_runtime_rpc(DAEMON_RPD, 6, b"")
            text, unavailable = self._public_runtime_text(
                "Layer 3 diagnostic state", resp)
            if unavailable:
                return unavailable
            return format_l3_shadow_state(text)
        return f"error: unknown route target: {' '.join(tokens)}"

    def _show_arp(self, tokens):
        if tokens:
            return f"error: unknown arp target: {' '.join(tokens)}"
        resp = self._public_runtime_rpc(DAEMON_RPD, 13, b"")
        text, unavailable = self._public_runtime_text("ARP table", resp)
        if unavailable:
            return unavailable
        return format_rpd_arp_table(text)

    def _show_rpd(self, tokens):
        if tokens and tokens[0] == "state" and len(tokens) > 1:
            return f"error: unknown rpd state target: {' '.join(tokens[1:])}"
        if tokens != ["state"]:
            return f"error: unknown rpd target: {' '.join(tokens)}"
        resp = self._public_runtime_rpc(DAEMON_RPD, 13, b"")
        text, unavailable = self._public_runtime_text("RPD state", resp)
        if unavailable:
            return unavailable
        return format_rpd_state(text)

    def _show_ospf(self, tokens):
        if tokens != ["neighbor"]:
            return f"error: unknown ospf target: {' '.join(tokens)}"
        resp = self._public_runtime_rpc(DAEMON_RPD, 13, b"")
        text, unavailable = self._public_runtime_text(
            "OSPF neighbor information", resp)
        if unavailable:
            return unavailable
        return format_rpd_state(text, view="ospf")

    def _show_bgp(self, tokens):
        if tokens != ["summary"]:
            return f"error: unknown bgp target: {' '.join(tokens)}"
        resp = self._public_runtime_rpc(DAEMON_RPD, 13, b"")
        text, unavailable = self._public_runtime_text("BGP summary", resp)
        if unavailable:
            return unavailable
        return format_rpd_state(text, view="bgp")

    def _show_spanning_tree(self, tokens):
        interface_filter = None
        if tokens:
            if tokens[0] == "capabilities":
                if len(tokens) > 1:
                    return (f"error: unknown spanning-tree capabilities "
                            f"target: {' '.join(tokens[1:])}")
                return format_spanning_tree_capabilities()
            if tokens[0] == "statistics":
                if len(tokens) > 1:
                    return (f"error: unknown spanning-tree statistics "
                            f"target: {' '.join(tokens[1:])}")
                resp = self._public_runtime_rpc(DAEMON_STPD, 1, b"")
                text, unavailable = self._public_runtime_text(
                    "Spanning-tree statistics", resp)
                if unavailable:
                    return unavailable
                return format_stp_monitor(text)
            if tokens[0] == "interface":
                if len(tokens) > 2:
                    return (f"error: unknown spanning-tree interface target: "
                            f"{' '.join(tokens[2:])}")
                interface_filter = tokens[1] if len(tokens) >= 2 else None
                resp = self._public_runtime_rpc(DAEMON_STPD, 3, b"")
                text, unavailable = self._public_runtime_text(
                    "Spanning-tree state", resp)
                if unavailable:
                    return unavailable
                hw_resp = self._public_runtime_rpc(DAEMON_SWITCHD, 51, b"")
                hw_text, hw_unavailable = self._public_runtime_text(
                    "Spanning-tree hardware state", hw_resp)
                if hw_unavailable:
                    return hw_unavailable
                return format_spanning_tree_state(text, interface_filter,
                                                  hw_text)
            elif tokens[0] != "bridge":
                return f"error: unknown spanning-tree target: {' '.join(tokens)}"
            if len(tokens) > 1:
                return (f"error: unknown spanning-tree bridge target: "
                        f"{' '.join(tokens[1:])}")
            resp = self._public_runtime_rpc(DAEMON_SWITCHD, 51, b"")
            text, unavailable = self._public_runtime_text(
                "Spanning-tree bridge", resp)
            if unavailable:
                return unavailable
            return format_spanning_tree(text, None)
        resp = self._public_runtime_rpc(DAEMON_STPD, 3, b"")
        text, unavailable = self._public_runtime_text("Spanning-tree state",
                                                      resp)
        if unavailable:
            return unavailable
        hw_resp = self._public_runtime_rpc(DAEMON_SWITCHD, 51, b"")
        hw_text, hw_unavailable = self._public_runtime_text(
            "Spanning-tree hardware state", hw_resp)
        if hw_unavailable:
            return hw_unavailable
        return format_spanning_tree_state(text, None, hw_text)

    def _clear(self, tokens):
        if len(tokens) >= 2 and tokens[0] == "interfaces" and tokens[1] == "statistics":
            if len(tokens) > 3:
                return (f"error: unknown clear interfaces statistics target: "
                        f"{' '.join(tokens[3:])}")
            name = tokens[2] if len(tokens) >= 3 else ""
            resp = self._public_action_rpc(
                DAEMON_STATSD, 2, name.encode() if name else b"")
            _, failed = self._public_action_text(
                "Clear interface statistics", resp)
            if failed:
                return failed
            return "Interface statistics cleared"
        if len(tokens) >= 2 and tokens[0] == "ethernet-switching" and tokens[1] == "table":
            return self._clear_eth_sw_table(tokens[2:])
        if (len(tokens) == 4 and tokens[0] == "ethernet-switching" and
                tokens[1] == "secure-access-port" and tokens[2] == "interface"):
            payload = f"interface={tokens[3]}".encode()
            resp = self._public_action_rpc(DAEMON_L2D, 6, payload)
            text, failed = self._public_action_text(
                "Clear secure access port state", resp)
            if failed:
                return failed
            text = text.strip()
            return text if text else f"secure-access-port cleared on {tokens[3]}"
        if (len(tokens) >= 2 and tokens[0] == "ethernet-switching" and
                tokens[1] == "mac-move"):
            if len(tokens) == 2:
                payload = b""
            elif len(tokens) == 4 and tokens[2] == "interface":
                payload = f"interface={tokens[3]}".encode()
            else:
                return "error: usage: clear ethernet-switching mac-move [interface <name>]"
            resp = self._public_action_rpc(DAEMON_L2D, 7, payload)
            text, failed = self._public_action_text(
                "Clear MAC move state", resp)
            if failed:
                return failed
            text = text.strip()
            return text if text else "MAC move state cleared"
        if (len(tokens) >= 3 and tokens[0] == "spanning-tree" and
                tokens[1] == "bpdu-guard" and tokens[2] == "interface"):
            if len(tokens) < 4:
                return "error: missing interface name"
            if len(tokens) > 4:
                return (f"error: unknown clear spanning-tree bpdu-guard "
                        f"interface target: {' '.join(tokens[4:])}")
            payload = f"interface={tokens[3]}".encode()
            resp = self._public_action_rpc(DAEMON_STPD, 2, payload)
            text, failed = self._public_action_text(
                "Clear BPDU guard state", resp)
            if failed:
                return failed
            text = text.strip()
            return text if text else f"BPDU guard cleared on {tokens[3]}"
        return "error: unknown clear command"

    def _clear_eth_sw_table(self, tokens):
        port = 0
        vid = 0
        i = 0
        seen = set()

        while i < len(tokens):
            tok = tokens[i]
            if tok == "interface":
                if "interface" in seen:
                    return "error: duplicate interface filter"
                if i + 1 >= len(tokens):
                    return "error: missing interface name"
                port = ifname_to_hw_port(tokens[i + 1])
                if port <= 0:
                    return f"error: unsupported ethernet-switching interface: {tokens[i + 1]}"
                seen.add("interface")
                i += 2
                continue
            if tok == "vlan":
                if "vlan" in seen:
                    return "error: duplicate vlan filter"
                if i + 1 >= len(tokens):
                    return "error: missing vlan name or id"
                vid = self._resolve_vlan_id(tokens[i + 1])
                if vid <= 0:
                    return f"error: vlan not found: {tokens[i + 1]}"
                seen.add("vlan")
                i += 2
                continue
            return f"error: unsupported clear ethernet-switching table filter: {' '.join(tokens[i:])}"

        payload = f"port={port} vid={vid}".encode()
        resp = self._public_action_rpc(DAEMON_SWITCHD, 53, payload)
        _, failed = self._public_action_text(
            "Clear ethernet switching table", resp)
        if failed:
            return failed

        scope = []
        if vid:
            scope.append(f"vlan {vid}")
        if port:
            scope.append(f"interface {port_to_ifname(port)}")
        suffix = " " + " ".join(scope) if scope else ""
        return f"Ethernet switching table cleared{suffix}"

    def _resolve_vlan_id(self, value):
        try:
            vid = int(value)
            return vid if 1 <= vid <= 4094 else 0
        except (TypeError, ValueError):
            pass

        xml = self._get_config_xml(active=True)
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return 0

        for vlan in root.iter():
            if xml_local_name(vlan.tag) != "vlan":
                continue
            name = xml_child_text(vlan, "name")
            if name != value:
                continue
            try:
                vid = int(xml_child_text(vlan, "vlan-id"))
                return vid if 1 <= vid <= 4094 else 0
            except ValueError:
                return 0
        return 0

    def _show_interface_optics(self, ifname):
        logical_port = ifname_to_hw_port(ifname)
        if logical_port <= 0:
            return f"error: optics diagnostics are available only for physical et interfaces: {ifname}"
        resp = self._optics_mux_rpc()
        text = format_interface_optics_mux(resp.decode(errors='replace'),
                                           ifname)
        if "Optical diagnostics                       : unavailable" not in text:
            return text
        return text + "\n" + "\n".join([
            f"  Legacy DOM reason                         : {OPTICS_UNAVAILABLE_REASON}",
            "  Module view                               : show chassis optics mux",
        ])

    def _show_all_interface_optics(self):
        try:
            names = physical_interface_names()
        except Exception:
            names = []
        if not names:
            return "\n".join([
                "Optical diagnostics: unavailable",
                f"Reason: {OPTICS_UNAVAILABLE_REASON}",
                "Module view: show chassis optics mux",
            ])
        resp = self._optics_mux_rpc()
        xml = resp.decode(errors='replace')
        return "\n\n".join(format_interface_optics_mux(xml, name)
                           for name in names)

    def _show_interface_optics_calibration(self):
        optics = self._optics_mux_rpc()
        optics_xml = optics.decode(errors='replace')
        interfaces_xml = self._optics_interface_terse_xml(optics_xml)
        return format_interface_optics_mux_calibration(
            optics_xml, interfaces_xml)

    def _show_interface_optics_calibration_check(self, mode):
        optics = self._optics_mux_rpc()
        optics_xml = optics.decode(errors='replace')
        interfaces_xml = self._optics_interface_terse_xml(optics_xml)
        return format_interface_optics_mux_calibration_check(
            optics_xml, interfaces_xml, mode)

    def _show_interface_optics_mapping(self):
        optics = self._optics_mux_rpc()
        optics_xml = optics.decode(errors='replace')
        interfaces_xml = self._optics_interface_terse_xml(optics_xml)
        return format_interface_optics_mux_mapping(optics_xml, interfaces_xml)

    def _optics_mux_rpc(self):
        resp = b""
        for attempt in range(OPTICS_MUX_RPC_RETRIES):
            resp = self._rpc(DAEMON_SWITCHD, 90, OPTICS_MUX_RPC_PAYLOAD,
                             timeout_ms=_optics_mux_rpc_timeout_ms())
            if self._optics_mux_usable(resp.decode(errors='replace')):
                return resp
            if attempt + 1 < OPTICS_MUX_RPC_RETRIES:
                time.sleep(OPTICS_MUX_RPC_RETRY_DELAY_SEC)
        return resp

    def _optics_interface_terse_xml(self, optics_xml):
        if not self._optics_mux_usable(optics_xml):
            return ""
        try:
            interfaces = self._rpc(
                DAEMON_IFD, 1, b"terse",
                timeout_ms=_optics_mux_rpc_timeout_ms())
            return interfaces.decode(errors='replace')
        except Exception:
            return ""

    def _optics_mux_usable(self, optics_xml):
        try:
            root = ET.fromstring(optics_xml)
        except ET.ParseError:
            return False
        return root.tag == "optics-mux-probe" and not root.attrib.get("error")

    def _handle_cfg(self, tokens):
        cmd = tokens[0]
        if cmd == "set":
            return self._cfg_set(tokens[1:])
        if cmd == "delete":
            return self._cfg_delete(tokens[1:])
        if cmd == "commit":
            return self._cfg_commit(tokens[1:])
        if cmd == "rollback":
            return self._cfg_rollback(tokens[1:])
        if cmd == "save":
            return self._cfg_save(tokens[1:])
        if cmd == "load":
            return self._cfg_load(tokens[1:])
        if cmd == "show":
            return self._cfg_show(tokens[1:])
        if cmd == "edit":
            return self._cfg_edit(tokens[1:])
        if cmd == "up":
            if len(tokens) != 1:
                return f"error: unknown up option: {' '.join(tokens[1:])}"
            if self.edit_path:
                self.edit_path.pop()
            return None
        if cmd == "top":
            if len(tokens) != 1:
                return f"error: unknown top option: {' '.join(tokens[1:])}"
            self.edit_path = []
            return None
        if cmd == "run":
            if len(tokens) == 1:
                return "error: incomplete run command"
            return self._handle_op(tokens[1:])
        return f"error: unknown config command: {cmd}"

    def _cfg_set(self, tokens):
        if not tokens:
            return "error: incomplete set command"
        lock_error = self._config_writable_error()
        if lock_error:
            return lock_error
        path_tokens = list(self.edit_path) + list(tokens)
        unsupported = unsupported_config_leaf(path_tokens)
        if unsupported:
            return unsupported
        path, value = cli_to_path(path_tokens)
        if path is None:
            return f"error: cannot parse: {' '.join(tokens)}"
        payload = path.encode() + b'\0' + value.encode()
        resp = self._configd_write_rpc(1, payload)
        _, error = self._configd_action_text(resp)
        if error:
            return error
        return None

    def _cfg_delete(self, tokens):
        if not tokens:
            return "error: incomplete delete command"
        lock_error = self._config_writable_error()
        if lock_error:
            return lock_error
        path_tokens = list(self.edit_path) + list(tokens)
        unsupported = unsupported_config_delete_leaf(path_tokens)
        if unsupported:
            return unsupported
        path = cli_to_delete_path(path_tokens)
        if path is None:
            return f"error: cannot parse"
        resp = self._configd_write_rpc(2, path.encode())
        _, error = self._configd_action_text(resp)
        if error:
            return error
        return None

    def _cfg_commit(self, tokens):
        lock_error = self._config_writable_error()
        if lock_error:
            return lock_error
        if tokens and tokens[0] == "check":
            if len(tokens) != 1:
                return "error: usage: commit check"
            resp = self._configd_commit_rpc(6, b"")
            _, error = self._configd_action_text(resp)
            if error:
                return error
            return "commit check passed"
        if tokens and tokens[0] == "confirmed":
            result = self._commit_confirmed_payload(tokens[1:])
            if result.startswith("error:"):
                return result
            resp = self._configd_commit_rpc(3, result.encode())
            _, error = self._configd_action_text(resp)
            if error:
                return error
            return ("commit confirmed will be automatically rolled back "
                    "unless confirmed; use 'commit' to confirm")
        if tokens and tokens[0] == "comment":
            if len(tokens) < 2:
                return "error: usage: commit comment <comment>"
            comment = " ".join(tokens[1:]).strip()
            if not comment:
                return "error: commit comment cannot be empty"
            resp = self._configd_commit_rpc(
                3, ("comment=" + comment).encode())
            _, error = self._configd_action_text(resp)
            if error:
                return error
            return "commit complete"
        if tokens:
            return f"error: unsupported commit option: {' '.join(tokens)}"
        resp = self._configd_commit_rpc(3, b"")
        _, error = self._configd_action_text(resp)
        if error:
            return error
        return "commit complete"

    def _commit_confirmed_payload(self, tokens):
        seconds = 600
        comment = ""
        rest = list(tokens)
        if rest and rest[0].isdigit():
            minutes = int(rest.pop(0), 10)
            if minutes < 1 or minutes > 60:
                return "error: commit confirmed timeout must be 1-60 minutes"
            seconds = minutes * 60
        if rest:
            if rest[0] != "comment" or len(rest) < 2:
                return "error: usage: commit confirmed [minutes] [comment <comment>]"
            comment = " ".join(rest[1:]).strip()
            if not comment:
                return "error: commit comment cannot be empty"
        payload = f"confirmed={seconds}"
        if comment:
            payload += "\ncomment=" + comment
        return payload

    def _cfg_rollback(self, tokens):
        lock_error = self._config_writable_error()
        if lock_error:
            return lock_error
        if len(tokens) > 1:
            return "error: rollback accepts at most one rollback number"
        generation = tokens[0] if tokens else "0"
        if generation == "rescue":
            path = self._rescue_config_path()
            if not os.path.exists(path):
                return "error: rescue configuration not present"
            return self._cfg_load(["override", path])
        if not generation.isdigit():
            return "error: rollback number must be a non-negative integer"
        resp = self._configd_write_rpc(4, generation.encode())
        text, error = self._configd_action_text(resp)
        if error:
            return error
        text = text.strip()
        if text:
            return text
        return "rollback complete"

    def _cfg_save(self, tokens):
        if len(tokens) != 1:
            return "error: usage: save <filename>"
        filename = tokens[0]
        if os.path.isdir(filename):
            return f"error: cannot save configuration to directory: {filename}"
        xml = self._get_config_xml(active=False).lstrip()
        if not xml.startswith("<"):
            return xml if xml else "error: cannot read candidate configuration"
        text = format_config_as_set(xml)
        try:
            with open(filename, "w", encoding="utf-8") as handle:
                handle.write(text)
                if text and not text.endswith("\n"):
                    handle.write("\n")
        except OSError as exc:
            return f"error: cannot save configuration: {exc}"
        return f"Wrote {filename}"

    def _cfg_load(self, tokens):
        if len(tokens) == 1 and tokens[0] == "factory-default":
            lock_error = self._config_writable_error()
            if lock_error:
                return lock_error
            result = self._cfg_clear_candidate()
            if result:
                return result
            return "load factory-default complete"
        if len(tokens) != 2 or tokens[0] not in (
                "merge", "override", "set"):
            return ("error: usage: load factory-default | "
                    "load merge|override|set <filename>")
        lock_error = self._config_writable_error()
        if lock_error:
            return lock_error
        mode = tokens[0]
        filename = tokens[1]
        if os.path.isdir(filename):
            return f"error: cannot load configuration from directory: {filename}"
        try:
            with open(filename, "r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except OSError as exc:
            return f"error: cannot load configuration: {exc}"

        statements = []
        applied = 0
        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("set "):
                return (f"error: load supports display-set files only "
                        f"(line {lineno}: {line})")
            try:
                tokens = shlex.split(line)[1:]
            except ValueError as exc:
                return f"error: line {lineno}: {exc}"
            path_tokens = list(self.edit_path) + list(tokens)
            unsupported = unsupported_config_leaf(path_tokens)
            if unsupported:
                return f"error: line {lineno}: {unsupported}"
            path, _ = cli_to_path(path_tokens)
            if path is None:
                return f"error: line {lineno}: cannot parse: {' '.join(tokens)}"
            statements.append((lineno, tokens))

        if mode == "override":
            result = self._cfg_clear_candidate()
            if result:
                return result

        for lineno, tokens in statements:
            result = self._cfg_set(tokens)
            if result:
                return f"error: line {lineno}: {result}"
            applied += 1
        return f"load {mode} complete: {applied} statements"

    def _cfg_clear_candidate(self):
        roots = (
            "/netlab:netlab-config/system",
            "/netlab:netlab-config/chassis",
            "/netlab:netlab-config/vlans",
            "/netlab:netlab-config/interfaces",
            "/netlab:netlab-config/interfaces-routing",
            "/netlab:netlab-config/routing-options",
            "/netlab:netlab-config/routing-instances",
            "/netlab:netlab-config/policy-options",
            "/netlab:netlab-config/protocols",
            "/netlab:netlab-config/forwarding-options",
            "/netlab:netlab-config/snmp",
            "/netlab:netlab-config/control-plane",
            "/netlab:netlab-config/class-of-service",
            "/netlab:netlab-config/ethernet-switching-options",
        )
        for path in roots:
            ec, resp = self._configd_delete_raw(path)
            if ec in (0, 1001):
                continue
            detail = resp.decode(errors="replace") if resp else ""
            return format_error(ec, detail)
        return None

    def _configd_delete_raw(self, path):
        payload, error = self._configd_guarded_payload(path.encode())
        if error:
            return 3006, error.encode()
        sess = CliSession()
        if not sess.connect():
            return 3002, b"cannot connect to mgmtd"
        ec, _, resp = sess.send_request(DAEMON_CONFIGD, 2, payload)
        sess.close()
        return ec, resp

    def _cfg_show(self, tokens):
        if tokens and tokens[0] == "|":
            return self._pipe_show(tokens[1:], active=False)
        if not tokens:
            tokens = []
        text = self._get_config_xml(active=False)
        if text.lstrip().startswith("<"):
            return format_config_hierarchy(text, tokens)
        return text if text else "(empty)"

    def _cfg_edit(self, tokens):
        if not tokens:
            return f"edit path: {' '.join(self.edit_path)}"
        self.edit_path = list(tokens)
        return None

    def _pipe_show(self, tokens, active=False, path_tokens=None):
        if not tokens:
            pipe_cmds = ["compare", "display", "match", "except", "count", "no-more"]
            return "error: incomplete pipe\nPossible completions:\n  " + "\n  ".join(pipe_cmds)
        if tokens[0] == "compare":
            if len(tokens) == 3 and tokens[1] == "rollback":
                return self._pipe_show_compare_rollback(
                    tokens[2], active=active, path_tokens=path_tokens)
            if len(tokens) > 1:
                return "error: usage: compare [rollback <rollback-number>]"
            if active:
                return self._pipe_show_compare_rollback(
                    "0", active=True, path_tokens=path_tokens)
            candidate_xml = self._get_config_xml(active=False).lstrip()
            if not candidate_xml.startswith("<"):
                return (candidate_xml if candidate_xml else
                        "error: cannot read candidate configuration")
            active_xml = self._get_config_xml(active=True).lstrip()
            if not active_xml.startswith("<"):
                return (active_xml if active_xml else
                        "error: cannot read active configuration")
            return self._format_config_hierarchy_compare(
                candidate_xml, active_xml,
                "No changes between candidate and active config",
                path_tokens=path_tokens)
        if tokens[0] == "display":
            if len(tokens) < 2:
                return "error: incomplete display pipe; use display set|xml|json"
            fmt = tokens[1]
            if len(tokens) > 2:
                return "error: unknown display option: " + " ".join(tokens[2:])
            xml = self._get_config_xml(active=active)
            if fmt == "set":
                return format_config_as_set(xml, path_tokens=path_tokens)
            if fmt == "xml":
                return xml
            if fmt == "json":
                return apply_pipe(xml, "display json")
            return "error: unknown display format: " + fmt
        # Partial pipe — show completions
        prefix = tokens[0]
        all_pipes = ["compare", "display", "match", "except", "count", "no-more"]
        matches = [p for p in all_pipes if p.startswith(prefix)]
        if matches:
            return "error: unknown pipe: " + prefix + "\nPossible completions:\n  " + "\n  ".join(matches)
        return "error: unknown pipe: " + " ".join(tokens)

    def _pipe_show_compare_rollback(self, generation_text, active=False,
                                    path_tokens=None):
        source_xml = self._get_config_xml(active=active).lstrip()
        if not source_xml.startswith("<"):
            label = "active" if active else "candidate"
            return source_xml if source_xml else f"error: cannot read {label} configuration"
        rollback_xml, error = self._rollback_config_xml(generation_text)
        if error:
            return error
        label = "active" if active else "candidate"
        return self._format_config_set_compare(
            source_xml, rollback_xml,
            f"No differences between {label} configuration and rollback "
            f"{generation_text}",
            path_tokens=path_tokens)

    def _rpc(self, daemon, method, payload, timeout_ms=0):
        s = CliSession()
        if not s.connect():
            return b"error: cannot connect to mgmtd"
        ec, plen, resp = s.send_request(daemon, method, payload,
                                        timeout_ms=timeout_ms)
        s.close()
        if ec != 0:
            msg = resp.decode(errors='replace') if resp else ""
            return format_error(ec, msg).encode()
        return resp


def main():
    cli = NetLabCLI()
    if not sys.stdin.isatty():
        cli._run_batch()
    else:
        cli.run()

def _run_batch(self):
    """Non-TTY batch mode: simple line-by-line processing."""
    s = CliSession()
    if not s.connect():
        print("error: mgmtd not running")
        sys.exit(1)
    s.close()
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line in ("quit", "exit") and self.mode != "config":
            break
        result = self.dispatch(line)
        if result is not None:
            print(result, flush=True)
    # ensure all output is flushed
    sys.stdout.flush()
NetLabCLI._run_batch = _run_batch

if __name__ == "__main__":
    main()
