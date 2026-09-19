"""
Junos-like completion engine — Tab completion + ? context help.
Prompt_toolkit is used only for input; all completion/help logic is here.
"""
import shlex
from completion_dynamic import dynamic_candidates
from completion_schema import CFG_SCHEMA, OP_SCHEMA


# ===== Token context parser =====
def parse_context(text: str):
    """Parse input text into consumed tokens and partial token."""
    if not text or not text.strip():
        return [], ""
    ends_with_space = text.endswith(" ")
    try:
        tokens = shlex.split(text)
    except ValueError:
        # Unclosed quote — split manually
        tokens = text.strip().split()
    if not tokens:
        return [], ""
    if ends_with_space:
        return tokens, ""
    else:
        return tokens[:-1], tokens[-1]


# ===== Schema walker =====
def _walk_schema(schema, consumed):
    """Walk the schema tree following consumed tokens. Returns the node at that path."""
    node = schema
    for tok in consumed:
        if isinstance(node, dict):
            if tok in node:
                child = node[tok]
                if isinstance(child, dict) and child.get("_hidden"):
                    return {}
                node = child
            else:
                # Try dynamic keys like <interface-name>
                found = False
                for key in node:
                    if key.startswith("<") and key.endswith(">"):
                        child = node[key]
                        if isinstance(child, dict) and child.get("_hidden"):
                            return {}
                        node = child
                        found = True
                        break
                if not found:
                    return {}
        else:
            return {}
    return node if isinstance(node, dict) else {}


# ===== Candidate extraction =====
def get_context_candidates(text: str, mode="operational", edit_path=None):
    """
    Return list of {word, help} for the current input context.
    """
    original_consumed, _ = parse_context(text)
    if mode == "config" and original_consumed and original_consumed[0] == "run":
        run_text = text.lstrip()[len("run"):].lstrip()
        return get_context_candidates(run_text, "operational", None)

    schema = CFG_SCHEMA if mode == "config" else OP_SCHEMA

    # Expand edit path
    expanded = text
    if mode == "config" and edit_path and text.strip():
        first = text.strip().split()[0] if text.strip() else ""
        if first in ("set", "delete", "show"):
            # Check if path is relative (no top-level keyword)
            tokens = text.strip().split()[1:] if len(text.strip().split()) > 1 else []
            if tokens and tokens[0] not in ("vlans", "interfaces", "protocols",
                                             "routing-options", "routing-instances",
                                             "policy-options",
                                             "system", "chassis", "control-plane",
                                             "class-of-service", "firewall",
                                             "ethernet-switching-options"):
                # Prepend edit path
                expanded = first + " " + " ".join(edit_path) + " " + " ".join(tokens)

    consumed, partial = parse_context(expanded)

    # Handle pipe: if consumed contains "|" or partial starts with "|"
    if "|" in consumed or partial.startswith("|"):
        pipe_partial = partial[1:] if partial.startswith("|") else partial
        # Build pipe context
        if "|" in consumed:
            pipe_idx = consumed.index("|")
            after_pipe = consumed[pipe_idx + 1:]
        else:
            after_pipe = []
        pipe_node = {
            "compare": {
                "_help": "Compare candidate with active or rollback",
                "_executable": True,
                "rollback": {
                    "_help": "Compare against rollback configuration",
                    "<rollback-number>": {
                        "_help": "Rollback configuration number",
                        "_dynamic": "rollback-numbers",
                        "_executable": True,
                    },
                },
            },
            "display": {"_help": "Display options",
                "set": {"_help": "Display as set commands"},
                "xml": {"_help": "Display as XML"},
                "json": {"_help": "Display as JSON"},
            },
            "match": {"_help": "Match lines containing pattern"},
            "except": {"_help": "Exclude lines containing pattern"},
            "count": {"_help": "Count output lines"},
            "no-more": {"_help": "Do not paginate output"},
        }
        node = _walk_schema(pipe_node, after_pipe) if after_pipe else pipe_node
        # Re-parse partial for pipe context
        if partial.startswith("|"):
            partial = partial[1:]

        if not after_pipe and not partial:
            # Show all pipe commands with help
            candidates = []
            for key, child in sorted(pipe_node.items()):
                help_text = child.get("_help", "") if isinstance(child, dict) else ""
                candidates.append({"word": key, "help": help_text})
            return candidates
        # Re-parse to get correct partial from after-pipe
        if "|" in text:
            pipe_text = text.split("|", 1)[1] if "|" in text else ""
            _, partial = parse_context(pipe_text)
    else:
        node = _walk_schema(schema, consumed)

    candidates = []
    for key, child in sorted(node.items()):
        if key.startswith("_"):
            continue
        if isinstance(child, dict) and child.get("_hidden"):
            continue
        help_text = child.get("_help", "") if isinstance(child, dict) else ""
        if key.startswith("<") and key.endswith(">"):
            dyn_type = child.get("_dynamic", "") if isinstance(child, dict) else ""
            dyn = dynamic_candidates(dyn_type, partial)
            if dyn:
                candidates.extend(dyn)
            runtime_if_partial = dyn_type in (
                "operational-interfaces", "physical-interfaces",
                "rstp-interfaces", "lldp-interfaces",
            ) and partial
            if (not dyn or not partial) and not runtime_if_partial and not (dyn_type == "rollback" and dyn):
                candidates.append({"word": key, "help": help_text, "dynamic": dyn_type})
        elif key.startswith(partial):
            candidates.append({"word": key, "help": help_text})

    # Add pipe if node allows it
    if node.get("_allow_pipe") and not partial and not any(c["word"] == "|" for c in candidates):
        candidates.append({"word": "|", "help": "Pipe through a command"})

    # Add <[Enter]> if node is executable
    if node.get("_executable") and not partial:
        candidates.append({"word": "<[Enter]>", "help": "Execute this command"})

    return candidates


# ===== Common prefix =====
def common_prefix(items):
    if not items:
        return ""
    prefix = items[0]
    for item in items[1:]:
        while not item.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    return prefix
