"""
CLI pipe filters — match, except, count, no-more, display set/xml/json.
"""
import re


def apply_pipe(output: str, pipe_cmd: str) -> str:
    """Apply a pipe filter to output text."""
    tokens = pipe_cmd.strip().split()
    if not tokens:
        return output

    cmd = tokens[0]
    args = tokens[1:]

    if cmd == "match":
        pattern = " ".join(args)
        try:
            regex = re.compile(pattern)
        except re.error as e:
            return f"error: invalid regex pattern: {e}"
        lines = output.split("\n")
        matched = [l for l in lines if regex.search(l)]
        return "\n".join(matched)

    elif cmd == "except":
        pattern = " ".join(args)
        try:
            regex = re.compile(pattern)
        except re.error as e:
            return f"error: invalid regex pattern: {e}"
        lines = output.split("\n")
        matched = [l for l in lines if not regex.search(l)]
        return "\n".join(matched)

    elif cmd == "count":
        lines = [l for l in output.split("\n") if l.strip()]
        return f"Count: {len(lines)} lines"

    elif cmd == "no-more":
        return output

    elif cmd == "display":
        if not args:
            return "error: incomplete display pipe; use display set|xml|json"
        fmt = args[0]
        if len(args) > 1:
            return "error: unknown display option: " + " ".join(args[1:])
        if fmt == "set":
            return _to_set_format(output)
        elif fmt == "xml":
            return output  # Already XML
        elif fmt == "json":
            return _to_json_format(output)
        else:
            return f"error: unknown display format: {fmt}"

    else:
        return output


def _to_set_format(xml: str) -> str:
    """Convert XML config to set-command format."""
    # Simple heuristic: extract leaf values and render as set lines
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return xml  # Return as-is if not valid XML

    lines = []
    _walk_set(root, "", lines)
    return "\n".join(lines)


def _walk_set(elem, path, lines):
    """Walk XML tree and emit set commands."""
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    current = f"{path} {tag}".strip()

    # Check if leaf node (has text but no children)
    children = list(elem)
    if not children and elem.text and elem.text.strip():
        lines.append(f"set {current} {elem.text.strip()}")
    elif not children:
        # Container node — don't emit, just recurse into imaginary children
        pass
    else:
        for child in children:
            _walk_set(child, current, lines)


def _to_json_format(xml: str) -> str:
    """Convert XML to JSON (basic)."""
    try:
        import xml.etree.ElementTree as ET
        import json
        root = ET.fromstring(xml)
        return json.dumps(_elem_to_dict(root), indent=2)
    except Exception:
        return xml


def _elem_to_dict(elem):
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    children = list(elem)
    if not children:
        return {tag: elem.text.strip() if elem.text else ""}
    result = {}
    child_dicts = {}
    for child in children:
        d = _elem_to_dict(child)
        for k, v in d.items():
            if k in child_dicts:
                if not isinstance(child_dicts[k], list):
                    child_dicts[k] = [child_dicts[k]]
                child_dicts[k].append(v)
            else:
                child_dicts[k] = v
    result[tag] = child_dicts
    return result
