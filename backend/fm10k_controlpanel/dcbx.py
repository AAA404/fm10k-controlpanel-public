"""Decode local-policy IEEE DCBX without treating advertisements as traffic proof."""
from .board import HardwareError


def decode(root, configuration, links):
    from .roce import dcbx_policy
    if root.tag != "dcbx" or root.get("mode") != "ieee-local" or root.get("peer-policy-applied") != "false":
        raise HardwareError("DCBX 原生回读缺失或策略模式不兼容")
    expected = dcbx_policy(configuration)
    selected = set(configuration.qos.roce.ports) if expected["enabled"] else set()

    def profile(node):
        if node is None:
            return None
        try:
            vectors = {key: [int(v) for v in node.get(key.replace("_", "-"), "").split()]
                       for key in ("priority_map", "bandwidth", "tsa_map")}
            if any(len(v) != 8 for v in vectors.values()):
                return None
            apps = [{key: int(a.attrib[key]) for key in ("selector", "protocol", "priority")}
                    for a in node.findall("application")]
            if (any(not 0 <= v <= 7 for v in vectors["priority_map"]) or
                    any(not 0 <= v <= 100 for v in vectors["bandwidth"]) or
                    any(v not in (0, 1, 2, 255) for v in vectors["tsa_map"]) or len(apps) > 32 or
                    any(not 1 <= a["selector"] <= 5 or not 0 <= a["priority"] <= 7 or
                        not 0 <= a["protocol"] <= (63 if a["selector"] == 5 else 65535) for a in apps)):
                return None
            return {**vectors, "enabled": node.get("enabled") == "true", "malformed": node.get("malformed") != "false",
                    "pfc_mask": int(node.attrib["pfc-mask"]), "pfc_willing": node.get("pfc-willing"),
                    "ets_willing": node.get("ets-willing"),
                    "complete": all(node.get(key + "-present") == "true" for key in ("pfc", "ets", "app")),
                    "applications": apps}
        except (ValueError, KeyError, TypeError):
            return None

    rows, seen = [], set()
    for node in root.findall("interface"):
        try:
            port = int(node.attrib["port"])
            tx_frames = int(node.attrib["tx-frames"])
        except (ValueError, KeyError):
            raise HardwareError("DCBX 端口回读无效") from None
        if port in seen or port not in configuration.ports or tx_frames < 0:
            raise HardwareError("DCBX 端口回读重复或越界")
        seen.add(port)
        local = profile(node.find("local"))
        good = bool(port in selected and local and local["enabled"] and local["complete"] and not local["malformed"] and
                    node.get("lldp-enabled") == "true" and local["pfc_willing"] == local["ets_willing"] == "false" and
                    all(local[k] == expected[k] for k in ("pfc_mask", "priority_map", "bandwidth", "tsa_map")) and
                    sorted(local["applications"], key=lambda a: (a["selector"], a["protocol"], a["priority"])) ==
                    sorted(expected["applications"], key=lambda a: (a["selector"], a["protocol"], a["priority"])))
        peers = [{"state": p.get("state", "unknown"), "system_name": p.get("system-name", ""),
                  "age_seconds": p.get("age-seconds"), "ttl": p.get("ttl"), "policy": profile(p.find("remote"))}
                 for p in node.findall("peer")]
        for peer in peers:
            try:
                current = 0 <= int(peer["age_seconds"]) < int(peer["ttl"])
            except (ValueError, TypeError):
                current = False
            if not current:
                peer["state"] = "expired"
            elif peer["state"] == "matched" and (not peer["policy"] or peer["policy"]["malformed"] or not peer["policy"]["complete"]):
                peer["state"] = "malformed-peer"
        state = "local-mismatch" if not good else "link-down" if links.get(port) != "up" else (
            "no-peer" if not peers else "multiple-peers" if len(peers) > 1 else peers[0]["state"])
        rows.append({"port": port, "configuration_matches": good, "state": state, "local": local,
                     "peers": peers, "tx_frames": tx_frames})
    for port in sorted(selected - seen):
        rows.append({"port": port, "configuration_matches": False, "state": "local-missing", "local": None,
                     "peers": [], "tx_frames": None})
    return {"mode": "ieee" if expected["enabled"] else "off", "quality": "valid", "peer_policy_applied": False,
            "configuration_matches": selected == seen and all(p["configuration_matches"] for p in rows),
            "ports": sorted(rows, key=lambda p: p["port"])}
