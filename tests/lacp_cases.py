"""Shared configuration edits for the production planner and LACP daemon."""
from copy import deepcopy
from xml.etree import ElementTree as ET

from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab_codec import compile_configuration


def lacp_configuration_cases(profile="sil001-hw4-b0"):
    raw = SwitchConfiguration(profile=profile).model_dump()
    for port in (1, 5, 9, 13, 17, 21):
        raw["ports"][port].update(enabled=True, pvid=1)
    raw["lags"] = [
        {"name": "ae0", "members": [1, 5], "mode": "active"},
        {"name": "ae1", "members": [9, 13], "mode": "active"},
        {"name": "ae2", "members": [17, 21], "mode": "static"},
    ]
    config = SwitchConfiguration.model_validate(raw)
    base = ET.fromstring(compile_configuration(config))
    ns = base.tag[:base.tag.index("}") + 1]
    ET.register_namespace("", ns[1:-1])

    def interface(root, name):
        return next(n for n in root.find(ns + "interfaces") if n.findtext(ns + "name") == name)

    def leaf(parent, path, value):
        for tag in path.split("/"):
            node = parent.find(ns + tag)
            if node is None:
                node = ET.SubElement(parent, ns + tag)
            parent = node
        parent.text = str(value)

    cases = {}
    def case(name, groups, edit):
        tree = deepcopy(base)
        edit(tree)
        cases[name] = (ET.tostring(tree), groups)

    case("unchanged", set(), lambda root: None)
    case("description", set(), lambda root: leaf(interface(root, "et-0/0/0"), "description", "uplink"))
    def reorder(root):
        interfaces = root.find(ns + "interfaces")
        interfaces[:] = list(reversed(interfaces))
    case("reordered", set(), reorder)
    for name, path, value in (
        ("minimum-links", "minimum-links", 2),
        ("periodic", "lacp/periodic", "slow"),
        ("actor-key", "lacp/actor-key", 23),
        ("passive", "lacp/mode", "passive"),
    ):
        case(name, {0}, lambda root, path=path, value=value:
             leaf(interface(root, "ae0"), "aggregated-ether-options/" + path, value))
    case("member-priority", {0}, lambda root:
         leaf(interface(root, "et-0/0/0"), "ether-options/lacp/port-priority", 4096))
    for name, value in (("system-id", "02:00:00:00:00:0e"), ("system-priority", 4096), ("port-priority", 4096)):
        case(name, {0, 1}, lambda root, name=name, value=value: leaf(root, "protocols/lacp/" + name, value))
    case("minimum-static", {2}, lambda root: leaf(interface(root, "ae2"), "aggregated-ether-options/minimum-links", 2))
    def remove_member(root):
        port = interface(root, "et-0/0/4")
        port.remove(port.find(ns + "ether-options"))
        leaf(port, "disable", "true")
    case("member-remove", {0}, remove_member)
    case("member-move", {0, 1}, lambda root: leaf(interface(root, "et-0/0/4"), "ether-options/ieee8023ad", "ae1"))
    def make_static(root):
        agg = interface(root, "ae0").find(ns + "aggregated-ether-options")
        agg.remove(agg.find(ns + "lacp"))
        leaf(agg, "static", "true")
    case("static", {0}, make_static)
    return config, ET.tostring(base), cases
