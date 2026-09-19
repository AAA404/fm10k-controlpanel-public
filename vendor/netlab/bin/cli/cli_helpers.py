"""Small helpers shared by CLI command handlers."""
import xml.etree.ElementTree as ET

from platform_profile import ifname_to_port


def ifname_to_hw_port(ifname):
    return ifname_to_port(ifname)


def xml_local_name(tag):
    return tag.split("}", 1)[1] if "}" in tag else tag


def xml_child_text(elem, child_name):
    for child in list(elem):
        if xml_local_name(child.tag) == child_name:
            return child.text.strip() if child.text else ""
    return ""


def interface_names_from_terse(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    names = []
    for iface in root.findall("interface"):
        node = iface.find("name")
        if node is not None and node.text:
            names.append(node.text.strip())
    return names
