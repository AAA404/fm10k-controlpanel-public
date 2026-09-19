"""Static operational and configuration command completion schemas."""

import copy

from public_capabilities import (GENERAL_ACL_INDEPENDENT,
                                 MANAGEMENT_SERVICES,
                                 public_capability_enabled)

# ===== Command schema with help text =====
# Special keys: _help = description, _executable = can press Enter, _dynamic = source type
OP_SCHEMA = {
    "show": {
        "_help": "Show system information",
        "_allow_pipe": True,
        "chassis": {
            "_help": "Show chassis information",
            "forwarding": {
                "_help": "Show PFE forwarding status",
                "_executable": True,
                "resources": {
                    "_help": "Show ASIC forwarding resource usage",
                    "_executable": True,
                },
                "config": {
                    "_help": "Show ASIC runtime switch configuration",
                    "_executable": True,
                },
                "sdk": {
                    "_help": "Show loaded forwarding runtime",
                    "_executable": True,
                },
            },
            "port-mode": {
                "_help": "Show active and configured chassis port-mode intent",
                "_executable": True,
            },
            "hardware": {"_help": "Show chassis hardware", "_executable": True},
            "alarms": {
                "_help": "Show chassis alarms",
                "_executable": True,
            },
            "environment": {
                "_help": "Show chassis environmental sensors",
                "_executable": True,
            },
            "routing-engine": {
                "_help": "Show routing engine runtime inventory",
                "_executable": True,
            },
            "optics": {
                "_help": "Show chassis optics information",
                "mux": {
                    "_help": "Show PE31625G24DIRA module mux telemetry",
                    "_executable": True,
                    "detail": {
                        "_help": "Show mux page coverage and raw sideband data",
                        "_executable": True,
                    },
                },
            },
        },
        "control-plane": {
            "_help": "Show control-plane information",
            "protection": {
                "_help": "Show control-plane protection state",
                "_executable": True,
            },
        },
        "forwarding-options": {
            "_help": "Show forwarding options",
            "port-mirroring": {
                "_help": "Show local port mirroring state",
                "_executable": True,
            },
        },
        "igmp-snooping": {
            "_help": "Show IPv4 IGMP snooping members and forwarding state",
            "_executable": True,
        },
        "class-of-service": {
            "_help": "Show class-of-service information",
            "_executable": True,
            "capabilities": {
                "_help": "Show hardware-backed CoS capability boundaries",
                "_executable": True,
            },
            "interfaces": {
                "_help": "Show interface CoS trust state",
                "_executable": True,
            },
            "forwarding": {
                "_help": "Show switch-priority forwarding map",
                "_executable": True,
            },
            "flow-control": {
                "_help": "Show pause and PFC hardware state",
                "_executable": True,
            },
            "scheduler": {
                "_help": "Show egress scheduler hardware state",
                "_executable": True,
            },
            "ets": {
                "_help": "Show scheduler-backed ETS state",
                "_executable": True,
            },
            "queues": {
                "_help": "Show read-only forwarding queue inventory",
                "_executable": True,
            },
            "watermarks": {
                "_help": "Show congestion and pause watermark hardware state",
                "_executable": True,
            },
        },
        "configuration": {
            "_help": "Show current configuration",
            "_executable": True, "_allow_pipe": True,
        },
        "version": {
            "_help": "Show software and platform version",
            "_executable": True,
        },
        "ntp": {
            "_help": "Show NTP operational state",
            "_executable": True,
            "associations": {
                "_help": "Show NTP peers and association state",
                "_executable": True,
            },
            "status": {
                "_help": "Show NTP synchronization status",
                "_executable": True,
            },
        },
        "snmp": {
            "_help": "Show SNMP operational state",
            "_executable": True,
            "statistics": {
                "_help": "Show SNMP packet statistics",
                "_executable": True,
                "subagents": {
                    "_help": "Show SNMP subagent statistics",
                    "_executable": True,
                },
            },
        },
        "ethernet-switching": {
            "_help": "Show ethernet-switching information",
            "_executable": True,
            "acl": {
                "_help": "Show unified hardware-backed ACL status",
                "_executable": True,
            },
            "acl-capabilities": {
                "_help": "Show hardware-backed ACL capability boundaries",
                "_executable": True,
            },
            "interfaces": {"_help": "Show L2 interface state", "_executable": True},
            "table": {"_help": "Show MAC address table", "_executable": True},
            "storm-control": {"_help": "Show storm control status", "_executable": True},
            "ingress-rate-limit": {"_help": "Show ingress port rate-limit status", "_executable": True},
            "egress-rate-limit": {"_help": "Show egress port rate-limit status", "_executable": True},
            "secure-access-port": {"_help": "Show port security status", "_executable": True},
            "mac-move": {"_help": "Show MAC move events", "_executable": True},
            "dhcp-snooping": {"_help": "Show DHCP snooping state", "_executable": True},
            "arp-inspection": {"_help": "Show dynamic ARP inspection state", "_executable": True},
            "user-filter": {"_help": "Show hardware-backed L2 user filters", "_executable": True},
            "ingress-acl": {"_help": "Show scoped hardware-backed ingress ACL terms", "_executable": True},
            "ingress-ipv4-acl": {"_help": "Show hardware-backed ingress IPv4 ACL terms", "_executable": True},
            "acl-policer": {"_help": "Show scoped hardware-backed ACL policer terms", "_executable": True},
            "egress-acl": {"_help": "Show scoped hardware-backed egress ACL terms", "_executable": True},
        },
        "interfaces": {
            "_help": "Show interface information",
            "_executable": True, "_allow_pipe": True,
            "terse": {"_help": "Terse output", "_executable": True, "_allow_pipe": True},
            "detail": {"_help": "Detailed output", "_executable": True},
            "extensive": {"_help": "Extensive output", "_executable": True},
            "descriptions": {"_help": "Show interface descriptions"},
            "diagnostics": {
                "_help": "Show interface diagnostics",
                "optics": {
                    "_help": "Show optics diagnostics from mux telemetry",
                    "_executable": True,
                    "calibration": {
                        "_help": "Show optics calibration status",
                        "_executable": True,
                        "check": {
                            "_help": "Check mux calibration readiness",
                            "active": {
                                "_help": "Check currently link-up optics ports",
                                "_executable": True,
                            },
                            "full": {
                                "_help": "Check all chassis mux optics ports",
                                "_executable": True,
                            },
                        },
                    },
                    "mapping": {
                        "_help": "Show interface-to-mux channel mapping",
                        "_executable": True,
                    },
                    "<interface-name>": {
                        "_help": "Name of interface",
                        "_dynamic": "physical-interfaces",
                        "_executable": True,
                    },
                },
            },
            "statistics": {
                "_help": "Show interface statistics",
                "_executable": True,
                "<interface-name>": {
                    "_help": "Name of interface",
                    "_dynamic": "physical-interfaces",
                    "_executable": True,
                },
            },
            "<interface-name>": {
                "_help": "Name of interface",
                "_dynamic": "operational-interfaces",
                "_executable": True,
                "detail": {"_help": "Detailed output", "_executable": True},
                "extensive": {"_help": "Extensive output", "_executable": True},
                "statistics": {"_help": "Show interface statistics", "_executable": True},
            },
        },
        "vlans": {
            "_help": "Show VLAN information",
            "_executable": True, "_allow_pipe": True,
            "brief": {"_help": "Brief output", "_executable": True},
            "detail": {"_help": "Detailed output", "_executable": True},
            "extensive": {"_help": "Extensive output", "_executable": True},
            "<vlan-name>": {
                "_help": "VLAN name",
                "_dynamic": "vlans",
                "_executable": True,
                "detail": {"_help": "Detailed output", "_executable": True},
                "extensive": {"_help": "Extensive output", "_executable": True},
            },
        },
        "lldp": {
            "_help": "Show LLDP information",
            "interfaces": {"_help": "Show LLDP interface state", "_executable": True},
            "local-information": {"_help": "Show local LLDP advertisement state", "_executable": True},
            "neighbors": {
                "_help": "Show LLDP neighbors",
                "_executable": True,
                "detail": {"_help": "Show detailed LLDP neighbor information", "_executable": True},
            },
            "statistics": {"_help": "Show LLDP statistics", "_executable": True},
        },
        "lacp": {
            "_help": "Show LACP information",
            "interfaces": {"_help": "Show LACP interfaces", "_executable": True},
        },
        "route": {
            "_help": "Show L3 route table",
            "_executable": True,
            "protocol": {
                "_help": "Show routes learned by protocol",
                "connected": {"_help": "Connected routes", "_executable": True},
                "static": {"_help": "Static routes", "_executable": True},
                "ospf": {"_help": "OSPF routes", "_executable": True},
                "bgp": {"_help": "BGP routes", "_executable": True},
            },
            "table": {
                "_help": "Show a specific IPv4 routing table",
                "<routing-table>": {
                    "_help": "Routing table name",
                    "_executable": True,
                },
            },
            "forwarding-table": {
                "_help": "Show installed L3 forwarding table",
                "_executable": True,
            },
            "state": {"_help": "Show L3 control-plane diagnostics", "_executable": True},
            "summary": {"_help": "Show L3 route summary", "_executable": True},
            "interfaces": {"_help": "Show L3 interface state", "_executable": True},
            "next-hop": {"_help": "Show L3 next-hop diagnostics", "_executable": True},
            "ecmp": {"_help": "Show L3 ECMP diagnostics", "_executable": True},
            "resources": {"_help": "Show L3 resource diagnostics", "_executable": True},
            "shadow": {"_help": "Show L3 switchd shadow diagnostics", "_executable": True},
        },
        "arp": {
            "_help": "Show L3 ARP table",
            "_executable": True,
        },
        "rpd": {
            "_help": "Show routing process diagnostics",
            "state": {"_help": "Show rpd generation and FRR gate state", "_executable": True},
        },
        "ospf": {
            "_help": "Show OSPF operational state",
            "neighbor": {"_help": "Show OSPF neighbors", "_executable": True},
        },
        "bgp": {
            "_help": "Show BGP operational state",
            "summary": {"_help": "Show BGP summary", "_executable": True},
        },
        "spanning-tree": {
            "_help": "Show spanning-tree state",
            "_executable": True,
            "bridge": {"_help": "Show hardware STP forwarding table", "_executable": True},
            "capabilities": {
                "_help": "Show RSTP/MSTP capability boundaries",
                "_executable": True,
            },
            "statistics": {"_help": "Show BPDU monitor statistics", "_executable": True},
            "interface": {
                "_help": "Show RSTP interface state",
                "_executable": True,
                "<interface-name>": {
                    "_help": "Name of interface",
                    "_dynamic": "physical-interfaces",
                    "_executable": True,
                },
            },
        },
        "system": {
            "_help": "Show system information",
            "_executable": True,
            "alarms": {"_help": "Show system alarms", "_executable": True},
            "uptime": {"_help": "Show system uptime", "_executable": True},
            "boot-messages": {
                "_help": "Show system boot messages",
                "_executable": True,
            },
            "memory": {
                "_help": "Show host memory usage",
                "_executable": True,
            },
            "buffers": {
                "_help": "Show host buffer counters",
                "_executable": True,
            },
            "queues": {
                "_help": "Show host message queue inventory",
                "_executable": True,
            },
            "virtual-memory": {
                "_help": "Show host virtual memory counters",
                "_executable": True,
            },
            "processes": {
                "_help": "Show host process table",
                "_executable": True,
                "extensive": {
                    "_help": "Show extended host process table",
                    "_executable": True,
                },
            },
            "connections": {
                "_help": "Show host network connection table",
                "_executable": True,
            },
            "statistics": {
                "_help": "Show host protocol statistics",
                "_executable": True,
            },
            "storage": {
                "_help": "Show filesystem usage",
                "_executable": True,
            },
            "core-dumps": {
                "_help": "Show system core dump files",
                "_executable": True,
            },
            "users": {
                "_help": "Show currently logged-in users",
                "_executable": True,
            },
            "login": {
                "_help": "Show local login user state",
                "_executable": True,
                "user": {
                    "_help": "Show a specific local user",
                    "<user-name>": {
                        "_help": "User name",
                        "_executable": True,
                    },
                },
            },
            "authentication": {
                "_help": "Show authentication order and AAA state",
                "_executable": True,
            },
            "radius-server": {
                "_help": "Show RADIUS authentication server state",
                "_executable": True,
            },
            "tacplus-server": {
                "_help": "Show TACACS+ authentication server state",
                "_executable": True,
            },
            "accounting": {
                "_help": "Show login and command accounting state",
                "_executable": True,
            },
            "software": {
                "_help": "Show software inventory and upgrade state",
                "_executable": True,
            },
            "license": {
                "_help": "Show system license state",
                "_executable": True,
            },
            "commit": {
                "_help": "Show committed configuration history",
                "_executable": True,
                "confirmed": {
                    "_help": "Show pending commit confirmed state",
                    "_executable": True,
                },
            },
            "rollback": {
                "_help": "Show available rollback configurations",
                "_executable": True,
                "<rollback-number>": {
                    "_help": "Rollback configuration number",
                    "_dynamic": "rollback-numbers",
                    "_executable": True,
                    "compare": {
                        "_help": "Compare this rollback configuration to another rollback",
                        "<rollback-number>": {
                            "_help": "Rollback configuration number",
                            "_dynamic": "rollback-numbers",
                            "_executable": True,
                        },
                    },
                },
            },
            "configuration": {
                "_help": "Show configuration rescue and archive state",
                "_executable": True,
                "rescue": {
                    "_help": "Show rescue configuration state",
                    "_executable": True,
                },
                "archive": {
                    "_help": "Show archived configuration files",
                    "_executable": True,
                    "<archive-file>": {
                        "_help": "Archived configuration file name",
                        "_executable": True,
                    },
                },
            },
            "services": {
                "_help": "Show management service configuration intent",
                "_executable": True,
                "ssh": {
                    "_help": "Show SSH service configuration intent",
                    "_executable": True,
                },
                "netconf": {
                    "_help": "Show NETCONF service configuration intent",
                    "_executable": True,
                },
                "restconf": {
                    "_help": "Show RESTCONF service configuration intent",
                    "_executable": True,
                },
                "gnmi": {
                    "_help": "Show gNMI service configuration intent",
                    "_executable": True,
                },
                "snmp": {
                    "_help": "Show SNMP service configuration intent",
                    "_executable": True,
                },
            },
            "ntp": {
                "_help": "Show NTP configuration intent",
                "_executable": True,
            },
            "syslog": {
                "_help": "Show syslog configuration intent",
                "_executable": True,
            },
            "management": {"_help": "Show management daemon status", "_executable": True},
        },
        "log": {
            "_help": "Show system and NetLab log files",
            "_executable": True,
            "messages": {"_help": "Show system messages log", "_executable": True},
            "secure": {"_help": "Show security log", "_executable": True},
            "boot": {"_help": "Show boot log", "_executable": True},
            "mgmtd": {"_help": "Show mgmtd log", "_executable": True},
            "configd": {"_help": "Show configd log", "_executable": True},
            "ifd": {"_help": "Show ifd log", "_executable": True},
            "l2d": {"_help": "Show l2d log", "_executable": True},
            "rpd": {"_help": "Show rpd log", "_executable": True},
            "switchd": {"_help": "Show switchd log", "_executable": True},
            "packetd": {"_help": "Show packetd log", "_executable": True},
            "stpd": {"_help": "Show stpd log", "_executable": True},
            "lldpd": {"_help": "Show lldpd log", "_executable": True},
            "lacpd": {"_help": "Show lacpd log", "_executable": True},
            "chassisd": {"_help": "Show chassisd log", "_executable": True},
            "supervisor": {"_help": "Show NetLab supervisor log", "_executable": True},
        },
        "|": {
            "_help": "Pipe through a command",
            "match": {"_help": "Match lines containing pattern"},
            "except": {"_help": "Exclude lines containing pattern"},
            "count": {"_help": "Count output lines"},
            "no-more": {"_help": "Do not paginate output"},
            "display": {
                "_help": "Display options",
                "set": {"_help": "Display as set commands"},
                "xml": {"_help": "Display as XML"},
                "json": {"_help": "Display as JSON"},
            },
            "compare": {
                "_help": "Compare configuration revisions",
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
        },
        "<[Enter]>": {"_help": "Execute this command"},
    },
    "request": {
        "_help": "Request system actions",
        "support": {
            "_help": "Request support bundle generation",
            "information": {
                "_help": "Collect support information into a local file",
                "_executable": True,
            },
        },
        "system": {
            "_help": "Request system operations",
            "configuration": {
                "_help": "Request configuration file operations",
                "rescue": {
                    "_help": "Manage rescue configuration",
                    "save": {
                        "_help": "Save active configuration as rescue",
                        "_executable": True,
                    },
                    "delete": {
                        "_help": "Delete rescue configuration",
                        "_executable": True,
                    },
                },
                "archive": {
                    "_help": "Archive active configuration",
                    "_executable": True,
                    "delete": {
                        "_help": "Delete an archived configuration file",
                        "<archive-file>": {
                            "_help": "Archived configuration file name",
                            "_executable": True,
                        },
                    },
                },
            },
            "software": {
                "_help": "Request software image operations",
                "add": {
                    "_help": "Install a software image (fail-closed until signing/A-B is configured)",
                    "<image-file>": {
                        "_help": "Software image file",
                        "_executable": True,
                        "validate": {
                            "_help": "Validate image before install",
                            "_executable": True,
                        },
                        "no-validate": {
                            "_help": "Skip image validation request",
                            "_executable": True,
                        },
                        "no-copy": {
                            "_help": "Do not copy image before install",
                            "_executable": True,
                        },
                        "reboot": {
                            "_help": "Request reboot after install",
                            "_executable": True,
                        },
                    },
                },
                "rollback": {
                    "_help": "Roll back to a previous software image (fail-closed until A-B is configured)",
                    "_executable": True,
                    "<package-name>": {
                        "_help": "Rollback image package name",
                        "_executable": True,
                        "with-old-snapshot-config": {
                            "_help": "Use the old snapshot configuration",
                            "_executable": True,
                        },
                    },
                    "with-old-snapshot-config": {
                        "_help": "Use the old snapshot configuration",
                        "_executable": True,
                    },
                },
                "validate": {
                    "_help": "Validate a software image file without installing it",
                    "<image-file>": {
                        "_help": "Software image file",
                        "_executable": True,
                    },
                },
            },
            "storage": {
                "_help": "Request storage maintenance operations",
                "cleanup": {
                    "_help": "Clean temporary storage (blocked until cleanup policy is configured)",
                    "_executable": True,
                },
            },
            "services": {
                "_help": "Request management service operations",
                "restart": {
                    "_help": "Restart a management service (blocked until supervisor gate is configured)",
                    "ssh": {
                        "_help": "Restart SSH service",
                        "_executable": True,
                    },
                    "netconf": {
                        "_help": "Restart NETCONF service",
                        "_executable": True,
                    },
                    "restconf": {
                        "_help": "Restart RESTCONF service",
                        "_executable": True,
                    },
                    "gnmi": {
                        "_help": "Restart gNMI service",
                        "_executable": True,
                    },
                    "snmp": {
                        "_help": "Restart SNMP service",
                        "_executable": True,
                    },
                },
            },
            "core-dumps": {
                "_help": "Request core dump file operations",
                "delete": {
                    "_help": "Delete core dump files (blocked until retention policy is configured)",
                    "all": {
                        "_help": "All core dump files",
                        "_executable": True,
                    },
                    "<core-file>": {
                        "_help": "Core dump file basename",
                        "_executable": True,
                    },
                },
            },
            "reconcile": {
                "_help": "Replay active configuration and clear recovered forwarding drift",
                "_executable": True,
            },
            "reboot": {
                "_help": "Request system reboot (blocked until supervisor gate is configured)",
                "_executable": True,
            },
            "halt": {
                "_help": "Request system halt (blocked until supervisor gate is configured)",
                "_executable": True,
            },
            "power-off": {
                "_help": "Request system power off (blocked until supervisor gate is configured)",
                "_executable": True,
            },
            "snapshot": {
                "_help": "Create a system snapshot (blocked until snapshot backend is configured)",
                "_executable": True,
            },
            "zeroize": {
                "_help": "Erase system configuration and data (blocked until factory reset gate is configured)",
                "_executable": True,
            },
        },
        "chassis": {
            "_help": "Request chassis operations",
            "port-mode": {
                "_help": "Apply or roll back restart-time chassis port mode through the deployment lifecycle",
                "apply": {
                    "_help": "Apply pending chassis port mode through the installed lifecycle runtime",
                    "_executable": True,
                },
                "rollback": {
                    "_help": "Restore previous chassis port mode through the installed lifecycle runtime",
                    "_executable": True,
                },
            },
        },
    },
    "clear": {
        "_help": "Clear operational state",
        "interfaces": {
            "_help": "Clear interface information",
            "statistics": {
                "_help": "Clear interface statistics",
                "_executable": True,
                "<interface-name>": {
                    "_help": "Name of interface",
                    "_dynamic": "physical-interfaces",
                    "_executable": True,
                },
            },
        },
        "ethernet-switching": {
            "_help": "Clear ethernet-switching information",
            "table": {
                "_help": "Clear dynamic MAC address table",
                "_executable": True,
                "interface": {
                    "_help": "Clear entries learned on interface",
                    "<interface-name>": {
                        "_help": "Name of interface",
                        "_dynamic": "physical-interfaces",
                        "_executable": True,
                        "vlan": {
                            "_help": "Restrict clear to VLAN",
                            "<vlan-name>": {
                                "_help": "VLAN name",
                                "_dynamic": "vlans",
                                "_executable": True,
                            },
                        },
                    },
                },
                "vlan": {
                    "_help": "Clear entries learned in VLAN",
                    "<vlan-name>": {
                        "_help": "VLAN name",
                        "_dynamic": "vlans",
                        "_executable": True,
                        "interface": {
                            "_help": "Restrict clear to interface",
                            "<interface-name>": {
                                "_help": "Name of interface",
                                "_dynamic": "physical-interfaces",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "secure-access-port": {
                "_help": "Clear secure-access-port shutdown state",
                "interface": {
                    "_help": "Clear secure-access-port state for an interface",
                    "<interface-name>": {
                        "_help": "Name of interface",
                        "_dynamic": "config-interfaces",
                        "_executable": True,
                    },
                },
            },
            "mac-move": {
                "_help": "Clear MAC move dampening state",
                "_executable": True,
                "interface": {
                    "_help": "Clear MAC move state for an interface",
                    "<interface-name>": {
                        "_help": "Name of interface",
                        "_dynamic": "physical-interfaces",
                        "_executable": True,
                    },
                },
            },
        },
        "spanning-tree": {
            "_help": "Clear spanning-tree operational state",
            "bpdu-guard": {
                "_help": "Clear BPDU guard state",
                "interface": {
                    "_help": "Clear BPDU guard state for an interface",
                    "<interface-name>": {
                        "_help": "Name of interface",
                        "_dynamic": "rstp-interfaces",
                        "_executable": True,
                    },
                },
            },
        },
    },
        "ping": {
            "_help": "Ping remote host",
            "<host>": {
                "_help": "Host name or address",
                "_executable": True,
                "count": {
                    "_help": "Number of packets to send",
                    "<1-20>": {
                        "_help": "Packet count",
                        "_executable": True,
                    },
                },
            },
        },
        "traceroute": {
            "_help": "Trace route to host",
            "<host>": {
                "_help": "Host name or address",
                "_executable": True,
            },
        },
    "file": {
        "_help": "Perform file operations",
        "copy": {
            "_help": "Copy a file",
            "<source>": {
                "_help": "Source file path",
                "<destination>": {
                    "_help": "Destination file path",
                    "_executable": True,
                },
            },
        },
        "checksum": {
            "_help": "Calculate file checksum",
            "md5": {
                "_help": "Calculate MD5 checksum",
                "<path>": {
                    "_help": "File path",
                    "_executable": True,
                },
            },
            "sha1": {
                "_help": "Calculate SHA1 checksum",
                "<path>": {
                    "_help": "File path",
                    "_executable": True,
                },
            },
            "sha256": {
                "_help": "Calculate SHA256 checksum",
                "<path>": {
                    "_help": "File path",
                    "_executable": True,
                },
            },
        },
        "compare": {
            "_help": "Compare two local files",
            "files": {
                "_help": "Compare file contents",
                "<file1>": {
                    "_help": "First file path",
                    "<file2>": {
                        "_help": "Second file path",
                        "_executable": True,
                        "context": {
                            "_help": "Display context diff",
                            "_executable": True,
                            "ignore-white-space": {
                                "_help": "Ignore white-space amount",
                                "_executable": True,
                            },
                        },
                        "unified": {
                            "_help": "Display unified diff",
                            "_executable": True,
                            "ignore-white-space": {
                                "_help": "Ignore white-space amount",
                                "_executable": True,
                            },
                        },
                        "ignore-white-space": {
                            "_help": "Ignore white-space amount",
                            "_executable": True,
                        },
                    },
                },
            },
        },
        "delete": {
            "_help": "Delete a file",
            "<path>": {
                "_help": "File path",
                "_executable": True,
            },
        },
        "rename": {
            "_help": "Rename or move a file",
            "<source>": {
                "_help": "Source file path",
                "<destination>": {
                    "_help": "Destination file path",
                    "_executable": True,
                },
            },
        },
        "list": {
            "_help": "List files",
            "_executable": True,
            "<path>": {
                "_help": "File or directory path",
                "_executable": True,
            },
        },
        "show": {
            "_help": "Show file contents",
            "<path>": {
                "_help": "File path",
                "_executable": True,
            },
        },
    },
    "configure": {
        "_help": "Enter configuration mode",
        "_executable": True,
        "exclusive": {
            "_help": "Enter configuration mode with exclusive candidate lock",
            "_executable": True,
        },
        "private": {
            "_help": "Enter private configuration mode",
            "_executable": True,
            "_hidden": True,
        },
    },
    "exit": {"_help": "Exit CLI / configuration mode", "_executable": True},
    "quit": {"_help": "Quit CLI", "_executable": True},
}

CFG_SCHEMA = {
    "set": {
        "_help": "Set configuration",
        "system": {
            "_help": "System configuration",
            "host-name": {
                "_help": "System host name",
                "<hostname>": {
                    "_help": "Host name",
                    "_executable": True,
                },
            },
            "domain-name": {
                "_help": "Default DNS search domain",
                "<domain-name>": {
                    "_help": "Domain name",
                    "_executable": True,
                },
            },
            "name-server": {
                "_help": "DNS resolver address",
                "<address>": {
                    "_help": "IPv4 or IPv6 resolver address",
                    "_executable": True,
                },
            },
            "authentication-order": {
                "_help": "Authentication methods in priority order",
                "password": {
                    "_help": "Use local password authentication",
                    "_executable": True,
                },
                "radius": {
                    "_help": "Use RADIUS authentication",
                    "_executable": True,
                },
                "tacplus": {
                    "_help": "Use TACACS+ authentication",
                    "_executable": True,
                },
            },
            "radius-server": {
                "_help": "RADIUS authentication server",
                "<address>": {
                    "_help": "RADIUS server address",
                    "_executable": True,
                    "secret": {
                        "_help": "Shared secret",
                        "<secret>": {
                            "_help": "Encrypted or local shared secret",
                            "_executable": True,
                        },
                    },
                    "port": {
                        "_help": "RADIUS authentication port",
                        "<1-65535>": {
                            "_help": "UDP port",
                            "_executable": True,
                        },
                    },
                    "source-address": {
                        "_help": "Source address for RADIUS packets",
                        "<address>": {
                            "_help": "Source IPv4 or IPv6 address",
                            "_executable": True,
                        },
                    },
                    "timeout": {
                        "_help": "RADIUS response timeout",
                        "<1-1000>": {
                            "_help": "Timeout in seconds",
                            "_executable": True,
                        },
                    },
                    "retry": {
                        "_help": "RADIUS retry count",
                        "<1-100>": {
                            "_help": "Retry count",
                            "_executable": True,
                        },
                    },
                },
            },
            "tacplus-server": {
                "_help": "TACACS+ authentication server",
                "<address>": {
                    "_help": "TACACS+ server address",
                    "_executable": True,
                    "secret": {
                        "_help": "Shared secret",
                        "<secret>": {
                            "_help": "Encrypted or local shared secret",
                            "_executable": True,
                        },
                    },
                    "port": {
                        "_help": "TACACS+ authentication port",
                        "<1-65535>": {
                            "_help": "TCP port",
                            "_executable": True,
                        },
                    },
                    "source-address": {
                        "_help": "Source address for TACACS+ packets",
                        "<address>": {
                            "_help": "Source IPv4 or IPv6 address",
                            "_executable": True,
                        },
                    },
                    "timeout": {
                        "_help": "TACACS+ response timeout",
                        "<1-1000>": {
                            "_help": "Timeout in seconds",
                            "_executable": True,
                        },
                    },
                    "single-connection": {
                        "_help": "Use one persistent TACACS+ connection",
                        "_executable": True,
                    },
                },
            },
            "services": {
                "_help": "Management services",
                "ssh": {
                    "_help": "Enable SSH service",
                    "_executable": True,
                    "root-login": {
                        "_help": "Root login policy",
                        "allow": {
                            "_help": "Allow root SSH login",
                            "_executable": True,
                        },
                        "deny": {
                            "_help": "Deny root SSH login",
                            "_executable": True,
                        },
                        "deny-password": {
                            "_help": "Deny password login for root",
                            "_executable": True,
                        },
                    },
                },
                "netconf": {
                    "_help": "NETCONF service",
                    "ssh": {
                        "_help": "Enable NETCONF over SSH",
                        "_executable": True,
                    },
                },
                "restconf": {
                    "_help": "RESTCONF service",
                    "https": {
                        "_help": "Enable RESTCONF over HTTPS",
                        "_executable": True,
                    },
                },
                "gnmi": {
                    "_help": "gNMI service",
                    "grpc": {
                        "_help": "Enable gNMI over gRPC",
                        "_executable": True,
                    },
                    "port": {
                        "_help": "gNMI gRPC TCP port",
                        "<1-65535>": {
                            "_help": "TCP port",
                            "_executable": True,
                        },
                    },
                },
            },
            "ntp": {
                "_help": "NTP configuration",
                "server": {
                    "_help": "NTP server",
                    "<address>": {
                        "_help": "NTP server address",
                        "_executable": True,
                        "prefer": {
                            "_help": "Prefer this NTP server",
                            "_executable": True,
                        },
                    },
                },
            },
            "syslog": {
                "_help": "System logging",
                "host": {
                    "_help": "Remote syslog host",
                    "<host>": {
                        "_help": "Host name or address",
                        "any": {
                            "_help": "Facility any",
                            "<level>": {
                                "_help": "Severity level",
                                "_executable": True,
                            },
                        },
                    },
                },
                "file": {
                    "_help": "Local syslog file",
                    "<filename>": {
                        "_help": "Log file name",
                        "any": {
                            "_help": "Facility any",
                            "<level>": {
                                "_help": "Severity level",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "login": {
                "_help": "Login user configuration",
                "user": {
                    "_help": "Local user",
                    "<user-name>": {
                        "_help": "User name",
                        "_executable": True,
                        "class": {
                            "_help": "Login class",
                            "super-user": {
                                "_help": "Full administrative access",
                                "_executable": True,
                            },
                            "operator": {
                                "_help": "Operational access",
                                "_executable": True,
                            },
                            "read-only": {
                                "_help": "Read-only access",
                                "_executable": True,
                            },
                        },
                        "authentication": {
                            "_help": "Authentication data",
                            "encrypted-password": {
                                "_help": "Encrypted password hash",
                                "<hash>": {
                                    "_help": "Password hash",
                                    "_executable": True,
                                },
                            },
                            "ssh-rsa": {
                                "_help": "SSH RSA public key",
                                "<key>": {
                                    "_help": "SSH public key",
                                    "_executable": True,
                                },
                            },
                        },
                    },
                },
            },
            "accounting": {
                "_help": "System accounting",
                "events": {
                    "_help": "Accounting event classes",
                    "login": {
                        "_help": "Audit login events",
                        "_executable": True,
                    },
                    "change-log": {
                        "_help": "Audit configuration changes",
                        "_executable": True,
                    },
                    "interactive-commands": {
                        "_help": "Audit interactive CLI commands",
                        "_executable": True,
                    },
                },
            },
        },
        "snmp": {
            "_help": "SNMP configuration",
            "contact": {
                "_help": "Administrative contact",
                "<text>": {
                    "_help": "Contact text",
                    "_executable": True,
                },
            },
            "location": {
                "_help": "System location",
                "<text>": {
                    "_help": "Location text",
                    "_executable": True,
                },
            },
            "community": {
                "_help": "SNMP community",
                "<community-name>": {
                    "_help": "Community name",
                    "_executable": True,
                    "authorization": {
                        "_help": "Community authorization",
                        "read-only": {
                            "_help": "Read-only community",
                            "_executable": True,
                        },
                        "read-write": {
                            "_help": "Read-write community",
                            "_executable": True,
                        },
                    },
                    "clients": {
                        "_help": "Permitted client address or prefix",
                        "<address-or-prefix>": {
                            "_help": "Client address or prefix",
                            "_executable": True,
                        },
                    },
                },
            },
            "trap-group": {
                "_help": "SNMP trap group",
                "<group-name>": {
                    "_help": "Trap group name",
                    "_executable": True,
                    "version": {
                        "_help": "Trap protocol version",
                        "v2": {
                            "_help": "SNMPv2 traps",
                            "_executable": True,
                        },
                    },
                    "targets": {
                        "_help": "Trap target address",
                        "<address>": {
                            "_help": "Target address",
                            "_executable": True,
                        },
                    },
                },
            },
        },
        "vlans": {
            "_help": "VLAN configuration",
            "<vlan-name>": {
                "_help": "VLAN name", "_dynamic": "vlans",
                "vlan-id": {
                    "_help": "IEEE 802.1Q VLAN identifier (1-4094)",
                    "<1-4094>": {"_help": "VLAN identifier", "_executable": True},
                },
                "description": {
                    "_help": "Text description",
                    "<text>": {"_help": "Description text", "_executable": True},
                },
                "interface": {"_help": "Add interface as VLAN member"},
            },
        },
        "interfaces": {
            "_help": "Interface configuration",
            "irb": {
                "_help": "Integrated routing and bridging interfaces",
                "unit": {
                    "_help": "Logical IRB unit",
                    "<1-4094>": {
                        "_help": "IRB unit number",
                        "family": {
                            "_help": "Protocol family",
                            "inet": {
                                "_help": "IPv4 family",
                                "address": {
                                    "_help": "IPv4 address and prefix",
                                    "<ipv4-prefix>": {
                                        "_help": "IPv4 address/prefix",
                                        "_executable": True,
                                        "arp": {
                                            "_help": "Static ARP entry on this IRB unit",
                                            "<ipv4-address>": {
                                                "_help": "Neighbor IPv4 address",
                                                "mac": {
                                                    "_help": "Neighbor MAC address",
                                                    "<mac-address>": {
                                                        "_help": "MAC address",
                                                        "_executable": True,
                                                    },
                                                },
                                                "egress-interface": {
                                                    "_help": "Physical egress interface for this neighbor",
                                                    "<interface-name>": {
                                                        "_help": "Physical egress interface",
                                                        "_dynamic": "physical-interfaces",
                                                        "_executable": True,
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "<interface-name>": {
                "_help": "Interface name", "_dynamic": "config-interfaces",
                "description": {
                    "_help": "Text description",
                    "<text>": {"_help": "Description text", "_executable": True},
                },
                "disable": {"_help": "Disable interface", "_executable": True},
                "mtu": {
                    "_help": "Interface MTU",
                    "<1514-9216>": {"_help": "MTU in bytes", "_executable": True},
                },
                "speed": {
                    "_help": "Physical interface speed",
                    "10g": {"_help": "Use fixed 10-Gigabit Ethernet", "_executable": True},
                    "25g": {"_help": "Use fixed 25-Gigabit Ethernet", "_executable": True},
                },
                "native-vlan-id": {
                    "_help": "Native VLAN ID for trunk",
                    "<1-4094>": {"_help": "VLAN identifier", "_executable": True},
                },
                "ether-options": {
                    "_help": "Physical Ethernet options",
                    "802.3ad": {
                        "_help": "Bind interface to aggregated Ethernet",
                        "<ae-interface>": {
                            "_help": "Aggregated Ethernet interface",
                            "_dynamic": "aggregates",
                            "_executable": True,
                        },
                    },
                    "lacp": {
                        "_help": "LACP physical member options",
                        "port-priority": {
                            "_help": "LACP actor port priority for this member",
                            "<1-65535>": {"_help": "Port priority", "_executable": True},
                        },
                    },
                },
                "aggregated-ether-options": {
                    "_help": "Aggregated Ethernet options",
                    "minimum-links": {
                        "_help": "Minimum active member links required",
                        "<1-16>": {"_help": "Minimum active links", "_executable": True},
                    },
                    "hash-policy": {
                        "_help": "ASIC LAG hash policy",
                        "rotation": {
                            "_help": "Select hardware hash rotation bank",
                            "a": {"_help": "Use hash rotation bank A", "_executable": True},
                            "b": {"_help": "Use hash rotation bank B", "_executable": True},
                        },
                    },
                    "lacp": {
                        "_help": "Link Aggregation Control Protocol",
                        "active": {"_help": "Actively negotiate LACP", "_executable": True},
                        "passive": {"_help": "Passively negotiate LACP", "_executable": True},
                        "actor-key": {
                            "_help": "LACP actor key advertised by this aggregate",
                            "<1-65535>": {"_help": "Actor operational key", "_executable": True},
                        },
                        "periodic": {
                            "_help": "LACP PDU transmit interval",
                            "fast": {"_help": "Fast periodic transmission", "_executable": True},
                            "slow": {"_help": "Slow periodic transmission", "_executable": True},
                        },
                    },
                },
                "unit": {
                    "_help": "Logical unit",
                    "0": {
                        "_help": "Unit number",
                        "family": {
                            "_help": "Protocol family",
                            "inet": {
                                "_help": "IPv4 routed interface family",
                                "address": {
                                    "_help": "IPv4 address and prefix",
                                    "<ipv4-prefix>": {
                                        "_help": "IPv4 address/prefix",
                                        "_executable": True,
                                        "arp": {
                                            "_help": "Static ARP entry on this routed interface",
                                            "<ipv4-address>": {
                                                "_help": "Neighbor IPv4 address",
                                                "mac": {
                                                    "_help": "Neighbor MAC address",
                                                    "<mac-address>": {
                                                        "_help": "MAC address",
                                                        "_executable": True,
                                                    },
                                                },
                                                "egress-interface": {
                                                    "_help": "Physical egress interface for this neighbor",
                                                    "<interface-name>": {
                                                        "_help": "Physical egress interface",
                                                        "_dynamic": "physical-interfaces",
                                                        "_executable": True,
                                                    },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                            "ethernet-switching": {
                                "_help": "Ethernet-switching family",
                                "interface-mode": {
                                    "_help": "Layer 2 interface mode: access or trunk",
                                    "access": {"_help": "Access mode (single VLAN)", "_executable": True},
                                    "trunk": {"_help": "Trunk mode (multiple VLANs)", "_executable": True},
                                },
                                "vlan": {
                                    "_help": "VLAN membership",
                                    "members": {
                                        "_help": "VLAN members list",
                                        "<vlan-name>": {
                                            "_help": "VLAN name",
                                            "_dynamic": "vlans",
                                            "_executable": True,
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        "routing-options": {
            "_help": "Layer 3 routing candidate configuration",
            "autonomous-system": {
                "_help": "Local BGP autonomous system",
                "<asn>": {"_help": "Local AS number", "_executable": True},
            },
            "static": {
                "_help": "Static L3 objects",
                "arp": {
                    "_help": "Static ARP adjacency",
                    "<ipv4-address>": {
                        "_help": "Neighbor IPv4 address",
                        "mac": {
                            "_help": "Neighbor MAC address",
                            "<mac-address>": {"_help": "MAC address", "_executable": True},
                        },
                        "interface": {
                            "_help": "Routed interface name",
                            "<rif-name>": {"_help": "Routed interface", "_executable": True},
                        },
                        "egress-interface": {
                            "_help": "Physical egress interface for next-hop MAC reachability",
                            "<interface-name>": {
                                "_help": "Physical egress interface",
                                "_dynamic": "physical-interfaces",
                                "_executable": True,
                            },
                        },
                    },
                },
                "next-hop": {
                    "_help": "Static next-hop object",
                    "<id>": {
                        "_help": "Next-hop id",
                        "arp": {
                            "_help": "Referenced ARP IPv4 address",
                            "<ipv4-address>": {"_help": "Neighbor IPv4 address", "_executable": True},
                        },
                        "interface": {
                            "_help": "Referenced routed interface",
                            "<rif-name>": {"_help": "Routed interface", "_executable": True},
                        },
                    },
                },
                "ecmp": {
                    "_help": "Static ECMP group",
                    "<id>": {
                        "_help": "ECMP group id",
                        "member": {
                            "_help": "Next-hop id member",
                            "<next-hop-id>": {"_help": "Next-hop id", "_executable": True},
                        },
                    },
                },
                "route": {
                    "_help": "Static IPv4 route",
                    "<ipv4-prefix>": {
                        "_help": "Destination IPv4 prefix",
                        "next-hop": {
                            "_help": "Next-hop IPv4 address",
                            "<ipv4-address>": {
                                "_help": "Next-hop IPv4 address",
                                "_executable": True,
                            },
                        },
                        "ecmp": {
                            "_help": "Referenced ECMP group id",
                            "<ecmp-id>": {"_help": "ECMP group id", "_executable": True},
                        },
                    },
                },
            },
        },
        "policy-options": {
            "_help": "Route policy configuration",
            "policy-statement": {
                "_help": "Routing policy statement",
                "<policy-name>": {
                    "_help": "Policy statement name",
                    "term": {
                        "_help": "Policy term",
                        "<term-name>": {
                            "_help": "Policy term name",
                            "from": {
                                "_help": "Match conditions",
                                "route-filter": {
                                    "_help": "Match IPv4 prefix",
                                    "<ipv4-prefix>": {
                                        "_help": "IPv4 prefix",
                                        "exact": {
                                            "_help": "Exact prefix match",
                                            "_executable": True,
                                        },
                                    },
                                },
                            },
                            "then": {
                                "_help": "Policy action",
                                "accept": {"_help": "Accept route", "_executable": True},
                                "reject": {"_help": "Reject route", "_executable": True},
                            },
                        },
                    },
                },
            },
        },
        "protocols": {
            "_help": "Protocol configuration",
            "ospf": {
                "_help": "OSPFv2 routing protocol",
                "area": {
                    "_help": "OSPF area",
                    "<area-id>": {
                        "_help": "OSPF area id",
                        "interface": {
                            "_help": "Enable OSPF on routed interface",
                            "<interface-name>": {
                                "_help": "Routed interface, for example irb.100",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "bgp": {
                "_help": "BGP routing protocol",
                "group": {
                    "_help": "BGP peer group",
                    "<group-name>": {
                        "_help": "BGP group name",
                        "type": {
                            "_help": "BGP group type",
                            "external": {"_help": "EBGP group", "_executable": True},
                            "internal": {"_help": "IBGP group", "_executable": True},
                        },
                        "neighbor": {
                            "_help": "BGP neighbor",
                            "<ipv4-address>": {
                                "_help": "BGP neighbor address",
                                "peer-as": {
                                    "_help": "Peer autonomous system",
                                    "<asn>": {"_help": "Peer ASN", "_executable": True},
                                },
                            },
                        },
                        "export": {
                            "_help": "Export policy",
                            "<policy-name>": {
                                "_help": "Policy statement name",
                                "_executable": True,
                            },
                        },
                        "hold-time": {
                            "_help": "BGP hold time in seconds",
                            "<seconds>": {
                                "_help": "Hold time divisible by three",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "igmp-snooping": {
                "_help": "IPv4 IGMP snooping",
                "_executable": True,
                "membership-timeout": {
                    "_help": "Dynamic membership aging interval",
                    "<10-3600>": {
                        "_help": "Seconds",
                        "_executable": True,
                    },
                },
                "vlan": {
                    "_help": "Bridge VLAN",
                    "<vlan-name>": {
                        "_help": "Configured VLAN name",
                        "interface": {
                            "_help": "Physical VLAN member",
                            "<interface-name>": {
                                "_help": "Physical interface",
                                "_dynamic": "config-interfaces",
                                "_executable": True,
                                "static-group": {
                                    "_help": "Static IPv4 multicast membership",
                                    "<ipv4-multicast-address>": {
                                        "_help": "IPv4 multicast group",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "rstp": {
                "_help": "Rapid Spanning Tree Protocol guard configuration",
                "bridge-priority": {
                    "_help": "RSTP bridge priority",
                    "<0-61440>": {"_help": "Priority, multiple of 4096", "_executable": True},
                },
                "hello-time": {
                    "_help": "RSTP hello interval",
                    "<1-10>": {"_help": "Seconds", "_executable": True},
                },
                "max-age": {
                    "_help": "RSTP maximum BPDU age",
                    "<6-40>": {"_help": "Seconds", "_executable": True},
                },
                "forward-delay": {
                    "_help": "RSTP forward delay",
                    "<4-30>": {"_help": "Seconds", "_executable": True},
                },
                "interface": {
                    "_help": "Interface RSTP edge/guard configuration",
                    "<interface-name>": {
                        "_help": "Name of interface",
                        "_dynamic": "rstp-interfaces",
                        "_executable": True,
                        "edge": {
                            "_help": "Treat this interface as an edge port",
                            "_executable": True,
                        },
                        "bpdu-block-on-edge": {
                            "_help": "Block an edge port when a BPDU is received",
                            "_executable": True,
                        },
                        "root-protection": {
                            "_help": "Block the interface if it receives a superior BPDU",
                            "_executable": True,
                        },
                        "loop-protection": {
                            "_help": "Keep an alternate path blocked if BPDUs stop arriving",
                            "_executable": True,
                        },
                        "path-cost": {
                            "_help": "Administrative path cost",
                            "<1-200000000>": {
                                "_help": "Cost",
                                "_executable": True,
                            },
                        },
                        "port-priority": {
                            "_help": "Port priority",
                            "<0-240>": {
                                "_help": "Priority, multiple of 16",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "mstp": {
                "_help": "Multiple Spanning Tree Protocol configuration",
                "configuration-name": {
                    "_help": "MST region configuration name",
                    "<name>": {"_help": "Region name", "_executable": True},
                },
                "revision-level": {
                    "_help": "MST region revision",
                    "<0-65535>": {"_help": "Revision", "_executable": True},
                },
                "bridge-priority": {
                    "_help": "CIST bridge priority",
                    "<0-61440>": {"_help": "Priority, multiple of 4096", "_executable": True},
                },
                "hello-time": {
                    "_help": "MSTP hello interval",
                    "<1-10>": {"_help": "Seconds", "_executable": True},
                },
                "max-age": {
                    "_help": "MSTP maximum BPDU age",
                    "<6-40>": {"_help": "Seconds", "_executable": True},
                },
                "forward-delay": {
                    "_help": "MSTP forward delay",
                    "<4-30>": {"_help": "Seconds", "_executable": True},
                },
                "max-hops": {
                    "_help": "MSTP maximum hop count",
                    "<6-40>": {"_help": "Remaining hops", "_executable": True},
                },
                "instance": {
                    "_help": "MST instance",
                    "<instance-id>": {
                        "_help": "MSTI ID",
                        "bridge-priority": {
                            "_help": "MSTI bridge priority",
                            "<0-61440>": {
                                "_help": "Priority, multiple of 4096",
                                "_executable": True,
                            },
                        },
                        "vlan": {
                            "_help": "VLAN mapped to this MSTI",
                            "<1-4094>": {"_help": "VLAN ID", "_executable": True},
                        },
                        "interface": {
                            "_help": "Per-MSTI interface port vector",
                            "<interface-name>": {
                                "_help": "Name of interface",
                                "_dynamic": "rstp-interfaces",
                                "_executable": True,
                                "path-cost": {
                                    "_help": "Per-MSTI administrative path cost",
                                    "<1-200000000>": {
                                        "_help": "Cost",
                                        "_executable": True,
                                    },
                                },
                                "port-priority": {
                                    "_help": "Per-MSTI port priority",
                                    "<0-240>": {
                                        "_help": "Priority, multiple of 16",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                    },
                },
                "interface": {
                    "_help": "Interface MSTP edge/guard configuration",
                    "<interface-name>": {
                        "_help": "Name of interface",
                        "_dynamic": "rstp-interfaces",
                        "_executable": True,
                        "edge": {
                            "_help": "Treat this interface as an edge port",
                            "_executable": True,
                        },
                        "bpdu-block-on-edge": {
                            "_help": "Block an edge port when a BPDU is received",
                            "_executable": True,
                        },
                        "root-protection": {
                            "_help": "Block the interface if it receives a superior BPDU",
                            "_executable": True,
                        },
                        "loop-protection": {
                            "_help": "Keep an alternate path blocked if BPDUs stop arriving",
                            "_executable": True,
                        },
                        "path-cost": {
                            "_help": "Administrative path cost",
                            "<1-200000000>": {
                                "_help": "Cost",
                                "_executable": True,
                            },
                        },
                        "port-priority": {
                            "_help": "Port priority",
                            "<0-240>": {
                                "_help": "Priority, multiple of 16",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "lldp": {
                "_help": "Link Layer Discovery Protocol",
                "disable": {
                    "_help": "Disable LLDP globally",
                    "_executable": True,
                },
                "transmit-interval": {
                    "_help": "LLDP transmit interval in seconds",
                    "<seconds>": {"_help": "Interval in seconds (5..3600)", "_executable": True},
                },
                "hold-multiplier": {
                    "_help": "TTL multiplier for LLDP advertisements",
                    "<count>": {"_help": "TTL multiplier (2..10)", "_executable": True},
                },
                "system-name": {
                    "_help": "Advertised LLDP system name",
                    "<name>": {"_help": "System name", "_executable": True},
                },
                "system-description": {
                    "_help": "Advertised LLDP system description",
                    "<text>": {"_help": "System description", "_executable": True},
                },
                "management-address": {
                    "_help": "Advertised LLDP management address",
                    "<address>": {"_help": "IPv4 or IPv6 management address", "_executable": True},
                },
                "interface": {
                    "_help": "LLDP interface configuration",
                    "<interface-name>": {
                        "_help": "Name of interface",
                        "_dynamic": "lldp-interfaces",
                        "_executable": True,
                        "disable": {
                            "_help": "Disable LLDP on this interface",
                            "_executable": True,
                        },
                    },
                },
            },
            "lacp": {
                "_help": "Link Aggregation Control Protocol",
                "system-id": {
                    "_help": "LACP actor system ID",
                    "<mac-address>": {"_help": "Actor system MAC address", "_executable": True},
                },
                "system-priority": {
                    "_help": "LACP actor system priority",
                    "<1-65535>": {"_help": "System priority", "_executable": True},
                },
                "port-priority": {
                    "_help": "LACP actor port priority",
                    "<1-65535>": {"_help": "Port priority", "_executable": True},
                },
            },
        },
        "control-plane": {
            "_help": "Control-plane configuration",
            "protection": {
                "_help": "Control-plane protection policy",
                "class": {
                    "_help": "Control-plane protocol class",
                    "rstp": {
                        "_help": "RSTP/BPDU CPU punt class",
                        "rate-pps": {
                            "_help": "Punt policer rate in packets per second",
                            "<pps>": {"_help": "Packets per second", "_executable": True},
                        },
                        "burst-pkts": {
                            "_help": "Punt policer burst in packets",
                            "<packets>": {"_help": "Packet burst", "_executable": True},
                        },
                    },
                    "lldp": {
                        "_help": "LLDP CPU punt class",
                        "rate-pps": {
                            "_help": "Punt policer rate in packets per second",
                            "<pps>": {"_help": "Packets per second", "_executable": True},
                        },
                        "burst-pkts": {
                            "_help": "Punt policer burst in packets",
                            "<packets>": {"_help": "Packet burst", "_executable": True},
                        },
                    },
                    "igmp": {
                        "_help": "IGMP snooping CPU copy class",
                        "rate-pps": {
                            "_help": "Punt policer rate in packets per second",
                            "<packets-per-second>": {
                                "_help": "Packets per second",
                                "_executable": True,
                            },
                        },
                        "burst-pkts": {
                            "_help": "Punt policer burst in packets",
                            "<packets>": {
                                "_help": "Packet burst",
                                "_executable": True,
                            },
                        },
                    },
                    "lacp": {
                        "_help": "LACP CPU punt class",
                        "rate-pps": {
                            "_help": "Punt policer rate in packets per second",
                            "<pps>": {"_help": "Packets per second", "_executable": True},
                        },
                        "burst-pkts": {
                            "_help": "Punt policer burst in packets",
                            "<packets>": {"_help": "Packet burst", "_executable": True},
                        },
                    },
                    "arp": {
                        "_help": "ARP CPU punt class",
                        "rate-pps": {
                            "_help": "Punt policer rate in packets per second",
                            "<pps>": {"_help": "Packets per second", "_executable": True},
                        },
                        "burst-pkts": {
                            "_help": "Punt policer burst in packets",
                            "<packets>": {"_help": "Packet burst", "_executable": True},
                        },
                    },
                    "icmp": {
                        "_help": "ICMP CPU punt class",
                        "rate-pps": {
                            "_help": "Punt policer rate in packets per second",
                            "<pps>": {"_help": "Packets per second", "_executable": True},
                        },
                        "burst-pkts": {
                            "_help": "Punt policer burst in packets",
                            "<packets>": {"_help": "Packet burst", "_executable": True},
                        },
                    },
                    "ospf": {
                        "_help": "OSPF CPU punt class",
                        "rate-pps": {
                            "_help": "Punt policer rate in packets per second",
                            "<pps>": {"_help": "Packets per second", "_executable": True},
                        },
                        "burst-pkts": {
                            "_help": "Punt policer burst in packets",
                            "<packets>": {"_help": "Packet burst", "_executable": True},
                        },
                    },
                    "bgp": {
                        "_help": "BGP TCP/179 CPU punt class",
                        "rate-pps": {
                            "_help": "Punt policer rate in packets per second",
                            "<pps>": {"_help": "Packets per second", "_executable": True},
                        },
                        "burst-pkts": {
                            "_help": "Punt policer burst in packets",
                            "<packets>": {"_help": "Packet burst", "_executable": True},
                        },
                    },
                },
            },
        },
        "class-of-service": {
            "_help": "Class of service configuration",
            "interfaces": {
                "_help": "Per-interface CoS trust",
                "<interface-name>": {
                    "_help": "Interface name",
                    "_dynamic": "config-interfaces",
                    "trust": {
                        "_help": "Ingress priority source",
                        "ieee-802.1p": {
                            "_help": "Trust IEEE 802.1p priority",
                            "_executable": True,
                        },
                        "dscp": {
                            "_help": "Prefer IP DSCP priority",
                            "_executable": True,
                        },
                        "none": {
                            "_help": "Use the configured default priority",
                            "_executable": True,
                        },
                    },
                    "default-priority": {
                        "_help": "Default priority for untrusted traffic",
                        "<0-7>": {
                            "_help": "IEEE 802.1p/switch priority",
                            "_executable": True,
                        },
                    },
                    "priority-flow-control": {
                        "_help": "Priority flow control class masks",
                        "rx-class-mask": {
                            "_help": "PFC classes honored on receive",
                            "<0-255>": {
                                "_help": "Traffic class bit mask",
                                "_executable": True,
                            },
                        },
                        "tx-class-mask": {
                            "_help": "PFC classes advertised on transmit",
                            "<0-255>": {
                                "_help": "Traffic class bit mask",
                                "_executable": True,
                            },
                        },
                        "lossless-smp-mask": {
                            "_help": "Lossless SMP auto-pause mask",
                            "<0-3>": {
                                "_help": "SMP bit mask",
                                "_executable": True,
                            },
                        },
                        "shared-pause-mask": {
                            "_help": "Shared watermark pause mask",
                            "<0-3>": {
                                "_help": "SMP bit mask",
                                "_executable": True,
                            },
                        },
                    },
                    "scheduler-map": {
                        "_help": "Apply egress scheduler map",
                        "<scheduler-map-name>": {
                            "_help": "Scheduler map name",
                            "_executable": True,
                        },
                    },
                },
            },
            "schedulers": {
                "_help": "Egress scheduler definitions",
                "<scheduler-name>": {
                    "_help": "Scheduler name",
                    "transmit-rate": {
                        "_help": "Maximum transmit rate in bits per second",
                        "<bps>": {
                            "_help": "Rate in bits per second",
                            "_executable": True,
                        },
                    },
                    "buffer-size": {
                        "_help": "Maximum burst size in bits",
                        "<bits>": {
                            "_help": "Burst size in bits",
                            "_executable": True,
                        },
                    },
                    "priority": {
                        "_help": "Scheduler priority",
                        "strict-high": {
                            "_help": "Use strict priority scheduling",
                            "_executable": True,
                        },
                        "low": {
                            "_help": "Use weighted scheduling",
                            "_executable": True,
                        },
                    },
                },
            },
            "forwarding": {
                "_help": "CoS forwarding maps",
                "switch-priority": {
                    "_help": "Switch priority to traffic class map",
                    "<0-15>": {
                        "_help": "Switch priority",
                        "traffic-class": {
                            "_help": "Hardware traffic class",
                            "<0-7>": {
                                "_help": "Traffic class",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "scheduler": {
                "_help": "Egress scheduler hardware controls",
                "template": {
                    "_help": "Reusable scheduler template",
                    "<template-name>": {
                        "_help": "Template name",
                        "traffic-class": {
                            "_help": "Traffic class scheduler mapping",
                            "<0-7>": {
                                "_help": "Traffic class",
                                "shaping-group": {
                                    "_help": "FM10000 shaping group",
                                    "<0-7>": {
                                        "_help": "Shaping group",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                        "traffic-class-enable-mask": {
                            "_help": "Traffic class enable bitmask",
                            "<1-255>": {
                                "_help": "8-bit traffic class enable mask",
                                "_executable": True,
                            },
                        },
                        "group": {
                            "_help": "Scheduler group strict/DRR controls",
                            "<0-7>": {
                                "_help": "Scheduler group",
                                "strict-priority": {
                                    "_help": "Enable strict priority",
                                    "true": {
                                        "_help": "Use strict priority",
                                        "_executable": True,
                                    },
                                    "false": {
                                        "_help": "Use DRR scheduling",
                                        "_executable": True,
                                    },
                                },
                                "weight": {
                                    "_help": "DRR quantum",
                                    "<0-16777215>": {
                                        "_help": "DRR weight",
                                        "_executable": True,
                                    },
                                },
                                "rate-bps": {
                                    "_help": "Shaping group rate",
                                    "<1-100000000000>": {
                                        "_help": "Rate in bits per second",
                                        "_executable": True,
                                    },
                                },
                                "burst-bits": {
                                    "_help": "Shaping group burst size",
                                    "<1-67100672>": {
                                        "_help": "Burst size in bits",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                    },
                },
                "policy": {
                    "_help": "Reusable ETS scheduler policy (alias of template)",
                    "<template-name>": {
                        "_help": "Policy name",
                        "traffic-class": {
                            "_help": "Traffic class scheduler mapping",
                            "<0-7>": {
                                "_help": "Traffic class",
                                "shaping-group": {
                                    "_help": "FM10000 shaping group",
                                    "<0-7>": {
                                        "_help": "Shaping group",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                        "traffic-class-enable-mask": {
                            "_help": "Traffic class enable bitmask",
                            "<1-255>": {
                                "_help": "8-bit traffic class enable mask",
                                "_executable": True,
                            },
                        },
                        "group": {
                            "_help": "Scheduler group strict/DRR controls",
                            "<0-7>": {
                                "_help": "Scheduler group",
                                "strict-priority": {
                                    "_help": "Enable strict priority",
                                    "true": {
                                        "_help": "Use strict priority",
                                        "_executable": True,
                                    },
                                    "false": {
                                        "_help": "Use DRR scheduling",
                                        "_executable": True,
                                    },
                                },
                                "weight": {
                                    "_help": "DRR quantum",
                                    "<0-16777215>": {
                                        "_help": "DRR weight",
                                        "_executable": True,
                                    },
                                },
                                "rate-bps": {
                                    "_help": "Shaping group rate",
                                    "<1-100000000000>": {
                                        "_help": "Rate in bits per second",
                                        "_executable": True,
                                    },
                                },
                                "burst-bits": {
                                    "_help": "Shaping group burst size",
                                    "<1-67100672>": {
                                        "_help": "Burst size in bits",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                    },
                },
                "interfaces": {
                    "_help": "Per-interface scheduler controls",
                    "<interface-name>": {
                        "_help": "Interface name",
                        "_dynamic": "config-interfaces",
                        "template": {
                            "_help": "Apply scheduler template",
                            "<template-name>": {
                                "_help": "Template name",
                                "_executable": True,
                            },
                        },
                        "policy": {
                            "_help": "Apply scheduler policy",
                            "<template-name>": {
                                "_help": "Policy name",
                                "_executable": True,
                            },
                        },
                        "traffic-class": {
                            "_help": "Traffic class scheduler mapping",
                            "<0-7>": {
                                "_help": "Traffic class",
                                "shaping-group": {
                                    "_help": "FM10000 shaping group",
                                    "<0-7>": {
                                        "_help": "Shaping group",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                        "traffic-class-enable-mask": {
                            "_help": "Traffic class enable bitmask",
                            "<1-255>": {
                                "_help": "8-bit traffic class enable mask",
                                "_executable": True,
                            },
                        },
                        "group": {
                            "_help": "Scheduler group strict/DRR controls",
                            "<0-7>": {
                                "_help": "Scheduler group",
                                "strict-priority": {
                                    "_help": "Enable strict priority",
                                    "true": {
                                        "_help": "Use strict priority",
                                        "_executable": True,
                                    },
                                    "false": {
                                        "_help": "Use DRR scheduling",
                                        "_executable": True,
                                    },
                                },
                                "weight": {
                                    "_help": "DRR quantum",
                                    "<0-16777215>": {
                                        "_help": "DRR weight",
                                        "_executable": True,
                                    },
                                },
                                "rate-bps": {
                                    "_help": "Shaping group rate",
                                    "<1-100000000000>": {
                                        "_help": "Rate in bits per second",
                                        "_executable": True,
                                    },
                                },
                                "burst-bits": {
                                    "_help": "Shaping group burst size",
                                    "<1-67100672>": {
                                        "_help": "Burst size in bits",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "ets": {
                "_help": "Scheduler-backed ETS controls",
                "policy": {
                    "_help": "Reusable ETS scheduler policy",
                    "<template-name>": {
                        "_help": "Policy name",
                        "traffic-class": {
                            "_help": "Traffic class scheduler mapping",
                            "<0-7>": {
                                "_help": "Traffic class",
                                "shaping-group": {
                                    "_help": "FM10000 shaping group",
                                    "<0-7>": {
                                        "_help": "Shaping group",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                        "traffic-class-enable-mask": {
                            "_help": "Traffic class enable bitmask",
                            "<1-255>": {
                                "_help": "8-bit traffic class enable mask",
                                "_executable": True,
                            },
                        },
                        "group": {
                            "_help": "ETS scheduler group strict/DRR controls",
                            "<0-7>": {
                                "_help": "Scheduler group",
                                "strict-priority": {
                                    "_help": "Enable strict priority",
                                    "true": {
                                        "_help": "Use strict priority",
                                        "_executable": True,
                                    },
                                    "false": {
                                        "_help": "Use DRR scheduling",
                                        "_executable": True,
                                    },
                                },
                                "weight": {
                                    "_help": "DRR quantum",
                                    "<0-16777215>": {
                                        "_help": "DRR weight",
                                        "_executable": True,
                                    },
                                },
                                "rate-bps": {
                                    "_help": "Shaping group rate",
                                    "<1-100000000000>": {
                                        "_help": "Rate in bits per second",
                                        "_executable": True,
                                    },
                                },
                                "burst-bits": {
                                    "_help": "Shaping group burst size",
                                    "<1-67100672>": {
                                        "_help": "Burst size in bits",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                    },
                },
                "interfaces": {
                    "_help": "Per-interface ETS scheduler controls",
                    "<interface-name>": {
                        "_help": "Interface name",
                        "_dynamic": "config-interfaces",
                        "policy": {
                            "_help": "Apply ETS scheduler policy",
                            "<template-name>": {
                                "_help": "Policy name",
                                "_executable": True,
                            },
                        },
                        "traffic-class": {
                            "_help": "Traffic class scheduler mapping",
                            "<0-7>": {
                                "_help": "Traffic class",
                                "shaping-group": {
                                    "_help": "FM10000 shaping group",
                                    "<0-7>": {
                                        "_help": "Shaping group",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                        "traffic-class-enable-mask": {
                            "_help": "Traffic class enable bitmask",
                            "<1-255>": {
                                "_help": "8-bit traffic class enable mask",
                                "_executable": True,
                            },
                        },
                        "group": {
                            "_help": "ETS scheduler group strict/DRR controls",
                            "<0-7>": {
                                "_help": "Scheduler group",
                                "strict-priority": {
                                    "_help": "Enable strict priority",
                                    "true": {
                                        "_help": "Use strict priority",
                                        "_executable": True,
                                    },
                                    "false": {
                                        "_help": "Use DRR scheduling",
                                        "_executable": True,
                                    },
                                },
                                "weight": {
                                    "_help": "DRR quantum",
                                    "<0-16777215>": {
                                        "_help": "DRR weight",
                                        "_executable": True,
                                    },
                                },
                                "rate-bps": {
                                    "_help": "Shaping group rate",
                                    "<1-100000000000>": {
                                        "_help": "Rate in bits per second",
                                        "_executable": True,
                                    },
                                },
                                "burst-bits": {
                                    "_help": "Shaping group burst size",
                                    "<1-67100672>": {
                                        "_help": "Burst size in bits",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "watermarks": {
                "_help": "FM10000 watermark controls",
                "switch-priority": {
                    "_help": "Per switch-priority soft-drop watermarks",
                    "<0-7>": {
                        "_help": "Switch priority",
                        "soft-drop": {
                            "_help": "Shared soft-drop watermark",
                            "<0-6291264>": {
                                "_help": "Watermark bytes",
                                "_executable": True,
                            },
                        },
                        "soft-drop-jitter": {
                            "_help": "Shared soft-drop jitter",
                            "<0-7>": {
                                "_help": "Jitter value",
                                "_executable": True,
                            },
                        },
                        "soft-drop-hog": {
                            "_help": "Soft-drop hog watermark",
                            "<0-6291264>": {
                                "_help": "Watermark bytes",
                                "_executable": True,
                            },
                        },
                    },
                },
                "interface": {
                    "_help": "Per-interface TX watermarks",
                    "<interface-name>": {
                        "_help": "Interface name",
                        "_dynamic": "config-interfaces",
                        "traffic-class": {
                            "_help": "Traffic class",
                            "<0-7>": {
                                "_help": "Traffic class",
                                "tx-hog": {
                                    "_help": "TX hog watermark",
                                    "<0-6291264>": {
                                        "_help": "Watermark bytes",
                                        "_executable": True,
                                    },
                                },
                                "tx-private": {
                                    "_help": "TX private watermark",
                                    "<0-6291264>": {
                                        "_help": "Watermark bytes",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        "chassis": {
            "_help": "Chassis configuration",
            "port-mode": {
                "_help": "Restart-time fixed front-panel speed shape",
                "24x10g": {"_help": "24 fixed 10G single-lane ports", "_executable": True},
                "24x25g": {"_help": "24 fixed 25G single-lane ports", "_executable": True},
                "12x25g-12x10g": {
                    "_help": "12 fixed 25G ports plus 12 fixed 10G ports",
                    "_executable": True,
                },
                "12x10g-3x40g": {"_help": "12 fixed 10G ports plus 3 fixed 40G ports", "_executable": True},
                "12x25g-3x100g": {"_help": "12 fixed 25G ports plus 3 fixed 100G ports", "_executable": True},
                "6x40g": {"_help": "6 fixed 40G four-lane ports", "_executable": True},
                "6x100g": {"_help": "6 fixed 100G four-lane ports", "_executable": True},
            },
            "network-services": {
                "_help": "Restart-time forwarding resource allocation",
                "l2": {"_help": "Layer 2 switching resources", "_executable": True},
                "l3": {"_help": "Layer 3 routing-capable resources", "_executable": True},
            },
        },
        "forwarding-options": {
            "_help": "Forwarding options",
            "port-mirroring": {
                "_help": "Local port mirroring",
                "instance": {
                    "_help": "SPAN session",
                    "<instance-name>": {
                        "_help": "Session name",
                        "_executable": True,
                        "output": {
                            "_help": "Mirror destination",
                            "interface": {
                                "_help": "Physical destination interface",
                                "<interface-name>": {
                                    "_help": "Physical interface",
                                    "_dynamic": "physical-interfaces",
                                    "_executable": True,
                                },
                            },
                        },
                        "input": {
                            "_help": "Mirror source",
                            "interface": {
                                "_help": "Physical source interface",
                                "<interface-name>": {
                                    "_help": "Physical interface",
                                    "_dynamic": "physical-interfaces",
                                    "_executable": True,
                                    "direction": {
                                        "_help": "Traffic direction",
                                        "ingress": {"_help": "Ingress traffic", "_executable": True},
                                        "egress": {"_help": "Egress traffic", "_executable": True},
                                        "both": {"_help": "Both directions", "_executable": True},
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        "ethernet-switching-options": {
            "_help": "Ethernet switching options",
            "mac-table-aging-time": {
                "_help": "Dynamic MAC table aging time",
                "<seconds>": {
                    "_help": "Aging time in seconds (0 disables aging)",
                    "_executable": True,
                },
            },
            "static": {
                "_help": "Static ethernet-switching entries",
                "mac-table-entry": {
                    "_help": "Static MAC address table entry",
                    "<mac-address>": {
                        "_help": "MAC address",
                        "vlan": {
                            "_help": "VLAN name",
                            "<vlan-name>": {
                                "_help": "VLAN name",
                                "_dynamic": "vlans",
                                "interface": {
                                    "_help": "Forwarding interface",
                                    "<interface-name>": {
                                        "_help": "Interface name",
                                        "_dynamic": "config-interfaces",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "storm-control": {
                "_help": "Storm control options",
                "interface": {
                    "_help": "Per-interface storm control",
                    "<interface-name>": {
                        "_help": "Interface name",
                        "_dynamic": "config-interfaces",
                        "bandwidth": {
                            "_help": "Storm-control rate in Kbps",
                            "<kbps>": {
                                "_help": "Rate in Kbps (22000..100000000)",
                                "_executable": True,
                            },
                        },
                        "burst-size": {
                            "_help": "Token bucket burst size in bytes",
                            "<bytes>": {
                                "_help": "Burst size in bytes",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "ingress-rate-limit": {
                "_help": "Per-interface ingress rate-limit options",
                "interface": {
                    "_help": "Per-interface ingress rate limit",
                    "<interface-name>": {
                        "_help": "Interface name",
                        "_dynamic": "config-interfaces",
                        "bandwidth": {
                            "_help": "Ingress rate limit in Kbps",
                            "<kbps>": {
                                "_help": "Rate in Kbps (22000..100000000)",
                                "_executable": True,
                            },
                        },
                        "burst-size": {
                            "_help": "Token bucket burst size in bytes",
                            "<bytes>": {
                                "_help": "Burst size in bytes",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "egress-rate-limit": {
                "_help": "Per-interface egress rate-limit options",
                "interface": {
                    "_help": "Per-interface egress rate limit",
                    "<interface-name>": {
                        "_help": "Interface name",
                        "_dynamic": "config-interfaces",
                        "bandwidth": {
                            "_help": "Egress rate limit in Kbps",
                            "<kbps>": {
                                "_help": "Rate in Kbps (22000..100000000)",
                                "_executable": True,
                            },
                        },
                        "burst-size": {
                            "_help": "Shaper burst size in bytes",
                            "<bytes>": {
                                "_help": "Burst size in bytes (1..8387584)",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "mac-move": {
                "_help": "MAC move dampening options",
                "dampening": {
                    "_help": "Dampen repeated MAC moves",
                    "threshold": {
                        "_help": "Move threshold in the window",
                        "<count>": {
                            "_help": "Move count threshold",
                            "_executable": True,
                        },
                    },
                    "window": {
                        "_help": "Dampening window in seconds",
                        "<seconds>": {
                            "_help": "Window in seconds",
                            "_executable": True,
                        },
                    },
                    "action": {
                        "_help": "Action when dampening threshold is exceeded",
                        "alarm": {
                            "_help": "Report move dampening only",
                            "_executable": True,
                        },
                        "shutdown": {
                            "_help": "Shut destination physical interface",
                            "_executable": True,
                        },
                    },
                },
            },
            "dhcp-snooping": {
                "_help": "DHCP snooping options",
                "vlan": {
                    "_help": "Enable DHCP snooping on VLAN",
                    "<vlan-name>": {
                        "_help": "VLAN name",
                        "_dynamic": "vlans",
                        "_executable": True,
                    },
                },
                "interface": {
                    "_help": "Per-interface DHCP snooping trust",
                    "<interface-name>": {
                        "_help": "Interface name",
                        "_dynamic": "config-interfaces",
                        "trusted": {
                            "_help": "Trust DHCP server packets on this interface",
                            "_executable": True,
                        },
                    },
                },
                "binding": {
                    "_help": "Static DHCP snooping binding",
                    "<mac-address>": {
                        "_help": "Client MAC address",
                        "vlan": {
                            "_help": "Binding VLAN",
                            "<vlan-name>": {
                                "_help": "VLAN name",
                                "_dynamic": "vlans",
                                "interface": {
                                    "_help": "Client interface",
                                    "<interface-name>": {
                                        "_help": "Interface name",
                                        "_dynamic": "config-interfaces",
                                        "_executable": True,
                                    },
                                },
                                "ip-address": {
                                    "_help": "Client IPv4 address",
                                    "<ipv4-address>": {
                                        "_help": "IPv4 address",
                                        "_executable": True,
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "arp-inspection": {
                "_help": "Dynamic ARP inspection options",
                "vlan": {
                    "_help": "Enable ARP inspection on VLAN",
                    "<vlan-name>": {
                        "_help": "VLAN name",
                        "_dynamic": "vlans",
                        "_executable": True,
                    },
                },
                "interface": {
                    "_help": "Per-interface ARP inspection trust",
                    "<interface-name>": {
                        "_help": "Interface name",
                        "_dynamic": "config-interfaces",
                        "trusted": {
                            "_help": "Trust ARP on this interface",
                            "_executable": True,
                        },
                    },
                },
            },
            "user-filter": {
                "_help": "Hardware-backed L2 user filter",
                "term": {
                    "_help": "Filter term",
                    "<term-name>": {
                        "_help": "Term name",
                        "vlan": {
                            "_help": "Match VLAN",
                            "<vlan-name>": {
                                "_help": "VLAN name",
                                "_dynamic": "vlans",
                                "_executable": True,
                            },
                        },
                        "interface": {
                            "_help": "Match ingress interface",
                            "<interface-name>": {
                                "_help": "Interface name",
                                "_dynamic": "config-interfaces",
                                "_executable": True,
                            },
                        },
                        "source-mac": {
                            "_help": "Match source MAC address",
                            "<mac-address>": {
                                "_help": "Source MAC address",
                                "_executable": True,
                            },
                        },
                        "destination-mac": {
                            "_help": "Match destination MAC address",
                            "<mac-address>": {
                                "_help": "Destination MAC address",
                                "_executable": True,
                            },
                        },
                        "action": {
                            "_help": "Filter action",
                            "drop": {
                                "_help": "Drop and count matching traffic",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "ingress-acl": {
                "_help": "Scoped hardware-backed ingress ACL",
                "term": {
                    "_help": "ACL term",
                    "<term-name>": {
                        "_help": "Term name",
                        "vlan": {
                            "_help": "Match VLAN",
                            "<vlan-name>": {
                                "_help": "VLAN name",
                                "_dynamic": "vlans",
                                "_executable": True,
                            },
                        },
                        "interface": {
                            "_help": "Match ingress interface",
                            "<interface-name>": {
                                "_help": "Interface name",
                                "_dynamic": "config-interfaces",
                                "_executable": True,
                            },
                        },
                        "source-mac": {
                            "_help": "Match source MAC address",
                            "<mac-address>": {
                                "_help": "Source MAC address",
                                "_executable": True,
                            },
                        },
                        "destination-mac": {
                            "_help": "Match destination MAC address",
                            "<mac-address>": {
                                "_help": "Destination MAC address",
                                "_executable": True,
                            },
                        },
                        "action": {
                            "_help": "ACL action",
                            "drop": {
                                "_help": "Drop and count matching traffic",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "ingress-ipv4-acl": {
                "_help": "Hardware-backed ingress IPv4 ACL",
                "term": {
                    "_help": "ACL term",
                    "<term-name>": {
                        "_help": "Term name",
                        "vlan": {
                            "_help": "Match VLAN",
                            "<vlan-name>": {
                                "_help": "VLAN name",
                                "_dynamic": "vlans",
                                "_executable": True,
                            },
                        },
                        "interface": {
                            "_help": "Match ingress interface",
                            "<interface-name>": {
                                "_help": "Interface name",
                                "_dynamic": "config-interfaces",
                                "_executable": True,
                            },
                        },
                        "source-ip": {
                            "_help": "Match exact IPv4 source address",
                            "<ipv4-address>": {
                                "_help": "IPv4 source address",
                                "_executable": True,
                            },
                        },
                        "source-prefix": {
                            "_help": "Match IPv4 source prefix",
                            "<ipv4-prefix>": {
                                "_help": "IPv4 source prefix",
                                "_executable": True,
                            },
                        },
                        "destination-ip": {
                            "_help": "Match exact IPv4 destination address",
                            "<ipv4-address>": {
                                "_help": "IPv4 destination address",
                                "_executable": True,
                            },
                        },
                        "destination-prefix": {
                            "_help": "Match IPv4 destination prefix",
                            "<ipv4-prefix>": {
                                "_help": "IPv4 destination prefix",
                                "_executable": True,
                            },
                        },
                        "protocol": {
                            "_help": "Match IPv4 protocol number",
                            "<0-255>": {
                                "_help": "Protocol number",
                                "_executable": True,
                            },
                        },
                        "dscp": {
                            "_help": "Match IPv4 DSCP",
                            "<0-63>": {
                                "_help": "DSCP value",
                                "_executable": True,
                            },
                        },
                        "ecn": {
                            "_help": "Match IPv4 ECN",
                            "<0-3>": {
                                "_help": "ECN value",
                                "_executable": True,
                            },
                        },
                        "source-port": {
                            "_help": "Match exact TCP/UDP source port",
                            "<0-65535>": {
                                "_help": "TCP/UDP source port",
                                "_executable": True,
                            },
                        },
                        "source-port-range": {
                            "_help": "Match TCP/UDP source port range",
                            "<start-end>": {
                                "_help": "Inclusive TCP/UDP source port range",
                                "_executable": True,
                            },
                        },
                        "destination-port": {
                            "_help": "Match exact TCP/UDP destination port",
                            "<0-65535>": {
                                "_help": "TCP/UDP destination port",
                                "_executable": True,
                            },
                        },
                        "destination-port-range": {
                            "_help": "Match TCP/UDP destination port range",
                            "<start-end>": {
                                "_help": "Inclusive TCP/UDP destination port range",
                                "_executable": True,
                            },
                        },
                        "tcp-flags": {
                            "_help": "Match TCP flags bit value",
                            "<0-63>": {
                                "_help": "TCP flags value",
                                "_executable": True,
                            },
                        },
                        "tcp-flags-mask": {
                            "_help": "Mask TCP flags bits",
                            "<1-63>": {
                                "_help": "TCP flags mask",
                                "_executable": True,
                            },
                        },
                        "action": {
                            "_help": "ACL action",
                            "drop": {
                                "_help": "Drop and count matching traffic",
                                "_executable": True,
                            },
                            "count": {
                                "_help": "Permit and count matching traffic",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "acl-policer": {
                "_help": "Scoped ACL compiler policer",
                "term": {
                    "_help": "Policer term",
                    "<term-name>": {
                        "_help": "Term name",
                        "interface": {
                            "_help": "Match ingress interface",
                            "<interface-name>": {
                                "_help": "Interface name",
                                "_dynamic": "config-interfaces",
                                "_executable": True,
                            },
                        },
                        "destination-mac": {
                            "_help": "Match destination MAC address",
                            "<mac-address>": {
                                "_help": "Destination MAC address",
                                "_executable": True,
                            },
                        },
                        "bandwidth": {
                            "_help": "Policer rate in Kbps",
                            "<kbps>": {
                                "_help": "Rate in Kbps (1..100000000)",
                                "_executable": True,
                            },
                        },
                        "burst-size": {
                            "_help": "Policer burst size in bytes",
                            "<bytes>": {
                                "_help": "Burst size in bytes (1024..268435456)",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "egress-acl": {
                "_help": "Scoped hardware-backed egress ACL",
                "term": {
                    "_help": "ACL term",
                    "<term-name>": {
                        "_help": "Term name",
                        "interface": {
                            "_help": "Match egress interface",
                            "<interface-name>": {
                                "_help": "Interface name",
                                "_dynamic": "config-interfaces",
                                "_executable": True,
                            },
                        },
                        "destination-mac": {
                            "_help": "Match destination MAC address",
                            "<mac-address>": {
                                "_help": "Destination MAC address",
                                "_executable": True,
                            },
                        },
                        "source-mac": {
                            "_help": "Match source MAC address",
                            "<mac-address>": {
                                "_help": "Source MAC address",
                                "_executable": True,
                            },
                        },
                        "action": {
                            "_help": "ACL action",
                            "drop": {
                                "_help": "Drop matching egress traffic",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
            "acl": {
                "_help": "General ACL compiler",
                "term": {
                    "_help": "ACL term",
                    "<term-name>": {
                        "_help": "Term name",
                        "ethernet": {
                            "_help": "Compile to ingress L2 MAC ACL",
                            "vlan": {
                                "_help": "Match VLAN",
                                "<vlan-name>": {
                                    "_help": "VLAN name",
                                    "_dynamic": "vlans",
                                    "_executable": True,
                                },
                            },
                            "interface": {
                                "_help": "Match ingress interface",
                                "<interface-name>": {
                                    "_help": "Interface name",
                                    "_dynamic": "config-interfaces",
                                    "_executable": True,
                                },
                            },
                            "source-mac": {
                                "_help": "Match source MAC address",
                                "<mac-address>": {
                                    "_help": "Source MAC address",
                                    "_executable": True,
                                },
                            },
                            "destination-mac": {
                                "_help": "Match destination MAC address",
                                "<mac-address>": {
                                    "_help": "Destination MAC address",
                                    "_executable": True,
                                },
                            },
                            "action": {
                                "_help": "ACL action",
                                "drop": {
                                    "_help": "Drop and count matching traffic",
                                    "_executable": True,
                                },
                            },
                        },
                        "inet": {
                            "_help": "Compile to ingress IPv4/L4 ACL",
                            "vlan": {
                                "_help": "Match VLAN",
                                "<vlan-name>": {
                                    "_help": "VLAN name",
                                    "_dynamic": "vlans",
                                    "_executable": True,
                                },
                            },
                            "interface": {
                                "_help": "Match ingress interface",
                                "<interface-name>": {
                                    "_help": "Interface name",
                                    "_dynamic": "config-interfaces",
                                    "_executable": True,
                                },
                            },
                            "source-ip": {
                                "_help": "Match exact IPv4 source address",
                                "<ipv4-address>": {
                                    "_help": "IPv4 source address",
                                    "_executable": True,
                                },
                            },
                            "source-prefix": {
                                "_help": "Match IPv4 source prefix",
                                "<ipv4-prefix>": {
                                    "_help": "IPv4 source prefix",
                                    "_executable": True,
                                },
                            },
                            "destination-ip": {
                                "_help": "Match exact IPv4 destination address",
                                "<ipv4-address>": {
                                    "_help": "IPv4 destination address",
                                    "_executable": True,
                                },
                            },
                            "destination-prefix": {
                                "_help": "Match IPv4 destination prefix",
                                "<ipv4-prefix>": {
                                    "_help": "IPv4 destination prefix",
                                    "_executable": True,
                                },
                            },
                            "protocol": {
                                "_help": "Match IPv4 protocol number",
                                "<0-255>": {
                                    "_help": "Protocol number",
                                    "_executable": True,
                                },
                            },
                            "dscp": {
                                "_help": "Match IPv4 DSCP",
                                "<0-63>": {
                                    "_help": "DSCP value",
                                    "_executable": True,
                                },
                            },
                            "ecn": {
                                "_help": "Match IPv4 ECN",
                                "<0-3>": {
                                    "_help": "ECN value",
                                    "_executable": True,
                                },
                            },
                            "source-port": {
                                "_help": "Match exact TCP/UDP source port",
                                "<0-65535>": {
                                    "_help": "TCP/UDP source port",
                                    "_executable": True,
                                },
                            },
                            "source-port-range": {
                                "_help": "Match TCP/UDP source port range",
                                "<start-end>": {
                                    "_help": "Inclusive TCP/UDP source port range",
                                    "_executable": True,
                                },
                            },
                            "destination-port": {
                                "_help": "Match exact TCP/UDP destination port",
                                "<0-65535>": {
                                    "_help": "TCP/UDP destination port",
                                    "_executable": True,
                                },
                            },
                            "destination-port-range": {
                                "_help": "Match TCP/UDP destination port range",
                                "<start-end>": {
                                    "_help": "Inclusive TCP/UDP destination port range",
                                    "_executable": True,
                                },
                            },
                            "tcp-flags": {
                                "_help": "Match TCP flags bit value",
                                "<0-63>": {
                                    "_help": "TCP flags value",
                                    "_executable": True,
                                },
                            },
                            "tcp-flags-mask": {
                                "_help": "Mask TCP flags bits",
                                "<1-63>": {
                                    "_help": "TCP flags mask",
                                    "_executable": True,
                                },
                            },
                            "action": {
                                "_help": "ACL action",
                                "drop": {
                                    "_help": "Drop and count matching traffic",
                                    "_executable": True,
                                },
                                "count": {
                                    "_help": "Permit and count matching traffic",
                                    "_executable": True,
                                },
                            },
                        },
                        "policer": {
                            "_help": "Compile to ACL policer pipeline",
                            "interface": {
                                "_help": "Match ingress interface",
                                "<interface-name>": {
                                    "_help": "Interface name",
                                    "_dynamic": "config-interfaces",
                                    "_executable": True,
                                },
                            },
                            "destination-mac": {
                                "_help": "Match destination MAC address",
                                "<mac-address>": {
                                    "_help": "Destination MAC address",
                                    "_executable": True,
                                },
                            },
                            "bandwidth": {
                                "_help": "Policer rate in Kbps",
                                "<kbps>": {
                                    "_help": "Rate in Kbps (1..100000000)",
                                    "_executable": True,
                                },
                            },
                            "burst-size": {
                                "_help": "Policer burst size in bytes",
                                "<bytes>": {
                                    "_help": "Burst size in bytes (1024..268435456)",
                                    "_executable": True,
                                },
                            },
                        },
                        "egress": {
                            "_help": "Compile to scoped egress ACL",
                            "interface": {
                                "_help": "Match egress interface",
                                "<interface-name>": {
                                    "_help": "Interface name",
                                    "_dynamic": "config-interfaces",
                                    "_executable": True,
                                },
                            },
                            "destination-mac": {
                                "_help": "Match destination MAC address",
                                "<mac-address>": {
                                    "_help": "Destination MAC address",
                                    "_executable": True,
                                },
                            },
                            "source-mac": {
                                "_help": "Match source MAC address",
                                "<mac-address>": {
                                    "_help": "Source MAC address",
                                    "_executable": True,
                                },
                            },
                            "action": {
                                "_help": "ACL action",
                                "drop": {
                                    "_help": "Drop matching egress traffic",
                                    "_executable": True,
                                },
                            },
                        },
                    },
                },
            },
            "secure-access-port": {
                "_help": "Port security options",
                "interface": {
                    "_help": "Interface port security",
                    "<interface-name>": {
                        "_help": "Interface name",
                        "_dynamic": "config-interfaces",
                        "mac-limit": {
                            "_help": "Alarm when dynamic MAC count exceeds limit",
                            "<limit>": {
                                "_help": "Dynamic MAC limit",
                                "_executable": True,
                            },
                        },
                        "action": {
                            "_help": "Action when dynamic MAC count exceeds limit",
                            "alarm": {
                                "_help": "Report violation only",
                                "_executable": True,
                            },
                            "drop": {
                                "_help": "Drop violating frames in hardware",
                                "_executable": True,
                            },
                            "restrict": {
                                "_help": "Drop and count violating frames",
                                "_executable": True,
                            },
                            "shutdown": {
                                "_help": "Disable physical interface until cleared",
                                "_executable": True,
                            },
                        },
                    },
                },
            },
        },
    },
    "delete": {"_help": "Delete configuration (same syntax as set)"},
    "commit": {
        "_help": "Commit configuration",
        "check": {"_help": "Validate configuration only", "_executable": True},
        "comment": {
            "_help": "Commit and record an audit comment",
            "<comment>": {
                "_help": "Commit comment text",
                "_executable": True,
            },
        },
        "confirmed": {
            "_help": "Commit with automatic rollback unless confirmed",
            "_executable": True,
            "<minutes>": {
                "_help": "Rollback timeout in minutes",
                "_executable": True,
                "comment": {
                    "_help": "Commit and record an audit comment",
                    "<comment>": {
                        "_help": "Commit comment text",
                        "_executable": True,
                    },
                },
            },
            "comment": {
                "_help": "Commit and record an audit comment",
                "<comment>": {
                    "_help": "Commit comment text",
                    "_executable": True,
                },
            },
        },
        "<[Enter]>": {"_help": "Commit and apply configuration"},
    },
    "rollback": {
        "_help": "Load a previous committed configuration into candidate",
        "_executable": True,
        "<rollback-number>": {
            "_help": "0=current active, 1=previous commit",
            "_dynamic": "rollback",
            "_executable": True,
        },
    },
    "load": {
        "_help": "Load configuration from a file",
        "factory-default": {
            "_help": "Replace candidate with factory-default configuration",
            "_executable": True,
        },
        "merge": {
            "_help": "Merge display-set configuration into candidate",
            "<filename>": {
                "_help": "Configuration file path",
                "_executable": True,
            },
        },
        "set": {
            "_help": "Load set-style configuration into candidate",
            "<filename>": {
                "_help": "Configuration file path",
                "_executable": True,
            },
        },
        "override": {
            "_help": "Replace candidate with display-set configuration",
            "<filename>": {
                "_help": "Configuration file path",
                "_executable": True,
            },
        },
    },
    "save": {
        "_help": "Save candidate configuration to a display-set file",
        "<filename>": {
            "_help": "Configuration file path",
            "_executable": True,
        },
    },
    "show": {
        "_help": "Show candidate configuration",
        "_executable": True,
        "_allow_pipe": True,
        "system": {
            "_help": "System configuration",
            "_executable": True,
            "_allow_pipe": True,
        },
        "vlans": {
            "_help": "VLAN configuration",
            "_executable": True,
            "_allow_pipe": True,
            "<vlan-name>": {
                "_help": "VLAN name",
                "_dynamic": "vlans",
                "_executable": True,
                "_allow_pipe": True,
            },
        },
        "interfaces": {
            "_help": "Interface configuration",
            "_executable": True,
            "_allow_pipe": True,
            "irb": {
                "_help": "Integrated routing and bridging interfaces",
                "_executable": True,
                "_allow_pipe": True,
                "unit": {
                    "_help": "Logical IRB unit",
                    "<1-4094>": {
                        "_help": "IRB unit number",
                        "_executable": True,
                        "_allow_pipe": True,
                        "family": {
                            "_help": "Protocol family",
                            "inet": {
                                "_help": "IPv4 family",
                                "_executable": True,
                                "_allow_pipe": True,
                                "address": {
                                    "_help": "IPv4 address and prefix",
                                    "_executable": True,
                                    "_allow_pipe": True,
                                },
                            },
                        },
                    },
                },
            },
            "<interface-name>": {
                "_help": "Interface name",
                "_dynamic": "config-interfaces",
                "_executable": True,
                "_allow_pipe": True,
            },
        },
        "protocols": {
            "_help": "Protocol configuration",
            "_executable": True,
            "_allow_pipe": True,
            "lldp": {
                "_help": "Link Layer Discovery Protocol configuration",
                "_executable": True,
                "_allow_pipe": True,
                "disable": {"_help": "Global LLDP disable", "_executable": True},
                "transmit-interval": {"_help": "LLDP transmit interval", "_executable": True},
                "hold-multiplier": {"_help": "LLDP TTL multiplier", "_executable": True},
                "system-name": {"_help": "Advertised system name", "_executable": True},
                "system-description": {"_help": "Advertised system description", "_executable": True},
                "management-address": {"_help": "Advertised management address", "_executable": True},
                "interface": {
                    "_help": "LLDP interface configuration",
                    "<interface-name>": {
                        "_help": "Name of interface",
                        "_dynamic": "lldp-interfaces",
                        "_executable": True,
                        "_allow_pipe": True,
                    },
                },
            },
            "igmp-snooping": {
                "_help": "IPv4 IGMP snooping configuration",
                "_executable": True,
                "_allow_pipe": True,
                "membership-timeout": {
                    "_help": "Dynamic membership aging interval",
                    "_executable": True,
                },
                "vlan": {
                    "_help": "Bridge VLAN",
                    "<vlan-name>": {
                        "_help": "Configured VLAN name",
                        "_executable": True,
                        "_allow_pipe": True,
                        "interface": {
                            "_help": "Physical VLAN member",
                            "<interface-name>": {
                                "_help": "Physical interface",
                                "_dynamic": "config-interfaces",
                                "_executable": True,
                                "_allow_pipe": True,
                            },
                        },
                    },
                },
            },
            "rstp": {
                "_help": "Rapid Spanning Tree Protocol configuration",
                "_executable": True,
                "_allow_pipe": True,
                "bridge-priority": {"_help": "RSTP bridge priority", "_executable": True},
                "hello-time": {"_help": "RSTP hello interval", "_executable": True},
                "max-age": {"_help": "RSTP maximum BPDU age", "_executable": True},
                "forward-delay": {"_help": "RSTP forward delay", "_executable": True},
                "interface": {
                    "_help": "Interface RSTP configuration",
                    "<interface-name>": {
                        "_help": "Name of interface",
                        "_dynamic": "rstp-interfaces",
                        "_executable": True,
                        "_allow_pipe": True,
                    },
                },
            },
            "mstp": {
                "_help": "Multiple Spanning Tree Protocol configuration",
                "_executable": True,
                "_allow_pipe": True,
                "configuration-name": {"_help": "MST region name", "_executable": True},
                "revision-level": {"_help": "MST region revision", "_executable": True},
                "bridge-priority": {"_help": "CIST bridge priority", "_executable": True},
                "hello-time": {"_help": "MSTP hello interval", "_executable": True},
                "max-age": {"_help": "MSTP maximum BPDU age", "_executable": True},
                "forward-delay": {"_help": "MSTP forward delay", "_executable": True},
                "max-hops": {"_help": "MSTP maximum hop count", "_executable": True},
                "instance": {
                    "_help": "MST instance",
                    "<instance-id>": {
                        "_help": "MSTI ID",
                        "_executable": True,
                        "_allow_pipe": True,
                        "interface": {
                            "_help": "Per-MSTI interface port vector",
                            "<interface-name>": {
                                "_help": "Name of interface",
                                "_dynamic": "rstp-interfaces",
                                "_executable": True,
                                "_allow_pipe": True,
                            },
                        },
                    },
                },
                "interface": {
                    "_help": "Interface MSTP configuration",
                    "<interface-name>": {
                        "_help": "Name of interface",
                        "_dynamic": "rstp-interfaces",
                        "_executable": True,
                        "_allow_pipe": True,
                    },
                },
            },
        },
        "control-plane": {
            "_help": "Control-plane configuration",
            "_executable": True,
            "_allow_pipe": True,
            "protection": {
                "_help": "Control-plane protection policy",
                "_executable": True,
                "_allow_pipe": True,
            },
        },
        "class-of-service": {
            "_help": "Class of service configuration",
            "_executable": True,
            "_allow_pipe": True,
        },
        "chassis": {
            "_help": "Chassis configuration",
            "_executable": True,
            "_allow_pipe": True,
            "port-mode": {
                "_help": "Restart-time fixed front-panel speed shape",
                "24x10g": {"_help": "24 fixed 10G single-lane ports", "_executable": True},
                "24x25g": {"_help": "24 fixed 25G single-lane ports", "_executable": True},
                "12x25g-12x10g": {
                    "_help": "12 fixed 25G ports plus 12 fixed 10G ports",
                    "_executable": True,
                },
                "12x10g-3x40g": {"_help": "12 fixed 10G ports plus 3 fixed 40G ports", "_executable": True},
                "12x25g-3x100g": {"_help": "12 fixed 25G ports plus 3 fixed 100G ports", "_executable": True},
                "6x40g": {"_help": "6 fixed 40G four-lane ports", "_executable": True},
                "6x100g": {"_help": "6 fixed 100G four-lane ports", "_executable": True},
            },
            "network-services": {
                "_help": "Restart-time forwarding resource allocation",
                "l2": {"_help": "Layer 2 switching resources", "_executable": True},
                "l3": {"_help": "Layer 3 routing-capable resources", "_executable": True},
            },
        },
        "ethernet-switching-options": {
            "_help": "Ethernet switching options",
            "_executable": True,
            "_allow_pipe": True,
        },
        "|": {
            "_help": "Pipe through a command",
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
            "display": {
                "_help": "Display options",
                "set": {"_help": "Display as set commands"},
                "xml": {"_help": "Display as XML"},
            },
        },
    },
    "edit": {"_help": "Edit a sub-configuration path", "_executable": True},
    "up": {"_help": "Go up one edit level", "_executable": True},
    "top": {"_help": "Go to top edit level", "_executable": True},
    "run": {"_help": "Run operational command from config mode"},
    "exit": {"_help": "Exit configuration mode", "_executable": True},
}


def _install_acl_group_schema():
    """Expose group/term ACL aliases using the existing compiler family schema."""
    acl = CFG_SCHEMA["set"]["ethernet-switching-options"]["acl"]
    term_schema = acl["term"]["<term-name>"]
    independent_term_schema = copy.deepcopy(term_schema)
    independent_term_schema.pop("egress", None)
    independent_term_schema.pop("egress-mac", None)
    term_schema.pop("policer", None)
    term_schema.pop("egress", None)
    term_schema.pop("egress-mac", None)

    def _action_node(help_text):
        return {
            "_help": "ACL action",
            "drop": {
                "_help": "Drop and count matching traffic",
                "_executable": True,
            },
            "count": {
                "_help": "Permit and count matching traffic",
                "_executable": True,
            },
            "policer": {
                "_help": help_text,
                "_executable": True,
            },
        }

    def _policer_rate_nodes():
        return {
            "bandwidth": {
                "_help": "Policer rate in Kbps",
                "<kbps>": {
                    "_help": "Rate in Kbps (1..100000000)",
                    "_executable": True,
                },
            },
            "burst-size": {
                "_help": "Policer burst size in bytes",
                "<bytes>": {
                    "_help": "Burst size in bytes (1024..268435456)",
                    "_executable": True,
                },
            },
        }

    independent_term_schema["ethernet"]["action"] = _action_node(
        "Police and count matching L2 traffic")
    independent_term_schema["ethernet"].update(_policer_rate_nodes())
    independent_term_schema["inet"]["action"] = _action_node(
        "Police and count matching IPv4/L4 traffic")
    independent_term_schema["inet"].update(_policer_rate_nodes())
    independent_term_schema["policer"]["vlan"] = copy.deepcopy(
        independent_term_schema["ethernet"]["vlan"])
    independent_term_schema["policer"]["source-mac"] = copy.deepcopy(
        independent_term_schema["ethernet"]["source-mac"])
    for key in (
            "source-ip", "source-prefix", "destination-ip",
            "destination-prefix", "protocol", "dscp", "ecn",
            "source-port", "source-port-range", "destination-port",
            "destination-port-range", "tcp-flags", "tcp-flags-mask"):
        independent_term_schema["policer"][key] = copy.deepcopy(
            independent_term_schema["inet"][key])

    acl["group"] = {
        "_help": "ACL group alias",
        "<acl-group-name>": {
            "_help": "ACL group name",
            "term": {
                "_help": "ACL term",
                "<term-name>": term_schema,
            },
        },
    }
    acl["independent-group"] = {
        "_help": "Independent ACL group",
        "<acl-group-name>": {
            "_help": "Independent ACL group name",
            "term": {
                "_help": "ACL term",
                "<term-name>": independent_term_schema,
            },
        },
    }


_install_acl_group_schema()


def _firewall_from_schema(family):
    common = {
        "vlan": {
            "_help": "Match VLAN",
            "<vlan-name>": {
                "_help": "VLAN name or ID",
                "_dynamic": "vlans",
                "_executable": True,
            },
        },
        "interface": {
            "_help": "Match ingress interface",
            "<interface-name>": {
                "_help": "Interface name",
                "_dynamic": "config-interfaces",
                "_executable": True,
            },
        },
    }
    if family == "ethernet-switching":
        common.update({
            "source-mac": {
                "_help": "Match source MAC address",
                "<mac-address>": {
                    "_help": "Source MAC address",
                    "_executable": True,
                },
            },
            "destination-mac": {
                "_help": "Match destination MAC address",
                "<mac-address>": {
                    "_help": "Destination MAC address",
                    "_executable": True,
                },
            },
        })
        return common
    common.update({
        "source-address": {
            "_help": "Match IPv4 source address or prefix",
            "<ipv4-prefix>": {
                "_help": "IPv4 address or prefix",
                "_executable": True,
            },
        },
        "destination-address": {
            "_help": "Match IPv4 destination address or prefix",
            "<ipv4-prefix>": {
                "_help": "IPv4 address or prefix",
                "_executable": True,
            },
        },
        "dscp": {
            "_help": "Match DSCP value",
            "<0-63>": {"_help": "DSCP value", "_executable": True},
        },
        "ecn": {
            "_help": "Match ECN value",
            "<0-3>": {"_help": "ECN value", "_executable": True},
        },
        "protocol": {
            "_help": "Match IP protocol",
            "<protocol>": {"_help": "Protocol name or number", "_executable": True},
        },
        "source-port": {
            "_help": "Match TCP/UDP source port",
            "<port>": {"_help": "Port number", "_executable": True},
        },
        "source-port-range": {
            "_help": "Match TCP/UDP source port range",
            "<range>": {"_help": "Port range", "_executable": True},
        },
        "destination-port": {
            "_help": "Match TCP/UDP destination port",
            "<port>": {"_help": "Port number", "_executable": True},
        },
        "destination-port-range": {
            "_help": "Match TCP/UDP destination port range",
            "<range>": {"_help": "Port range", "_executable": True},
        },
        "tcp-flags": {
            "_help": "Match TCP flags",
            "<flags>": {"_help": "TCP flags value", "_executable": True},
        },
        "tcp-flags-mask": {
            "_help": "Match TCP flags mask",
            "<mask>": {"_help": "TCP flags mask", "_executable": True},
        },
    })
    return common


def _firewall_policer_schema():
    return {
        "_help": "ACL policer compiler",
        "from": {
            "_help": "Policer match conditions",
            "interface": {
                "_help": "Match ingress interface",
                "<interface-name>": {
                    "_help": "Interface name",
                    "_dynamic": "config-interfaces",
                    "_executable": True,
                },
            },
            "destination-mac": {
                "_help": "Match destination MAC address",
                "<mac-address>": {
                    "_help": "Destination MAC address",
                    "_executable": True,
                },
            },
        },
        "then": {
            "_help": "Policer parameters",
            "bandwidth": {
                "_help": "Committed bandwidth in kbps",
                "<kbps>": {
                    "_help": "Bandwidth in kbps",
                    "_executable": True,
                },
            },
            "burst-size": {
                "_help": "Committed burst size in bytes",
                "<bytes>": {
                    "_help": "Burst size in bytes",
                    "_executable": True,
                },
            },
        },
    }


def _firewall_egress_schema():
    return {
        "_help": "Egress ACL compiler",
        "from": {
            "_help": "Egress match conditions",
            "interface": {
                "_help": "Match egress interface",
                "<interface-name>": {
                    "_help": "Interface name",
                    "_dynamic": "config-interfaces",
                    "_executable": True,
                },
            },
            "source-mac": {
                "_help": "Match source MAC address",
                "<mac-address>": {
                    "_help": "Source MAC address",
                    "_executable": True,
                },
            },
            "destination-mac": {
                "_help": "Match destination MAC address",
                "<mac-address>": {
                    "_help": "Destination MAC address",
                    "_executable": True,
                },
            },
        },
        "then": {
            "_help": "Egress ACL action",
            "discard": {
                "_help": "Drop matching egress traffic",
                "_executable": True,
            },
        },
    }


def _install_firewall_schema():
    """Install Junos-style firewall filter facade over the ACL compiler."""
    def family_schema(family):
        term_schema = {
            "_help": "Term name",
            "from": {
                "_help": "Match conditions",
                **_firewall_from_schema(family),
            },
            "then": {
                "_help": "Term action",
                "discard": {
                    "_help": "Drop and count matching traffic",
                    "_executable": True,
                },
                "accept": {
                    "_help": "Permit and count matching traffic",
                    "_executable": True,
                },
                "count": {
                    "_help": "Permit and count matching traffic",
                    "_executable": True,
                },
            },
        }
        if family == "ethernet-switching":
            term_schema["policer"] = _firewall_policer_schema()
            term_schema["egress"] = _firewall_egress_schema()
        return {
            "_help": f"{family} firewall filters",
            "filter": {
                "_help": "Firewall filter",
                "<filter-name>": {
                    "_help": "Filter name",
                    "term": {
                        "_help": "Filter term",
                        "<term-name>": term_schema,
                    },
                },
            },
        }

    CFG_SCHEMA["set"]["firewall"] = {
        "_help": "Firewall filter configuration",
        "family": {
            "_help": "Protocol family",
            "ethernet-switching": family_schema("ethernet-switching"),
            "inet": family_schema("inet"),
        },
    }


_install_firewall_schema()


def _is_terminal_delete_value_node(node, node_key):
    if node_key == "members":
        return False
    if node.get("_dynamic") in (
        "interfaces", "config-interfaces", "operational-interfaces",
        "physical-interfaces", "rstp-interfaces", "lldp-interfaces", "vlans",
    ):
        return False
    children = [(key, child) for key, child in node.items()
                if not key.startswith("_")]
    if not children:
        return False
    for _, child in children:
        if not isinstance(child, dict) or not child.get("_executable"):
            return False
        if any(not key.startswith("_") for key in child):
            return False
    return True


def _delete_schema_from_set(node, node_key="", root=False):
    """Build delete completion from set schema while making hierarchy executable."""
    out = {}
    if "_help" in node:
        out["_help"] = node["_help"]
    if "_dynamic" in node:
        out["_dynamic"] = node["_dynamic"]
    if "_hidden" in node:
        out["_hidden"] = node["_hidden"]
    if not root:
        out["_executable"] = True

    if _is_terminal_delete_value_node(node, node_key):
        return out

    for key, child in node.items():
        if key.startswith("_"):
            continue
        if isinstance(child, dict):
            out[key] = _delete_schema_from_set(child, key)
        else:
            out[key] = child
    return out


CFG_SCHEMA["set"]["routing-instances"] = {
    "_help": "IPv4 virtual routing instance",
    "<instance-name>": {
        "_help": "VRF name",
        "instance-type": {
            "_help": "Routing instance type",
            "vrf": {"_help": "IPv4 VRF", "_executable": True},
        },
        "interface": {
            "_help": "Assign an existing routed interface",
            "<rif-name>": {
                "_help": "Routed interface",
                "_executable": True,
            },
        },
        "routing-options": {
            "_help": "VRF-scoped routing options",
            "static": copy.deepcopy(
                CFG_SCHEMA["set"]["routing-options"]["static"]),
        },
    },
}
CFG_SCHEMA["show"]["routing-instances"] = {
    "_help": "VRF configuration",
    "_executable": True,
    "_allow_pipe": True,
    "<instance-name>": {
        "_help": "VRF name",
        "_executable": True,
        "_allow_pipe": True,
    },
}

CFG_SCHEMA["delete"] = _delete_schema_from_set(CFG_SCHEMA["set"], root=True)
CFG_SCHEMA["delete"]["_help"] = "Delete configuration (same syntax as set)"


def _mark_hidden(schema, path):
    node = schema
    for token in path:
        if not isinstance(node, dict) or token not in node:
            return
        node = node[token]
    if isinstance(node, dict):
        node["_hidden"] = True


def _install_public_namespace_cleanup():
    """Keep diagnostics and compatibility paths out of public completion."""
    show = OP_SCHEMA["show"]
    show["firewall"] = {
        "_help": "Show firewall filter state",
        "_executable": True,
        "family": {
            "_help": "Firewall family",
            "ethernet-switching": {
                "_help": "Show ethernet-switching firewall filters",
                "_executable": True,
            },
            "inet": {
                "_help": "Show inet firewall filters",
                "_executable": True,
            },
        },
    }
    runtime = copy.deepcopy(show["chassis"]["forwarding"]["sdk"])
    runtime["_help"] = "Show forwarding runtime state"
    legacy_sdk = copy.deepcopy(show["chassis"]["forwarding"]["sdk"])
    legacy_sdk["_hidden"] = True

    show["diagnostics"] = {
        "_help": "Show diagnostic forwarding state",
        "forwarding": {
            "_help": "Forwarding-plane diagnostics",
            "resources": copy.deepcopy(show["chassis"]["forwarding"]["resources"]),
            "config": copy.deepcopy(show["chassis"]["forwarding"]["config"]),
            "runtime": runtime,
            "sdk": legacy_sdk,
        },
        "l3": {
            "_help": "Layer 3 diagnostics",
            "state": copy.deepcopy(show["route"]["state"]),
            "interfaces": copy.deepcopy(show["route"]["interfaces"]),
            "next-hop": copy.deepcopy(show["route"]["next-hop"]),
            "ecmp": copy.deepcopy(show["route"]["ecmp"]),
            "resources": copy.deepcopy(show["route"]["resources"]),
            "shadow": copy.deepcopy(show["route"]["shadow"]),
        },
        "ethernet-switching": {
            "_help": "Ethernet-switching ACL diagnostics",
            "acl": copy.deepcopy(show["ethernet-switching"]["acl"]),
            "acl-capabilities": copy.deepcopy(
                show["ethernet-switching"]["acl-capabilities"]),
            "user-filter": copy.deepcopy(show["ethernet-switching"]["user-filter"]),
            "ingress-acl": copy.deepcopy(show["ethernet-switching"]["ingress-acl"]),
            "ingress-ipv4-acl": copy.deepcopy(
                show["ethernet-switching"]["ingress-ipv4-acl"]),
            "acl-policer": copy.deepcopy(show["ethernet-switching"]["acl-policer"]),
            "egress-acl": copy.deepcopy(show["ethernet-switching"]["egress-acl"]),
        },
        "class-of-service": {
            "_help": "Class-of-service diagnostics",
            "capabilities": copy.deepcopy(show["class-of-service"]["capabilities"]),
            "queues": copy.deepcopy(show["class-of-service"]["queues"]),
            "watermarks": copy.deepcopy(show["class-of-service"]["watermarks"]),
            "ets": copy.deepcopy(show["class-of-service"]["ets"]),
        },
    }

    for path in (
            ("show", "chassis", "forwarding", "config"),
            ("show", "chassis", "forwarding", "sdk"),
            ("show", "route", "state"),
            ("show", "route", "next-hop"),
            ("show", "route", "ecmp"),
            ("show", "route", "resources"),
            ("show", "route", "shadow"),
            ("show", "ethernet-switching", "acl-capabilities"),
            ("show", "ethernet-switching", "user-filter"),
            ("show", "ethernet-switching", "ingress-acl"),
            ("show", "ethernet-switching", "ingress-ipv4-acl"),
            ("show", "ethernet-switching", "acl-policer"),
            ("show", "ethernet-switching", "egress-acl"),
            ("show", "class-of-service", "queues"),
            ("show", "class-of-service", "watermarks"),
            ("show", "class-of-service", "ets"),
    ):
        _mark_hidden(OP_SCHEMA, path)

    for root in ("set", "delete"):
        for path in (
                (root, "ethernet-switching-options", "user-filter"),
                (root, "ethernet-switching-options", "ingress-acl"),
                (root, "ethernet-switching-options", "ingress-ipv4-acl"),
                (root, "ethernet-switching-options", "acl-policer"),
                (root, "ethernet-switching-options", "egress-acl"),
                (root, "class-of-service", "scheduler"),
                (root, "class-of-service", "ets"),
                (root, "class-of-service", "watermarks"),
                (root, "routing-options", "static", "arp"),
                (root, "routing-options", "static", "next-hop"),
                (root, "routing-options", "static", "ecmp"),
                (root, "routing-options", "static", "route", "<ipv4-prefix>",
                 "ecmp"),
        ):
            _mark_hidden(CFG_SCHEMA, path)

    for root in ("set", "delete"):
        esw = CFG_SCHEMA.get(root, {}).get("ethernet-switching-options")
        if not isinstance(esw, dict):
            continue
        acl = esw.get("acl")
        if isinstance(acl, dict) and isinstance(
                acl.get("independent-group"), dict):
            esw["acl"] = {
                "_help": acl.get("_help", "General ACL compiler"),
                "independent-group": acl["independent-group"],
            }
        for owner in ("user-filter", "ingress-acl", "ingress-ipv4-acl",
                      "acl-policer", "egress-acl"):
            if owner in esw:
                help_text = esw[owner].get("_help", "") if isinstance(esw[owner], dict) else ""
                esw[owner] = {"_help": help_text, "_hidden": True}

    set_schema = CFG_SCHEMA.get("set", {})
    if not public_capability_enabled(GENERAL_ACL_INDEPENDENT):
        esw = set_schema.get("ethernet-switching-options", {})
        if isinstance(esw, dict) and "acl" in esw:
            esw["acl"] = {
                "_help": "Independent General ACL (promotion closed)",
                "_hidden": True,
            }
    if not public_capability_enabled(MANAGEMENT_SERVICES):
        system = set_schema.get("system", {})
        if isinstance(system, dict) and "services" in system:
            system["services"] = {
                "_help": "Management services (runtime owner unavailable)",
                "_hidden": True,
            }
        if "snmp" in set_schema:
            set_schema["snmp"] = {
                "_help": "SNMP service (runtime owner unavailable)",
                "_hidden": True,
            }

    set_igmp = (CFG_SCHEMA.get("set", {}).get("protocols", {})
                .get("igmp-snooping", {}).get("vlan", {})
                .get("<vlan-name>", {}).get("interface", {})
                .get("<interface-name>", {}).get("static-group"))
    delete_igmp = (CFG_SCHEMA.get("delete", {}).get("protocols", {})
                   .get("igmp-snooping", {}).get("vlan", {})
                   .get("<vlan-name>", {}).get("interface", {})
                   .get("<interface-name>", {}).get("static-group"))
    if isinstance(set_igmp, dict) and isinstance(delete_igmp, dict):
        value = set_igmp.get("<ipv4-multicast-address>")
        if isinstance(value, dict):
            delete_igmp["<ipv4-multicast-address>"] = copy.deepcopy(value)


_install_public_namespace_cleanup()
