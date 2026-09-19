# Implemented Features / 已实现功能

Statuses are evidence-oriented:

- **Stable / 稳定** — complete source owner and routine contract coverage.
- **Bounded / 有限开放** — implemented for an explicit subset or capacity.
- **Experimental / 实验性** — source path exists but production qualification
  or a complete service boundary is missing.
- **Closed / 关闭** — rejected by the public capability boundary.

| Domain / 领域 | Status / 状态 | Implemented / 已实现 | Important boundary / 主要边界 |
| --- | --- | --- | --- |
| Configuration | Stable | YANG candidate/active, compare, commit check, commit confirmed, rollback, journal recovery, replay | No northbound NETCONF/RESTCONF/gNMI service |
| Interface/L2 | Stable | access/trunk/native VLAN, PVID, static/dynamic FDB, counters | Single-card FM10000 target |
| LAG and discovery | Stable | LAG/LACP and LLDP state/configuration | No MLAG or EVPN multihoming |
| Spanning tree | Stable | RSTP and MSTP, per-VLAN hardware STP state | PVST/Rapid-PVST closed |
| Multicast L2 | Bounded | IPv4 IGMP snooping, static/dynamic membership, aging and replication ownership | No MLD or L3 multicast routing |
| L2 security | Bounded | storm control, ingress/egress rate limit, secure access port, MAC move dampening, DHCP snooping, ARP inspection | Capacity and selector set are FM10000-specific |
| ACL | Bounded | scoped L2/IPv4 ingress, scoped egress MAC filter, counters, narrow policer | Independent/general egress and broad actions closed |
| QoS | Bounded | priority trust/map, static PFC, scheduler groups, strict/DRR, shaping, selected watermarks | No complete queue/drop profile, WRED, ECN marking or DCBX |
| IPv4 L3 | Bounded | RIF, static ARP/routes, ECMP, RIB/FIB generations, rollback/replay, one static VRF | IPv4 unicast only; finite profile capacities |
| OSPF/BGP | Experimental | FRR lifecycle, RIB/FPM decode, dynamic FIB programming path | Long-duration production promotion incomplete |
| SPAN | Bounded | one local physical-port session with direction and read-back | No multi-session, VLAN/LAG source or remote encapsulation |
| sFlow | Experimental | hidden sampler/read-back owner and bounded capture ring | No public collector/exporter service |
| Observability | Bounded | interfaces, FDB, STP/LACP/LLDP, routes, ACL/QoS, ASIC resources, events, counters and chassis views | No full streaming telemetry/SNMP agent |
| Platform | Bounded | fixed FM10840 profiles, port-mode transaction source, PE31625G24DIRA optics mux model | Port-mode mutation requires a deployment lifecycle runtime; dynamic auto-detect/hot mode is not productized |
| IPv6, VXLAN, EVPN, NAT, MLAG | Closed | — | Outside current IPv4 single-card leaf scope |

## What “implemented” means / “已实现”的含义

A feature is not marked stable merely because the SDK exposes an API. NetLab
expects a configuration owner, bounded plan, SDK write, hardware read-back,
failure rollback, restart replay, operational CLI and tests. Missing links move
the feature to bounded, experimental or closed.

不能因为 SDK 有某个 API 就宣称功能完成。NetLab 要求配置 owner、有界 plan、SDK
写入、硬件读回、失败回滚、重启 replay、operational CLI 和测试形成闭环；缺少
任何关键环节都会降级为有限开放、实验性或关闭。
