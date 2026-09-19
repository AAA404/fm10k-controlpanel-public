# NetLab platform profile for the current FM10420 lab adapter.
#
# This file is the runtime data authority for interface naming, switch/port
# mapping, port roles, default protocol enablement, lane/QSFP mapping, and
# system identity.  To run a different SKU such as FM10840 24x25G, 6x100G, or
# 12x25G+3x100G, point NETLAB_PLATFORM_PROFILE at a different profile with the
# same record format.

platform model=FM10420 chassis-name=PE3100G2DQIR serial=FM10420-PE3100G2DQIR system-name=NetLab-FM10420 system-description="NetLab FM10420 switch" system-mac=00:e0:ed:39:90:f9 max-ae=8 rstp-bridge-priority=32768 rstp-hello-sec=2 rstp-bpdu-stale-sec=180 lacp-system-priority=32768 lacp-port-priority=32768 lacp-ttl-sec=90

switch index=0 number=0 uio-dev=/dev/uio0 cpu-port=4 management-pep=2

# The current FM10420 build is an L2/security-focused profile.  Route slices
# are disabled so ACL/flow TCAM has enough width for control-plane protection,
# DHCP snooping, DAI bindings, and future L2 safety features.  L3-capable SKUs
# should use a profile with route/ACL boundaries sized for their feature mix.
ffu ipv4-uc-first=-1 ipv4-uc-last=-1 ipv4-mc-first=-1 ipv4-mc-last=-1 ipv6-uc-first=-1 ipv6-uc-last=-1 ipv6-mc-first=-1 ipv6-mc-last=-1 acl-first=0 acl-last=31 cvlan-first=-1 cvlan-last=-1 bst-routing-first=-1 bst-routing-last=-1

xcvr resource-id=0 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=2 state-gpio-index=0 state-gpio-base=0
xcvr resource-id=1 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=4 state-gpio-index=0 state-gpio-base=8

port name=et-0/0/0 interface-id=1001 media=et fpc=0 pic=0 port=0 switch-index=0 port-index=1 logical-port=1 front-panel-port=1 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,10G,40G,100G,SW_LED hw-resource-id=0 epl-port=1 lane=0 default-speed=100000000000 line-rate=100000000000 scheduler-speed=100000000000 supported-speeds=100000000000 rstp-cost=1 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/1 interface-id=1002 media=et fpc=0 pic=0 port=1 switch-index=0 port-index=2 logical-port=2 front-panel-port=2 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,10G,40G,100G,SW_LED hw-resource-id=1 epl-port=6 lane=0 default-speed=100000000000 line-rate=100000000000 scheduler-speed=100000000000 supported-speeds=100000000000 rstp-cost=1 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/2 interface-id=1003 media=et fpc=0 pic=0 port=2 switch-index=0 port-index=3 logical-port=3 front-panel-port=3 role=internal pcie-port=0 default-speed=100000000000 line-rate=100000000000 scheduler-speed=100000000000 supported-speeds=100000000000 rstp-cost=1 flags=

# RDI maps portIndex.4 to LOG=4 PCIE=2 and cpuPort=4.  It is the SDK
# CPU/control port, not a user-configurable Ethernet interface, so NetLab keeps
# it only in the switch cpu-port field and intentionally does not expose an
# et-0/0/3 interface for it.

lane ifname=et-0/0/0 switch-index=0 port-index=1 logical-port=1 index=0 epl=1 sdk-lane=0 polarity=INVERT_NONE
lane ifname=et-0/0/0 switch-index=0 port-index=1 logical-port=1 index=1 epl=1 sdk-lane=1 polarity=INVERT_NONE
lane ifname=et-0/0/0 switch-index=0 port-index=1 logical-port=1 index=2 epl=1 sdk-lane=2 polarity=INVERT_NONE
lane ifname=et-0/0/0 switch-index=0 port-index=1 logical-port=1 index=3 epl=1 sdk-lane=3 polarity=INVERT_NONE
lane ifname=et-0/0/1 switch-index=0 port-index=2 logical-port=2 index=0 epl=6 sdk-lane=0 polarity=INVERT_NONE
lane ifname=et-0/0/1 switch-index=0 port-index=2 logical-port=2 index=1 epl=6 sdk-lane=1 polarity=INVERT_NONE
lane ifname=et-0/0/1 switch-index=0 port-index=2 logical-port=2 index=2 epl=6 sdk-lane=2 polarity=INVERT_NONE
lane ifname=et-0/0/1 switch-index=0 port-index=2 logical-port=2 index=3 epl=6 sdk-lane=3 polarity=INVERT_NONE
