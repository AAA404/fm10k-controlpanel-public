# NetLab platform profile for the FM10840 / rubyRapid auto 6x40G100G platform.
#
# Source facts are derived from the local Intel IES RDI platform file:
#   platformName=rubyRapid
#   numSwitches=1
#   switch.0.uioDevName=/dev/uio0
#   switch.0.switchNumber=0
#   switch.0.numPorts=10
#   switch.0.cpuPort=9
#   switch.0.bootCfg.mgmtPep=4
#
# Exposed user ports:
#   portIndex 1..6 map to logical ports 1..6 and QSFP EPL 0,1,2,5,6,7.
#
# Hidden/control paths:
#   portIndex 7 LOG=7 PCIE=0
#   portIndex 8 LOG=8 PCIE=2
#   portIndex 9 LOG=9 PCIE=4 and is the SDK CPU/control port
#   portIndex 0 LOG=0 PCIE=8 is not represented because NetLab profiles require
#   positive SDK logical ports and the RDI marks cpuPort as LOG=9.
#
# Replace system-mac with the board-specific MAC before using more than one
# NetLab switch in the same L2 domain.

platform model=FM10840 chassis-name=RubyRapid-6x40G100G-Auto serial=FM10840-RUBYRAPID-6X40G100G-AUTO system-name=NetLab-FM10840 system-description="NetLab FM10840 rubyRapid auto 6x40G100G switch" system-mac=02:00:00:10:84:00 max-ae=8 rstp-bridge-priority=32768 rstp-hello-sec=2 rstp-bpdu-stale-sec=180 lacp-system-priority=32768 lacp-port-priority=32768 lacp-ttl-sec=90

board model=PE31625G24DiRA-MPS asic=FM10840 fci-count=2 i2c-bus=0 mux-address=0x58 cpld-ram-address=0x59 reset-gpio-address=0x64 fci0-mux=0x01 fci1-mux=0x02 environment-mux=0x04 power-mux=0x08 shared-memory-bytes=4194304 tcam-entries=32768 mac-nexthop-entries=16384

switch index=0 number=0 uio-dev=/dev/uio0 cpu-port=9 management-pep=4

# This FM10840 profile keeps the current NetLab L2/security feature mix:
# route slices disabled and ACL/flow TCAM reserved for control-plane
# protection, DHCP snooping, DAI bindings, and future L2 safety features.
# L3-capable FM10840 deployments should use a separate profile with route/ACL
# boundaries sized for that feature mix.
ffu ipv4-uc-first=-1 ipv4-uc-last=-1 ipv4-mc-first=-1 ipv4-mc-last=-1 ipv6-uc-first=-1 ipv6-uc-last=-1 ipv6-mc-first=-1 ipv6-mc-last=-1 acl-first=0 acl-last=31 cvlan-first=-1 cvlan-last=-1 bst-routing-first=-1 bst-routing-last=-1

xcvr resource-id=0 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=1 state-gpio-index=0 state-gpio-base=0
xcvr resource-id=1 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=1 state-gpio-index=0 state-gpio-base=0
xcvr resource-id=2 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=1 state-gpio-index=0 state-gpio-base=0
xcvr resource-id=3 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=2 state-gpio-index=0 state-gpio-base=1
xcvr resource-id=4 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=2 state-gpio-index=0 state-gpio-base=1
xcvr resource-id=5 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=2 state-gpio-index=0 state-gpio-base=1

# This auto 6x40G100G profile uses the corrected split configuration where user-facing
# line/default speed and SDK scheduler speed are all 100G.
port name=et-0/0/0 interface-id=1001 media=et fpc=0 pic=0 port=0 switch-index=0 port-index=1 logical-port=1 front-panel-port=1 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,40G,100G hw-resource-id=0 epl-port=0 lane=0 default-speed=100000000000 line-rate=100000000000 scheduler-speed=100000000000 supported-speeds=40000000000,100000000000 rstp-cost=1 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/1 interface-id=1002 media=et fpc=0 pic=0 port=1 switch-index=0 port-index=2 logical-port=2 front-panel-port=2 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,40G,100G hw-resource-id=1 epl-port=1 lane=0 default-speed=100000000000 line-rate=100000000000 scheduler-speed=100000000000 supported-speeds=40000000000,100000000000 rstp-cost=1 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/2 interface-id=1003 media=et fpc=0 pic=0 port=2 switch-index=0 port-index=3 logical-port=3 front-panel-port=3 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,40G,100G hw-resource-id=2 epl-port=2 lane=0 default-speed=100000000000 line-rate=100000000000 scheduler-speed=100000000000 supported-speeds=40000000000,100000000000 rstp-cost=1 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/3 interface-id=1004 media=et fpc=0 pic=0 port=3 switch-index=0 port-index=4 logical-port=4 front-panel-port=4 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,40G,100G hw-resource-id=3 epl-port=5 lane=0 default-speed=100000000000 line-rate=100000000000 scheduler-speed=100000000000 supported-speeds=40000000000,100000000000 rstp-cost=1 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/4 interface-id=1005 media=et fpc=0 pic=0 port=4 switch-index=0 port-index=5 logical-port=5 front-panel-port=5 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,40G,100G hw-resource-id=4 epl-port=6 lane=0 default-speed=100000000000 line-rate=100000000000 scheduler-speed=100000000000 supported-speeds=40000000000,100000000000 rstp-cost=1 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/5 interface-id=1006 media=et fpc=0 pic=0 port=5 switch-index=0 port-index=6 logical-port=6 front-panel-port=6 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,40G,100G hw-resource-id=5 epl-port=7 lane=0 default-speed=100000000000 line-rate=100000000000 scheduler-speed=100000000000 supported-speeds=40000000000,100000000000 rstp-cost=1 flags=external,trunk,lldp-default,rstp,lacp

port name=pcie0 interface-id=2007 media=et fpc=0 pic=0 port=6 switch-index=0 port-index=7 logical-port=7 front-panel-port=7 role=internal pcie-port=0 default-speed=0 line-rate=0 scheduler-speed=0 flags=hidden
port name=pcie2 interface-id=2008 media=et fpc=0 pic=0 port=7 switch-index=0 port-index=8 logical-port=8 front-panel-port=8 role=internal pcie-port=2 default-speed=0 line-rate=0 scheduler-speed=0 flags=hidden
port name=cpu0 interface-id=2009 media=et fpc=0 pic=0 port=8 switch-index=0 port-index=9 logical-port=9 front-panel-port=9 role=cpu-control pcie-port=4 default-speed=10000000000 line-rate=10000000000 scheduler-speed=10000000000 supported-speeds=10000000000 flags=hidden,cpu-control

lane ifname=et-0/0/0 switch-index=0 port-index=1 logical-port=1 index=0 epl=0 sdk-lane=0 polarity=INVERT_NONE
lane ifname=et-0/0/0 switch-index=0 port-index=1 logical-port=1 index=1 epl=0 sdk-lane=1 polarity=INVERT_NONE
lane ifname=et-0/0/0 switch-index=0 port-index=1 logical-port=1 index=2 epl=0 sdk-lane=2 polarity=INVERT_NONE
lane ifname=et-0/0/0 switch-index=0 port-index=1 logical-port=1 index=3 epl=0 sdk-lane=3 polarity=INVERT_NONE
lane ifname=et-0/0/1 switch-index=0 port-index=2 logical-port=2 index=0 epl=1 sdk-lane=0 polarity=INVERT_NONE
lane ifname=et-0/0/1 switch-index=0 port-index=2 logical-port=2 index=1 epl=1 sdk-lane=1 polarity=INVERT_NONE
lane ifname=et-0/0/1 switch-index=0 port-index=2 logical-port=2 index=2 epl=1 sdk-lane=2 polarity=INVERT_NONE
lane ifname=et-0/0/1 switch-index=0 port-index=2 logical-port=2 index=3 epl=1 sdk-lane=3 polarity=INVERT_NONE
lane ifname=et-0/0/2 switch-index=0 port-index=3 logical-port=3 index=0 epl=2 sdk-lane=0 polarity=INVERT_NONE
lane ifname=et-0/0/2 switch-index=0 port-index=3 logical-port=3 index=1 epl=2 sdk-lane=1 polarity=INVERT_NONE
lane ifname=et-0/0/2 switch-index=0 port-index=3 logical-port=3 index=2 epl=2 sdk-lane=2 polarity=INVERT_NONE
lane ifname=et-0/0/2 switch-index=0 port-index=3 logical-port=3 index=3 epl=2 sdk-lane=3 polarity=INVERT_NONE
lane ifname=et-0/0/3 switch-index=0 port-index=4 logical-port=4 index=0 epl=5 sdk-lane=0 polarity=INVERT_NONE
lane ifname=et-0/0/3 switch-index=0 port-index=4 logical-port=4 index=1 epl=5 sdk-lane=1 polarity=INVERT_NONE
lane ifname=et-0/0/3 switch-index=0 port-index=4 logical-port=4 index=2 epl=5 sdk-lane=2 polarity=INVERT_NONE
lane ifname=et-0/0/3 switch-index=0 port-index=4 logical-port=4 index=3 epl=5 sdk-lane=3 polarity=INVERT_NONE
lane ifname=et-0/0/4 switch-index=0 port-index=5 logical-port=5 index=0 epl=6 sdk-lane=0 polarity=INVERT_NONE
lane ifname=et-0/0/4 switch-index=0 port-index=5 logical-port=5 index=1 epl=6 sdk-lane=1 polarity=INVERT_NONE
lane ifname=et-0/0/4 switch-index=0 port-index=5 logical-port=5 index=2 epl=6 sdk-lane=2 polarity=INVERT_NONE
lane ifname=et-0/0/4 switch-index=0 port-index=5 logical-port=5 index=3 epl=6 sdk-lane=3 polarity=INVERT_NONE
lane ifname=et-0/0/5 switch-index=0 port-index=6 logical-port=6 index=0 epl=7 sdk-lane=0 polarity=INVERT_NONE
lane ifname=et-0/0/5 switch-index=0 port-index=6 logical-port=6 index=1 epl=7 sdk-lane=1 polarity=INVERT_NONE
lane ifname=et-0/0/5 switch-index=0 port-index=6 logical-port=6 index=2 epl=7 sdk-lane=2 polarity=INVERT_NONE
lane ifname=et-0/0/5 switch-index=0 port-index=6 logical-port=6 index=3 epl=7 sdk-lane=3 polarity=INVERT_NONE
