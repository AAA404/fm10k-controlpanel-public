# NetLab platform profile for FM10840 / RubyRapid in auto 12x10G25G+3x40G100G split mode.
#
# This profile must be kept in sync with the active SDK RDI file. The matching
# RDI has 12 auto-detect 10G/25G logical ports, 3 four-lane auto-detect
# 40G/100G logical ports, two disabled PCIe scheduler paths, and LOG 18 as the
# CPU/control port.

platform model=FM10840 chassis-name=RubyRapid-12x10G25G-3x40G100G-Auto serial=FM10840-RUBYRAPID-MIXED-AUTO system-name=NetLab-FM10840 system-description="NetLab FM10840 rubyRapid auto 12x10G25G plus 3x40G100G switch" system-mac=02:00:00:10:84:00 max-ae=8 rstp-bridge-priority=32768 rstp-hello-sec=2 rstp-bpdu-stale-sec=180 lacp-system-priority=32768 lacp-port-priority=32768 lacp-ttl-sec=90

board model=PE31625G24DiRA-MPS asic=FM10840 fci-count=2 i2c-bus=0 mux-address=0x58 cpld-ram-address=0x59 reset-gpio-address=0x64 fci0-mux=0x01 fci1-mux=0x02 environment-mux=0x04 power-mux=0x08 shared-memory-bytes=4194304 tcam-entries=32768 mac-nexthop-entries=16384

switch index=0 number=0 uio-dev=/dev/uio0 cpu-port=18 management-pep=4

# L2-only FFU profile: route lookup slices are intentionally disabled.
# ACL/filter slices stay reserved for control-plane protection and L2 safety
# features. Use a separate L3 profile when routed switching is introduced.
ffu ipv4-uc-first=-1 ipv4-uc-last=-1 ipv4-mc-first=-1 ipv4-mc-last=-1 ipv6-uc-first=-1 ipv6-uc-last=-1 ipv6-mc-first=-1 ipv6-mc-last=-1 acl-first=0 acl-last=31 cvlan-first=-1 cvlan-last=-1 bst-routing-first=-1 bst-routing-last=-1

xcvr resource-id=0 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=1 state-gpio-index=0 state-gpio-base=0
xcvr resource-id=1 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=1 state-gpio-index=0 state-gpio-base=0
xcvr resource-id=2 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=1 state-gpio-index=0 state-gpio-base=0
xcvr resource-id=3 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=2 state-gpio-index=0 state-gpio-base=1
xcvr resource-id=4 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=2 state-gpio-index=0 state-gpio-base=1
xcvr resource-id=5 type=QSFP i2c-bus=switchI2C mux-index=0 mux-value=2 state-gpio-index=0 state-gpio-base=1

port name=et-0/0/0 interface-id=1001 media=et fpc=0 pic=0 port=0 switch-index=0 port-index=1 logical-port=1 front-panel-port=1 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,10G,25G hw-resource-id=0 epl-port=0 lane=0 default-speed=25000000000 line-rate=25000000000 scheduler-speed=25000000000 supported-speeds=10000000000,25000000000 rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/1 interface-id=1002 media=et fpc=0 pic=0 port=1 switch-index=0 port-index=2 logical-port=2 front-panel-port=2 role=external interface-type=QSFP_LANE1 ethernet-mode=AUTODETECT capabilities=LAG,10G,25G hw-resource-id=0 epl-port=0 lane=1 default-speed=25000000000 line-rate=25000000000 scheduler-speed=25000000000 supported-speeds=10000000000,25000000000 rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/2 interface-id=1003 media=et fpc=0 pic=0 port=2 switch-index=0 port-index=3 logical-port=3 front-panel-port=3 role=external interface-type=QSFP_LANE2 ethernet-mode=AUTODETECT capabilities=LAG,10G,25G hw-resource-id=0 epl-port=0 lane=2 default-speed=25000000000 line-rate=25000000000 scheduler-speed=25000000000 supported-speeds=10000000000,25000000000 rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/3 interface-id=1004 media=et fpc=0 pic=0 port=3 switch-index=0 port-index=4 logical-port=4 front-panel-port=4 role=external interface-type=QSFP_LANE3 ethernet-mode=AUTODETECT capabilities=LAG,10G,25G hw-resource-id=0 epl-port=0 lane=3 default-speed=25000000000 line-rate=25000000000 scheduler-speed=25000000000 supported-speeds=10000000000,25000000000 rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/4 interface-id=1005 media=et fpc=0 pic=0 port=4 switch-index=0 port-index=5 logical-port=5 front-panel-port=5 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,10G,25G hw-resource-id=1 epl-port=1 lane=0 default-speed=25000000000 line-rate=25000000000 scheduler-speed=25000000000 supported-speeds=10000000000,25000000000 rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/5 interface-id=1006 media=et fpc=0 pic=0 port=5 switch-index=0 port-index=6 logical-port=6 front-panel-port=6 role=external interface-type=QSFP_LANE1 ethernet-mode=AUTODETECT capabilities=LAG,10G,25G hw-resource-id=1 epl-port=1 lane=1 default-speed=25000000000 line-rate=25000000000 scheduler-speed=25000000000 supported-speeds=10000000000,25000000000 rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/6 interface-id=1007 media=et fpc=0 pic=0 port=6 switch-index=0 port-index=7 logical-port=7 front-panel-port=7 role=external interface-type=QSFP_LANE2 ethernet-mode=AUTODETECT capabilities=LAG,10G,25G hw-resource-id=1 epl-port=1 lane=2 default-speed=25000000000 line-rate=25000000000 scheduler-speed=25000000000 supported-speeds=10000000000,25000000000 rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/7 interface-id=1008 media=et fpc=0 pic=0 port=7 switch-index=0 port-index=8 logical-port=8 front-panel-port=8 role=external interface-type=QSFP_LANE3 ethernet-mode=AUTODETECT capabilities=LAG,10G,25G hw-resource-id=1 epl-port=1 lane=3 default-speed=25000000000 line-rate=25000000000 scheduler-speed=25000000000 supported-speeds=10000000000,25000000000 rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/8 interface-id=1009 media=et fpc=0 pic=0 port=8 switch-index=0 port-index=9 logical-port=9 front-panel-port=9 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,10G,25G hw-resource-id=2 epl-port=2 lane=0 default-speed=25000000000 line-rate=25000000000 scheduler-speed=25000000000 supported-speeds=10000000000,25000000000 rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/9 interface-id=1010 media=et fpc=0 pic=0 port=9 switch-index=0 port-index=10 logical-port=10 front-panel-port=10 role=external interface-type=QSFP_LANE1 ethernet-mode=AUTODETECT capabilities=LAG,10G,25G hw-resource-id=2 epl-port=2 lane=1 default-speed=25000000000 line-rate=25000000000 scheduler-speed=25000000000 supported-speeds=10000000000,25000000000 rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/10 interface-id=1011 media=et fpc=0 pic=0 port=10 switch-index=0 port-index=11 logical-port=11 front-panel-port=11 role=external interface-type=QSFP_LANE2 ethernet-mode=AUTODETECT capabilities=LAG,10G,25G hw-resource-id=2 epl-port=2 lane=2 default-speed=25000000000 line-rate=25000000000 scheduler-speed=25000000000 supported-speeds=10000000000,25000000000 rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/11 interface-id=1012 media=et fpc=0 pic=0 port=11 switch-index=0 port-index=12 logical-port=12 front-panel-port=12 role=external interface-type=QSFP_LANE3 ethernet-mode=AUTODETECT capabilities=LAG,10G,25G hw-resource-id=2 epl-port=2 lane=3 default-speed=25000000000 line-rate=25000000000 scheduler-speed=25000000000 supported-speeds=10000000000,25000000000 rstp-cost=4 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/12 interface-id=1013 media=et fpc=0 pic=0 port=12 switch-index=0 port-index=13 logical-port=13 front-panel-port=13 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,40G,100G hw-resource-id=3 epl-port=5 lane=0 default-speed=100000000000 line-rate=100000000000 scheduler-speed=100000000000 supported-speeds=40000000000,100000000000 rstp-cost=1 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/13 interface-id=1014 media=et fpc=0 pic=0 port=13 switch-index=0 port-index=14 logical-port=14 front-panel-port=14 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,40G,100G hw-resource-id=4 epl-port=6 lane=0 default-speed=100000000000 line-rate=100000000000 scheduler-speed=100000000000 supported-speeds=40000000000,100000000000 rstp-cost=1 flags=external,trunk,lldp-default,rstp,lacp
port name=et-0/0/14 interface-id=1015 media=et fpc=0 pic=0 port=14 switch-index=0 port-index=15 logical-port=15 front-panel-port=15 role=external interface-type=QSFP_LANE0 ethernet-mode=AUTODETECT capabilities=LAG,40G,100G hw-resource-id=5 epl-port=7 lane=0 default-speed=100000000000 line-rate=100000000000 scheduler-speed=100000000000 supported-speeds=40000000000,100000000000 rstp-cost=1 flags=external,trunk,lldp-default,rstp,lacp

port name=pcie0 interface-id=2016 media=et fpc=0 pic=0 port=15 switch-index=0 port-index=16 logical-port=16 front-panel-port=16 role=internal pcie-port=0 default-speed=0 line-rate=0 scheduler-speed=0 flags=hidden
port name=pcie2 interface-id=2017 media=et fpc=0 pic=0 port=16 switch-index=0 port-index=17 logical-port=17 front-panel-port=17 role=internal pcie-port=2 default-speed=0 line-rate=0 scheduler-speed=0 flags=hidden
port name=cpu0 interface-id=2018 media=et fpc=0 pic=0 port=17 switch-index=0 port-index=18 logical-port=18 front-panel-port=18 role=cpu-control pcie-port=4 default-speed=10000000000 line-rate=10000000000 scheduler-speed=10000000000 supported-speeds=10000000000 flags=hidden,cpu-control

lane ifname=et-0/0/12 switch-index=0 port-index=13 logical-port=13 index=0 epl=5 sdk-lane=0 polarity=INVERT_NONE
lane ifname=et-0/0/12 switch-index=0 port-index=13 logical-port=13 index=1 epl=5 sdk-lane=1 polarity=INVERT_NONE
lane ifname=et-0/0/12 switch-index=0 port-index=13 logical-port=13 index=2 epl=5 sdk-lane=2 polarity=INVERT_NONE
lane ifname=et-0/0/12 switch-index=0 port-index=13 logical-port=13 index=3 epl=5 sdk-lane=3 polarity=INVERT_NONE
lane ifname=et-0/0/13 switch-index=0 port-index=14 logical-port=14 index=0 epl=6 sdk-lane=0 polarity=INVERT_NONE
lane ifname=et-0/0/13 switch-index=0 port-index=14 logical-port=14 index=1 epl=6 sdk-lane=1 polarity=INVERT_NONE
lane ifname=et-0/0/13 switch-index=0 port-index=14 logical-port=14 index=2 epl=6 sdk-lane=2 polarity=INVERT_NONE
lane ifname=et-0/0/13 switch-index=0 port-index=14 logical-port=14 index=3 epl=6 sdk-lane=3 polarity=INVERT_NONE
lane ifname=et-0/0/14 switch-index=0 port-index=15 logical-port=15 index=0 epl=7 sdk-lane=0 polarity=INVERT_NONE
lane ifname=et-0/0/14 switch-index=0 port-index=15 logical-port=15 index=1 epl=7 sdk-lane=1 polarity=INVERT_NONE
lane ifname=et-0/0/14 switch-index=0 port-index=15 logical-port=15 index=2 epl=7 sdk-lane=2 polarity=INVERT_NONE
lane ifname=et-0/0/14 switch-index=0 port-index=15 logical-port=15 index=3 epl=7 sdk-lane=3 polarity=INVERT_NONE
