# CLI Demo / CLI 示例

The CLI follows a candidate/active workflow. These examples use documentation
addresses and symbolic ports. Commands are real NetLab syntax; output values
depend on the attached hardware and running daemons.

CLI 使用 candidate/active 工作流。示例采用文档保留地址与符号端口；命令是
真实 NetLab 语法，输出值取决于硬件和运行中的 daemon。

## Inspect the switch / 查看交换机

```text
user@netlab> show chassis hardware
user@netlab> show interfaces terse
user@netlab> show interfaces extensive
user@netlab> show vlans
user@netlab> show ethernet-switching table
user@netlab> show spanning-tree bridge
user@netlab> show lacp interfaces
user@netlab> show route summary
user@netlab> show route forwarding-table
```

## Create an L2 trunk / 创建 L2 trunk

```text
user@netlab> configure
[edit]
user@netlab# set vlans blue vlan-id 100
user@netlab# set interfaces et-0/0/0 unit 0 family ethernet-switching interface-mode trunk
user@netlab# set interfaces et-0/0/0 unit 0 family ethernet-switching vlan members blue
user@netlab# show | compare
user@netlab# commit check
user@netlab# commit comment "add blue trunk"
```

Verification / 验证：

```text
user@netlab> show vlans
user@netlab> show interfaces terse
user@netlab> show ethernet-switching table
```

## Configure IPv4 / 配置 IPv4

IPv4 features require an L3-capable platform profile.

```text
[edit]
user@netlab# set interfaces irb unit 100 family inet address 192.0.2.1/24
user@netlab# set routing-options static route 198.51.100.0/24 next-hop 192.0.2.2
user@netlab# commit check
user@netlab# commit confirmed 5 comment "remote L3 change"
```

```text
user@netlab> show arp
user@netlab> show route
user@netlab> show route protocol static
user@netlab> show route forwarding-table
```

## Safe change and rollback / 安全变更与回滚

`commit confirmed` automatically restores the previous configuration unless a
later `commit` confirms the change.

`commit confirmed` 会在超时后自动恢复旧配置，除非后续执行 `commit` 确认。

```text
[edit]
user@netlab# commit confirmed 5 comment "verify before confirm"
user@netlab# run show system commit confirmed
user@netlab# commit

# Or inspect and restore history / 或查看并恢复历史
user@netlab# rollback 1
user@netlab# show | compare
user@netlab# commit check
user@netlab# commit
```

## Capability guardrails / 能力边界

The CLI may contain schema vocabulary for work that is deliberately closed.
The visible completion surface and `configd` capability authority reject such
intent before hardware mutation. Examples currently closed include management
services without runtime owners, IPv6 routing, VXLAN/EVPN, NAT and MLAG.

CLI schema 可能包含规划中的词汇；可见补全和 `configd` capability authority 会
在硬件写入前拒绝未开放能力。目前关闭的范围包括缺少 runtime owner 的管理服务、
IPv6 路由、VXLAN/EVPN、NAT 和 MLAG。
