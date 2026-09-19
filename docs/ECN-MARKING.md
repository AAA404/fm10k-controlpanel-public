# ECN 标记机制与实验通道

当前提供一个可运行的 **Linux 软件 ECN 实验通道**，用真实的 RED 队列和报文验证 ECN 标记。它独立于交换机 SDK 和产品配置，不经过 FM10840 的物理数据口。FM10840 二层硬件直通的拥塞 CE 标记仍不支持，界面的 PFC+ECN / ECN-only 模式继续不可配置。

需要接入物理网卡时，使用[外部软件标记节点](ECN-PHYSICAL-GATEWAY.md)，并独立验证端点反馈。

## 硬件路径核查

依据 Intel FM10000 数据手册 `333497-002` 和本机 IES 4.3.2 对应实现：

| 环节 | 实际能力 | 对 ECN 的限制 |
|---|---|---|
| FFU `SET_DSCP` | 改写 DSCP 和优先级 | §11.5.3.5 / 表 11-11 的 DSCP 值仅占 5:0，保留字段要求为 0；没有设置 ECN 的动作 |
| MODIFY | 对 IPv4/IPv6 改写 DSCP，并更新 IPv4 校验和 | §5.8.5；不是改写整个 TOS / Traffic Class 字节 |
| CM | 统计队列占用、概率丢弃、生成及响应 PFC | §5.7.10；没有将拥塞状态传递给 CE 改写动作的接口 |
| TE 封装 / NAT | 设置新外层 TOS，改写地址、端口和 TTL | §8.10 的普通内层 TOS 保持；设置外层 TOS不等于标记原始转发包 |
| TE 解封装 | 将被移除的外层 ECN 复制到内层 | §8.11；只能传播已有 ECN，不能决定何时因本机拥塞生成 CE |

SDK 的 DSCP ACL 动作也检查值小于 64。不能将完整 TOS 值传入 DSCP API，不能写保留位尝试打开隐藏功能。`FM_QOS_WRED` 的通用声明和其他芯片的 FCN/VCN 接口不构成本型号的支持证据。

将流量送往 CPU 或外部可编程数据面能够实现软件标记，但需要改变实际转发路径并承担吞吐与延迟代价。当前实验仅建立独立软件路径，未将生产流量重定向到 CPU，也没有将控制口的 Linux qdisc 当成 ASIC 出口队列。

## 可运行实现

入口为 `scripts/verify_ecn_marking.py`，策略和报文证据校验位于 `backend/fm10k_controlpanel/ecn_lab.py`。只依赖 Python 标准库、Linux、iproute2 及 veth、bridge、HTB、RED、flower 内核支持。

```sh
# 只查看策略，无需 root，不改变网络。
python3 scripts/verify_ecn_marking.py describe

# 必须指定一个尚不存在的证据目录。
sudo python3 scripts/verify_ecn_marking.py run --evidence /tmp/fm10840-ecn-lab
```

运行时创建唯一命名的三个网络命名空间：发送端 → 二层桥 → 接收端。所有 veth 都直接创建在这些命名空间内部，发包前等待桥端口的载波与 forwarding 状态就绪。没有 IP 地址、物理网卡、默认路由或交换机配置变更。

软件桥出口的 DSCP 26、UDP/4791 流量进入 1 Mbit/s 的 HTB + RED 队列；RED 的平均队列阈值为 8 KiB / 24 KiB，硬上限为 64 KiB。DSCP 48 的 UDP/4791 流量进入独立的高优先级 FIFO；其他流量使用另一个 FIFO。分类器使用 `0xfc` 掩码匹配 DSCP，保留 ECN，并明确 `skip_hw`。这些参数用于短时制造可重复的软件拥塞，不能直接用作 ASIC 阈值或线速性能配置。

RED 根据它实际管理的队列作标记决定：ECT(0)/ECT(1) 可以转为 CE，Not-ECT 在拥塞时丢弃，已是 CE 的报文保持 CE。队列满时也可能尾丢弃 ECT 报文，所以实验不作无损保证。

## 验收内容与证据

一次运行包含低负载、拥塞和恢复三个阶段。每阶段检查 28 种报文组合，覆盖 IPv4 / IPv6、无 VLAN / PCP3 VLAN 10、四种 ECN 值、CNP DSCP 分类以及不同 UDP 端口和 DSCP 的旁路流量。

- 同时保存发送成功记录、桥入口抓包、接收端抓包；只有实际抓包中的 ECT→CE 转换才算标记证据。使用 TPACKET_V2 在内核抓包钩子处复制报文字节，避免普通 packet socket 的浅拷贝被后续 RED 改写污染入口证据。
- 校验 DSCP、PCP/VLAN、IPv6 flow label、地址、端口和载荷没有被改变；验证 IPv4 头与 UDP 校验和。
- 分别要求 ECT(0)、ECT(1) 在拥塞阶段出现 CE；Not-ECT 不能变成 CE，且必须观察到拥塞丢包；已标记 CE 不能被清除。
- 低负载阶段不允许新 CE 或丢包。恢复阶段记录 RED 平均队列值衰减时的所有过渡报文，随后要求每种数据报文最后两次探测均无新增 CE、无丢失；不重置队列来制造恢复。CNP 分类、不同端口及不同 DSCP 的流量在三个阶段均不得误标记或丢包。
- 同时保存 RED 标记 / 丢弃计数和抓包 socket 丢包计数。空抓包、入口证据缺失、抓包溢出、校验和错误和清理失败都会使运行失败。

结果在 `report.json`，分阶段目录包含 `submitted.pcap`、`ingress.pcap`、`egress.pcap`、`qdiscs.json` 和抓包统计。发送的是带标识符的合成 UDP 报文，不是有效 RDMA 操作或 CNP 报文；实验结果不能证明 DCQCN、网卡响应、交换芯片拥塞标记或 100G 性能。

正常结束、命令失败和 SIGINT/SIGTERM 都会清理本次创建的命名空间，停止本次启动的抓包进程。不会删除原有命名空间。SIGKILL / 掉电无法执行清理；若进程被强制杀死，先检查对应 `report.json` 中的唯一命名空间名称及其中的 `tx/in/out/rx/br0` veth 拓扑，再清理确认属于该次运行的遗留对象。
