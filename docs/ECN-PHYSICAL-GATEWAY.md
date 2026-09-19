# 外部 Linux ECN 节点实验

该工具在两个隔离网段之间建立临时 Linux 软件转发路径，对选定 RoCE 流量使用 RED 标记。标记来自外部节点，FM10840 本机拥塞 ECN 仍不支持。

## 准备与运行

先准备两个独立、空闲且无业务 IP/路由的 Linux 网口，并将端点流量明确接入两个不同二层网段。工具检查默认队列状态，再把网口移入本次创建的命名空间。下面使用虚构网口名及基准测试地址，运行前必须替换为实际隔离环境：

```sh
sudo python3 scripts/roce_ecn_gateway.py   --ingress test-in --egress test-out   --source 198.18.0.2 --destination 198.18.0.1   --rate-mbit 100 --lifetime 180 --evidence /tmp/roce-ecn-gateway
```

只有指定 IPv4 地址对、UDP/4791、DSCP26 的流量进入 HTB+RED；CNP DSCP48 和其他流量使用旁路。实验阈值用于短时制造拥塞，不是线速网络配置建议。工具不修改交换机配置、RDMA QP 或报文载荷，也不以副本报文代替原始传输。

## 抓包与结论边界

入口抓包位于物理口，出口抓包位于 RED veth 的另一端 RX。`ready.json` 给出本次命名空间和抓包点；`scripts/verify_roce_ecn_capture.py` 检查两侧唯一 QP/PSN、IPv4/UDP 校验和、ECT→CE 及其他报文字节保持，并核对 CNP 地址、opcode、目标 QP 和 DSCP。

校验器比较 ICRC 字节而不重新计算 ICRC。端点真实传输完成、网卡错误、PFC、重试及吞吐必须另外记录；相同整形速率下的 CNP 返回/阻断对照才有助于判断反馈作用。软件队列吞吐不能推导 ASIC 或网卡线速能力。

## 恢复

默认运行 180 秒，可选 10–600 秒；正常到期、停止文件、SIGINT、SIGTERM 和失败均尝试归还网口。恢复失败时保留命名空间和恢复元数据。SIGKILL 或掉电无法保证清理，需依据本次状态文件核对对象后恢复，不能删除不属于该次运行的网络配置。

日志与抓包保存在操作者指定的位置，发布前需要独立脱敏。无需物理网口的实验见 [隔离软件通道](ECN-MARKING.md)。
