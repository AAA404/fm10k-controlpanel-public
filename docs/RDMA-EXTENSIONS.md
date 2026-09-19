# RDMA 分类、对端策略与恢复

RoCE 配置通过同一 `SwitchConfiguration` 和 configd 事务链路完成。分类、队列映射、PFC、DCBX 和 watchdog 是相互关联的配置，修改后应核对实际硬件终态。

## 分类与队列

DSCP 分类表包含 64 项。数据 DSCP 使用 TC3/SMP1；CNP 采用不同 DSCP、优先级 6 与严格优先 TC7，避免随数据队列被 PFC 暂停。配置停用或改变 DSCP 时清除原有分类，不能遗留旧映射。PCP 模式继续支持 VLAN PCP3。

原生控制面保存和恢复分类、调度、暂停源映射、共享缓冲及相关寄存器的前镜像。确认超时、部分写入和服务恢复需要检查所有关联字段，不能只看 Web 表单值。

## IEEE DCBX

本机发布固定 ETS/PFC/APP 策略并声明 non-willing。对端缺失、策略不一致、畸形 TLV、TTL 到期和撤销分别显示，不以 LLDP 邻居存在代替策略匹配。是否由网卡固件自动采纳策略由端点决定，需要单独核实。

## 工具与限制

`scripts/verify_rdma_extensions.py --evidence <新目录>` 检查 DSCP/CNP/DCBX、分类清理、超时回滚、恢复和停用。可显式指定 `--restart-native` 检查服务重启回放；该选项会中断原生交换服务。工具要求所有数据口确认 Down，结束后恢复进入时的配置。

此工具不发包，不测吞吐，也不证明 PFC 报文、端点 DCQCN 或长期稳定性。外部端点验证与拥塞场景见 [硬件验收](HARDWARE_ACCEPTANCE.md)，升级条件见 [部署](DEPLOYMENT.md)。
