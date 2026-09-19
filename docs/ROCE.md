# RoCEv2、PFC 与 DCBX

面向外接 RoCEv2 网卡的单板、无环二层网络，支持 10/25/40/100G 端口配置。各端点应独立配置 VLAN、MTU、优先级及 PFC；端口 Up 或配置回读成功不等于流量、拥塞或无损验收通过。

## 配置

- 静态 PFC 使用优先级 3、TC3 和独立 SMP1 缓冲；PCP 与 DSCP 分类择一使用。
- DSCP 模式将数据 DSCP 映射到 TC3；CNP DSCP 独立映射到优先级 6 / TC7，使用严格优先且不启用 PFC。数据和 CNP DSCP 必须不同。
- 支持混合 Access / Trunk 业务 VLAN，变更通过统一候选配置、差异预览、提交、确认或回滚生效。
- IEEE DCBX 以 non-willing 模式通告本机固定策略，检查 ETS/PFC/APP 差异及邻居有效期，不自动接受邻居覆盖配置。
- PFC watchdog 默认关闭；启用前了解其恢复丢包和漏检边界，见 [watchdog](PFC-WATCHDOG.md)。

速率、MTU、优先级或 PFC 变更可能重算全芯片缓冲，不能只按一个端口看待变更范围。配置模型拒绝不支持的成员关系和资源组合。RoCE over LAG、FM10840 本机拥塞 ECN、PFC+ECN 和 ECN-only 均不开放。

## 诊断与验收

诊断提供配置匹配、缓冲就绪、队列占用、PFC/Pause、拥塞丢弃、端口错误、暂停剩余时间及 DCBX 状态。无效或过期计数保留不可用状态；服务进程中的观测历史不是持久硬件验收证据。

页面和 API 不附带其他设备的历史测试结果。`traffic_validation` 保持独立于配置状态，当前部署应使用 [验收方法](HARDWARE_ACCEPTANCE.md) 验证报文分类、双向传输、背压、普通业务隔离及恢复。

`scripts/verify_roce_board.py` 和 `scripts/verify_rdma_extensions.py` 检查板卡配置与恢复，不产生 RDMA 流量。`scripts/verify_rdma_peers.py` 在显式指定的两个端点执行 perftest 矩阵；传输成功仍不能单独证明拥塞无损。

外部 Linux ECN 节点见 [软件实验](ECN-MARKING.md)与[物理路径实验](ECN-PHYSICAL-GATEWAY.md)。它们改变测试流量的路径，不赋予 ASIC 本机 ECN 能力。

部署与回退流程见 [部署说明](DEPLOYMENT.md)，页面和数据格式见 [RoCE 页面](ROCE-UI.md)。
