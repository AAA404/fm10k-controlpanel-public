# 光模块诊断与二维接收眼图

端口详情中的光模块页签提供 Lane 发射状态、PHY 状态、RX 功率和受限的眼图采集。读数带采样时间、质量和来源；缺失或失败保持为空，不用模拟值或对端读数代替本端测量。

## 读数含义

| 项目 | 含义与限制 |
|---|---|
| TX 使能 | 两个 OBT 的 12-bit 控制掩码；不表示实际光输出或 TX 功率 |
| RX 功率 | 通过身份、能力及页面校验后的 CXP RX 数据，以 µW / dBm 显示；零值与未就绪分别处理 |
| TX/RX ready、Activity、DFE | 电气侧状态及均衡信息，不能据此认定 Ethernet Link 或光纤质量 |
| PCS、CRC/FCS、错误计数 | 受端口模式和回读范围限制；累计错误不能直接换算为 BER |
| 二维接收眼图 | 基于采样点与工作点的 XOR 错误计数，保留实际采样参数及信号来源 |

TX 功率监测不支持。模块料号、管理内存图及能力位必须匹配，机械尺寸相似不能证明寄存器兼容。合口计数属于主口；迟到的诊断请求不得覆盖新的端口或模式选择。

## 采集和恢复

提供快速、标准和精细采样参数，以及进度、取消、原始数据导出。内部 PRBS31 回环标记为 `internal_prbs31_loopback`，不能评价模块或外部光链路。外部信号不足时明确拒绝或报告不可用，不绘制假数据。

锁定旧 SBus master 的兼容采集要求所有数据口 Link Down。唯一 SDK 工作线程持有独占锁，等待校准、保存 Lane 状态，必要时将单独提供的参考微码临时加载到 EPL master 的易失性指令 RAM；不写持久 Flash。

结束、取消或失败都恢复原主控及其配套代码，校验 CRC/版本、DFE、映射和相关控制位。恢复失败不能显示完成，并会阻止后续扫描或配置修改。硬件调用按有界步骤推进，Web 不获得任意寄存器访问权。

参考微码由 `hardware/eye-firmware.json` 锁定，获取和转换见 [构建说明](BUILD.md)。AAPL 适配代码的许可见 [第三方声明](THIRD_PARTY_NOTICES.md)。

## API

- `GET /api/v1/optics`、`GET /api/v1/optics/ports/{port}`：模块和端口诊断。
- `POST /api/v1/optics/ports/{port}/eye`：提交 `lane`、`request_id`、`x_resolution`、`y_step`、`dwell_bits`、`signal_source`。
- `GET /api/v1/optics/eye`、`GET /api/v1/optics/eyes/{id}`：当前或指定任务。
- `POST /api/v1/optics/eyes/{id}/cancel`：取消并恢复。
- `GET /api/v1/optics/eyes/{id}/export?format=json|csv`：导出已读取数据，部分结果保留实际状态。

接口要求登录，开始和取消还检查 CSRF。Web 每进程缓存有界数量的任务；原生服务重启会清除原生眼图状态，重要结果应由操作者保存到私有位置。
