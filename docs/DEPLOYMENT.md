# Debian 13 部署与恢复

目标系统为 Debian 13 amd64。新安装请使用[完整 Release 自动安装器](INSTALL.md)，后续更新使用[GitHub 升级](OTA.md)。单独安装 Web 包仍默认使用模拟模式并监听回环地址。本文保留手工部署与旧安装迁移的说明。

## Web 包与 HTTPS

从源码构建前端和安装包，然后在目标 Debian 系统安装：

```sh
python3 scripts/build_deb.py --output artifacts/fm10k-controlpanel.deb
sudo apt install ./artifacts/fm10k-controlpanel.deb
```

包使用专用 `fm10k-web` 用户。配置位于 `/etc/fm10k-controlpanel/panel.env`，持久状态位于 `/var/lib/fm10k-controlpanel`。初次访问时创建管理员，不提供通用初始密码。

`fm10k-https --help` 提供 HTTPS 配置生成参数。使用目标管理主机名或地址生成、检查并安装 Nginx 配置及证书；启用 HTTPS 后设置 `PANEL_SECURE_COOKIE=1`。私钥仅保留在目标设备的受限目录。自签名证书需要由管理客户端显式信任，验收工具不跳过 TLS 校验。

## 原生准备与接管

首先完成[外部输入导入](BUILD.md)，核对 PCI subsystem、VPD 修订、UIO、驱动、SDK 摘要及两个 OBT 的匹配关系。代码和配套构建放在 `/opt/fm10k-controlpanel/native`；设备实际管理地址由操作者显式提供。

`install_native_observation.py prepare --management-ip <管理地址>` 准备关闭端口的启动快照、服务单元、HTTPS 和动态链接检查；`cutover` 阶段备份并停用旧硬件操作者，再启动原生观测服务。`prepare`、`cutover` 和 `refresh-boot` 是不同阶段，不能在已部署系统上重复执行初始化。

`stage_basic100g.py` 只接受未经修改的观测基线，属于会中断数据平面的一次性迁移。`stage_native_control.py` 从已核对的观测/基线安装切换到 configd 管理的二层回放。使用这些工具前检查脚本要求、服务停止状态及完整备份；它们不是可在任意现有配置上运行的通用安装器。

switchd 必须是唯一 ASIC / SDK / I²C 操作者。不要为诊断另外启动 TestPoint、旧栈或直接访问硬件的程序。B0/A11 输入及配置备份不能交叉恢复。

## 升级与恢复

升级前结束活动事务、确认所有数据口 Down、停止眼图任务，并用 `backup_board_system.py` 保存文件系统、EFI 和分区元数据。备份应复制到独立存储并校验；备份包含设备和账户信息，不属于源码制品。

已初始化的 RoCE 安装可使用 `deploy_roce.py --preserve-buffer`。必须显式传入 `--expected-version`、`--target-version`、目标包、匹配的回退包及证据目录；首次混合缓冲迁移还要求 `--system-backup`。配套原生构建与 `release-files.json` 应由部署制品准备流程提供。

部署程序检查已安装版本、目标/回退包版本及原生构建，保存 native、启动文件和配置检查点后再更新。初始化或配置一致性检查失败时恢复检查点。工具不更新 SDK、驱动或持久固件。

配置备份与系统恢复是不同层次的操作。Web 的“配置管理 → 备份与恢复”处理交换配置；账户、证书、系统文件和原生程序应纳入独立备份。恢复后核对服务、HTTPS、配置修订、硬件回读和[验收项](HARDWARE_ACCEPTANCE.md)。
