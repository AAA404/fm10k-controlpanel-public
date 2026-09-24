# Release 自动安装

完整 Release 面向**全新的 Debian 13 amd64**，从本地提供的授权输入构建并安装原生交换程序、驱动与 Web 面板。它不是旧 TestPoint/NetFab 栈的自动迁移工具。已有旧栈、已有配置或不明确的设备身份会被拒绝。

## 安装条件

| 检查项 | 要求 |
|---|---|
| 系统 | Debian 13、x86_64、systemd 为 PID 1，Python 3.11+；运行依赖由 Debian Python 3.13 提供 |
| 内核 | 6.12 系列，已安装或 APT 索引中可取得当前内核的匹配 headers；若索引为空，先更新索引再运行检查 |
| 板卡 | 唯一的 `8086:15a4 / 1374:01d0`，BDF `0000:01:00.0`；完整、校验通过的 Silicom VPD 与已支持 B0/A11 修订 |
| PCI 资源 | 固件必须已为该 function 分配 BAR0（至少 1 MiB）及 BAR4；仅有 BAR2 时配套驱动无法绑定，检查阶段会拒绝安装 |
| 驱动 | 首次安装自动构建 `fm10k-uio 6.12.101-ies2`；只允许未绑定或 fm10k 驱动，不能用于 VFIO/直通或多 function 共用驱动的环境 |
| UIO | 最终 `/dev/uio0` 必须唯一对应上述 PCI function；已有不相关 UIO 设备时拒绝 |
| SDK | 本地 IES 4.3.2 的固定头文件集合与两份 amd64 库，逐项匹配 `hardware/sdk-inputs.json` |
| 平台配置 | 本地原厂文件，SHA-256 与 VPD 识别的 B0/A11 Profile 一致 |
| 管理网络 | 已配置地址的独立管理网卡；不能直接或经 VLAN、bridge、bond 依赖 ASIC CPU 网卡 |
| 资源 | `/opt` 与 `/var` 各自所在文件系统至少 4 GiB 可用空间，至少 512 MiB RAM；构建使用单进程 |
| Secure Boot | 自动安装要求关闭；签名模块部署须另行管理 |
| 现有状态 | 没有旧交换服务、ASIC/SDK 使用进程、原生安装或管理员数据 |

Profile 与原厂输入取得方式见[构建说明](BUILD.md)。压缩包包含开源 libyang 2.1.148 源码及其锁定摘要，SDK、原厂平台和眼图参考微码均不随包提供。

若固件已分配 BAR0/BAR4，但 Linux 启动日志出现 PCI bridge 资源重新分配失败并释放 BAR，可在已确认的板卡上试用 `pci=realloc=off` 启动参数，重启后用 `lspci -vv -s 01:00.0` 和安装检查确认两个 BAR 仍已分配。此参数属于主机启动配置；安装器不会自行修改 GRUB。管理地址通过 DHCP 获取时，安装器生成的 nginx 服务配置会等待指定网卡取得指定地址，再启动 HTTPS，并在安装健康检查中验证 HTTPS 入口。

如需使用依赖参考微码的二维眼图路径，可先用 `scripts/prepare_eye_firmware.py` 转换合法取得的原始头文件，在检查和安装时额外传入 `--eye-firmware /path/to/sbus-master-101a.bin`。脚本核对锁定摘要并安装文件，不执行眼图采集；未提供时保留对应诊断能力限制。后续升级会校验并保留已安装的匹配微码。

## 取得并检查制品

通过可信的仓库 Release 页面取得 `fm10k-controlpanel-0.2.1.tar.gz`、对应 `.deb`、`release-manifest.json` 和 `SHA256SUMS`。私有仓库可在工作站使用已授权的 GitHub CLI 下载；不用把工作站的凭据复制给设备。草稿仅供维护者审核，设备在线更新不会选中草稿。

```sh
sha256sum -c SHA256SUMS
tar -xzf fm10k-controlpanel-0.2.1.tar.gz
cd fm10k-controlpanel-0.2.1
sudo ./install.sh check \
  --sdk /path/to/ies \
  --platform /path/to/licensed-platform.cfg \
  --management-interface mgmt0 \
  --management-ip 192.0.2.10
```

示例中的路径、接口和地址必须替换为目标机器实际值。只读检查输出 JSON，每项包含结果和原因；任何必要项失败时退出码为 1。未指定动作时也只做检查。检查包括包内每个文件的大小、权限和 SHA-256；不会运行 apt、modprobe、I²C 命令或交换服务。

摘要用于检测损坏和发布内容不一致，不替代下载来源的真实性。应从受信的 GitHub Release 取得清单，不能把未知来源的清单和压缩包互相校验后视为可信。

## 显式安装

准备好空白目标机器并确认安装条件后，执行相同参数，将动作改为 `install`：

```sh
sudo ./install.sh install \
  --sdk /path/to/ies \
  --platform /path/to/licensed-platform.cfg \
  --management-interface mgmt0 \
  --management-ip 192.0.2.10
```

此动作会安装 Debian 依赖、构建固定 libyang/原生程序/匹配内核的 DKMS 驱动，生成原生启动文件和 HTTPS 配置，启动服务并核对原生配置回读与 Web 版本。长时间构建后会重新检查设备身份和占用情况，再进入驱动与服务切换。脚本不配置管理 IP、路由或防火墙，不刷写持久固件。

新配置的数据口全部关闭，启用前通过 Web 配置业务 VLAN 与端口。管理员密码随机生成在 `/var/lib/fm10k-controlpanel-native/initial-admin.json`，只有 root 能读取；首次安装成功后从该文件取得访问地址与密码并更改密码。自签名证书位于 `/etc/fm10k-controlpanel/tls/`，管理客户端需要显式信任。

安装目录为 `/opt/fm10k-controlpanel/native`，原生配置保存在 `/var/lib/fm10k-controlpanel-native/`。版本元数据与回退 Web 包保存在 `/var/lib/fm10k-controlpanel-updates/`，不要删除。在线更新需要这些数据证明旧版本可恢复。

首次安装失败会记录 `installation_failed` 并尝试停止新服务，保留构建产物和配置供本地排查；不声称恢复一份不存在的旧交换系统。修复原因后应整理失败安装状态或恢复空白系统再重试，不能重复初始化已经有业务配置的安装。
不要手工把 `installation.json` 改成 `ready` 或仅启用 systemd 服务来绕过失败状态；只有安装器的健康检查、开机启用及状态收尾全部成功，安装才算完成。对已失败的 v0.2.0 安装，应先恢复安装前的空白系统或单独制定恢复方案，再使用修复后的包验收。

## 后续更新与验收

完整安装成功后，“系统与维护 → GitHub 在线升级”可检查稳定版本并提交维护更新。使用方式、私有仓库凭据与中断恢复见 [OTA](OTA.md)。原驱动、SDK、libyang ABI 和启动配置在在线更新中保持匹配；改变这些前提的版本需要单独迁移。

软件构建、模拟测试及容器包安装不代表实板验收。部署者应在自己的维护环境中完成[硬件验收](HARDWARE_ACCEPTANCE.md)，尤其是端口拓扑、温控、配置回放和数据流量；不要在承载现有业务的板卡上运行验收脚本。
