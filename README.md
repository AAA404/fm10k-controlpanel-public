# fm10k-controlpanel

面向 Silicom PE31625G24DiRA / Intel FM10840 的 Debian 13 amd64 管理面，提供中文 Web 界面、二层交换配置、双 OBT 端口管理及硬件温控。

## 功能与范围

- 六个 EPL、24 个固定逻辑槽位，支持 10G / 25G 拆分和 40G / 100G 合口。
- VLAN、MAC、静态 LAG / LACP、RSTP、LLDP、IGMP、镜像与流量策略。
- 配置预览、版本校验、限时确认、回滚和备份恢复。
- 静态 PFC、PCP / DSCP 分类、CNP 队列、IEEE DCBX 与默认关闭的 PFC watchdog。
- 温度、PWM / RPM、RX 光功率和受限的二维接收眼图采集。
- 管理员账户、HTTPS 和受限的系统时间同步。

单独安装 Web 包时默认启动模拟后端，模拟结果不表示真实报文转发或硬件验收。完整 Release 提供原生交换服务与 Web 面板的自动安装、GitHub 版本检查和带检查点的配套升级。原生硬件控制需要匹配的板卡、驱动、专有 SDK 和单独提供的平台配置。FM10840 本机拥塞 ECN、RoCE over LAG 和三层配置未开放。端口标称速率不是实测吞吐承诺；每次部署应完成自己的功能和流量验收。

## Release 安装

从 [GitHub Releases](https://github.com/AAA404/fm10k-controlpanel-public/releases) 下载完整压缩包、配套 `.deb`、`release-manifest.json` 和 `SHA256SUMS`，核对摘要并解压。目标为全新的 Debian 13 amd64、6.12 系列内核、唯一的受支持板卡及独立管理网卡。SDK 与对应修订的平台文件需要本地提供。

```sh
sha256sum -c SHA256SUMS
tar -xzf fm10k-controlpanel-0.2.2.tar.gz
cd fm10k-controlpanel-0.2.2
sudo ./install.sh check --sdk /path/to/ies --platform /path/to/licensed-platform.cfg \
  --management-interface mgmt0 --management-ip 192.0.2.10
```

`check` 只读检查，不安装软件、不加载驱动、不启动交换服务。检查通过并安排好目标机器的安装后，将 `check` 改为 `install` 执行完整安装。初始数据口全部关闭，管理员密码随机生成并保存在设备上的 root 专属文件中。详细条件和恢复方式见[安装说明](docs/INSTALL.md)。

## 本地启动

需要 Python 3.11+、Node.js 22.12+、C 编译器和 OpenSSL。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.lock
.venv/bin/python -m pip install -e . --no-deps
npm --prefix frontend ci
npm --prefix frontend run build
.venv/bin/python -m fm10k_controlpanel
```

打开 <http://127.0.0.1:8080> 创建管理员。初始数据口关闭，启用前先配置业务 VLAN。本地状态写入被 Git 忽略的 `local-state/`。

```sh
.venv/bin/python -m pytest -q
npm --prefix frontend exec -- playwright install chromium
FM10K_PYTHON=.venv/bin/python node scripts/ui_smoke.cjs
bash scripts/verify_debian.sh
```

浏览器测试使用隔离的模拟状态；Debian 检查在一次性容器内构建公共控制面、驱动和 Web 包。公共检查不需要原厂平台文件或 SDK。

## 文档

- [构建与外部输入](docs/BUILD.md)
- [安装、HTTPS、升级和恢复](docs/DEPLOYMENT.md)
- [Release 自动安装](docs/INSTALL.md)
- [功能范围](docs/CAPABILITY_MATRIX.md)
- [原生控制面与板级映射](docs/NATIVE_INTEGRATION.md)
- [光模块与眼图](docs/OPTICS.md)
- [RDMA / RoCE](docs/ROCE.md) · [页面与接口](docs/ROCE-UI.md)
- [PFC watchdog](docs/PFC-WATCHDOG.md) · [软件 ECN 实验](docs/ECN-MARKING.md)
- [系统时间](docs/TIME_SYNC.md) · [确认窗口与协议计时](docs/NATIVE_TIMERS.md)
- [硬件验收方法](docs/HARDWARE_ACCEPTANCE.md) · [更新说明](docs/RELEASE_NOTES.md)
- [GitHub 在线升级](docs/OTA.md)

## 源码结构与许可

`backend/` 为 FastAPI 服务，`frontend/` 为 Vue / TypeScript 界面，`hardware/native/` 为板级算法，`vendor/netlab/` 为保留来源和许可的原生控制面，`deploy/` 与 `scripts/` 提供构建和维护工具，`tests/` 提供回归用例。

原生模式由 configd 管理活动配置，switchd 独占 ASIC / SDK / I²C；真实请求失败时不会降级为模拟成功。不要同时运行旧 TestPoint 栈和原生交换服务。

项目自有代码采用 [Apache-2.0](LICENSE)。Linux 驱动及 Avago 适配代码保留各自许可，详见 [NOTICE](NOTICE) 和 [第三方声明](docs/THIRD_PARTY_NOTICES.md)。`SOURCE_MANIFEST.json` 记录导入源码的原始摘要及外部输入；原厂配置、IES SDK、参考固件和设备状态不随源码分发。
