# 构建与外部输入

公共源码可独立构建模拟面板、NetLab 公共控制面和 Linux 驱动。硬件运行还需要自行取得并有权使用的原厂输入；项目许可证不授予这些材料的使用或再分发权。

## 开发环境

使用 Python 3.11+、Node.js 22.12+、C 编译器和 OpenSSL。在仓库根目录运行：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.lock
.venv/bin/python -m pip install -e . --no-deps
npm --prefix frontend ci
npm --prefix frontend run build
.venv/bin/python -m pytest -q
```

`requirements-dev.lock` 固定开发依赖；Debian 安装包使用 Debian 13 自带的 Python 3.13 / FastAPI / Pydantic / Uvicorn。需要 libyang 的 Linux 原生用例在容器中执行，macOS 明确跳过不支持的用例。

浏览器回归使用隔离模拟状态。先安装 Chromium，再运行 `FM10K_PYTHON=.venv/bin/python node scripts/ui_smoke.cjs`。可用 `FM10K_BROWSER_CHANNEL` 指定已安装的浏览器通道。截图和报告写入被忽略的 `artifacts/`。

## Debian 13 amd64

```sh
bash scripts/verify_debian.sh
```

构建镜像固定 Debian 基础摘要及 libyang 2.1.148。源码只读挂载，编译在容器临时目录进行；结果写入 `artifacts/debian13/`。容器不加载驱动，也不访问 ASIC、I²C 或 UIO。

公共检查包含前端、Python/C 用例、NetLab 公共契约、人工平台样例的启动生成与 YANG 校验、驱动编译、Web 包安装、HTTPS 和 systemd 单元检查。人工平台样例只存在于测试进程，不能通过生产生成器的原厂摘要校验。

## 原厂平台配置

| Profile | 修订 | 本地默认路径 | SHA-256 |
|---|---|---|---|
| `sil001-hw4-b0` | B0 / hw_version 4 | `hardware/sdk/platforms/sil001-hw4-b0.cfg` | `38c481b5d8035df14bc517735cd8e1c1ba9936fdc512fd18c849878fe323da98` |
| `sil001-hw5-a11` | A11 / hw_version 5 | `hardware/sdk/platforms/sil001-hw5-a11.cfg` | `8f5c1700c48984d539ff526f4a4ba18c814db27282de2afe33c90a2888c87d96` |

两个文件均不在仓库或 Web 包中。使用未经修改的原始文件导入：

```sh
python3 scripts/import_platform.py --profile sil001-hw5-a11 --input /path/to/licensed-platform.cfg
python3 scripts/generate_boot.py --profile sil001-hw5-a11   --output artifacts/boot-review --system-mac 02:10:84:00:00:01 --serial LAB-EXAMPLE
```

也可直接向生成器传入 `--reference /path/to/licensed-platform.cfg`。示例身份用于软件检查，部署时应使用目标设备的真实身份。B0 与 A11 配置不可互换；导入和生成都检查锁定摘要，未知输入会被拒绝。

默认生成关闭所有数据口的配置；`--active-xml` 使用不可变 configd 快照中的 profile，不能通过另传 profile 改换板卡修订。生成结果始终标记 `hardware_write_ready=false`，不代替实时硬件准入。

## SDK 与参考固件

`hardware/sdk-inputs.json` 固定 IES 4.3.2 的头文件集合及两个 amd64 库。用 `scripts/import_sdk.py --help` 查看本地导入方式，再运行：

```sh
python3 scripts/check_sdk.py --sdk hardware/sdk/ies
FM10K_CHECK_NATIVE=1 bash scripts/verify_debian.sh
```

SDK 存放在被忽略的 `hardware/sdk/`，不得混用其他版本的头文件与运行库。编译和链接检查不代表实板功能通过。启用私有输入的构建日志和原生程序应在本地保管，不上传公共 CI。

眼图参考微码由 `hardware/eye-firmware.json` 单独锁定，用 `scripts/prepare_eye_firmware.py --input <已合法取得的头文件>` 转换；不随 Web 包或源码提供，详见[光学接口](OPTICS.md)。

## 发布内容检查

```sh
python3 scripts/check_public.py --history
python3 scripts/check_public.py --package artifacts/debian13/fm10k-controlpanel_0.1.0~dev1_all.deb
```

打包文档白名单位于 `deploy/public-documents.json`。检查覆盖 Git 文件、可达历史和安装包内容；可以额外提供本地 `--private-markers <JSON文件>`，其内容为不应外发的字符串数组。该文件及检查产物应保存在忽略目录中。
