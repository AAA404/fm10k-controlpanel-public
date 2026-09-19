# 在线升级状态

在线升级为预留功能。仓库可见性变化不会自动启用升级；设备不需要 GitHub Token，也不会自动下载或安装新版本。

- 系统页面显示安装版本、源码更新源和“在线升级尚未启用”。
- `GET /api/v1/updates` 返回 `enabled: false`、`state: reserved` 与当前版本。
- `POST /api/v1/updates/check` 和 `POST /api/v1/updates/install` 在登录及 CSRF 检查后返回 HTTP 501。
- 当前使用配套 Debian 包和[检查点恢复流程](DEPLOYMENT.md)维护设备。

未来接入 GitHub Releases 需要单独实现版本化制品清单、完整性校验、配置协调、安装健康检查和设备端回退。原生控制面、SDK 和驱动升级也需要独立评估。
