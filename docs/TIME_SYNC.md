# 在线时间同步

入口为「系统与维护 → 日期与时间」，使用 Debian 的 `systemd-timesyncd` 与 NTP 时间服务器同步设备时钟。

协议间隔、维护等待和配置确认窗口使用单调时钟，详见 [原生计时](NATIVE_TIMERS.md)。校时入口要求先结束活动配置事务。

## 页面操作

- 显示设备时间、设备时区、自动同步状态、当前实际服务器和最近成功同步时间。显示时区沿用系统配置，本页不修改时区。
- 时间服务器每行一个，支持主机名、IPv4、IPv6，最多四个，也可填写内网 NTP 地址。
- 国内常用备选包括阿里云 `ntp.aliyun.com`、腾讯云 `ntp.tencent.com`、国家授时中心 `ntp.ntsc.ac.cn`、中国 NTP Pool 服务器池 `cn.pool.ntp.org`。选择后可添加到列表，自动避免重复；添加只修改草稿，仍需保存后生效。备选项不代表当前管理网络已能访问该服务器。
- “保存并同步”持久保存服务器并开启自动同步；“立即同步”保留现有服务器并重新尝试连接。服务器列表有未保存修改时，需先保存。
- 页面可见时每五秒刷新状态，后台刷新保留正在编辑的服务器列表，不切换按钮加载/禁用状态。保存前已发出的旧读取不能覆盖保存结果；后台读取成功也不会清除操作失败提示。请求发送成功不代表时钟已经同步；只有内核同步标志和本次 timesyncd 实例的有效 NTP 响应同时成立才显示“已同步”。
- 外网 NTP 需要管理网络的 DNS 及 UDP 123 连通；仅能通过 HTTP/HTTPS 代理上网不代表 NTP 可用。服务器超时保持“等待服务器响应”，可改用可达的内网服务器。
- 配置事务尚在执行或待确认时拒绝发起校时。登录会话的 12 小时有效期、登录限流、LLDP 邻居 TTL 与传感器采样均使用单调时钟，不受 NTP 前跳或回拨影响。页面展示的时间仍为系统时间。

## 接口与权限

`GET /api/v1/system/time` 需要登录；`POST /api/v1/system/time/sync` 需要登录和 CSRF，接受 `{}`（重试）或 `{"servers":["ntp.aliyun.com","ntp.tencent.com"]}`（保存并重试）。设置独立于交换配置，记录操作审计，不增加交换配置修订，也不写交换芯片。

Web 仍以 `fm10k-web` 运行，保持原 systemd 沙盒，不获得 `CAP_SYS_TIME` 或 sudo。`fm10k-time.socket` 只允许 root 和 `fm10k-web` 连接；由 systemd 为每个连接启动一次有运行时限的固定动作 helper，并检查 Linux socket peer UID。接口只允许查询状态或保存/重试 NTP，不能传入命令、文件路径、任意时间或其他系统操作。

helper 仅写 `/etc/systemd/timesyncd.conf.d/99-fm10k-panel.conf`，然后调用固定的 `timedatectl set-ntp true` 与 `systemctl restart systemd-timesyncd.service`；时钟调整由系统 NTP 服务执行。设置或回读失败时恢复原文件及启用状态；检测到其他活动 NTP daemon 时拒绝替换。`FallbackNTP` 在显式保存服务器时清空，已配置的 DHCP/运行时 NTP 来源另外展示，实际服务器以回读为准。

模拟模式仅在模拟状态目录保存测试设置，始终标记“模拟模式”，不连接 helper、不访问 NTP、不修改开发电脑时间。

## 部署

Web 包安装 `fm10k-time.socket`、`fm10k-time@.service` 并启动 socket；不会在安装时改写已有 NTP 服务器或触发校时。`systemd-timesyncd` 为推荐依赖，未安装时页面显示服务不可用。卸载面板停止 socket，保留既有 NTP 配置和系统时间服务。

使用 `systemd-analyze verify` 检查两个 unit；以 `fm10k-web` 身份通过 Unix socket 核对状态；保存后应同时核对服务器回读及 `timedatectl show-timesync --all`。只有实际收到有效服务器响应，才能记录真实校时通过。
