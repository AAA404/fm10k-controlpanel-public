# Hardware and SDK / 硬件与 SDK

## Public boundary / 公共边界

NetLab OS does not distribute the Intel FM10000 SDK, SDK source modifications,
firmware, or prebuilt switch binaries. You must obtain and use those materials
under terms that authorize you to do so.

NetLab OS 不分发 Intel FM10000 SDK、SDK 源码修改、固件或预编译 switch 二进制。
使用者必须自行取得合法授权。

The source expects an SDK `ies` directory containing headers and
`build/libFocalpointSDK.so`:

```bash
make hardware NETLAB_SDK_DIR=/path/to/authorized-sdk/ies
```

The default `make` target never looks for or downloads vendor content.

Public CI also excludes SDK-backed hardware unit tests. Their source fixtures
are available for authorized hardware developers, but they are not part of
the portable public test gate.

默认 `make` 不查找、下载或恢复任何厂商内容。

公共 CI 同样不执行依赖 SDK 的硬件单元测试。相关源码 fixture 可供持有合法 SDK
的硬件开发者使用，但不属于可移植的公共测试门禁。

## Driver / 驱动

Use the maintained public driver repository:
[netlab-fm10k-driver](https://github.com/netlab-switch/netlab-fm10k-driver).
It is the single driver source authority. This repository deliberately carries
no duplicate driver patch.

请直接使用独立公开的 `netlab-fm10k-driver`；它是唯一驱动源码权威，本仓库
不复制驱动 patch。

## Platform profiles / 平台 profile

`config/platform/` contains public profile examples for several FM10840 port
shapes. A profile describes logical capabilities and limits; it does not grant
permission to use a vendor SDK or replace board-level validation.

`config/platform/` 包含多种 FM10840 端口形态的公开 profile 示例。profile 只
描述逻辑能力与容量，不提供 SDK 使用权，也不能替代板级验证。

## Safety / 安全边界

- Never run two SDK owners against one device.
- Keep SDK and driver versions aligned with the target kernel and board.
- Treat hardware tests as state-changing unless explicitly documented as
  read-only.
- Start with isolated/fake-hardware tests and an out-of-band recovery path.
- Do not interpret a successful compile as hardware qualification.

- 禁止两个 SDK owner 同时访问一块设备。
- SDK、驱动、内核和板卡版本必须匹配。
- 除非明确标为只读，否则硬件测试都应视为会改变状态。
- 先运行 isolated/fake-hardware 测试，并准备带外恢复路径。
- 编译成功不等于完成硬件资格验证。
