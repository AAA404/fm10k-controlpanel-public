# Development / 开发指南

## Build / 构建

```bash
make                              # public control plane
make BUILD=debug                  # debug symbols, no optimization
make cli                          # .venv with hash-pinned CLI dependencies
make check PYTHON=.venv/bin/python
```

For a custom libyang 2.x installation:

```bash
make NETLAB_LIBYANG_PREFIX=/opt/libyang2
make check PYTHON=.venv/bin/python NETLAB_LIBYANG_PREFIX=/opt/libyang2
```

## Source rules / 源码规则

- Put each runtime authority in one daemon.
- Validate capacity before allocating or programming hardware.
- Never treat a partial snapshot as complete state.
- A public configuration path needs apply, read-back, rollback and replay.
- Vendor SDK material and live laboratory inventory must not enter this repo.

- 每个 runtime authority 只能属于一个 daemon。
- 分配资源或写硬件前先验证容量。
- 不能把部分 snapshot 当成完整状态。
- 公开配置必须具备 apply、读回、rollback 和 replay。
- 厂商 SDK 材料与真实实验室 inventory 禁止进入本仓库。

## Test layout / 测试结构

Public tests are isolated contract and fake-hardware tests selected by
`scripts/run-public-tests.py`. They must not stop services, contact lab
equipment, download private artifacts, or require the FM10000 SDK.

The manifest currently contains 21 SDK-free control-plane tests. Hardware
fixtures may remain in `tests/integration/` for authorized SDK users, but they
are deliberately excluded from public CI.

公共测试由 `scripts/run-public-tests.py` 显式选择，只允许 isolated contract 和
fake-hardware 测试；不能停止服务、访问实验室设备、下载私有制品或依赖 SDK。

当前清单包含 21 项无 SDK 控制面测试。`tests/integration/` 可以保留供合法 SDK
使用者运行的硬件 fixture，但公共 CI 明确不执行它们。
