# Contributing

Thank you for helping improve NetLab OS.

## Before opening a change

1. Read [docs/architecture.md](docs/architecture.md) and preserve the single
   owner for configuration, protocol and hardware state.
2. Do not contribute vendor SDK material, firmware, binary artifacts, live lab
   inventory, credentials, or source derived from materials you cannot
   redistribute.
3. Keep public feature claims aligned with apply, read-back, rollback, replay,
   operational visibility and test evidence.
4. Open an issue before proposing a new public API, YANG path or capability
   promotion.

## Development loop

```bash
make
make cli
make check PYTHON=.venv/bin/python
git diff --check
```

Changes should be focused and include tests. Commit messages should explain why
the change is needed. By submitting a contribution, you agree that it is
licensed under Apache License 2.0 and that you have the right to submit it.

Hardware tests are opt-in and must document whether they change configuration,
restart services, manipulate ports or send traffic.
