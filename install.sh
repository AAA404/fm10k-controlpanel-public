#!/bin/sh
set -eu
release_root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3.11+ is required. On Debian 13: apt-get install python3' >&2
    exit 1
fi
# No implicit installation: with no action, the Python entry point only checks.
exec python3 -I -B "$release_root/scripts/install_release.py" "$@"
