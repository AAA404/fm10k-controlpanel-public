#!/bin/bash
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$project_root/artifacts/debian13"
if ! docker build --platform linux/amd64 -f "$project_root/deploy/Dockerfile.debian13" \
    -t fm10k-controlpanel-build:debian13 "$project_root" \
    >"$project_root/artifacts/debian13/build-image.log" 2>&1; then
    tail -n 60 "$project_root/artifacts/debian13/build-image.log"
    exit 1
fi
docker run --rm --platform linux/amd64 \
    --mount "type=bind,source=$project_root,target=/src,readonly" \
    --mount "type=bind,source=$project_root/artifacts/debian13,target=/results" \
    --env "FM10K_CHECK_NATIVE=${FM10K_CHECK_NATIVE:-0}" \
    fm10k-controlpanel-build:debian13 python3 /src/scripts/check_debian.py
