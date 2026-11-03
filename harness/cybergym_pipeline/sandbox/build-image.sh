#!/bin/bash
set -Eeuo pipefail

# Run on the dedicated worker. Context is harness/, not the repository/tasks,
# so private task material is never sent to this image build.
sandbox_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
harness_dir=$(cd -- "$sandbox_dir/../.." && pwd)
image=${CYBERGYM_SANDBOX_IMAGE:-cdb-cybergym-sandbox:28.5.2-v2}
build_args=(build --pull=false --file "$sandbox_dir/Dockerfile" --tag "$image")
for key in HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
    if [[ -n "${!key:-}" ]]; then
        build_args+=(--build-arg "$key")
    fi
done
build_args+=("$@")
build_args+=("$harness_dir")
printf 'Building %s from harness/ (no task/gold context)\n' "$image"
docker "${build_args[@]}"
docker image inspect --format 'image_id={{.Id}} version={{index .Config.Labels "org.opencontainers.image.version"}}' "$image"
