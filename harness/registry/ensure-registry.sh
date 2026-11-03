#!/usr/bin/env bash
# Start the Docker Hub pull-through cache on the worker. Blobs live on GPFS.
# Upstream credentials, when present, are copied from the worker's Docker
# config into a root-only file. They are not printed and not stored in git.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE="${CDB_REGISTRY_DATA_ROOT:-/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/docker}"
DATA="$BASE/data"
CONFIG="$BASE/config.yml"
NAME=cdb-hub-cache

if [[ -f /mnt/shared-storage-user/datafactory-share/wuyida/netproxy/proxy-env.sh ]]; then
    # shellcheck disable=SC1091
    source /mnt/shared-storage-user/datafactory-share/wuyida/netproxy/proxy-env.sh
fi

mkdir -p "$DATA"
python3 - "$ROOT/harness/registry/config.yml" "$CONFIG" << 'PY'
import base64, pathlib, sys
template = pathlib.Path(sys.argv[1]).read_text()
destination = pathlib.Path(sys.argv[2])
auth_file = pathlib.Path("/root/.docker/config.json")
username = password = ""
if auth_file.is_file():
    import json
    auths = json.loads(auth_file.read_text()).get("auths") or {}
    for key in ("https://index.docker.io/v1/", "https://index.docker.io/v1", "docker.io"):
        encoded = (auths.get(key) or {}).get("auth") or ""
        if not encoded:
            continue
        decoded = base64.b64decode(encoded).decode()
        username, _, password = decoded.partition(":")
        break
extra = ""
if username and password:
    extra = f"  username: {username!r}\n  password: {password!r}\n"
text = template.replace("  ttl: 168h\n", extra + "  ttl: 168h\n")
destination.write_text(text)
destination.chmod(0o600)
print("registry_auth", "yes" if username else "no")
PY

if docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null | grep -qx true; then
    curl -fsS --max-time 5 http://127.0.0.1:5000/v2/ >/dev/null
    echo "cdb-hub-cache already running"
    exit 0
fi
docker rm -f "$NAME" >/dev/null 2>&1 || true
if ! docker image inspect registry:2 >/dev/null 2>&1; then
    docker pull registry:2
fi
docker run -d --name "$NAME" --restart unless-stopped --network host \
    -v "$CONFIG":/etc/docker/registry/config.yml:ro \
    -v "$DATA":/var/lib/registry \
    -e HTTP_PROXY="${HTTP_PROXY:-}" \
    -e HTTPS_PROXY="${HTTPS_PROXY:-}" \
    -e http_proxy="${http_proxy:-${HTTP_PROXY:-}}" \
    -e https_proxy="${https_proxy:-${HTTPS_PROXY:-}}" \
    -e NO_PROXY="localhost,127.0.0.1,::1" \
    -e no_proxy="localhost,127.0.0.1,::1" \
    registry:2 >/dev/null
for _ in $(seq 1 30); do
    if curl -fsS --max-time 3 http://127.0.0.1:5000/v2/ >/dev/null; then
        echo "cdb-hub-cache ready"
        exit 0
    fi
    sleep 1
done
echo "cdb-hub-cache did not become ready" >&2
docker logs --tail 40 "$NAME" >&2 || true
exit 1
