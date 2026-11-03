#!/usr/bin/env bash
# Run evaluation on mmap-compatible NVMe storage.
# Load the model endpoint and credentials with CDB_MODEL_ENV_FILE.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="/root/.nvm/versions/node/v22.23.2/bin:/usr/bin:/usr/local/bin:$PATH"
# shellcheck disable=SC1091
source "$ROOT/harness/on-worker.sh"
on_worker "$@"

export CDB_SANDBOX_IMAGE="${CDB_SANDBOX_IMAGE:-cdb-sandbox:28}"
export CDB_REGISTRY_MIRRORS="${CDB_REGISTRY_MIRROR:-}"
export CDB_MIN_FREE_GIB="${CDB_MIN_FREE_GIB:-20}"
export CDB_STALE_CLEANUP_HOURS="${CDB_STALE_CLEANUP_HOURS:-24}"
export NO_PROXY="${NO_PROXY:-localhost,127.0.0.1,::1,100.102.49.113,100.102.49.114,100.96.0.0/12,10.0.0.0/8,client}"
export no_proxy="$NO_PROXY"

if [[ $# -ge 1 && "$1" == "storage" ]]; then
    shift
    exec python3 "$ROOT/harness/storage.py" report \
        --root "$CDB_DOCKER_DATA_ROOT" "$@"
fi
if [[ $# -ge 1 && "$1" == "storage-cleanup" ]]; then
    shift
    # Dry run by default; append --apply to explicitly delete eligible markers.
    exec python3 "$ROOT/harness/storage.py" cleanup \
        --root "$CDB_DOCKER_DATA_ROOT" \
        --older-than-hours "$CDB_STALE_CLEANUP_HOURS" "$@"
fi

if [[ -n "${CDB_PROXY_ENV_FILE:-}" ]]; then
    # shellcheck disable=SC1090
    source "$CDB_PROXY_ENV_FILE"
elif [[ -f "$ROOT/config/proxy.env" ]]; then
    source "$ROOT/config/proxy.env"
fi
export NO_PROXY="${NO_PROXY},100.102.49.113,100.102.49.114,client"
export no_proxy="$NO_PROXY"
if [[ -n "${CDB_MODEL_ENV_FILE:-}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$CDB_MODEL_ENV_FILE"
    set +a
fi
: "${ANTHROPIC_BASE_URL:?set ANTHROPIC_BASE_URL in CDB_MODEL_ENV_FILE}"
: "${ANTHROPIC_AUTH_TOKEN:?set ANTHROPIC_AUTH_TOKEN in CDB_MODEL_ENV_FILE}"
export ANTHROPIC_BASE_URL ANTHROPIC_AUTH_TOKEN
if [[ $# -ge 1 && "$1" == "build" ]]; then
    shift
    # The controller image itself is built by the host daemon, outside a
    # sandbox's docker-kkrepo wrapper. Resolve only its Docker Hub bases
    # through kkRepo; keep the original names as local stage references.
    python3 - "$ROOT/harness/agent_image/Dockerfile" <<'PY'
import runpy
import sys
from pathlib import Path
mirror = runpy.run_path(str(Path(sys.argv[1]).with_name('docker-kkrepo')))
mirror['prepare_dockerfile'](Path(sys.argv[1]))
PY
    exec docker build --network=host \
        --build-arg HTTP_PROXY="${HTTP_PROXY:-${http_proxy:-}}" \
        --build-arg HTTPS_PROXY="${HTTPS_PROXY:-${https_proxy:-}}" \
        --build-arg NO_PROXY="$NO_PROXY" \
        -t "$CDB_SANDBOX_IMAGE" "$ROOT/harness/agent_image" "$@"
fi

if [[ $# -ge 1 && "$1" == "worker-preflight" ]]; then
    shift
    exec python3 "$ROOT/harness/preflight.py" "$@"
fi

# Historical webexploit integration checks are not the CVE-Factory preflight.
if [[ $# -ge 1 && "$1" == "preflight" ]]; then
    shift
    exec python3 "$ROOT/harness/families/webexploit/integration.py" \
        --results "$ROOT/runtime/integration-$(date +%Y%m%d-%H%M%S)" "$@"
fi

# CDB_MODEL is allowed for explicit cross-model evaluations; credentials come
# from the local model environment file. Other batch settings are edited here.
TASKS="$ROOT/delivery/cvefactory-verified-40-20261026/tasks"
CONCURRENCY=20
MODEL="${CDB_MODEL:-glm-5.3}"
MAX_TURNS=50
TIMEOUT=18000
GRADE_TIMEOUT=3600
# One batch directory, tasks underneath: runtime/cvefactory-YYYYMMDDHHMM/<task_id>/
RESULTS="${1:-$ROOT/runtime/cvefactory-$(date +%Y%m%d%H%M)}"
shift 2>/dev/null || true
capture_batch_log "$RESULTS"
echo "CyberDockerBench free-debug: tasks=$TASKS results=$RESULTS concurrency=$CONCURRENCY docker_data=$CDB_DOCKER_DATA_ROOT driver=$CDB_STORAGE_DRIVER"
exec python3 "$ROOT/harness/run_batch.py" --tasks "$TASKS" --results "$RESULTS" \
    --concurrency "$CONCURRENCY" --model "$MODEL" \
    --max-turns "$MAX_TURNS" --timeout "$TIMEOUT" --grade-timeout "$GRADE_TIMEOUT" \
    --min-free-gib "$CDB_MIN_FREE_GIB" \
    --stale-cleanup-hours "$CDB_STALE_CLEANUP_HOURS" "$@"
