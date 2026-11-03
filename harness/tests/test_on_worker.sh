#!/usr/bin/env bash
# The three eval scripts SSH from wuyida-01 to the worker. No local /var/tmp path.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/harness/on-worker.sh"

out=$(CDB_ON_WORKER= CDB_NVME_PRESENT=no CDB_WORKER_SSH=print on_worker --batch demo)
[[ "$out" == "ssh $CDB_WORKER cd $ROOT && CDB_ON_WORKER=1 CDB_MODEL_ENV_FILE='' CDB_MODEL='' exec $0 --batch demo" ]]
out=$(CDB_ON_WORKER= CDB_NVME_PRESENT=no CDB_WORKER_SSH=print CDB_MODEL=deepseek-v4.1-flash on_worker --batch demo)
[[ "$out" == *"CDB_ON_WORKER=1 CDB_MODEL_ENV_FILE='' CDB_MODEL=deepseek-v4.1-flash exec $0 --batch demo"* ]]
[[ "$out" != *"/var/tmp"* ]]

set +e
(CDB_NVME_PRESENT=no CDB_ON_WORKER=1 CDB_WORKER_SSH=print on_worker) >/tmp/cdb-on-worker-out 2>/tmp/cdb-on-worker-err
code=$?
set -e
[[ "$code" -eq 1 ]]
grep -q 'has no /nvme' /tmp/cdb-on-worker-err

CDB_NVME_PRESENT=yes CDB_WORKER_SSH=print CDB_ON_WORKER= on_worker
[[ "$CDB_DOCKER_DATA_ROOT" == /nvme/cyberdockerbench/docker-data ]]
[[ "$CDB_STORAGE_DRIVER" == overlay2 ]]
[[ "$CDB_LOCAL_DOCKER_DATA" == 1 ]]
[[ -z "${CDB_REGISTRY_MIRROR:-}" ]]
[[ -z "${CDB_REGISTRY_MIRRORS:-}" ]]
[[ -z "${CYBERGYM_REGISTRY_MIRROR:-}" ]]
CDB_NVME_PRESENT=yes CDB_WORKER_SSH=print CDB_ON_WORKER= CDB_ENABLE_HUB_CACHE=1 on_worker
pod_host="$(hostname -I | awk '{print $1}')"
[[ "$CDB_REGISTRY_MIRROR" == "http://${pod_host}:5000" ]]
[[ "$CDB_REGISTRY_MIRROR" != *"${CDB_WORKER#*@}"* ]]

for script in run-factory-eval.sh run-cybergym-eval.sh run-webexploit-eval.sh; do
    grep -q 'source "$ROOT/harness/on-worker.sh"' "$ROOT/$script"
    grep -q 'on_worker "$@"' "$ROOT/$script"
done
if grep -n '/var/tmp' "$ROOT/run-factory-eval.sh" "$ROOT/run-cybergym-eval.sh" \
        "$ROOT/run-webexploit-eval.sh" "$ROOT/harness/on-worker.sh"; then
    echo 'local docker fallback is still in a launch script' >&2
    exit 1
fi
printf 'on-worker ok\n'
