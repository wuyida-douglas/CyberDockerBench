#!/usr/bin/env bash
# Launch a CyberGym family batch using CDB_MODEL_ENV_FILE for model credentials.
# Usage: ./run-cybergym-eval.sh <batch-name> [concurrency]
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="/root/.nvm/versions/node/v22.23.2/bin:/usr/bin:/usr/local/bin:$PATH"
# shellcheck disable=SC1091
source "$ROOT/harness/on-worker.sh"
on_worker "$@"

# Same egress proxy as CVE-Factory runs (worker-side sandbox daemons read it too).
if [[ -n "${CDB_PROXY_ENV_FILE:-}" ]]; then
    # shellcheck disable=SC1090
    source "$CDB_PROXY_ENV_FILE"
fi
export NO_PROXY="${NO_PROXY:-localhost,127.0.0.1,::1,10.0.0.0/8,100.96.0.0/12,.pjlab.org.cn,.pjlab.local,.svc,.cluster.local},100.102.49.113,100.102.49.114"
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
BATCH="${1:?batch name required, e.g. cybergym-20261028a}"
CONCURRENCY="${2:-20}"
MODEL="${CDB_MODEL:-glm-5.3}"
MAX_TURNS=150
TIMEOUT="${CDB_TIMEOUT:-18000}"
ORACLE_TIMEOUT="${CDB_ORACLE_TIMEOUT:-1800}"
# Per-task results live on gpfs2 (large workspaces); link the batch into
# repo runtime/ so every family shows a uniform <batch-name> entry there.
RUNTIME="${CDB_RUNTIME:-$ROOT/runtime/cybergym}"
mkdir -p "$RUNTIME/results" "$ROOT/runtime"
ln -sfn "$RUNTIME/results/$BATCH" "$ROOT/runtime/$BATCH"

TASKLIST_FILE="${3:-}"
if [[ -n "$TASKLIST_FILE" ]]; then
    mapfile -t TASKS < "$TASKLIST_FILE"
else
    mapfile -t TASKS < <(python3 -c "
import json
m = json.load(open('$ROOT/results/cybergym-preparation/delivery-manifest.json'))
print('\n'.join(m['selected_tasks']))")
fi

echo "CyberGym eval: batch=$BATCH tasks=${#TASKS[@]} concurrency=$CONCURRENCY model=$MODEL"
exec python3 "$ROOT/harness/cybergym_pipeline/run_batch.py" \
    --tasks "${TASKS[@]}" --batch "$BATCH" --model "$MODEL" \
    --runtime "$RUNTIME" \
    --concurrency "$CONCURRENCY" --timeout "$TIMEOUT" --max-turns "${CDB_MAX_TURNS:-$MAX_TURNS}" \
    --oracle-timeout "$ORACLE_TIMEOUT"
