#!/usr/bin/env bash
# Launch all three baseline families with the same immutable base-model endpoint.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$ROOT/harness/on-worker.sh"
STAMP="${1:-$(date +%Y%m%d-%H%M%S)}"
export CDB_MODEL_ENV_FILE="$ROOT/config/qwen36-baseline.env"
export CDB_MODEL=qwen36-baseline
FACTORY_CONCURRENCY="${FACTORY_CONCURRENCY:-25}"
CYBERGYM_CONCURRENCY="${CYBERGYM_CONCURRENCY:-15}"
WEBEXPLOIT_CONCURRENCY="${WEBEXPLOIT_CONCURRENCY:-25}"

printf 'Baseline batch %s: Factory=%s CyberGym=%s WebExploit=%s; Docker only on %s\n' \
    "$STAMP" "$FACTORY_CONCURRENCY" "$CYBERGYM_CONCURRENCY" "$WEBEXPLOIT_CONCURRENCY" "$CDB_WORKER"
"$ROOT/run-factory-eval.sh" "baseline-qwen36-factory-$STAMP" --concurrency "$FACTORY_CONCURRENCY" > "$ROOT/runtime/baseline-qwen36-factory-$STAMP.console.log" 2>&1 &
factory_pid=$!
CDB_RUNTIME="$ROOT/runtime/cybergym" "$ROOT/run-cybergym-eval.sh" "baseline-qwen36-cybergym-$STAMP" "$CYBERGYM_CONCURRENCY" > "$ROOT/runtime/baseline-qwen36-cybergym-$STAMP.console.log" 2>&1 &
cybergym_pid=$!
"$ROOT/run-webexploit-eval.sh" --tasks "$ROOT/delivery/webexploit-30-20261026/tasks" \
    --results "$ROOT/runtime/baseline-qwen36-webexploit-$STAMP" \
    --model qwen36-baseline --concurrency "$WEBEXPLOIT_CONCURRENCY" \
    --timeout 18000 --max-turns 150 > "$ROOT/runtime/baseline-qwen36-webexploit-$STAMP.console.log" 2>&1 &
web_pid=$!
printf 'Factory PID=%s CyberGym PID=%s WebExploit PID=%s\n' "$factory_pid" "$cybergym_pid" "$web_pid" | tee "$ROOT/runtime/baseline-qwen36-$STAMP.pids"
status=0
for pid in "$factory_pid" "$cybergym_pid" "$web_pid"; do
    wait "$pid" || status=1
done
exit "$status"
