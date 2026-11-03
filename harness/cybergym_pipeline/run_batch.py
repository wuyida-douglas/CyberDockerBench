"""Concurrent CyberGym batch runner: prepare -> agent -> export -> grade per task.

One worker process per task slot; the pipeline itself is sequential within a
task. Run this on the worker. Credentials come from the environment and are
passed only into the Claude process, never on argv.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harness.requeue import (  # noqa: E402
    INFRASTRUCTURE_ATTEMPTS,
    api_error_from_transcript,
    archive_attempt_dir,
    infrastructure_requeue_reason,
)


def run_one(task_id: str, args) -> dict:
    from harness.cybergym_pipeline.pipeline import Pipeline
    from harness.task_api import TaskSpec

    task_dir = ROOT / "tasks" / task_id
    result = Path(args.runtime) / "results" / args.batch / task_id / args.attempt
    pipeline = Pipeline(TaskSpec.load(task_dir), result, Path(args.runtime) / "attempt-data")
    record = {"task_id": task_id, "batch": args.batch, "attempt": args.attempt,
              "started_at": time.time()}
    try:
        pipeline.prepare()
        agent = pipeline.run_agent(args.model, args.timeout, args.max_turns)
        if agent["agent_status"] not in {"completed", "max_turns"}:
            # A truncated stream or failed CLI has not made a model submission.
            # Preserve its transcript and never grade a half-written workspace.
            raise RuntimeError(f"Claude session {agent['agent_status']}: "
                               f"{agent['claude_result']}")
        api_error = api_error_from_transcript(pipeline.result / "trajectory.jsonl")
        if api_error:
            # The session died on the gateway. Export would only report the
            # missing files that the session never got to write.
            record.update(state="error", failure_class="pipeline", error=api_error,
                          reward=0)
            pipeline.checkpoint("attempt_error", error=api_error)
        else:
            pipeline.export()
            report = pipeline.grade(args.oracle_timeout)
            record.update(reward=report.get("reward", 0),
                          failure_stage=report.get("failure_stage"),
                          failure_class=report.get("failure_class"),
                          error=report.get("error"),
                          state="graded")
            pipeline.checkpoint("attempt_complete", reward=report.get("reward", 0),
                                failure_stage=report.get("failure_stage"))
    except Exception as exc:  # noqa: BLE001 - record and continue the batch
        api_error = ""
        try:
            api_error = api_error_from_transcript(pipeline.result / "trajectory.jsonl") or ""
        except Exception:
            api_error = ""
        error = api_error or f"{type(exc).__name__}: {exc}"
        failure = "pipeline"
        if not api_error and ("preflight" in error.lower() or "networkfailure" in error.lower()):
            failure = "network"
        record.update(state="error", failure_class=failure, error=error,
                      reward=0, traceback=traceback.format_exc()[-4000:])
        try:
            pipeline.checkpoint("attempt_error", error=record["error"])
        except Exception:
            pass
    finally:
        try:
            pipeline.stop(remove_data=not args.keep_data)
        except Exception:
            pass
    record["finished_at"] = time.time()
    result.mkdir(parents=True, exist_ok=True)
    (result / "batch-record.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
    return record


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tasks", nargs="+", required=True, help="task ids under ./tasks")
    parser.add_argument("--batch", required=True)
    parser.add_argument("--attempt", default="detail")
    parser.add_argument("--runtime", default="/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cyberdockerbench/cybergym/runtime")
    parser.add_argument("--model", required=True)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=18000)
    parser.add_argument("--max-turns", type=int, default=150)
    parser.add_argument("--oracle-timeout", type=int, default=1800)
    parser.add_argument("--keep-data", action="store_true")
    args = parser.parse_args(argv)

    if not (os.environ.get("ANTHROPIC_AUTH_TOKEN") or os.environ.get("ANTHROPIC_API_KEY")):
        print("ANTHROPIC_AUTH_TOKEN/ANTHROPIC_API_KEY must be exported by run-cybergym-eval.sh", file=sys.stderr)
        return 2

    summary_dir = Path(args.runtime) / "results" / args.batch
    try:
        summary_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        print(f"refusing to reuse result directory: {summary_dir}; "
              "use a fresh --batch for every run", file=sys.stderr)
        return 2
    print(f"CyberGym batch: {len(args.tasks)} tasks, concurrency={args.concurrency}, batch={args.batch}", flush=True)

    records: list[dict] = []
    requeues: list[dict] = []
    pending = list(args.tasks)
    attempts: dict[str, int] = {}
    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        inflight: dict[cf.Future, str] = {}

        def submit_available() -> None:
            while pending and len(inflight) < args.concurrency:
                task_id = pending.pop(0)
                attempts[task_id] = attempts.get(task_id, 0) + 1
                inflight[pool.submit(run_one, task_id, args)] = task_id

        def write_summary() -> None:
            (summary_dir / "batch-summary.json").write_text(json.dumps(
                {"batch": args.batch, "model": args.model, "records": records,
                 "requeues": requeues, "finished": len(records),
                 "total": len(args.tasks),
                 "infrastructure_attempts": INFRASTRUCTURE_ATTEMPTS},
                ensure_ascii=False, indent=2) + "\n")

        submit_available()
        while inflight:
            done, _ = cf.wait(inflight, return_when=cf.FIRST_COMPLETED)
            for future in done:
                task_id = inflight.pop(future)
                try:
                    record = future.result()
                except Exception as exc:  # noqa: BLE001
                    record = {"task_id": task_id, "state": "runner_error",
                              "error": f"{type(exc).__name__}: {exc}"}
                record["attempt"] = attempts[task_id]
                reason = infrastructure_requeue_reason(record)
                task_root = summary_dir / task_id
                if reason and attempts[task_id] < INFRASTRUCTURE_ATTEMPTS:
                    record["requeue"] = reason
                    requeues.append(record)
                    print(f"[requeue {attempts[task_id]}/{INFRASTRUCTURE_ATTEMPTS}] {task_id}: "
                          f"{reason} {str(record.get('error') or '')[:160]}", flush=True)
                    archive_attempt_dir(task_root, attempts[task_id])
                    pending.append(task_id)
                else:
                    if reason:
                        record["requeue_exhausted"] = reason
                    records.append(record)
                    print(f"[{len(records)}/{len(args.tasks)}] {task_id}: "
                          f"state={record.get('state')} reward={record.get('reward')} "
                          f"failure={record.get('failure_class') or str(record.get('error') or '')[:120]}",
                          flush=True)
                write_summary()
            submit_available()

    passed = sum(1 for r in records if r.get("reward") == 1)
    print(f"batch complete: {passed}/{len(records)} passed; summary={summary_dir / 'batch-summary.json'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
