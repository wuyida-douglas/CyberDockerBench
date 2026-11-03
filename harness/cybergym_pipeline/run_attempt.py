"""One-command, explicit-model CyberGym attempt with resumable evidence.

This entry point does not select a paid model implicitly and does not pretend
that official reference verification is a successful agent submission. The
agent remains optional so infrastructure and task preparation can be tested
without consuming model calls.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .pipeline import Pipeline
from .prepare.prepare import DEFAULT_STORE
from harness.task_api import TaskSpec

ROOT = Path(__file__).resolve().parents[2]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "run", "export", "grade", "stop", "status", "audit"))
    parser.add_argument("--task", help="delivered task ID, e.g. cybergym-arvo-1513")
    parser.add_argument("--manifest", type=Path,
                        default=ROOT / "results/cybergym-preparation/delivery-manifest.json")
    parser.add_argument("--model", help="required for run; no default paid model")
    parser.add_argument("--batch", default="manual")
    parser.add_argument("--attempt", default="detail")
    parser.add_argument("--runtime", type=Path,
                        default=Path("/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cyberdockerbench/cybergym/runtime"))
    parser.add_argument("--timeout", type=int, default=18000)
    parser.add_argument("--max-turns", type=int, default=150)
    parser.add_argument("--oracle-timeout", type=int, default=60)
    parser.add_argument("--keep-data", action="store_true")
    parser.add_argument("--clean-proxy-env", action="store_true",
                        help="do not load a worker proxy-env file; explicit environment still applies")
    args = parser.parse_args(argv)
    if args.clean_proxy_env:
        os.environ['CYBERGYM_LOAD_PROXY_ENV'] = '0'
    if args.command == "audit":
        from .prepare.prepare import command_audit
        selected = json.loads(args.manifest.read_text(encoding="utf-8"))["selected_tasks"]
        return command_audit(argparse.Namespace(tasks=ROOT / "tasks", only=selected,
                                                store=DEFAULT_STORE, allow_unverified=False))
    if not args.task or not args.task.startswith("cybergym-") or "/" in args.task:
        parser.error("a safe --task cybergym-... is required for this command")
    task = ROOT / "tasks" / args.task
    result = args.runtime / "results" / args.batch / args.task / args.attempt
    pipeline = Pipeline(TaskSpec.load(task), result, args.runtime / "attempt-data")
    if args.command == "prepare":
        pipeline.prepare()
        print(json.dumps({"task": args.task, "workspace": str(pipeline.workspace)}, indent=2))
        return 0
    if args.command == "status":
        from .status import main as status_main
        return status_main([str(args.runtime / "results"), "--json"])
    if args.command == "stop":
        pipeline.stop(remove_data=not args.keep_data)
        return 0
    if args.command == "run":
        if not args.model:
            parser.error("run requires an explicit --model")
        pipeline.prepare()
        pipeline.run_agent(args.model, args.timeout, args.max_turns)
        # Freeze only the declarative source before grading.
        pipeline.export()
    elif args.command == "export":
        pipeline.export()
    if args.command in {"run", "export", "grade"}:
        report = pipeline.grade(args.oracle_timeout)
        pipeline.checkpoint("attempt_complete", reward=report.get("reward", 0),
                            failure_stage=report.get("failure_stage"))
        if not args.keep_data:
            pipeline.stop(remove_data=True)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        print(f"result={result}", file=sys.stderr)
        return 0 if report.get("reward") == 1 else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
