"""Recoverable CyberGym preparation driver; never invokes a solving agent.

Examples (from the CyberDockerBench repository root):

  python3 -m harness.cybergym_pipeline.prepare.prepare prepare --selection harness/cybergym_pipeline/selection.json
  python3 -m harness.cybergym_pipeline.prepare.prepare verify --worker root@100.96.153.163
  python3 -m harness.cybergym_pipeline.prepare.prepare audit
  python3 -m harness.cybergym_pipeline.prepare.prepare summary

All caches and private image archives belong under the GPFS2 store. `prepare`
only writes unverified packages. `verify` sets reference_verified solely after
both official roles have actually run with the private PoC and matched the
expected sanitizer behavior. `audit` additionally requires public input integrity
and no leaks. `summary` selects at most three tasks per project, only from tasks
that have passed both verification and audit.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import os
import re
import sqlite3
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .audit import audit_task
from .materialize import prepare_task
from .verify import verify_task

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_STORE = Path("/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cyberdockerbench/cybergym")


def read_selection(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["tasks"] if isinstance(data, dict) else data


def database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(f"file:{path}?immutable=1", uri=True, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def mappings(path: Path) -> dict[int, int]:
    result = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            old, new = line.strip().split(",", 1)
            result[int(old)] = int(new)
    return result


def stack_from_output(output: str) -> list[str]:
    text = output.replace("\x1b", "")
    frames = []
    for match in re.finditer(r"(?m)^\s+#\d+\s+\S+\s+in\s+([A-Za-z_~][\w:~.-]*)", text):
        name = match.group(1)
        if name.startswith(("fuzzer::", "__libc_", "_start", "LLVMFuzzer", "__interceptor_", "__asan_")):
            continue
        if name not in frames:
            frames.append(name)
        if len(frames) == 6:
            break
    return frames


def task_directory(tasks: Path, upstream_id: str) -> Path:
    return tasks / upstream_id.replace(":", "-").replace("arvo-", "cybergym-arvo-")


def write_checkpoint(store: Path, state: dict) -> None:
    store.mkdir(parents=True, exist_ok=True)
    target = store / "checkpoint.json"
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)


def command_prepare(args) -> int:
    selection = read_selection(Path(args.selection))
    legacy = json.loads(Path(args.legacy_selection).read_text(encoding="utf-8"))
    candidates = {item["task_id"]: item for item in legacy}
    mapping = mappings(Path(args.mappings))
    db = database(Path(args.arvo_db))
    state_path = Path(args.store) / "checkpoint.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {"tasks": {}}
    state.setdefault("tasks", {})
    selected_tasks = [item for item in selection
                      if not args.only or f"cybergym-arvo-{item['upstream_task_id'].split(':')[1]}" in args.only]

    def prepare_one(item):
        upstream_id = item["upstream_task_id"]
        issue = int(upstream_id.split(":")[1])
        task_id = f"cybergym-arvo-{issue}"
        try:
            if upstream_id not in candidates:
                upstream = json.loads((Path(args.arvo_meta) / "archive_data" / "meta" / f"{issue}.json").read_text()) if (Path(args.arvo_meta) / "archive_data" / "meta" / f"{issue}.json").is_file() else {"project": item.get("project")}
                candidate = {"task_id": upstream_id, "project": upstream.get("project"),
                             "project_language": item.get("language")}
            else:
                candidate = candidates[upstream_id]
            upstream_path = Path(args.arvo_meta) / "archive_data" / "meta" / f"{issue}.json"
            if not upstream_path.is_file():
                import urllib.request
                upstream_path.parent.mkdir(parents=True, exist_ok=True)
                with urllib.request.urlopen(f"https://raw.githubusercontent.com/n132/ARVO-Meta/main/archive_data/meta/{issue}.json", timeout=60) as response:
                    upstream_path.write_bytes(response.read())
            upstream = json.loads(upstream_path.read_text(encoding="utf-8"))
            modern_id = mapping.get(issue, issue)
            record = db.execute("SELECT * FROM arvo WHERE localId = ?", (modern_id,)).fetchone()
            if not record:
                raise ValueError(f"no ARVO database record for {upstream_id} -> {modern_id}")
            if not record["reproduced"] or not record["patch_located"]:
                raise ValueError(f"ARVO record is not reproduced with a located patch: {modern_id}")
            # AFL and honggfuzz references still expose a single-input runner;
            # the target is built with the historical engine and real srcmap.
            if record["fuzz_engine"] not in {"libfuzzer", "afl", "honggfuzz"}:
                raise ValueError(f"unsupported fuzz engine: {record['fuzz_engine']}")
            record = dict(record)
            item = dict(item)
            item.setdefault("record", record)
            if not item.get("expected_stack"):
                item["expected_stack"] = stack_from_output(record["crash_output"])
            if not item["expected_stack"]:
                description = next((comment.get("content", "") for comment in upstream.get("report", {}).get("comments", [])
                                    if comment.get("descriptionNum") == 1), "")
                stack_match = re.search(r"Crash State:\n((?:  .+\n)+)", description)
                item["expected_stack"] = [line.strip() for line in stack_match.group(1).splitlines()] if stack_match else []
            if not item["expected_stack"]:
                if record["sanitizer"].lower() not in {'msan', 'memory'}:
                    raise ValueError("no expected application stack frames")
                # Some MSan reports have no application frames. Preserve that
                # upstream fact explicitly; the strict vul/fix differential is
                # still required rather than accepting an arbitrary failure.
                item["expected_stack"] = []
                item["stack_evidence_optional"] = True
            # The existing preparation checkpoint preserves private verification.
            task_path = Path(args.tasks) / task_id
            if (task_path / "input" / "manifest.json").is_file() and args.resume:
                result = {"task_id": task_id, "status": "prepared_existing_private_checkpoint"}
            else:
                result = prepare_task(candidate, upstream, item, args)
            result.update({"upstream_task_id": upstream_id, "sanitizer": record["sanitizer"]})
            print(f"[prepare] {task_id}: {result['status']}", flush=True)
            return task_id, result
        except Exception as exc:
            result = {"status": "prepare_failed", "upstream_task_id": upstream_id,
                      "error": f"{type(exc).__name__}: {exc}"}
            print(f"[prepare] {task_id}: FAILED {exc}", flush=True)
            return task_id, result
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.prepare_concurrency) as pool:
        for task_id, result in pool.map(prepare_one, selected_tasks):
            state["tasks"][task_id] = result
            state["updated_at"] = datetime.now(timezone.utc).isoformat()
            write_checkpoint(Path(args.store), state)
    return 0


def iter_task_dirs(args, require_selected=False) -> list[Path]:
    tasks = Path(args.tasks)
    if args.only:
        return [tasks / name for name in args.only]
    if require_selected:
        return [task_directory(tasks, item["upstream_task_id"]) for item in read_selection(Path(args.selection))]
    return sorted(path for path in tasks.iterdir() if path.is_dir() and path.name.startswith("cybergym-"))


def command_verify(args) -> int:
    state_path = Path(args.store) / "checkpoint.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {"tasks": {}}
    state.setdefault("tasks", {})
    for task_dir in iter_task_dirs(args, require_selected=True):
        if not (task_dir / "metadata.yaml").is_file():
            state["tasks"][task_dir.name] = {"status": "missing_prepare", "reference_verified": False}
            write_checkpoint(Path(args.store), state)
            continue
        if args.resume:
            existing = task_dir / "gold" / "verify_reference.json"
            if existing.is_file() and json.loads(existing.read_text()).get("passed") is True:
                print(f"[verify] {task_dir.name}: checkpoint already passed", flush=True)
                continue
        print(f"[verify] {task_dir.name}: starting private reference runs", flush=True)
        result = verify_task(task_dir, args.worker, Path(args.store) / "reference-archive" / task_dir.name,
                             timeout=args.run_timeout)
        previous = state["tasks"].get(task_dir.name, {})
        previous.update({"task_id": task_dir.name, "status": "reference_passed" if result["passed"] else "reference_failed",
                         "reference_verified": result["passed"], "failures": result["failures"],
                         "duration_seconds": result["duration_seconds"]})
        state["tasks"][task_dir.name] = previous
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        write_checkpoint(Path(args.store), state)
        print(f"[verify] {task_dir.name}: passed={result['passed']} failures={result['failures']}", flush=True)
    return 0


def command_audit(args) -> int:
    tasks = []
    for task_dir in iter_task_dirs(args):
        try:
            report = audit_task(task_dir, require_verified=not args.allow_unverified)
        except Exception as exc:
            report = {"task_id": task_dir.name, "passed": False,
                      "issues": [f"audit error: {type(exc).__name__}: {exc}"]}
        report["audit_log"] = str(Path(args.store) / "audits" / f"{task_dir.name}.json")
        destination = Path(report["audit_log"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tasks.append(report)
        print(f"[audit] {task_dir.name}: passed={report['passed']} issues={len(report['issues'])}", flush=True)
    passed = bool(tasks) and all(item["passed"] for item in tasks)
    output = Path(args.store) / "audit-summary.json"
    output.write_text(json.dumps({"passed": passed, "total": len(tasks), "tasks": tasks},
                                 ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if passed else 1


def command_summary(args) -> int:
    rows = []
    for task_dir in iter_task_dirs(args):
        if not (task_dir / "metadata.yaml").is_file():
            # An acquisition placeholder is not a materialized failed task.
            print(f"[summary] {task_dir.name}: skipping unmaterialized directory", flush=True)
            continue
        metadata = yaml.safe_load((task_dir / "metadata.yaml").read_text(encoding="utf-8"))
        verification_path = task_dir / "gold" / "verify_reference.json"
        verification = json.loads(verification_path.read_text()) if verification_path.exists() else {}
        try:
            audit = audit_task(task_dir)
        except Exception as exc:
            audit = {"passed": False, "issues": [str(exc)]}
        rows.append({"task_id": task_dir.name, "project": metadata.get("project"),
                     "sanitizer": metadata.get("sanitizer_label") or metadata.get("sanitizer"), "language": metadata.get("language"),
                     "fuzz_target": metadata.get("fuzz_target"), "crash_type": metadata.get("crash_type"),
                     "reference_verified": metadata.get("reference_verified") is True and verification.get("passed") is True,
                     "audit_passed": audit.get("passed") is True,
                     "verification_duration_seconds": verification.get("duration_seconds"),
                     "commands": {role: data.get("command") for role, data in (verification.get("runs") or {}).items()},
                     "failures": verification.get("failures") or audit.get("issues", [])})
    counts = collections.Counter()
    selected = []
    # selection.json expresses quality priority without allowing unverified fillers.
    requested = read_selection(Path(args.selection))
    order = {f"cybergym-arvo-{item['upstream_task_id'].split(':')[1]}": index for index, item in enumerate(requested)}
    for row in sorted(rows, key=lambda item: order.get(item["task_id"], 10_000)):
        if row["reference_verified"] and row["audit_passed"] and counts[row["project"]] < 3:
            selected.append(row)
            counts[row["project"]] += 1
        if len(selected) == args.target:
            break
    selected_ids = {row["task_id"] for row in selected}
    failures = [row for row in rows if row["task_id"] not in selected_ids and not row["reference_verified"]]
    result = {
        "schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": args.target, "verified_count": sum(row["reference_verified"] for row in rows),
        "selected_count": len(selected), "selected_tasks": [row["task_id"] for row in selected],
        "distribution": {
            "projects": dict(collections.Counter(row["project"] for row in selected)),
            "sanitizers": dict(collections.Counter(row["sanitizer"] for row in selected)),
            "languages": dict(collections.Counter(row["language"] for row in selected)),
        },
        "tasks": rows, "failures_and_replacements_needed": failures,
        "evidence_scope": "Official-reference GOLD differential and public-input audit only; no agent solution or agent source/live rebuild has been run.",
        "commands": {
            "prepare": "python3 -m harness.cybergym_pipeline.prepare.prepare prepare",
            "verify": f"python3 -m harness.cybergym_pipeline.prepare.prepare verify --worker {args.worker}",
            "audit": "python3 -m harness.cybergym_pipeline.prepare.prepare audit",
            "summary": "python3 -m harness.cybergym_pipeline.prepare.prepare summary",
        },
        "agent_execution": "none; this pipeline performs only source import and private reference reproduction",
        "remaining_issues": [] if len(selected) == args.target else [
            f"Only {len(selected)} of {args.target} selected tasks passed both real reference verification and public-input audit.",
            "Historical issue reproducer endpoints may be unreachable; official reference-image /tmp/poc is recorded as the private fallback.",
            "Public normal seed corpus is not bundled unless independently fetched and checked; agents must author smoke inputs.",
        ],
    }
    result_path = Path(args.output)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    checkpoint_path = Path(args.store) / "preparation-summary.json"
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    manifest_path = result_path.with_name("delivery-manifest.json")
    delivery = {
        "schema_version": 1, "generated_at": result["generated_at"],
        "target": args.target, "selected_count": len(selected),
        "selected_tasks": result["selected_tasks"], "distribution": result["distribution"],
        "max_tasks_per_project": 3,
        "evidence_scope": result["evidence_scope"],
        "preparation_summary": str(result_path),
        "task_root": str(Path(args.tasks).resolve()),
    }
    delivery_path = manifest_path.with_suffix(".json.tmp")
    delivery_path.write_text(json.dumps(delivery, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(delivery_path, manifest_path)
    print(json.dumps({key: result[key] for key in ("verified_count", "selected_count", "distribution", "remaining_issues")}, indent=2))
    return 0 if len(selected) == args.target else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "verify", "audit", "summary"])
    parser.add_argument("--tasks", type=Path, default=ROOT / "tasks")
    parser.add_argument("--selection", default=str(ROOT / "harness" / "cybergym_pipeline" / "selection.json"))
    parser.add_argument("--legacy-selection", default="/tmp/cdb/cybergym_selected.json")
    parser.add_argument("--store", type=Path, default=DEFAULT_STORE)
    parser.add_argument("--cache", type=Path, default=DEFAULT_STORE / "downloads")
    parser.add_argument("--oss-fuzz-git", type=Path, default=DEFAULT_STORE / "upstream" / "oss-fuzz.git")
    parser.add_argument("--arvo-db", type=Path, default=DEFAULT_STORE / "upstream" / "arvo.db")
    parser.add_argument("--arvo-meta", type=Path, default=DEFAULT_STORE / "upstream" / "arvo-meta")
    parser.add_argument("--mappings", type=Path, default=DEFAULT_STORE / "upstream" / "arvo" / "arvo" / "oss_fuzz_mappings.csv")
    parser.add_argument("--worker", default="root@100.96.153.163")
    parser.add_argument("--target", type=int, default=40)
    parser.add_argument("--run-timeout", type=int, default=600)
    parser.add_argument("--prepare-concurrency", type=int, default=4)
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--allow-unverified", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "cybergym-preparation" / "preparation-summary.json")
    args = parser.parse_args()
    return {"prepare": command_prepare, "verify": command_verify,
            "audit": command_audit, "summary": command_summary}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
