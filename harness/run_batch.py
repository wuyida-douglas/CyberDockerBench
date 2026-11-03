"""One-command, resumable 20-concurrency free-debug evaluation batch."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from harness.docker_sandbox import sweep_finished_sandboxes
from harness.requeue import (
    INFRASTRUCTURE_ATTEMPTS, archive_attempt_dir, file_task_view, filed_path,
    infrastructure_requeue_reason)
from harness.storage import StorageError, cleanup_stale_docker_data, validate_storage_root

# Batch defaults are edited here, not supplied through CDB_* variables.
DEFAULT_CONCURRENCY = 20
DEFAULT_MODEL = 'glm-5.3'
DEFAULT_MAX_TURNS = 50
DEFAULT_TIMEOUT = 18000
DEFAULT_GRADE_TIMEOUT = 10800
RUNNER_GRACE_SECONDS = 3600


def generation_paths(root: Path, generation: int) -> tuple[Path, Path]:
    output = root / ('generation-01' if generation == 1 else f'generation-{generation:02d}')
    output.mkdir(parents=True, exist_ok=True)
    return output, output / 'state.json'


def tasks_from(value: Path) -> list[Path]:
    value = value.resolve()
    if value.is_file():
        manifest = json.loads(value.read_text())
        entries = manifest.get('tasks', manifest.get('valid', manifest if isinstance(manifest, list) else []))
        if isinstance(entries, dict):
            entries = list(entries)
        base = value.parent
        if value.parent.name.startswith('cvefactory-verified-') and (value.parent / 'tasks').is_dir():
            base = value.parent / 'tasks'
        paths = []
        for entry in entries:
            if isinstance(entry, str):
                paths.append(Path(entry))
            elif isinstance(entry, dict) and entry.get('valid', True):
                candidate = entry.get('path', entry.get('task_path', entry.get('task_id')))
                if candidate:
                    paths.append(Path(candidate))
        if paths:
            tasks = [(path if path.is_absolute() else (base / path)).resolve()
                     for path in paths]
            if len({task.name for task in tasks}) != len(tasks):
                raise ValueError(f'duplicate task ids in manifest: {value}')
            return tasks
        raise ValueError(f'no task paths in manifest: {value}')
    if not value.is_dir():
        raise FileNotFoundError(value)
    if (value / 'input').is_dir():
        return [value]
    return sorted(path for path in value.iterdir()
                  if path.is_dir() and (path / 'input').is_dir())


def audit(record: dict, root: Path, batch: str, task: Path) -> None:
    """Append the first attributable failure; never rewrite historic evidence."""
    if record.get('reward') == 1:
        return
    category = record.get('failure_class') or 'pipeline'
    output = root / task.name
    detail = {}
    for filename in ('result.json', 'agent-result.json'):
        try:
            detail = json.loads((output / filename).read_text())
            break
        except (OSError, json.JSONDecodeError):
            continue
    item = {
        'batch': batch, 'task_id': task.name,
        'classification': category if category in {
            'pipeline', 'network', 'export', 'grader', 'task_input', 'agent_semantic',
        } else 'pipeline',
        'evidence': [str(filed_path(output, 'trajectory.jsonl')),
                     str(filed_path(output, 'result.json')),
                     str(filed_path(output, 'agent-result.json'))],
        'root_cause': record.get('error') or detail.get('error') or record.get('status'),
        'failure_stage': detail.get('failure_stage') or detail.get('pipeline', {}).get('failed_phase'),
        'change': 'pending', 'regression': 'pending', 'outcome': 'needs_rerun',
    }
    with (root / 'audit.jsonl').open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(item, ensure_ascii=False) + '\n')


def archive_failed_attempt(root: Path, task: Path, attempt: int) -> None:
    """Move one failed attempt aside so the next run can stage a fresh workspace."""
    archive_attempt_dir(root / task.name, attempt, keep=frozenset({'.batch.lock'}))


def agent_execution_failure(record: dict) -> dict | None:
    """Separate API/session infrastructure errors from a valid incomplete answer."""
    agent = record.get('agent', {})
    if (agent.get('status') not in ('error', 'incomplete', 'timeout')
            or record.get('pipeline', {}).get('failed_phase') == 'agent'):
        return None
    text = str(agent.get('error', '')) + ' ' + str(record.get('error') or '')
    if not any(token in text.lower() for token in (
            'rate limit', 'overloaded', 'api error', 'connection error',
            'authentication', 'invalid api key', 'unauthorized', 'forbidden',
            'timed out', 'timeout', 'status 429', 'status 401', 'status 403',
            'status 500', 'status 502', 'status 503', 'status 504')):
        return None
    return {'status': 'error', 'failure_class': 'pipeline',
            'error': 'Claude/API execution failed; inspect trajectory: ' + text}


def run_one(task: Path, root: Path, args: argparse.Namespace) -> dict:
    name = task.name
    output = root / name
    output.mkdir(parents=True, exist_ok=True)
    lock = output / '.batch.lock'
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(descriptor, str(os.getpid()).encode())
        os.close(descriptor)
    except FileExistsError:
        return {'task_id': name, 'status': 'locked', 'reward': 0}
    started = time.time()
    child_env = dict(os.environ)
    child_env['CDB_MIN_FREE_GIB'] = str(
        getattr(args, 'min_free_gib', os.environ.get('CDB_MIN_FREE_GIB', '0')))
    stored_agent = filed_path(output, 'agent-result.json')
    stored_grade = filed_path(output, 'result.json')
    bundle = filed_path(output, 'bundle') / 'delivery'
    agent_result = output / 'agent-result.json'
    grade_result = output / 'result.json'
    try:
        agent_record = json.loads(stored_agent.read_text()) if stored_agent.exists() else {}
        if (agent_record.get('export', {}).get('status') != 'completed'
                or not (bundle / 'bundle.json').is_file() or args.force_agent):
            # An agent rerun invalidates the previous grade; do not let an
            # incomplete/timeout rerun silently reuse the old reward.
            if stored_grade.exists():
                os.replace(stored_grade, output / 'previous-result.json')
            command = [sys.executable, str(ROOT / 'harness/run_agent.py'),
                       '--task', str(task), '--results', str(output),
                       '--model', args.model, '--max-turns', str(args.max_turns),
                       '--timeout', str(args.timeout)]
            if stored_agent.exists():
                os.replace(stored_agent, output / 'previous-agent-result.json')
            with (output / 'runner-console.log').open('w') as log:
                cp = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                    cwd=ROOT, timeout=args.timeout + RUNNER_GRACE_SECONDS,
                                    env=child_env)
            if (output / 'result.json').exists():
                os.replace(output / 'result.json', agent_result)
            record = json.loads(agent_result.read_text()) if agent_result.exists() else {}
            execution_failure = agent_execution_failure(record)
            if cp.returncode or record.get('export', {}).get('status') != 'completed' or execution_failure:
                category = record.get('failure_category') or 'pipeline'
                error = record.get('error') or record.get('export', {}).get('error')
                if execution_failure:
                    category = execution_failure['failure_class']
                    error = execution_failure['error']
                return {'task_id': name,
                        'status': 'failed' if category == 'agent_semantic' else 'error',
                        'reward': 0,
                        'failure_class': category,
                        'agent_status': record.get('agent', {}).get('status'),
                        'export_status': record.get('export', {}).get('status'),
                        'error': error,
                        'exit_code': cp.returncode}
        if not agent_result.exists() and stored_agent.exists():
            agent_result = stored_agent
        if not grade_result.exists() and stored_grade.exists():
            grade_result = stored_grade
        if not agent_result.exists():
            return {'task_id': name, 'status': 'agent_incomplete', 'reward': 0,
                    'failure_class': 'pipeline', 'error': 'missing frozen bundle'}
        record = json.loads(agent_result.read_text())
        execution_failure = agent_execution_failure(record)
        if execution_failure:
            return {'task_id': name, 'reward': 0, **execution_failure,
                    'agent_status': record.get('agent', {}).get('status'),
                    'result': str(agent_result)}
        # A turn-limited/incomplete session may still leave a complete frozen
        # project. Grade that real delivery; only API/transport errors above
        # are excluded. Its incomplete agent status stays in agent-result.json.
        if not args.skip_grade and (not grade_result.exists() or args.force_grade):
            if grade_result.exists():
                os.replace(grade_result, output / 'previous-result.json')
            bundle = filed_path(output, 'bundle') / 'delivery'
            if not bundle.is_dir():
                return {'task_id': name, 'status': 'pipeline_error', 'reward': 0,
                        'failure_class': 'pipeline', 'error': 'missing frozen delivery'}
            command = [sys.executable, '-c',
                'import sys,json; from pathlib import Path; '
                'from harness.task_api import TaskSpec, GradeRequest; '
                'from harness.registry import FamilyRegistry; '
                'from harness.execution import execute_grade; '
                't=TaskSpec.load(Path(sys.argv[1])); '
                'r=execute_grade(FamilyRegistry().create(t.family), GradeRequest(t,Path(sys.argv[2]),stage=Path(sys.argv[3]))); '
                'print(json.dumps(r)); sys.exit(0)',
                str(task), str(output), str(bundle)]
            with (output / 'grader-console.log').open('w') as log:
                cp = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                    cwd=ROOT, timeout=args.grade_timeout, env=child_env)
            if cp.returncode and not grade_result.exists():
                return {'task_id': name, 'status': 'pipeline_error', 'reward': 0,
                        'failure_class': 'pipeline', 'exit_code': cp.returncode}
            if cp.returncode:
                return {'task_id': name, 'status': 'pipeline_error', 'reward': 0,
                        'failure_class': 'grader', 'exit_code': cp.returncode,
                        'error': 'grader exited nonzero after writing a result; '
                                 'previous evidence must not be reused'}
        result = json.loads(grade_result.read_text()) if grade_result.exists() else record
        reward = int(result.get('reward', 0))
        if not args.skip_grade and not grade_result.exists():
            return {'task_id': name, 'status': 'pipeline_error', 'reward': 0,
                    'failure_class': 'pipeline', 'error': 'grader produced no result.json'}
        if not args.skip_grade and result.get('status') == 'running':
            return {'task_id': name, 'status': 'pipeline_error', 'reward': 0,
                    'failure_class': 'grader',
                    'error': 'grader terminated before recording a final verdict'}
        return {'task_id': name, 'reward': reward,
                'status': 'passed' if reward == 1 else (
                    'failed' if result.get('failure_class') == 'agent_semantic' else 'error'),
                'failure_class': result.get('failure_class'),
                'result': str(grade_result if grade_result.exists() else agent_result),
                'duration_sec': round(time.time() - started, 3)}
    except Exception as exc:
        (output / 'batch-error.log').write_text(traceback.format_exc())
        return {'task_id': name, 'status': 'pipeline_error', 'reward': 0,
                'failure_class': 'pipeline', 'error': str(exc),
                'duration_sec': round(time.time() - started, 3)}
    finally:
        lock.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tasks', required=True, type=Path,
                        help='task directory, parent directory, or delivery manifest.json')
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--concurrency', type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--model', default=DEFAULT_MODEL,
                        help='model alias accepted by the configured Anthropic-compatible endpoint')
    parser.add_argument('--max-turns', type=int, default=DEFAULT_MAX_TURNS)
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument('--grade-timeout', type=int, default=DEFAULT_GRADE_TIMEOUT)
    parser.add_argument('--min-free-gib', type=float,
                        default=float(os.environ.get('CDB_MIN_FREE_GIB', '20')))
    parser.add_argument('--stale-cleanup-hours', type=float,
                        default=float(os.environ.get('CDB_STALE_CLEANUP_HOURS', '24')))
    parser.add_argument('--skip-grade', action='store_true')
    parser.add_argument('--force-agent', action='store_true')
    parser.add_argument('--force-grade', action='store_true')
    parser.add_argument('--resume', action='store_true',
                        help='skip recorded final tasks and release locks left by an interrupted driver')
    parser.add_argument('--only', nargs='*',
                        help='task directory names to run; other tasks are left untouched')
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.concurrency < 1 or args.concurrency > 40:
        parser.error('concurrency must be between 1 and 40 for this evaluation profile')
    if args.min_free_gib < 0 or args.stale_cleanup_hours < 0:
        parser.error('storage thresholds cannot be negative')
    tasks = tasks_from(args.tasks)
    if args.only:
        wanted = set(args.only)
        tasks = [task for task in tasks if task.name in wanted]
        missing = wanted.difference(task.name for task in tasks)
        if missing:
            parser.error('unknown task: ' + ', '.join(sorted(missing)))
    if args.limit:
        tasks = tasks[:args.limit]
    if not tasks:
        parser.error('no tasks found')
    if args.resume:
        pending_tasks = []
        for task in tasks:
            output = args.results / task.name
            record = filed_path(output, 'agent-result.json')
            if record.is_file():
                print(f'resume: keep recorded result for {task.name}', flush=True)
                continue
            try:
                (output / '.batch.lock').unlink()
            except FileNotFoundError:
                pass
            pending_tasks.append(task)
        tasks = pending_tasks
    if not tasks:
        parser.error('resume found no incomplete tasks')
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=True)
    storage: dict = {'mode': 'named-docker-volumes'}
    if os.environ.get('CDB_LOCAL_DOCKER_DATA', '') == '1':
        data_root = Path(os.environ.get('CDB_DOCKER_DATA_ROOT', '/var/tmp'))
        try:
            stale_cleanup = cleanup_stale_docker_data(
                data_root, args.stale_cleanup_hours, apply=True)
            storage = validate_storage_root(data_root, args.min_free_gib)
            storage['stale_cleanup'] = stale_cleanup
        except (StorageError, OSError, ValueError) as exc:
            parser.error(str(exc))
    started = datetime.now(timezone.utc).isoformat()
    summary = {'started_at': started, 'tasks': len(tasks), 'concurrency': args.concurrency,
               'model': args.model, 'status': 'running', 'storage': storage,
               'infrastructure_attempts': INFRASTRUCTURE_ATTEMPTS,
               'results': [], 'requeues': []}
    (root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(f'batch={root} tasks={len(tasks)} concurrency={args.concurrency}', flush=True)
    interrupted = False
    exit_code = 0
    data_root = Path(os.environ['CDB_DOCKER_DATA_ROOT']) if os.environ.get('CDB_DOCKER_DATA_ROOT') else None

    def record_progress() -> None:
        summary['finished'] = len(summary['results'])
        summary['passed'] = sum(item.get('reward') == 1 for item in summary['results'])
        (root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            pending = list(tasks)
            attempts: dict[str, int] = {}
            inflight: dict[concurrent.futures.Future, Path] = {}

            def submit_available() -> None:
                while pending and len(inflight) < args.concurrency:
                    task = pending.pop(0)
                    attempts[task.name] = attempts.get(task.name, 0) + 1
                    inflight[pool.submit(run_one, task, root, args)] = task

            try:
                submit_available()
                while inflight:
                    done, _ = concurrent.futures.wait(
                        inflight, return_when=concurrent.futures.FIRST_COMPLETED)
                    for future in done:
                        task = inflight.pop(future)
                        result = future.result()
                        result['attempt'] = attempts[task.name]
                        reason = infrastructure_requeue_reason(result)
                        if reason and attempts[task.name] < INFRASTRUCTURE_ATTEMPTS:
                            result['requeue'] = reason
                            summary['requeues'].append(result)
                            record_progress()
                            print(json.dumps(result, ensure_ascii=False), flush=True)
                            archive_failed_attempt(root, task, attempts[task.name])
                            pending.append(task)
                            continue
                        if reason:
                            result['requeue_exhausted'] = reason
                        audit(result, root, root.name, task)
                        file_task_view(root / task.name)
                        summary['results'].append(result)
                        record_progress()
                        print(json.dumps(result, ensure_ascii=False), flush=True)
                    submit_available()
            except KeyboardInterrupt:
                interrupted = True
                exit_code = 130
            except BaseException:
                interrupted = True
                summary['status'] = 'interrupted'
                summary['finished_at'] = datetime.now(timezone.utc).isoformat()
                (root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
                raise
    finally:
        if summary.get('status') == 'running':
            summary['status'] = 'interrupted' if interrupted else 'completed'
            summary['finished_at'] = datetime.now(timezone.utc).isoformat()
        try:
            summary['sweep'] = sweep_finished_sandboxes(data_root)
        except (OSError, subprocess.SubprocessError) as exc:
            summary['sweep'] = {'errors': [str(exc)]}
        (root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    if interrupted and exit_code == 0:
        return 1
    if exit_code == 0:
        print(f"completed: {summary['passed']}/{len(tasks)} passed; results={root}", flush=True)
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
