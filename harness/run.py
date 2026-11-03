#!/usr/bin/env python3
"""Unified task-family CLI; does not replace the established family entrypoints.

python3 harness/run.py families
python3 harness/run.py inspect --tasks tasks
python3 harness/run.py prepare --tasks tasks --results results/<batch> --only TASK
python3 harness/run.py grade --tasks tasks --results results/<batch> --only TASK --stage BUNDLE
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from harness.execution import TaskBusy, execute_grade, write_json  # noqa: E402
from harness.registry import FamilyRegistry, PluginError  # noqa: E402
from harness.task_api import GradeRequest, PrepareRequest, TaskSpec  # noqa: E402


def selected_tasks(args: argparse.Namespace, registry: FamilyRegistry) -> list[TaskSpec]:
    root = Path(args.tasks).resolve()
    families = {registry.resolve(name).family for name in (args.family or [])}
    only = set(args.only or [])
    tasks = []
    for path in sorted(root.iterdir()):
        if not path.is_dir() or (only and path.name not in only):
            continue
        if not (path / 'metadata.yaml').is_file():
            if only:
                raise ValueError(f'{path.name}: missing metadata.yaml')
            continue
        spec = TaskSpec.load(path)
        descriptor = registry.resolve(spec.family)
        if families and descriptor.family not in families:
            continue
        tasks.append(replace(spec, family=descriptor.family))
    missing = only - {task.task_id for task in tasks}
    if missing:
        raise ValueError(f'unknown, unsupported, or filtered tasks: {sorted(missing)}')
    if not tasks:
        raise ValueError('no matching tasks')
    return tasks


def parse_options(values: list[str] | None) -> dict[str, Any]:
    options: dict[str, Any] = {}
    for value in values or []:
        key, separator, raw = value.partition('=')
        if not separator or not key:
            raise ValueError(f'--set expects key=json-value, got {value!r}')
        try:
            options[key] = json.loads(raw)
        except json.JSONDecodeError:
            options[key] = raw  # Convenient unquoted strings such as backend=host.
    return options


def families_command(registry: FamilyRegistry) -> int:
    rows = [{'family': item.family, 'aliases': item.manifest.get('aliases', []),
             'description': item.description, 'path': str(item.directory)}
            for item in registry.descriptors.values()]
    print(json.dumps({'families': rows, 'discovery_issues': registry.issues},
                     ensure_ascii=False, indent=2))
    return 1 if registry.issues else 0


def inspect_command(args: argparse.Namespace, registry: FamilyRegistry) -> int:
    root = Path(args.tasks).resolve()
    only = set(args.only or [])
    rows = []
    for path in sorted(root.iterdir()):
        if not path.is_dir() or not (path / 'metadata.yaml').is_file():
            continue
        if only and path.name not in only:
            continue
        try:
            spec = TaskSpec.load(path)
            descriptor = registry.resolve(spec.family)
            plugin = registry.create(spec.family)
            errors = plugin.validate_task(spec)
            rows.append({'task_id': spec.task_id, 'family': descriptor.family,
                         'task_type': spec.task_type, 'supported': True,
                         'valid': not errors, 'errors': errors})
        except (ValueError, TypeError, PluginError) as exc:
            rows.append({'task_id': path.name, 'supported': False,
                         'valid': False, 'errors': [str(exc)]})
    missing = only - {row['task_id'] for row in rows}
    for name in sorted(missing):
        rows.append({'task_id': name, 'supported': False, 'valid': False,
                     'errors': ['task directory or metadata.yaml not found']})
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0 if rows and all(row['valid'] for row in rows) else 1


def prepare_command(args: argparse.Namespace, registry: FamilyRegistry) -> int:
    tasks = selected_tasks(args, registry)
    results = Path(args.results).resolve()
    prepared = []
    for task in tasks:
        request = PrepareRequest(task, results / task.task_id / 'workspace')
        plugin = registry.create(task.family)
        errors = plugin.validate_task(task)
        if errors:
            raise ValueError(f'{task.task_id}: invalid task: {errors}')
        plugin.prepare_workspace(request)
        prepared.append(str(request.workspace))
        print(f'[prepared] {task.task_id}: {request.workspace}', flush=True)
    return 0 if len(prepared) == len(tasks) else 1


def grade_command(args: argparse.Namespace, registry: FamilyRegistry) -> int:
    tasks = selected_tasks(args, registry)
    results = Path(args.results).resolve()
    options = parse_options(args.set)
    if args.stage and (len(tasks) != 1 or args.submission_root):
        raise ValueError('--stage grades exactly one task and excludes --submission-root')
    if not args.stage and not args.submission_root:
        raise ValueError('grading requires --stage or --submission-root; private answers are not graded')
    requests = []
    for task in tasks:
        stage = Path(args.stage) if args.stage else Path(args.submission_root) / task.task_id
        requests.append(GradeRequest(task, results, stage=stage,
                                     keep_data=args.keep_data, options=options))

    def run_one(request: GradeRequest) -> dict[str, Any]:
        try:
            plugin = registry.create(request.task.family)
            record = execute_grade(plugin, request, force=args.force)
        except TaskBusy as exc:
            record = {'task_id': request.task.task_id, 'family': request.task.family,
                      'reward': 0, 'status': 'skipped_locked', 'error': str(exc)}
        print(f"[grade] {request.task.task_id}: family={request.task.family} "
              f"reward={record['reward']} status={record['status']}", flush=True)
        return record

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        records = list(pool.map(run_one, requests))
    summary = {
        'schema_version': 1,
        'requested': len(requests),
        'reward_1': sum(record['reward'] == 1 for record in records),
        'by_family': {},
        'results': records,
    }
    for record in records:
        counts = summary['by_family'].setdefault(record['family'], {'total': 0, 'reward_1': 0})
        counts['total'] += 1
        counts['reward_1'] += int(record['reward'] == 1)
    write_json(results / 'summary.json', summary)
    print(json.dumps({'requested': summary['requested'], 'reward_1': summary['reward_1'],
                      'by_family': summary['by_family']}, ensure_ascii=False, indent=2))
    # Unsupported/invalid inputs are setup errors, not evidence of task difficulty.
    return 0 if all(record['reward'] == 1 for record in records) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--family-path', type=Path, action='append',
                        help='additional family root; or use CDB_FAMILY_PATH')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('families', help='discover installed adapters')
    inspect = commands.add_parser('inspect', help='validate metadata and adapter-owned contracts')
    inspect.add_argument('--tasks', type=Path, default=ROOT / 'tasks')
    inspect.add_argument('--only', nargs='+')
    prepare = commands.add_parser('prepare', help='materialize a new public-input workspace')
    for command in (prepare, commands.add_parser('grade', help='grade tasks in parallel')):
        command.add_argument('--tasks', type=Path, default=ROOT / 'tasks')
        command.add_argument('--results', type=Path, required=True)
        command.add_argument('--family', action='append', help='select family; repeatable')
        command.add_argument('--only', nargs='+')
    grade = commands.choices['grade']
    grade.add_argument('--concurrency', type=int, default=2)
    grade.add_argument('--submission-root', type=Path,
                       help='directory containing <task_id>/ frozen submissions')
    grade.add_argument('--stage', type=Path, help='one explicit frozen package; requires --only')
    grade.add_argument('--set', action='append', metavar='KEY=VALUE',
                       help='family-specific grading option, for example keep_data=true')
    grade.add_argument('--keep-data', action='store_true')
    grade.add_argument('--force', action='store_true', help='regrade an existing result root')
    args = parser.parse_args()
    if args.command == 'grade' and not 1 <= args.concurrency <= 64:
        parser.error('--concurrency must be between 1 and 64')
    paths = [ROOT / 'harness' / 'families', *(args.family_path or [])]
    registry = FamilyRegistry(paths)
    if args.command == 'families':
        return families_command(registry)
    try:
        if args.command == 'inspect':
            return inspect_command(args, registry)
        if args.command == 'prepare':
            return prepare_command(args, registry)
        return grade_command(args, registry)
    except (ValueError, TypeError, OSError, PluginError) as exc:
        parser.exit(2, f'error: {exc}\n')


if __name__ == '__main__':
    raise SystemExit(main())
