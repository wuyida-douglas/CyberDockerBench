"""Cross-process attempt locking and normalized, atomic result records."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from harness.task_api import GradeRequest, TaskFamily

RESULT_SCHEMA_VERSION = 1


class TaskBusy(RuntimeError):
    """Another runner owns this exact task/result attempt."""


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    """Atomic replace prevents concurrent readers seeing half a JSON document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n',
                         encoding='utf-8')
    os.replace(temporary, path)


@contextmanager
def grade_lock(out_dir: Path, wait: bool = False):
    """Lock a (task, result root), not every same-named task on the machine."""
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(str(out_dir.resolve()).encode()).hexdigest()[:24]
    lock_path = Path(tempfile.gettempdir()) / f'cdb-grade-{digest}.lock'
    with lock_path.open('a+') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except BlockingIOError as exc:
            raise TaskBusy(f'grading attempt is already locked: {out_dir}') from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def normalized_result(request: GradeRequest, raw: Mapping[str, Any]) -> dict[str, Any]:
    """Preserve family evidence while making common fields authoritative."""
    if not isinstance(raw, Mapping) or raw.get('reward') not in (0, 1):
        raise ValueError('family grade() must return a mapping with reward 0 or 1')
    record = dict(raw)
    record.update({
        'schema_version': RESULT_SCHEMA_VERSION,
        'task_id': request.task.task_id,
        'family': request.task.family,
        'task_type': request.task.task_type,
        'reward': int(raw['reward']),
        'status': raw.get('status') or ('passed' if raw['reward'] else 'failed'),
        'stage': str(request.stage) if request.stage else raw.get('stage'),
    })
    return record


def execute_grade(plugin: TaskFamily, request: GradeRequest, *,
                  wait_for_lock: bool = False, force: bool = False) -> dict[str, Any]:
    """Execute exactly one attempt; no global mutable family or Docker state."""
    with grade_lock(request.out_dir, wait=wait_for_lock):
        # A legacy alias (bugfix) still records the canonical family in results.
        request = replace(request, task=replace(request.task, family=plugin.family))
        output = request.out_dir / 'result.json'
        if output.is_file():
            previous = json.loads(output.read_text(encoding='utf-8'))
            if previous.get('task_id', request.task.task_id) != request.task.task_id:
                raise FileExistsError(f'result belongs to a different task: {output}')
            if (previous.get('family') not in (None, plugin.family)
                    or previous.get('task_type', request.task.task_type) != request.task.task_type):
                raise FileExistsError(f'result belongs to another family or task type: {output}; '
                                      'use a different --results directory')
            if not force:
                return {**previous, 'status': 'skipped_existing',
                        'previous_status': previous.get('status')}
        started = time.time()
        write_json(request.out_dir / 'running.json', {
            'task_id': request.task.task_id, 'family': request.task.family,
            'pid': os.getpid(),
        })
        try:
            raw = plugin.grade(request)
            record = normalized_result(request, raw)
        except Exception as exc:
            record = {
                'schema_version': RESULT_SCHEMA_VERSION,
                'task_id': request.task.task_id, 'family': request.task.family,
                'task_type': request.task.task_type,
                'stage': str(request.stage) if request.stage else None,
                'reward': 0, 'status': 'error',
                'error': f'{exc.__class__.__name__}: {exc}',
            }
        record['duration_sec'] = round(time.time() - started, 3)
        record['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
        write_json(output, record)
        (request.out_dir / 'running.json').unlink(missing_ok=True)
        return record
