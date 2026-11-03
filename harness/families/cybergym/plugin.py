"""CyberGym adapter: synthesize and verify environments, not exploit scripts."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Mapping

from harness.cybergym_pipeline.prepare.audit import audit_tree
from harness.task_api import GradeRequest, PrepareRequest, TaskFamily, TaskSpec
from .contract import TASK_CONTRACT


class CyberGymFamily(TaskFamily):
    family = 'cybergym'
    default_options: Mapping[str, Any] = {}
    required_deliverables = ('docker-compose.yaml', 'Dockerfile', 'smoke.sh')
    compose_project_prefix = 'cdb-cybergym-'

    def validate_task(self, task: TaskSpec) -> list[str]:
        if task.task_type != 'binary-env-synthesis':
            return [f'task_type must be binary-env-synthesis, got {task.task_type!r}']
        errors = audit_tree(task.path / 'input')['issues']
        for name in ('TASK.md', 'description.md', 'error.txt',
                     'manifest.json', 'srcmap-vul.json', 'srcmap-fix.json',
                     'sources-vul.tar.gz', 'sources-fix.tar.gz'):
            if not (task.path / 'input' / name).is_file():
                errors.append(f'missing public input: {name}')
        return errors

    def prepare_workspace(self, request: PrepareRequest) -> None:
        super().prepare_workspace(request)
        instruction = request.workspace / 'TASK.md'
        description = instruction.read_text(encoding='utf-8') if instruction.is_file() else ''
        instruction.write_text(description.rstrip() + '\n\n' + TASK_CONTRACT, encoding='utf-8')
        (request.workspace / 'test-results').mkdir(exist_ok=True)

    def grade(self, request: GradeRequest) -> Mapping[str, Any]:
        unknown = set(request.options) - {'keep_data'}
        if unknown:
            raise ValueError(f'unsupported cybergym options: {sorted(unknown)}')
        if request.stage is None:
            raise ValueError('grade requires a frozen source delivery')
        from .grader import grade
        return grade(request.task.path, request.results, request.stage,
                     keep_data=bool(request.options.get('keep_data', request.keep_data)))


def create_plugin() -> TaskFamily:
    return CyberGymFamily()
