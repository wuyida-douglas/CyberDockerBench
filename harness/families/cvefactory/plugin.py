"""CVE-Factory public-workspace and source-rebuild grading adapter."""
from __future__ import annotations

from typing import Any, Mapping

from harness.task_api import GradeRequest, PrepareRequest, TaskFamily, TaskSpec
from .workspace import prepare_workspace, validate_public_task
from .grader import grade


class CveFactoryFamily(TaskFamily):
    family = 'cvefactory'
    default_options: Mapping[str, Any] = {}
    required_deliverables = ('docker-compose.yaml', 'solution.sh', 'tests/test_func.py',
                             'tests/test_vuln.py', 'tests/run-tests.sh')

    def validate_task(self, task: TaskSpec) -> list[str]:
        # A reference gold, when present in a historical task directory, is not
        # read or delivered. Agent tests are the only grading criterion.
        return validate_public_task(task.path)

    def prepare_workspace(self, request: PrepareRequest) -> None:
        prepare_workspace(request.task.path, request.workspace)

    def grade(self, request: GradeRequest) -> Mapping[str, Any]:
        unknown = set(request.options) - {'keep_data'}
        if unknown:
            raise ValueError(f'unsupported cvefactory options: {sorted(unknown)}')
        if request.stage is None:
            raise ValueError('grade requires a frozen session bundle/stage')
        return grade(request.task.path, request.results, request.stage,
                     keep_data=bool(request.options.get('keep_data', request.keep_data)))


def create_plugin() -> TaskFamily:
    return CveFactoryFamily()
