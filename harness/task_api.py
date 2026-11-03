"""Stable task-family API. Family plugins must not modify this module.

The task type describes the problem; the family selects an implementation.
For example, legacy ``task_type: bugfix`` routes to ``cvefactory`` through its
manifest alias. New packages should declare ``family`` explicitly.
"""
from __future__ import annotations

import hashlib
import re
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

API_VERSION = 1
FAMILY_RE = re.compile(r'^[a-z][a-z0-9_]*$')
TASK_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')


@dataclass(frozen=True)
class TaskSpec:
    """One immutable task definition; no workspace or Docker state."""

    path: Path
    task_id: str
    family: str
    task_type: str
    metadata: Mapping[str, Any]

    @classmethod
    def load(cls, path: Path | str, family: str | None = None) -> 'TaskSpec':
        # Task metadata parsing requires PyYAML; standalone infrastructure probes do not.
        import yaml

        path = Path(path).resolve()
        metadata_path = path / 'metadata.yaml'
        if not metadata_path.is_file():
            raise ValueError(f'{path.name}: missing metadata.yaml')
        metadata = yaml.safe_load(metadata_path.read_text(encoding='utf-8'))
        if not isinstance(metadata, dict):
            raise ValueError(f'{path.name}: metadata.yaml must contain a mapping')
        task_id = metadata.get('task_id', path.name)
        if not isinstance(task_id, str) or not TASK_ID_RE.fullmatch(task_id):
            raise ValueError(f'{path.name}: invalid or missing task_id')
        task_type = metadata.get('task_type')
        if not isinstance(task_type, str) or not task_type.strip():
            raise ValueError(f'{path.name}: metadata task_type must be a non-empty string')
        # CVE-Factory imports historically appended .importing to their source
        # package id. Canonical directory names own runs; preserve the metadata.
        if (task_type == 'bugfix' and task_id == f'{path.name}.importing'
                and metadata.get('family', 'cvefactory') == 'cvefactory'):
            task_id = path.name
        if task_id != path.name:
            raise ValueError(f'{path.name}: metadata task_id must equal directory name')
        selected = family or metadata.get('family') or task_type
        if selected == 'bugfix':
            # Legacy registry alias, resolved without reading a task's gold.
            selected = 'cvefactory'
        if not isinstance(selected, str) or not FAMILY_RE.fullmatch(selected):
            raise ValueError(f'{path.name}: family must match {FAMILY_RE.pattern}')
        return cls(path, task_id, selected, task_type.strip(), MappingProxyType(dict(metadata)))


@dataclass(frozen=True)
class PrepareRequest:
    """Materialize public input without exposing the private task directory."""

    task: TaskSpec
    workspace: Path


@dataclass(frozen=True)
class GradeRequest:
    """A single grading attempt, independent of every other attempt."""

    task: TaskSpec
    results: Path
    stage: Path  # Required frozen agent delivery, never a private answer.
    keep_data: bool = False
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, 'results', Path(self.results).resolve())
        object.__setattr__(self, 'stage', Path(self.stage).resolve())

    @property
    def out_dir(self) -> Path:
        return self.results / self.task.task_id

    @property
    def attempt_id(self) -> str:
        """Unique, deterministic namespace for resources owned by this attempt."""
        scope = f'{self.results}\0{self.task.task_id}'
        return hashlib.sha256(scope.encode()).hexdigest()[:16]


class TaskFamily(ABC):
    """Stateless family adapter. A new instance is used for each request.

    Implementations own task-specific semantics. They must not mutate TaskSpec,
    the original task package, another result directory, or a shared registry.
    """

    family: str
    default_options: Mapping[str, Any] = {}
    required_deliverables: tuple[str, ...] = ()
    compose_project_prefix: str = 'cdb-'

    def export(self, sandbox: Any, destination: Path) -> Any:
        """Freeze this family's live Compose project through the shared exporter."""
        from harness.bundle import export_bundle
        project = getattr(sandbox, 'compose_project',
                          self.compose_project_prefix + str(getattr(sandbox, 'task_id', 'task')))
        return export_bundle(sandbox, destination, project=project)

    def instruction(self, workspace: Path) -> str:
        return (workspace / 'TASK.md').read_text(encoding='utf-8')

    def validate_task(self, task: TaskSpec) -> list[str]:
        """Return package errors; an empty list means valid. Never raise for bad input."""
        return []

    def prepare_workspace(self, request: PrepareRequest) -> None:
        """Default public-input staging; override for a custom agent contract.

        The destination must not exist. This prevents an agent or retry from
        silently deleting a live workspace. The source must be self-contained.
        """
        source = (request.task.path / 'input').resolve()
        destination = request.workspace.resolve()
        if not source.is_dir() or source.is_symlink():
            raise ValueError(f'{request.task.task_id}: missing public input directory')
        if destination.exists():
            raise FileExistsError(f'refusing to replace existing workspace: {destination}')
        root = source.resolve()
        for path in source.rglob('*'):
            if path.is_symlink():
                target = path.resolve(strict=True)
                if path.readlink().is_absolute():
                    raise ValueError(f'unsafe absolute input symlink: {path}')
                if not target.is_relative_to(root):
                    raise ValueError(f'input symlink escapes public input: {path}')
        shutil.copytree(source, destination, symlinks=True,
                        ignore=shutil.ignore_patterns('BUILDING.md', 'build.md'))
        instruction = request.task.path / 'instruction.md'
        if instruction.is_file():
            shutil.copy2(instruction, destination / 'TASK.md')

    @abstractmethod
    def grade(self, request: GradeRequest) -> Mapping[str, Any]:
        """Grade one frozen stage and return a mapping containing reward 0 or 1.

        Exceptions are infrastructure/grader errors; the shared executor records
        them as reward=0, status=error. They are not semantic task failures.
        """
