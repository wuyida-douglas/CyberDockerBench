"""Manifest-based task-family discovery. No central registration edits required."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any, Iterable, Mapping

from harness.task_api import API_VERSION, FAMILY_RE, TaskFamily

ROOT = Path(__file__).resolve().parent.parent
ALIAS_RE = re.compile(r'^[a-z][a-z0-9_-]*$')


class PluginError(RuntimeError):
    """A manifest or adapter violates the family API."""


@dataclass(frozen=True)
class FamilyDescriptor:
    family: str
    directory: Path
    manifest: Mapping[str, Any]

    @property
    def entrypoint(self) -> Path:
        return self.directory / str(self.manifest.get('entrypoint', 'plugin.py'))

    @property
    def description(self) -> str:
        return str(self.manifest.get('description', ''))


@lru_cache(maxsize=128)
def _load_module(path: str, mtime_ns: int, size: int) -> ModuleType:
    del mtime_ns, size  # Cache identity includes the current file version.
    source = Path(path)
    digest = hashlib.sha256(path.encode()).hexdigest()[:12]
    name = f'_cdb_family_{source.parent.name}_{digest}'
    # The family directory is its own namespace package. Relative helper imports
    # therefore cannot collide with another family's identically named module.
    spec = importlib.util.spec_from_file_location(
        name, source, submodule_search_locations=[str(source.parent)])
    if spec is None or spec.loader is None:
        raise PluginError(f'cannot load family entrypoint: {source}')
    module = importlib.util.module_from_spec(spec)
    # Modules using dataclasses expect their module to exist during execution.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


class FamilyRegistry:
    """Discover independent directories and isolate unselected broken plugins."""

    def __init__(self, paths: Iterable[Path] | None = None) -> None:
        self.roots = tuple(Path(p).expanduser().resolve() for p in (
            paths if paths is not None else family_paths()))
        self.descriptors: dict[str, FamilyDescriptor] = {}
        self.aliases: dict[str, str] = {}
        self.issues: list[str] = []
        ambiguous: set[str] = set()
        for directory in sorted(self.roots):
            if not directory.is_dir():
                continue
            for manifest_path in sorted(directory.glob('*/plugin.json')):
                try:
                    descriptor = self._read_manifest(manifest_path)
                except (OSError, ValueError, TypeError, json.JSONDecodeError, PluginError) as exc:
                    self.issues.append(f'{manifest_path.parent}: {exc}')
                    continue
                family = descriptor.family
                if family in self.descriptors:
                    self.issues.append(f'{family}: duplicate family name at {directory}')
                    self.descriptors.pop(family, None)
                    ambiguous.add(family)
                    continue
                if family in ambiguous:
                    continue
                self.descriptors[family] = descriptor
        for family, descriptor in self.descriptors.items():
            names = [family, *descriptor.manifest.get('aliases', [])]
            for name in names:
                owner = self.aliases.get(name)
                if owner is not None and owner != family:
                    self.issues.append(f'alias {name!r}: claimed by both {owner} and {family}')
                    ambiguous.add(name)
                else:
                    self.aliases[name] = family
        for name in ambiguous:
            self.aliases.pop(name, None)

    @staticmethod
    def _read_manifest(path: Path) -> FamilyDescriptor:
        manifest = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(manifest, dict):
            raise PluginError('plugin.json must contain an object')
        if manifest.get('api_version') != API_VERSION:
            raise PluginError(f'api_version must be {API_VERSION}')
        family = manifest.get('family')
        if not isinstance(family, str) or not FAMILY_RE.fullmatch(family):
            raise PluginError(f'family must match {FAMILY_RE.pattern}')
        if family != path.parent.name:
            raise PluginError('family must equal its directory name')
        aliases = manifest.get('aliases', [])
        if (not isinstance(aliases, list) or len(set(aliases)) != len(aliases)
                or any(not isinstance(a, str) or not ALIAS_RE.fullmatch(a) for a in aliases)):
            raise PluginError('aliases must be unique lowercase names')
        entrypoint = path.parent / manifest.get('entrypoint', 'plugin.py')
        if not entrypoint.is_file() or entrypoint.parent != path.parent:
            raise PluginError('entrypoint must be a Python file in the family directory')
        return FamilyDescriptor(family, path.parent.resolve(), manifest)

    def resolve(self, name: str) -> FamilyDescriptor:
        family = self.aliases.get(name)
        if family is None:
            available = ', '.join(sorted(self.descriptors)) or '(none)'
            raise PluginError(f'unknown or ambiguous family {name!r}; available: {available}')
        return self.descriptors[family]

    def create(self, name: str) -> TaskFamily:
        descriptor = self.resolve(name)
        path = descriptor.entrypoint
        stat = path.stat()
        module = _load_module(str(path), stat.st_mtime_ns, stat.st_size)
        factory = getattr(module, descriptor.manifest.get('factory', 'create_plugin'), None)
        if not callable(factory):
            raise PluginError(f'{descriptor.family}: missing callable create_plugin()')
        plugin = factory()
        if not isinstance(plugin, TaskFamily):
            raise PluginError(f'{descriptor.family}: create_plugin() must return TaskFamily')
        if plugin.family != descriptor.family:
            raise PluginError(f'{descriptor.family}: adapter family does not match manifest')
        return plugin


def family_paths() -> list[Path]:
    """Built-ins plus optional external roots, without editing the core."""
    paths = [ROOT / 'harness' / 'families']
    extra = os.environ.get('CDB_FAMILY_PATH', '')
    paths.extend(Path(part) for part in extra.split(os.pathsep) if part.strip())
    return paths
