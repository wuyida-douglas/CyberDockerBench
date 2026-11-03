"""Validate a frozen source tree before starting any Docker daemon."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import yaml

EXCLUDED = {'result.json', 'running.json', 'api-env.json', 'agent-credentials.json'}


def walk_files(root: Path):
    for directory, dirs, files in os.walk(root, followlinks=False):
        current = Path(directory)
        for name in dirs:
            path = current / name
            if path.is_symlink():
                yield path
                dirs.remove(name)
        for name in files:
            yield current / name


def hash_path(path: Path) -> str:
    if path.is_symlink():
        return 'link:' + os.readlink(path)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def validate_source(root: Path) -> dict:
    errors = []
    compose_path = root / 'docker-compose.yaml'
    for name in ('Dockerfile', 'smoke.sh'):
        if not (root / name).is_file():
            errors.append(f'missing frozen source deliverable {name}')
    if not compose_path.is_file():
        errors.append('missing frozen source deliverable docker-compose.yaml')
    if errors:
        return {'valid': False, 'errors': errors, 'files': {}}
    try:
        compose = yaml.safe_load(compose_path.read_text())
        services = compose.get('services', {}) if isinstance(compose, dict) else {}
        for role in ('vul', 'fix'):
            service = services.get(role)
            if not isinstance(service, dict):
                errors.append(f'compose service {role} is missing')
                continue
            if not service.get('build') and not service.get('image'):
                errors.append(f'compose service {role} has neither source build nor image')
            labels = service.get('labels', {})
            if isinstance(labels, list):
                labels = dict(item.split('=', 1) for item in labels if '=' in item)
            if labels.get('cdb.cybergym.role') != role:
                errors.append(f'compose service {role} lacks its exact cdb.cybergym.role label')
    except (OSError, yaml.YAMLError) as exc:
        errors.append(f'invalid docker-compose.yaml: {exc}')
    files = {}
    for path in walk_files(root):
        relative = path.relative_to(root)
        if relative.name in EXCLUDED or any(part == '.git' for part in relative.parts):
            continue
        if path.is_symlink():
            target = (path.parent / os.readlink(path)).resolve()
            if root.resolve() != target and root.resolve() not in target.parents:
                errors.append(f'escaping symlink {relative}')
        elif not path.is_file():
            errors.append(f'non-regular source file {relative}')
        else:
            files[str(relative)] = {'sha256': hash_path(path), 'bytes': path.stat().st_size}
    return {'valid': not errors, 'errors': errors, 'files': files}


def freeze_source(source: Path, destination: Path) -> dict:
    if destination.exists():
        raise FileExistsError(f'frozen source already exists: {destination}')
    import shutil
    shutil.copytree(source, destination, symlinks=True,
                    ignore=shutil.ignore_patterns('.git', '__pycache__', 'api-env.json',
                                                  'agent-credentials.json', 'result.json'))
    report = validate_source(destination)
    (destination / 'source-integrity.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
