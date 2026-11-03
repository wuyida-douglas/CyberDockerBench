"""Docker-data capacity checks and conservative per-attempt garbage collection.

Only directories owned by a current sandbox marker are eligible for stale
cleanup. Unmarked legacy directories are reported but never deleted.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

DATA_SUFFIX = '-docker-data'
OWNER_SUFFIX = '.owner.json'
OWNER_SCHEMA = 1


class StorageError(RuntimeError):
    """Storage cannot safely hold a private Docker daemon."""


def filesystem_type(path: Path | str) -> str:
    cp = subprocess.run(['findmnt', '-n', '-o', 'FSTYPE', '-T', str(path)],
                        capture_output=True, text=True, timeout=30)
    return cp.stdout.strip() if cp.returncode == 0 else 'unknown'


def validate_storage_root(root: Path | str, min_free_gib: float = 0) -> dict[str, Any]:
    root = Path(root).expanduser()
    if not root.is_absolute():
        raise StorageError(f'Docker data root must be absolute: {root}')
    if min_free_gib < 0:
        raise StorageError('minimum free storage cannot be negative')
    root.mkdir(parents=True, exist_ok=True)
    resolved = root.resolve()
    filesystem = filesystem_type(resolved)
    if filesystem == 'virtiofs':
        raise StorageError(
            f'{resolved} is virtiofs; Docker volume/containerd metadata requires '
            'mmap-compatible local storage. Use NVMe/local XFS or ext4, not the '
            'shared workspace mount.')
    usage = shutil.disk_usage(resolved)
    free_gib = usage.free / (1024 ** 3)
    if free_gib < min_free_gib:
        raise StorageError(
            f'insufficient Docker storage at {resolved}: {free_gib:.1f} GiB free, '
            f'{min_free_gib:.1f} GiB required. Clean stale attempts or choose '
            'CDB_DOCKER_DATA_ROOT on a larger local filesystem.')
    return {
        'root': str(resolved),
        'filesystem': filesystem,
        'free_gib': round(free_gib, 2),
        'min_free_gib': min_free_gib,
        'total_gib': round(usage.total / (1024 ** 3), 2),
    }


def owner_marker(data_dir: Path | str) -> Path:
    data_dir = Path(data_dir)
    return data_dir.with_name(data_dir.name + OWNER_SUFFIX)


def write_owner_marker(data_dir: Path | str, *, task_id: str, sandbox_name: str,
                       container: str, runtime_root: Path | str) -> Path:
    data_dir = Path(data_dir)
    marker = owner_marker(data_dir)
    payload = {
        'schema_version': OWNER_SCHEMA,
        'task_id': task_id,
        'sandbox_name': sandbox_name,
        'container': container,
        'runtime_root': str(runtime_root),
        'pid': os.getpid(),
        'created_at': time.time(),
    }
    temporary = marker.with_name(f'.{marker.name}.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    os.replace(temporary, marker)
    return marker


def remove_owner_marker(data_dir: Path | str) -> None:
    owner_marker(data_dir).unlink(missing_ok=True)


def _container_exists(name: str) -> bool | None:
    """True/False when Docker answers definitively; None when inspection is unsafe.

    A hung daemon (e.g. vfs layer churn after a large build) makes inspect
    time out; that is an unsafe inspection, so return None like any other
    ambiguous answer instead of raising and aborting the caller's grade.
    """
    try:
        cp = subprocess.run(['docker', 'inspect', '--format', '{{.State.Running}}', name],
                            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if cp.returncode == 0:
        return True
    if re.search(r'no such|not found', cp.stderr, re.IGNORECASE):
        return False
    return None


def cleanup_stale_docker_data(root: Path | str, older_than_hours: float, *,
                              apply: bool = False, now: float | None = None,
                              container_exists: Callable[[str], bool | None] | None = None,
                              ) -> dict[str, Any]:
    """Collect only expired, marked attempts whose outer container is gone.

    A missing Docker daemon or ambiguous inspection result skips deletion. The
    age grace also protects the short interval between marker creation and
    container creation. Unmarked directories are never candidates.
    """
    if older_than_hours < 0:
        raise ValueError('older_than_hours cannot be negative')
    root = Path(root).expanduser().resolve()
    report: dict[str, Any] = {
        'root': str(root), 'enabled': older_than_hours > 0,
        'apply': apply, 'older_than_hours': older_than_hours,
        'actions': [], 'errors': [],
    }
    if older_than_hours == 0 or not root.is_dir():
        return report
    now = time.time() if now is None else now
    exists_check = container_exists or _container_exists
    for marker in sorted(root.glob(f'cdb-*{DATA_SUFFIX}{OWNER_SUFFIX}')):
        action: dict[str, Any] = {'marker': str(marker), 'action': 'skipped'}
        report['actions'].append(action)
        try:
            if marker.is_symlink():
                raise StorageError('owner marker is a symlink')
            payload = json.loads(marker.read_text(encoding='utf-8'))
            data_name = marker.name[:-len(OWNER_SUFFIX)]
            sandbox_name = data_name[:-len(DATA_SUFFIX)]
            if payload.get('schema_version') != OWNER_SCHEMA:
                raise StorageError('unsupported owner marker schema')
            if payload.get('sandbox_name') != sandbox_name:
                raise StorageError('owner marker sandbox name mismatch')
            container = payload.get('container')
            if not isinstance(container, str) or not container:
                raise StorageError('owner marker has no container')
            age_hours = (now - float(payload['created_at'])) / 3600
            action['age_hours'] = round(age_hours, 2)
            if age_hours < older_than_hours:
                action['reason'] = 'young'
                continue
            present = exists_check(container)
            if present is None:
                action['reason'] = 'container inspection unavailable'
                continue
            if present:
                action['reason'] = 'container exists'
                continue
            data_dir = marker.parent / data_name
            if data_dir.parent != root or data_dir.is_symlink():
                raise StorageError('unsafe data directory')
            if data_dir.exists() and not data_dir.is_dir():
                raise StorageError('data path is not a directory')
            action['data_dir'] = str(data_dir)
            action['action'] = 'would_remove'
            action['reason'] = 'stale marked attempt without a container'
            if apply:
                if data_dir.exists():
                    shutil.rmtree(data_dir)
                marker.unlink(missing_ok=True)
                action['action'] = 'removed'
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError,
                StorageError, subprocess.SubprocessError) as exc:
            action['action'] = 'error'
            action['reason'] = str(exc)
            report['errors'].append({'marker': str(marker), 'error': str(exc)})
    return report


def storage_report(root: Path | str) -> dict[str, Any]:
    root = Path(root).expanduser().resolve()
    report: dict[str, Any] = {'root': str(root), 'exists': root.is_dir()}
    if root.is_dir():
        usage = shutil.disk_usage(root)
        report.update({
            'filesystem': filesystem_type(root),
            'free_gib': round(usage.free / (1024 ** 3), 2),
            'total_gib': round(usage.total / (1024 ** 3), 2),
            'marked_attempts': len(list(root.glob(f'cdb-*{DATA_SUFFIX}{OWNER_SUFFIX}'))),
            'unmarked_directories': [
                path.name for path in root.glob(f'cdb-*{DATA_SUFFIX}')
                if path.is_dir() and not owner_marker(path).exists()
            ],
        })
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest='command', required=True)
    for name in ('report', 'cleanup'):
        command = subcommands.add_parser(name)
        command.add_argument('--root', type=Path, required=True)
        if name == 'cleanup':
            command.add_argument('--older-than-hours', type=float, default=24)
            command.add_argument('--apply', action='store_true',
                                 help='actually delete; default is a dry run')
    args = parser.parse_args()
    if args.command == 'report':
        result = storage_report(args.root)
    else:
        result = cleanup_stale_docker_data(
            args.root, args.older_than_hours, apply=args.apply)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result.get('errors') else 0


if __name__ == '__main__':
    raise SystemExit(main())
