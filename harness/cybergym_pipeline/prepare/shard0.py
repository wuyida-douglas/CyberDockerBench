#!/usr/bin/env python3
"""Shard-0-only acquisition and packaging for the ten assigned OSS-Fuzz/ARVO tasks.

Downloads are content checked, cached read-only, atomically published and resumable.
This module never invokes an agent or imports official images into public inputs.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
CACHE = Path('/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cybergym/shard0-cache')
RESULTS = ROOT / 'results/cybergym-preparation/shard0'
IDS = (1513, 1538, 8241, 17715, 61993, 65135, 5797, 5429, 65319, 1461)
META = 'https://raw.githubusercontent.com/n132/ARVO-Meta/main/archive_data/meta/{}.json'
HF = 'https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main/data/arvo/{}/{}'
DB_URL = 'https://github.com/n132/ARVO-Meta/releases/download/v3.0.0/arvo.db'
SRCMAP = 'https://storage.googleapis.com/clusterfuzz-builds/{project}/{project}-{sanitizer}-{stamp}.srcmap.json'
SANITIZERS = {'asan': 'address', 'msan': 'memory', 'ubsan': 'undefined',
              'address': 'address', 'memory': 'memory', 'undefined': 'undefined'}


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def atomic_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.tmp-' + str(os.getpid()))
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n')
    os.replace(tmp, path)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, target: Path, expected: str | None = None) -> Path:
    """Shared read-only cache. Only one process fetches a URL; readers see full files."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file() and target.stat().st_size:
        if expected and sha256(target) != expected:
            raise ValueError(f'cached checksum mismatch: {target}')
        return target
    lockfile = target.with_name(target.name + '.lock')
    lockfile.parent.mkdir(parents=True, exist_ok=True)
    with lockfile.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if target.is_file() and target.stat().st_size:
            return target
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.fetch-', delete=False) as stream:
            tmp = Path(stream.name)
            error = None
            try:
                request = urllib.request.Request(url, headers={'User-Agent': 'cdb-shard0-source-acquisition/1'})
                with urllib.request.urlopen(request, timeout=120) as response:
                    while block := response.read(1024 * 1024):
                        stream.write(block)
                stream.flush()
                os.fsync(stream.fileno())
                if expected and sha256(tmp) != expected:
                    raise ValueError(f'downloaded checksum mismatch: {url}')
                os.chmod(tmp, 0o444)
                os.replace(tmp, target)
            except Exception as exc:
                error = str(exc)
                tmp.unlink(missing_ok=True)
                raise RuntimeError(f'{url}: {error}') from exc
    return target


def fetch_bytes(url: str) -> bytes:
    request = urllib.request.Request(url, headers={'User-Agent': 'cdb-shard0-source-acquisition/1'})
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read()


def checkpoint(i: int, stage: str, **detail: object) -> None:
    atomic_json(RESULTS / f'{i}/checkpoint.json', {'arvo_id': i, 'stage': stage, 'updated_at': now(), **detail})


def description_text(meta: dict) -> str:
    return next(c.get('content', '') for c in meta['report']['comments']
                if c.get('descriptionNum') == 1)


def discover_timestamps(meta: dict) -> tuple[str, str]:
    vulnerable = fixed = None
    for comment in meta['report']['comments']:
        text = comment.get('content', '')
        for url in re.findall(r'https?://oss-fuzz\.com/revisions\?[^\s]+', text):
            match = re.search(r'range=\d{12}:(\d{12})', url)
            if not match:
                continue
            if 'Regressed:' in text[max(0, text.find(url) - 50):text.find(url)]:
                vulnerable = match.group(1)
            if 'Fixed:' in text[max(0, text.find(url) - 50):text.find(url)] or 'verified as fixed in' in text.lower():
                fixed = match.group(1)
    if not vulnerable or not fixed:
        raise ValueError('missing vulnerable/fixed source revision timestamps')
    return vulnerable, fixed


def fuzz_target(meta: dict) -> str:
    description = description_text(meta)
    return (re.search(r'Fuzz target binary:\s*(\S+)', description) or
            re.search(r'Fuzz Target:\s*(\S+)', description)).group(1)


def expected_stack(meta: dict) -> list[str]:
    description = description_text(meta)
    block = description.split('Crash State:', 1)[1].split('Sanitizer:', 1)[0]
    return re.findall(r'^\s+(\S+)\s*$', block, re.MULTILINE)


def acquire(i: int) -> dict:
    record_dir = CACHE / str(i)
    try:
        checkpoint(i, 'downloading_metadata')
        meta_path = download(META.format(i), record_dir / 'meta.json')
        meta = json.loads(meta_path.read_text())
        if meta['localId'] != i:
            raise ValueError('ARVO metadata id mismatch')
        files = {'meta.json': {'url': META.format(i), 'sha256': sha256(meta_path)}}
        expected_listing = json.loads(fetch_bytes(
            f'https://huggingface.co/api/datasets/sunblaze-ucb/cybergym/tree/main/data/arvo/{i}'))
        hashes = {entry['path'].rsplit('/', 1)[-1]: entry.get('lfs', {}).get('oid')
                  for entry in expected_listing}
        for name in ('repo-vul.tar.gz', 'repo-fix.tar.gz', 'description.txt', 'error.txt', 'patch.diff'):
            url = HF.format(i, name)
            path = download(url, record_dir / name, hashes.get(name))
            files[name] = {'url': url, 'sha256': sha256(path), 'bytes': path.stat().st_size}
        timestamps = discover_timestamps(meta)
        project = re.search(r'^Project:\s*(\S+)', description_text(meta), re.MULTILINE).group(1)
        for role, timestamp in zip(('vul', 'fix'), timestamps):
            url = SRCMAP.format(project=project, sanitizer=SANITIZERS[meta['sanitizer']], stamp=timestamp)
            path = download(url, record_dir / f'srcmap-{role}.json')
            revisions = json.loads(path.read_text())
            if not revisions or not all(item.get('rev') for item in revisions.values()):
                raise ValueError(f'empty or incomplete {role} srcmap')
            files[f'srcmap-{role}.json'] = {'url': url, 'sha256': sha256(path), 'bytes': path.stat().st_size}
        manifest = {'arvo_id': i, 'acquired_at': now(), 'source_archives_verified': True,
                    'srcmap_timestamps': dict(zip(('vul', 'fix'), timestamps)), 'files': files}
        atomic_json(RESULTS / f'{i}/acquisition.json', manifest)
        checkpoint(i, 'acquired', files=sorted(files), srcmap_timestamps=timestamps)
        print(f'ACQUIRED {i}: {len(files)} files and two revision maps', flush=True)
        return {'arvo_id': i, 'status': 'acquired', 'files': files}
    except Exception as exc:
        checkpoint(i, 'acquisition_failed', reason=f'{type(exc).__name__}: {exc}')
        return {'arvo_id': i, 'status': 'failed', 'reason': str(exc)}


def inspect(i: int) -> dict:
    meta = json.loads((CACHE / str(i) / 'meta.json').read_text())
    description = next(c.get('content', '') for c in meta['report']['comments'] if c.get('descriptionNum') == 1)
    def field(pattern: str) -> str:
        match = re.search(pattern, description)
        return match.group(1).strip() if match else ''
    stack = re.findall(r'^  (\S+)$', description, re.MULTILINE)
    srcmaps = {role: json.loads((CACHE / str(i) / f'srcmap-{role}.json').read_text())
               for role in ('vul', 'fix')}
    result = {'arvo_id': i, 'project': meta['project'], 'repo': meta.get('repo_addr'),
              'fix': meta.get('fix_commit'), 'sanitizer': meta['sanitizer'], 'engine': meta['fuzzer'],
              'fuzz_target': field(r'Fuzz target binary:\s*(.+)') or field(r'Fuzz Target:\s*(.+)'),
              'crash_type': meta['crash_type'], 'expected_stack': stack, 'srcmaps': srcmaps,
              'files': [p.name for p in (CACHE / str(i)).rglob('*') if p.is_file()]}
    atomic_json(RESULTS / f'{i}/inspect.json', result)
    print(json.dumps(result), flush=True)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('acquire', 'prepare', 'inspect'))
    parser.add_argument('--ids', type=lambda s: [int(x) for x in s.split(',')], default=list(IDS))
    args = parser.parse_args()
    if any(i not in IDS for i in args.ids):
        parser.error('id outside shard-0')
    CACHE.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)
    if args.command == 'acquire':
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(acquire, args.ids))
        atomic_json(RESULTS / 'acquisition-summary.json', {'updated_at': now(), 'results': results})
        return int(any(r['status'] != 'acquired' for r in results))
    if args.command == 'prepare':
        from types import SimpleNamespace
        from harness.cybergym_pipeline.prepare.materialize import prepare_task
        import yaml
        results = []
        for i in args.ids:
            try:
                if not (RESULTS / str(i) / 'acquisition.json').is_file():
                    raise RuntimeError('acquisition must complete before materialization')
                meta = json.loads((CACHE / str(i) / 'meta.json').read_text())
                checkpoint(i, 'materializing')
                config = SimpleNamespace(tasks=ROOT / 'tasks', cache=CACHE,
                                         oss_fuzz_git=CACHE / 'oss-fuzz/.git')
                selection = {'srcmap_timestamps': discover_timestamps(meta),
                             'expected_stack': expected_stack(meta),
                             'record': {'fuzz_target': fuzz_target(meta), 'fuzz_engine': meta['fuzzer'],
                                        'language': 'c' if meta['project'] in {'openssl', 'php-src', 'gpac'} else 'c++'}}
                result = prepare_task({'task_id': f'arvo:{i}', 'project_language': selection['record']['language']},
                                      meta, selection, config)
                atomic_json(RESULTS / f'{i}/materialization.json', result)
                checkpoint(i, 'materialized_unverified', fuzz_target=selection['record']['fuzz_target'])
                results.append(result)
                print('MATERIALIZED', result, flush=True)
            except Exception as exc:
                checkpoint(i, 'materialization_failed', reason=f'{type(exc).__name__}: {exc}')
                results.append({'arvo_id': i, 'status': 'failed', 'reason': str(exc)})
        atomic_json(RESULTS / 'materialization-summary.json', {'updated_at': now(), 'results': results})
        return int(any(r.get('status') == 'failed' for r in results))
    for i in args.ids:
        inspect(i)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
