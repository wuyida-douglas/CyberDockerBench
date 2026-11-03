#!/usr/bin/env python3
"""Shard-1 source acquisition, packaging, reference verification and audit.

Only the ten assigned ARVO tasks are touched. No solving agent is invoked.
Reference images are used exclusively by the private worker-side oracle.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
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

from harness.cybergym_pipeline.prepare.audit import audit_task, audit_tar, is_executable_bytes
from harness.cybergym_pipeline.prepare.materialize import (
    INSTRUCTION, _cleaned_tar_bytes, historical_recipe,
    parse_sanitizer, sanitize_text, sha256, source_timestamp,
)
from harness.cybergym_pipeline.prepare.verify import pull_reference, verify_task
CACHE = Path('/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cybergym/shard1-cache')
RESULTS = ROOT / 'results/cybergym-preparation/shard1'
TASKS = ROOT / 'tasks'
WORKER = 'root@100.96.153.163'
IDS = (1976, 3956, 6483, 1621, 8505, 20200, 53118, 33340, 368, 759)
META = 'https://raw.githubusercontent.com/n132/ARVO-Meta/main/archive_data/meta/{}.json'
HF = 'https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main/data/arvo/{}/{}'
# The report's project is libjpeg-turbo.dev, but its build recipe lives here.
RECIPE_PROJECT = {'libjpeg-turbo.dev': 'libjpeg-turbo'}
SANITIZER_BUCKET = {'address': '', 'memory': '', 'undefined': ''}


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_json(path: Path, value: object) -> None:
    """Use a unique sibling temporary and atomic rename, including on GPFS2."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.tmp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.tmp-', dir=path.parent)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def checkpoint(issue: int, stage: str, **details: object) -> None:
    write_json(RESULTS / str(issue) / 'checkpoint.json', {
        'arvo_id': issue, 'stage': stage, 'updated_at': now(), **details,
    })


def download(url: str, target: Path, expected: str | None = None) -> Path:
    """A resumable shared cache whose readers only see checksum-complete files."""
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(target.name + '.lock')
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if target.is_file() and target.stat().st_size:
            actual = sha256(target)
            if expected and actual != expected:
                raise ValueError(f'cached checksum mismatch: {target}')
            return target
        error = None
        for attempt in range(1, 5):
            temporary = None
            try:
                request = urllib.request.Request(url, headers={'User-Agent': 'cdb-shard1-preparation/1'})
                with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.fetch-', delete=False) as stream:
                    temporary = Path(stream.name)
                    with urllib.request.urlopen(request, timeout=180) as response:
                        while block := response.read(1024 * 1024):
                            stream.write(block)
                    stream.flush()
                    os.fsync(stream.fileno())
                if not temporary.stat().st_size:
                    raise ValueError('empty download')
                actual = sha256(temporary)
                if expected and actual != expected:
                    raise ValueError(f'sha256 mismatch: expected {expected}, got {actual}')
                os.chmod(temporary, 0o444)
                os.replace(temporary, target)
                return target
            except Exception as exc:
                error = exc
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
                if attempt < 4:
                    time.sleep(attempt * 2)
        raise RuntimeError(f'{url}: {type(error).__name__}: {error}') from error


def fetch_bytes(url: str) -> bytes:
    request = urllib.request.Request(url, headers={'User-Agent': 'cdb-shard1-preparation/1'})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def report_description(meta: dict) -> str:
    return next(c.get('content', '') for c in meta['report']['comments']
                if c.get('descriptionNum') == 1)


def discover_timestamps(meta: dict) -> tuple[str, str]:
    vulnerable = fixed = None
    for comment in meta['report']['comments']:
        text = comment.get('content', '')
        for url in re.findall(r'https?://[^\s]+/revisions\?[^\s]+', text):
            match = re.search(r'range=\d{12}:(\d{12})', url)
            if not match:
                continue
            prefix = text[max(0, text.find(url) - 60):text.find(url)]
            if 'Regressed:' in prefix and vulnerable is None:
                vulnerable = match.group(1)
            if ('Fixed:' in prefix or 'verified as fixed' in text.lower()) and fixed is None:
                fixed = match.group(1)
    if not vulnerable or not fixed:
        raise ValueError('no explicit vulnerable/fixed build ranges in upstream report')
    return vulnerable, fixed


def fuzz_target(meta: dict) -> str:
    text = report_description(meta)
    match = re.search(r'Fuzz target binary:\s*(\S+)', text) or re.search(r'Fuzz Target:\s*(\S+)', text)
    if not match:
        raise ValueError('upstream report does not identify the fuzz target')
    return match.group(1)


def expected_stack(meta: dict) -> list[str]:
    text = report_description(meta).split('Crash State:', 1)[1]
    text = re.split(r'\n\s*\n|Sanitizer:', text, maxsplit=1)[0]
    frames = re.findall(r'^\s+(\S+)\s*$', text, re.MULTILINE)
    if not frames:
        raise ValueError('upstream report has no expected stack')
    return frames


def historical_source_recipe(oss_fuzz_git: Path, project: str, timestamp: datetime.datetime,
                             output: Path) -> dict:
    """Recover old recipes whose Dockerfile copies build.sh from the source tree.

    The shared historical_recipe intentionally requires a project-level build.sh.
    Keep that behavior for other shards, but handle this authentic historical
    layout locally, with every extracted file recorded and checked for binaries.
    """
    stamp = timestamp.isoformat().replace('+00:00', 'Z')
    commit = subprocess.check_output([
        'git', f'--git-dir={oss_fuzz_git}', 'log', f'--before={stamp}',
        '-n1', '--format=%H',
    ], text=True).strip()
    if not commit:
        raise ValueError(f'no OSS-Fuzz history at {stamp}')
    names: list[str] = []
    for root in (f'projects/{project}', f'targets/{project}'):
        names = subprocess.check_output([
            'git', f'--git-dir={oss_fuzz_git}', 'ls-tree', '-r', '--name-only', commit, '--', root,
        ], text=True).splitlines()
        if names:
            break
    required = {'Dockerfile', 'project.yaml'}
    basenames = {PurePosixPath(name).name for name in names}
    if not required.issubset(basenames):
        raise ValueError(f'incomplete historical recipe {project}@{commit}: missing {required - basenames}')
    output.mkdir(parents=True, exist_ok=True)
    files = {}
    for name in names:
        data = subprocess.check_output(['git', f'--git-dir={oss_fuzz_git}', 'show', f'{commit}:{name}'])
        relative = PurePosixPath(name).relative_to(root)
        if any(part in {'.git', '.svn', '.hg', '__pycache__'} for part in relative.parts):
            continue
        if is_executable_bytes(data[:8192]):
            raise ValueError(f'compiled recipe asset: {name}')
        destination = output.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        files[str(relative)] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    provenance = {
        'upstream': 'https://github.com/google/oss-fuzz', 'commit': commit,
        'project_directory': root, 'srcmap_timestamp': stamp,
        'source': 'historical OSS-Fuzz git; not extracted from any reference image',
        'files': files,
    }
    write_text(output / 'provenance.json', json.dumps(provenance, indent=2) + '\n')
    return provenance


def source_recipe(oss_fuzz_git: Path, project: str, timestamp: datetime.datetime,
                  output: Path) -> dict:
    try:
        return historical_recipe(oss_fuzz_git, project, timestamp, output)
    except ValueError as exc:
        if 'missing' not in str(exc) or 'build.sh' not in str(exc):
            raise
        return historical_source_recipe(oss_fuzz_git, project, timestamp, output)


def srcmap_candidates(meta: dict, timestamp: str) -> list[str]:
    sanitizer = parse_sanitizer(meta['sanitizer'])[1]
    project = meta['project']
    # The historical build's directory may differ from its OSS-Fuzz recipe name.
    map_project = 'libjpeg-turbo' if project == 'libjpeg-turbo.dev' else project
    buckets = ['']
    if project == 'libjpeg-turbo' and timestamp.startswith('202104'):
        # This report explicitly identifies the i386 ASan build.
        buckets = ['-i386', '']
    if meta['fuzzer'] == 'afl':
        buckets = ['-afl', '']
    return [f'https://storage.googleapis.com/clusterfuzz-builds{bucket}/{map_project}/'
            f'{map_project}-{sanitizer}-{timestamp}.srcmap.json' for bucket in buckets]


def acquire(issue: int) -> dict:
    try:
        checkpoint(issue, 'acquiring')
        raw = CACHE / str(issue)
        meta_path = download(META.format(issue), raw / 'meta.json')
        meta = json.loads(meta_path.read_text(encoding='utf-8'))
        if meta['localId'] != issue:
            raise ValueError('ARVO-Meta localId mismatch')
        listing = json.loads(fetch_bytes(
            f'https://huggingface.co/api/datasets/sunblaze-ucb/cybergym/tree/main/data/arvo/{issue}'))
        expected = {entry['path'].rsplit('/', 1)[-1]: entry.get('lfs', {}).get('oid')
                    for entry in listing}
        files = {'meta.json': {'url': META.format(issue), 'sha256': sha256(meta_path)}}
        for name in ('repo-vul.tar.gz', 'repo-fix.tar.gz', 'description.txt', 'error.txt'):
            if not expected.get(name):
                raise ValueError(f'public dataset listing lacks checksum for {name}')
            path = download(HF.format(issue, name), raw / name, expected[name])
            files[name] = {'url': HF.format(issue, name), 'sha256': sha256(path),
                           'bytes': path.stat().st_size}
        timestamps = discover_timestamps(meta)
        for role, timestamp in zip(('vul', 'fix'), timestamps):
            failures = []
            for url in srcmap_candidates(meta, timestamp):
                try:
                    path = download(url, raw / f'srcmap-{role}.json')
                    revisions = json.loads(path.read_text(encoding='utf-8'))
                    if not revisions or not all(isinstance(item, dict) and item.get('rev')
                                                for item in revisions.values()):
                        raise ValueError('srcmap has empty revision entries')
                    files[f'srcmap-{role}.json'] = {
                        'url': url, 'sha256': sha256(path), 'bytes': path.stat().st_size,
                        'revisions': revisions,
                    }
                    break
                except Exception as exc:
                    failures.append(f'{url}: {exc}')
            else:
                raise RuntimeError('; '.join(failures))
        record = {'arvo_id': issue, 'status': 'acquired', 'acquired_at': now(),
                  'srcmap_timestamps': dict(zip(('vul', 'fix'), timestamps)), 'files': files}
        write_json(RESULTS / str(issue) / 'acquisition.json', record)
        checkpoint(issue, 'acquired', srcmap_timestamps=timestamps)
        print('ACQUIRED', issue, timestamps, flush=True)
        return record
    except Exception as exc:
        reason = f'{type(exc).__name__}: {exc}'
        checkpoint(issue, 'acquisition_failed', reason=reason)
        print('ACQUISITION FAILED', issue, reason, flush=True)
        return {'arvo_id': issue, 'status': 'failed', 'stage': 'acquire', 'reason': reason}


def supplement_harness(raw: Path, recipe: Path, role: str) -> dict:
    """Recover harness files from the exact supplied source, never an image.

    Older libjpeg-turbo Dockerfiles run ``cp fuzz/build.sh $SRC/`` rather than
    carrying a separate project-level build.sh. Keep that actual file and its
    precise source member in the public recipe bundle.
    """
    archive_path = raw / f'sources-{role}.tar.gz'
    if not archive_path.is_file():
        archive_path = raw / f'repo-{role}.tar.gz'
    supplements = {}
    build_destination = recipe / 'build.sh'
    with tarfile.open(archive_path, 'r:*') as archive:
        members = {member.name: member for member in archive.getmembers() if member.isfile()}
        selected = []
        if not build_destination.is_file():
            matches = [m for n, m in members.items() if n.endswith('/fuzz/build.sh')]
            if len(matches) != 1:
                raise ValueError(f'{role}: incomplete historical recipe and no unique source build.sh')
            selected.append((matches[0], build_destination))
        for name, member in members.items():
            if (name.endswith(('/fuzz/build.sh', '/fuzz/decompress.cc', '/fuzz/compress.cc',
                               '/fuzz/transform.cc', '/fuzz/decompress_yuv.cc', '/fuzz/compress_yuv.cc',
                               '/tools/oss-fuzzshark/fuzzshark.c', '/tools/oss-fuzzshark/build.sh',
                               '/src/tools/ftfuzzer/ftfuzzer.cc'))):
                selected.append((member, recipe / 'upstream-harness' / PurePosixPath(name).name))
        for member, destination in selected:
            data = archive.extractfile(member).read()
            if is_executable_bytes(data[:8192]):
                raise ValueError(f'compiled harness supplement: {member.name}')
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            supplements[str(destination.relative_to(recipe))] = {
                'source_archive': f'sources-{role}.tar.gz', 'source_member': member.name,
                'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                'reason': 'actual in-tree upstream fuzz harness/build recipe referenced by historical Dockerfile',
            }
    if supplements:
        write_json(recipe / 'supplemental-harness-provenance.json', supplements)
        provenance = json.loads((recipe / 'provenance.json').read_text(encoding='utf-8'))
        provenance['supplemental_harness'] = supplements
        # The upstream OSS-Fuzz commit contains Dockerfile/project.yaml, not the
        # in-tree build.sh supplied by the exact role's source archive.
        write_json(recipe / 'provenance.json', provenance)
    return supplements


def strip_build_state(raw: Path, role: str) -> dict:
    """Remove generated build/cache state while retaining actual source recipes.

    The cache is immutable; replace the cleaned derivative atomically and
    refresh its cleaning record. This is used only after the original archive
    has already passed the binary/VCS/reproducer filters.
    """
    archive_path = raw / f'sources-{role}.tar.gz'
    if not archive_path.is_file():
        return {'changed': False, 'reason': 'clean archive not acquired yet'}
    old_report_path = raw / f'cleaning-{role}.json'
    old_report = json.loads(old_report_path.read_text(encoding='utf-8'))
    generated = []
    with tarfile.open(archive_path, 'r:gz') as archive:
        for member in archive:
            pure = PurePosixPath(member.name)
            reason = None
            if any(part in {'CMakeFiles', 'CMakeTmp', '_deps', '.deps', '.libs'} for part in pure.parts):
                reason = 'generated build/cache directory'
            elif pure.name in {'CMakeCache.txt', 'cmake_install.cmake', 'cmake_uninstall.cmake',
                               'CTestTestfile.cmake', 'compile_commands.json', 'build.ninja',
                               '.ninja_deps', '.ninja_log', 'config.log', 'config.status', 'libtool'}:
                reason = 'generated build/cache file'
            elif member.isfile() and pure.name == 'Makefile':
                header = archive.extractfile(member).read(4096)
                if (b'Generated from Makefile.in by configure' in header
                        or header.startswith(b'# CMAKE generated file: DO NOT EDIT!')):
                    reason = 'Makefile generated by configure/CMake; source templates retained'
            if reason:
                generated.append({'path': member.name, 'reason': reason})
    if not generated:
        return {'changed': False, 'removed': []}
    rejected = {item['path'] for item in generated}
    temporary = archive_path.with_name(f'.{archive_path.name}.source-clean-')
    fd, name = tempfile.mkstemp(prefix=temporary.name, dir=archive_path.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        kept = 0
        with tarfile.open(archive_path, 'r:gz') as source, tarfile.open(temporary, 'w:gz', compresslevel=6) as target:
            for member in source:
                if member.name in rejected:
                    continue
                if member.isdir():
                    target.addfile(member)
                    continue
                data = source.extractfile(member).read()
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                info.mode = member.mode & 0o777
                info.mtime = member.mtime
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                target.addfile(info, io.BytesIO(data))
                kept += 1
        problems = audit_tar(temporary)['issues']
        if problems:
            raise ValueError(f'{role}: regenerated source failed binary/VCS audit: {problems[:5]}')
        os.replace(temporary, archive_path)
    finally:
        temporary.unlink(missing_ok=True)
    report = dict(old_report)
    report.update({'source_archive_sha256': sha256(raw / f'repo-{role}.tar.gz'),
                   'output_archive_sha256': sha256(archive_path), 'kept_files': kept,
                   'removed': old_report.get('removed', []) + generated,
                   'source_format': 'CyberGym public source archive; independently cleaned',
                   'policy': 'No VCS metadata, /out, compiled outputs, generated build/cache state, symlinks, reference images or reproducers.'})
    write_json(old_report_path, report)
    return {'changed': True, 'removed': generated, 'kept_files': kept,
            'output_archive_sha256': report['output_archive_sha256']}


def redact_source_issue_links(raw: Path, role: str) -> dict:
    """Redact issue/reproducer URLs without discarding historical source notes."""
    archive_path = raw / f'sources-{role}.tar.gz'
    if not archive_path.is_file():
        return {'changed': False, 'reason': 'clean archive not acquired yet'}
    old_report_path = raw / f'cleaning-{role}.json'
    old_report = json.loads(old_report_path.read_text(encoding='utf-8'))
    prior = {item['path']: item for item in old_report.get('redactions', [])}
    pattern = re.compile(
        rb'(?:https?://(?:bugs\.chromium\.org/p/oss-fuzz/issues/detail\?id=\d+'
        rb'|oss-fuzz\.com/download[^\s\x00]*testcase_id=\d+[^\s\x00]*)|testcase_id=\d+)')
    fd, name = tempfile.mkstemp(prefix='.issue-redacted-', dir=archive_path.parent)
    os.close(fd)
    temporary = Path(name)
    redactions = []
    kept = 0
    try:
        with tarfile.open(archive_path, 'r:gz') as source, tarfile.open(temporary, 'w:gz', compresslevel=6) as target:
            for member in source:
                if member.isdir():
                    target.addfile(member)
                    continue
                original = source.extractfile(member).read()
                data = pattern.sub(b'[upstream issue/reproducer link removed]', original)
                if data != original:
                    redactions.append({'path': member.name, 'reason': 'raw OSS-Fuzz issue/reproducer URL removed',
                                       'original_sha256': hashlib.sha256(original).hexdigest(),
                                       'redacted_sha256': hashlib.sha256(data).hexdigest(),
                                       'source_content_preserved': True})
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                info.mode = member.mode & 0o777
                info.mtime = member.mtime
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                target.addfile(info, io.BytesIO(data))
                kept += 1
        redactions.sort(key=lambda item: item['path'])
        if not redactions:
            temporary.unlink(missing_ok=True)
            return {'changed': False, 'redactions': list(prior.values())}
        if prior and redactions != sorted(prior.values(), key=lambda item: item['path']):
            raise ValueError(f'{role}: unexpected repeat redaction changed source')
        if audit_tar(temporary)['issues']:
            raise ValueError(f'{role}: redacted source failed source audit')
        with tarfile.open(temporary, 'r:gz') as check:
            for member in check:
                if member.isfile() and pattern.search(check.extractfile(member).read()):
                    raise ValueError(f'{role}: raw issue/reproducer URL remains in {member.name}')
        os.replace(temporary, archive_path)
    finally:
        temporary.unlink(missing_ok=True)
    report = dict(old_report)
    report.update({'source_archive_sha256': sha256(raw / f'repo-{role}.tar.gz'),
                   'output_archive_sha256': sha256(archive_path), 'kept_files': kept,
                   'redactions': redactions,
                   'policy': old_report.get('policy', '') + '; raw issue/reproducer URLs redacted in public source notes.'})
    write_json(old_report_path, report)
    return {'changed': True, 'redactions': redactions}


def materialize(issue: int) -> dict:
    task_dir = TASKS / f'cybergym-arvo-{issue}'
    try:
        checkpoint(issue, 'materializing')
        raw = CACHE / str(issue)
        acquisition = json.loads((RESULTS / str(issue) / 'acquisition.json').read_text(encoding='utf-8'))
        meta = json.loads((raw / 'meta.json').read_text(encoding='utf-8'))
        timestamps = tuple(acquisition['srcmap_timestamps'][role] for role in ('vul', 'fix'))
        sanitizer, sanitizer_env = parse_sanitizer(meta['sanitizer'])
        target = fuzz_target(meta)
        stack = expected_stack(meta)
        temporary = Path(tempfile.mkdtemp(prefix=f'.input-{issue}-', dir=task_dir.parent))
        try:
            for role, timestamp in zip(('vul', 'fix'), timestamps):
                cleaned = raw / f'sources-{role}.tar.gz'
                if not cleaned.is_file():
                    part = cleaned.with_suffix('.tar.gz.part')
                    report = _cleaned_tar_bytes(raw / f'repo-{role}.tar.gz', part)
                    os.replace(part, cleaned)
                    write_json(raw / f'cleaning-{role}.json', report)
                if issue in (1621, 53118):
                    strip_build_state(raw, role)
                if issue in (368, 759):
                    redact_source_issue_links(raw, role)
                problems = audit_tar(cleaned)['issues']
                if problems:
                    raise ValueError(f'unsafe cleaned {role} source: {problems[:4]}')
                for name in (f'sources-{role}.tar.gz', f'srcmap-{role}.json', f'cleaning-{role}.json'):
                    shutil.copy2(raw / name, temporary / name)
                recipe_project = RECIPE_PROJECT.get(meta['project'], meta['project'])
                recipe = source_recipe(CACHE / 'oss-fuzz/.git', recipe_project,
                                       source_timestamp(f'x-{timestamp}.srcmap.json'),
                                       temporary / 'oss-fuzz' / role)
                supplement_harness(raw, temporary / 'oss-fuzz' / role, role)
                revisions = json.loads((raw / f'srcmap-{role}.json').read_text(encoding='utf-8'))
                write_json(temporary / f'oss-fuzz-{role}.json', {
                    'revision': recipe['commit'], 'srcmap_timestamp': timestamp,
                    'recipe_path': f'oss-fuzz/{role}', 'source': recipe['source'],
                    'source_revisions': revisions,
                })
            description = sanitize_text((raw / 'description.txt').read_text(encoding='utf-8', errors='replace'))
            write_text(temporary / 'description.md',
                       f'# {meta["project"]} / arvo:{issue}\n\n{description.strip()}\n\n'
                       '## Public provenance\n\nHistorical OSS-Fuzz source and recipes; '
                       'no raw issue, reference image or private reproducer is included.\n')
            write_text(temporary / 'error.txt', sanitize_text(
                (raw / 'error.txt').read_text(encoding='utf-8', errors='replace')))
            values = {'project': meta['project'], 'upstream_task_id': f'arvo:{issue}',
                      'sanitizer': sanitizer, 'sanitizer_env': sanitizer_env,
                      'fuzz_target': target, 'fuzz_engine': meta['fuzzer']}
            write_json(temporary / 'normal-input-contract.json', {
                'status': 'not_bundled',
                'requirement': 'Author a normal non-crashing smoke input and test it on both versions.',
                'seed_source': 'No verified public historical seed corpus has been imported.',
            })
            write_json(temporary / 'target.json', {
                'project': meta['project'], 'upstream_task_id': f'arvo:{issue}',
                'engine': meta['fuzzer'], 'sanitizer': sanitizer, 'sanitizer_env': sanitizer_env,
                'fuzz_target': target, 'crash_type': meta['crash_type'],
                'source_revisions': {role: acquisition['files'][f'srcmap-{role}.json']['revisions']
                                     for role in ('vul', 'fix')},
            })
            files = {str(path.relative_to(temporary)): {'sha256': sha256(path), 'bytes': path.stat().st_size}
                     for path in sorted(temporary.rglob('*')) if path.is_file() and path.name != 'manifest.json'}
            write_json(temporary / 'manifest.json', {
                'schema_version': 1, 'task_id': f'cybergym-arvo-{issue}',
                'source_versions': ['vul', 'fix'], 'private_inputs_excluded': True, 'files': files,
            })
            # Only shard-owned public input is replaced; gold is never staged here.
            old = task_dir / 'input'
            if old.exists():
                shutil.rmtree(old)
            os.replace(temporary, old)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        task_dir.mkdir(parents=True, exist_ok=True)
        (task_dir / 'gold').mkdir(exist_ok=True)
        # Superseded single-version inputs and patch solutions are not part of
        # this dual-version task. Keep the already acquired private gold intact.
        for legacy in ('materials', 'solution', 'tests'):
            shutil.rmtree(task_dir / legacy, ignore_errors=True)
        instruction = INSTRUCTION.format(**values)
        write_text(task_dir / 'instruction.md', instruction)
        write_text(task_dir / 'input' / 'TASK.md', instruction)
        # TASK.md is created after the first digest pass; include it in the manifest.
        manifest_path = task_dir / 'input' / 'manifest.json'
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        manifest['files']['TASK.md'] = {'sha256': sha256(task_dir / 'input' / 'TASK.md'),
                                       'bytes': (task_dir / 'input' / 'TASK.md').stat().st_size}
        write_json(manifest_path, manifest)
        metadata = {
            'task_id': task_dir.name, 'family': 'cybergym', 'task_type': 'binary-env-synthesis',
            'project': meta['project'], 'upstream_task_id': f'arvo:{issue}',
            'sanitizer': sanitizer, 'sanitizer_env': sanitizer_env,
            'fuzz_target': target, 'fuzz_engine': meta['fuzzer'],
            'language': 'c++' if meta['project'] in ('poppler', 'wireshark', 'freetype2') else 'c',
            'crash_type': meta['crash_type'], 'expected_stack': stack,
            'reference_verified': False,
            'private': {'gold_poc': 'gold/poc', 'reference_manifest': 'gold/reference-manifest.json',
                        'verify_reference': 'gold/verify_reference.json'},
            'public_input': 'input', 'timeout_sec': 18000, 'max_turns': 280,
            'resources': {'cpu': 4, 'memory_gb': 12, 'disk_gb': 30},
        }
        import yaml
        write_text(task_dir / 'metadata.yaml', yaml.safe_dump(metadata, sort_keys=False))
        evidence_path = task_dir / 'gold' / 'verify_reference.json'
        evidence = json.loads(evidence_path.read_text(encoding='utf-8')) if evidence_path.is_file() else {}
        if has_reference_evidence(task_dir, evidence):
            metadata['reference_verified'] = True
            metadata['reference_verification'] = {
                'verified_at': evidence.get('finished_at'), 'worker': evidence.get('worker'),
                'image_digests': {role: details.get('official_manifest_digest') or details.get('digest')
                                  for role, details in (evidence.get('images') or {}).items()},
                'evidence': 'gold/verify_reference.json',
                'resumed_from_existing_evidence': True,
            }
            write_text(task_dir / 'metadata.yaml', yaml.safe_dump(metadata, sort_keys=False))
        write_json(task_dir / 'gold' / 'upstream-private.json', {
            'upstream': meta, 'record': {'fuzz_target': target, 'fuzz_engine': meta['fuzzer'],
                                         'expected_stack': stack},
            'srcmap_timestamps': dict(zip(('vul', 'fix'), timestamps)),
            'srcmap_urls': {role: acquisition['files'][f'srcmap-{role}.json']['url']
                            for role in ('vul', 'fix')},
            'provenance': 'ARVO-Meta report and authoritative ClusterFuzz build srcmaps; private only',
        })
        result = {'arvo_id': issue, 'task_id': task_dir.name,
                  'status': 'reference_verified' if metadata['reference_verified'] else 'materialized_unverified',
                  'project': meta['project'], 'sanitizer': sanitizer, 'fuzz_target': target,
                  'srcmap_timestamps': dict(zip(('vul', 'fix'), timestamps))}
        write_json(RESULTS / str(issue) / 'materialization.json', result)
        checkpoint(issue, 'reference_verified' if metadata['reference_verified'] else 'materialized_unverified',
                   fuzz_target=target)
        print('MATERIALIZED', issue, flush=True)
        return result
    except Exception as exc:
        reason = f'{type(exc).__name__}: {exc}'
        checkpoint(issue, 'materialization_failed', reason=reason)
        print('MATERIALIZATION FAILED', issue, reason, flush=True)
        return {'arvo_id': issue, 'status': 'failed', 'stage': 'materialize', 'reason': reason}


def prefetch_worker_images(issue: int) -> dict:
    task_dir = TASKS / f'cybergym-arvo-{issue}'
    logs = task_dir / 'gold' / 'reference-logs'
    records = {}
    try:
        for role in ('vul', 'fix'):
            image = f'n132/arvo:{issue}-{role}'
            records[role] = pull_reference(image, WORKER, CACHE / 'reference-images', logs, attempts=4)
        checkpoint(issue, 'worker_images_ready', images=records)
        return {'arvo_id': issue, 'status': 'images_ready'}
    except Exception as exc:
        reason = f'{type(exc).__name__}: {exc}'
        checkpoint(issue, 'worker_image_download_failed', reason=reason, images=records)
        return {'arvo_id': issue, 'status': 'failed', 'stage': 'worker_images', 'reason': reason}


def verify(issue: int) -> dict:
    task_dir = TASKS / f'cybergym-arvo-{issue}'
    try:
        checkpoint(issue, 'verifying_reference', worker=WORKER)
        evidence = verify_task(task_dir, WORKER, CACHE / 'reference-images', timeout=600)
        write_json(RESULTS / str(issue) / 'verify_reference.json', evidence)
        checkpoint(issue, 'reference_verified' if evidence['passed'] else 'reference_failed',
                   failures=evidence['failures'])
        print('VERIFIED' if evidence['passed'] else 'REFERENCE FAILED', issue,
              evidence['failures'], flush=True)
        return {'arvo_id': issue, 'status': 'verified' if evidence['passed'] else 'failed',
                'passed': evidence['passed'], 'failures': evidence['failures']}
    except Exception as exc:
        reason = f'{type(exc).__name__}: {exc}'
        checkpoint(issue, 'reference_failed', reason=reason)
        return {'arvo_id': issue, 'status': 'failed', 'stage': 'verify', 'reason': reason}


def has_reference_evidence(task_dir: Path, evidence: dict) -> bool:
    """Recognize an existing real differential; never create a passing claim."""
    if not (evidence.get('passed') is True and evidence.get('reference_verified') is True):
        return False
    poc = task_dir / 'gold' / 'poc'
    manifest_path = task_dir / 'gold' / 'reference-manifest.json'
    if not poc.is_file() or not manifest_path.is_file():
        return False
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if (manifest.get('gold_poc') or {}).get('sha256') != sha256(poc):
        return False
    if evidence.get('gold_poc_sha256') != manifest['gold_poc']['sha256']:
        return False
    runs = evidence.get('runs') or {}
    for role in ('vul', 'fix'):
        run = runs.get(role) or {}
        log = task_dir / 'gold' / 'reference-logs' / str(run.get('log', ''))
        if not run.get('command') or not run.get('digest') or not run.get('log'):
            return False
        if run.get('passed') is not True or run.get('timed_out') is True or not log.is_file():
            return False
        if sha256(log) != run.get('log_sha256'):
            return False
        image = (evidence.get('images') or {}).get(role) or {}
        if image.get('digest') != run.get('digest'):
            return False
    vulnerable = runs['vul']
    if not (vulnerable.get('expected_sanitizer_observed') is True
            and vulnerable.get('crash_type_observed') is True
            and all((vulnerable.get('expected_stack_observed') or {}).values())):
        return False
    return runs['fix'].get('any_sanitizer_observed') is False and runs['fix'].get('return_code') == 0


def normalize_metadata(issue: int) -> dict:
    """Reconcile a resumed task with cached evidence, without running a reference."""
    task_dir = TASKS / f'cybergym-arvo-{issue}'
    metadata_path = task_dir / 'metadata.yaml'
    import yaml
    metadata = yaml.safe_load(metadata_path.read_text(encoding='utf-8'))
    if metadata.get('family') != 'cybergym' or metadata.get('task_type') != 'binary-env-synthesis':
        raise ValueError(f'{issue}: task was not materialized by this shard')
    materialization = json.loads((RESULTS / str(issue) / 'materialization.json').read_text(encoding='utf-8'))
    sanitizer = materialization['sanitizer']
    if sanitizer not in {'ASan', 'MSan', 'UBSan'}:
        raise ValueError(f'{issue}: non-normalized sanitizer {sanitizer!r}')
    if not materialization.get('fuzz_target') or not metadata.get('expected_stack') or not metadata.get('crash_type'):
        raise ValueError(f'{issue}: missing real target, crash type or expected stack')
    if metadata.get('fuzz_target') != materialization['fuzz_target']:
        raise ValueError(f'{issue}: target mismatch with upstream acquisition record')
    sanitizer_env = {'ASan': 'address', 'MSan': 'memory', 'UBSan': 'undefined'}[sanitizer]
    evidence_path = task_dir / 'gold' / 'verify_reference.json'
    evidence = json.loads(evidence_path.read_text(encoding='utf-8')) if evidence_path.is_file() else {}
    verified = has_reference_evidence(task_dir, evidence)
    metadata.update({'sanitizer': sanitizer, 'sanitizer_env': sanitizer_env,
                     'reference_verified': verified})
    if verified:
        metadata['reference_verification'] = {
            'verified_at': evidence.get('finished_at'), 'worker': evidence.get('worker'),
            'image_digests': {role: details.get('official_manifest_digest') or details.get('digest')
                              for role, details in (evidence.get('images') or {}).items()},
            'evidence': 'gold/verify_reference.json',
            'resumed_from_existing_evidence': True,
        }
    else:
        metadata.pop('reference_verification', None)
    write_text(metadata_path, yaml.safe_dump(metadata, sort_keys=False))
    cp_path = RESULTS / str(issue) / 'checkpoint.json'
    cp = json.loads(cp_path.read_text(encoding='utf-8')) if cp_path.is_file() else {}
    stage = 'reference_verified' if verified else 'public_ready_reference_pending'
    checkpoint(issue, stage, errors=cp.get('errors', []))
    return {'arvo_id': issue, 'reference_verified': verified,
            'sanitizer': sanitizer, 'fuzz_target': metadata['fuzz_target']}


def audit(issue: int) -> dict:
    task_dir = TASKS / f'cybergym-arvo-{issue}'
    try:
        # Public preparation is deliberately independent of private reference verification.
        report = audit_task(task_dir, require_verified=False)
        metadata = normalize_metadata(issue)
        report['reference_verified'] = metadata['reference_verified']
        report['reference_verification_required'] = not metadata['reference_verified']
        write_json(RESULTS / str(issue) / 'audit.json', report)
        if metadata['reference_verified']:
            strict = audit_task(task_dir, require_verified=True)
            write_json(RESULTS / str(issue) / 'audit-with-reference.json', strict)
            if not strict['passed']:
                report['passed'] = report['valid'] = False
                report['errors'].extend(strict['errors'])
                report['issues'].extend(strict['errors'])
                write_json(RESULTS / str(issue) / 'audit.json', report)
        checkpoint(issue, ('reference_verified' if metadata['reference_verified']
                           else 'public_ready_reference_pending') if report['passed'] else 'audit_failed',
                   errors=report['errors'])
        print('PUBLIC AUDIT', issue, report['passed'], report['errors'][:3], flush=True)
        return report
    except Exception as exc:
        report = {'task_id': task_dir.name, 'passed': False, 'valid': False,
                  'errors': [f'{type(exc).__name__}: {exc}']}
        write_json(RESULTS / str(issue) / 'audit.json', report)
        checkpoint(issue, 'audit_failed', errors=report['errors'])
        return report


def summary(ids: list[int]) -> dict:
    import yaml
    from collections import Counter
    rows = []
    for issue in ids:
        task_dir = TASKS / f'cybergym-arvo-{issue}'
        checkpoint_path = RESULTS / str(issue) / 'checkpoint.json'
        cp = json.loads(checkpoint_path.read_text(encoding='utf-8')) if checkpoint_path.is_file() else {}
        metadata_path = task_dir / 'metadata.yaml'
        metadata = yaml.safe_load(metadata_path.read_text(encoding='utf-8')) if metadata_path.is_file() else {}
        verify_path = task_dir / 'gold' / 'verify_reference.json'
        evidence = json.loads(verify_path.read_text(encoding='utf-8')) if verify_path.is_file() else {}
        audit_path = RESULTS / str(issue) / 'audit.json'
        audit_report = json.loads(audit_path.read_text(encoding='utf-8')) if audit_path.is_file() else {}
        passed = metadata.get('reference_verified') is True and evidence.get('passed') is True and audit_report.get('passed') is True
        reference_verified = metadata.get('reference_verified') is True and has_reference_evidence(task_dir, evidence)
        public_ready = (audit_report.get('passed') is True
                        and bool(metadata.get('fuzz_target')) and bool(metadata.get('expected_stack'))
                        and metadata.get('sanitizer') in {'ASan', 'MSan', 'UBSan'})
        rows.append({'arvo_id': issue, 'task_id': task_dir.name, 'project': metadata.get('project'),
                     'sanitizer': metadata.get('sanitizer'), 'sanitizer_env': metadata.get('sanitizer_env'),
                     'fuzz_target': metadata.get('fuzz_target'), 'crash_type': metadata.get('crash_type'),
                     'expected_stack': metadata.get('expected_stack'),
                     'passed': passed and reference_verified, 'public_ready': public_ready,
                     'reference_verified': reference_verified,
                     'reference_verification_required': not reference_verified,
                     'audit_passed': audit_report.get('passed') is True, 'stage': cp.get('stage'),
                     'failures': evidence.get('failures', []), 'errors': audit_report.get('errors', []),
                     'evidence': str(verify_path.relative_to(ROOT)) if reference_verified else None})
    verified = [row for row in rows if row['reference_verified']]
    public_ready = [row for row in rows if row['public_ready']]
    result = {
        'schema_version': 1, 'shard': 1, 'generated_at': now(), 'worker': WORKER,
        'requested_ids': ids, 'requested': len(ids),
        'public_ready': len(public_ready), 'all_public_ready': len(public_ready) == len(rows),
        'reference_verified': len(verified),
        'ready': sum(row['passed'] for row in rows),
        'all_ready': all(row['passed'] for row in rows),
        'reference_verification_required_ids': [row['arvo_id'] for row in rows if not row['reference_verified']],
        'replacement_required_ids': [row['arvo_id'] for row in rows if not row['public_ready']],
        'distribution': {
            'project': dict(Counter(row['project'] for row in public_ready)),
            'sanitizer': dict(Counter(row['sanitizer'] for row in public_ready)),
            'crash_type': dict(Counter(row['crash_type'] for row in public_ready)),
        },
        'verified_distribution': {
            'project': dict(Counter(row['project'] for row in verified)),
            'sanitizer': dict(Counter(row['sanitizer'] for row in verified)),
            'crash_type': dict(Counter(row['crash_type'] for row in verified)),
        },
        'interfaces': {
            'public_input': 'tasks/<task_id>/input; TASK.md and input/TASK.md',
            'submission': 'source Dockerfile + docker-compose.yaml with vul/fix services',
            'role_labels': ['cdb.cybergym.role=vul', 'cdb.cybergym.role=fix'],
            'runner': '/usr/local/bin/run_poc /tmp/poc',
            'smoke': 'self-authored non-crashing /tmp/smoke input and smoke.sh',
            'private_oracle': 'gold/poc; gold/verify_reference.json; gold/reference-manifest.json',
        },
        'public_input_policy': 'source-only; no reference images, private PoCs, raw reproducer links, compiled outputs or VCS metadata',
        'tasks': rows,
    }
    write_json(RESULTS / 'shard1-summary.json', result)
    print(json.dumps({k: v for k, v in result.items() if k != 'tasks'}, indent=2), flush=True)
    return result


def selected(ids: list[int]) -> list[int]:
    if any(issue not in IDS for issue in ids) or len(set(ids)) != len(ids):
        raise ValueError(f'ids must be unique and within shard-1: {IDS}')
    return ids


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('acquire', 'materialize', 'verify', 'audit', 'summary', 'run', 'prefetch'))
    parser.add_argument('--ids', type=lambda text: [int(x) for x in text.split(',')], default=list(IDS))
    args = parser.parse_args()
    ids = selected(args.ids)
    RESULTS.mkdir(parents=True, exist_ok=True)
    if args.command == 'summary':
        return 0 if summary(ids)['all_ready'] else 1
    if args.command in ('audit',):
        reports = [audit(issue) for issue in ids]
        summary(ids)
        return int(not all(report['passed'] for report in reports))
    if args.command in ('verify', 'prefetch'):
        function = verify if args.command == 'verify' else prefetch_worker_images
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(function, ids))
        summary(ids)
        return int(any(row.get('status') == 'failed' or row.get('passed') is False for row in results))
    if args.command == 'materialize':
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(materialize, ids))
        summary(ids)
        return int(any(row.get('status') == 'failed' for row in results))
    # Acquisition is strictly capped at two downloads/work units.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        acquisitions = list(pool.map(acquire, ids))
    write_json(RESULTS / 'acquisition-summary.json', {'updated_at': now(), 'results': acquisitions})
    if args.command == 'acquire':
        return int(any(row.get('status') == 'failed' for row in acquisitions))
    acquired = [row['arvo_id'] for row in acquisitions if row.get('status') == 'acquired']
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        prepared = list(pool.map(materialize, acquired))
    materialized = [row['arvo_id'] for row in prepared if row.get('status') == 'materialized_unverified']
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        images = list(pool.map(prefetch_worker_images, materialized))
    ready = [row['arvo_id'] for row in images if row.get('status') == 'images_ready']
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(verify, ready))
    audit_rows = [audit(issue) for issue in materialized]
    result = summary(ids)
    return 0 if result['all_ready'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
