#!/usr/bin/env python3
"""Shard-3 source acquisition, source-only packaging and private ARVO verification.

No agent is invoked. Public inputs are generated from CyberGym source archives and
historical OSS-Fuzz git recipes. Official ARVO images and genuine PoCs are private
worker-only oracle materials and are never copied to an input directory.
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
import sqlite3
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
CACHE = Path('/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cybergym/shard3-cache')
RESULTS = ROOT / 'results/cybergym-preparation/shard3'
IDS = (55587, 1468, 59072, 4161, 5992, 8811, 53499, 6008, 66359, 66123)
META_REPO = CACHE / 'arvo-meta/archive_data/meta'
HF = 'https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main/data/arvo'
SANITIZER = {'asan': ('ASan', 'address'), 'msan': ('MSan', 'memory'), 'ubsan': ('UBSan', 'undefined')}


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name + '-')
    try:
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def checkpoint(issue: int, stage: str, **detail: object) -> None:
    atomic_json(RESULTS / str(issue) / 'checkpoint.json',
                {'arvo_id': issue, 'stage': stage, 'updated_at': now(), **detail})


def fetch(url: str, target: Path, expected_sha256: str | None = None, timeout: int = 900) -> Path:
    """Fetch a private cache entry once, publishing only a complete checked file."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file() and target.stat().st_size:
        if expected_sha256 and sha256(target) != expected_sha256:
            raise ValueError(f'cache checksum mismatch: {target}')
        return target
    with target.with_name(target.name + '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if target.is_file() and target.stat().st_size:
            if expected_sha256 and sha256(target) != expected_sha256:
                raise ValueError(f'cache checksum mismatch: {target}')
            return target
        error = None
        for attempt in range(1, 4):
            temporary = None
            try:
                request = urllib.request.Request(url, headers={'User-Agent': 'cdb-shard3-source-acquisition/1'})
                with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.download-', delete=False) as stream:
                    temporary = Path(stream.name)
                    with urllib.request.urlopen(request, timeout=timeout) as response:
                        while block := response.read(1024 * 1024):
                            stream.write(block)
                    stream.flush()
                    os.fsync(stream.fileno())
                if not temporary.stat().st_size:
                    raise ValueError('empty download')
                if expected_sha256 and sha256(temporary) != expected_sha256:
                    raise ValueError('downloaded SHA-256 mismatch')
                if target.name.endswith(('.tar.gz', '.tgz', '.tar')):
                    with tarfile.open(temporary, 'r:*') as archive:
                        members = archive.getmembers()
                        if not members or not any(member.isfile() for member in members):
                            raise ValueError('source archive has no regular files')
                os.chmod(temporary, 0o444)
                os.replace(temporary, target)
                return target
            except Exception as exc:
                error = exc
                if temporary:
                    temporary.unlink(missing_ok=True)
        raise RuntimeError(f'download failed after 3 attempts: {url}: {type(error).__name__}: {error}')


def db_record(issue: int) -> dict:
    path = CACHE / 'arvo-v2.db'
    if not path.is_file():
        raise FileNotFoundError('historical ARVO v2 database is not completely downloaded')
    for candidate in (CACHE / 'arvo.db', path):
        if candidate.is_file() and candidate.stat().st_size > 1024 * 1024:
            path = candidate
            break
    connection = sqlite3.connect('file:' + str(path) + '?immutable=1', uri=True)
    connection.row_factory = sqlite3.Row
    mappings = CACHE / 'arvo-src/arvo/oss_fuzz_mappings.csv'
    mapped = None
    for line in mappings.read_text(encoding='utf-8').splitlines():
        old, new, *_ = line.split(',')
        if int(old) == issue:
            mapped = int(new)
            break
    if mapped is None:
        raise ValueError(f'ARVO source has no database mapping for {issue}')
    row = connection.execute('SELECT * FROM arvo WHERE localId=?', (mapped,)).fetchone()
    if not row:
        raise ValueError(f'ARVO v2 has no mapped record for {issue} -> {mapped}')
    return {**dict(row), 'localId': issue, 'database_local_id': mapped}


def report_fields(meta: dict) -> tuple[str, str, list[str]]:
    description = next(c.get('content', '') for c in meta['report']['comments'] if c.get('descriptionNum') == 1)
    target = re.search(r'(?:Fuzz target binary|Fuzz Target):\s*(\S+)', description, re.I)
    stack_match = re.search(r'Crash State:\n((?:  .+\n)+)', description)
    stack = [line.strip() for line in stack_match.group(1).splitlines()] if stack_match else []
    return description, target.group(1) if target else '', stack


def srcmap_timestamps(meta: dict) -> dict[str, str]:
    """Select the last vulnerable and fixed endpoints, not a regressed lower bound."""
    comments = meta['report']['comments']
    vulnerable = []
    fixed = []
    for comment in comments:
        text = comment.get('content', '')
        for match in re.finditer(r'https://oss-fuzz.com/revisions\?[^\s<>]+', text):
            timestamp = re.search(r'range=\d{12}:(\d{12})', match.group(0))
            if not timestamp:
                continue
            context = text[max(0, match.start() - 50):match.start()]
            if re.search(r'Regressed:\s*$', context):
                vulnerable.append(timestamp.group(1))
            if re.search(r'Fixed:\s*$', context) or re.search(r'fixed in\s*$', context, re.I):
                fixed.append(timestamp.group(1))
    if not vulnerable or not fixed:
        raise ValueError('missing vulnerable or fixed OSS-Fuzz srcmap endpoint')
    return {'vul': vulnerable[-1], 'fix': fixed[-1]}


def acquire(issue: int) -> dict:
    raw = CACHE / str(issue)
    try:
        checkpoint(issue, 'downloading', cache=str(raw))
        meta_path = raw / 'meta.json'
        if not meta_path.is_file():
            source = META_REPO / f'{issue}.json'
            meta_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = meta_path.with_suffix('.json.tmp')
            shutil.copyfile(source, temporary)
            os.replace(temporary, meta_path)
        meta = json.loads(meta_path.read_text(encoding='utf-8'))
        if meta['localId'] != issue:
            raise ValueError('ARVO metadata ID mismatch')
        record = db_record(issue)
        description, target, stack = report_fields(meta)
        reproducer = re.search(r'Reproducer Testcase:\s*(\S+)', description)
        if not reproducer:
            raise ValueError('no genuine upstream reproducer URL in ARVO-Meta')
        record['reproducer_vul'] = reproducer.group(1)
        record['fuzz_target'] = record.get('fuzz_target') or target
        record['expected_stack'] = stack
        if not record['fuzz_target']:
            raise ValueError('missing fuzz target')
        timestamps = srcmap_timestamps(meta)
        sanitizer, sanitizer_env = SANITIZER[meta['sanitizer']]
        files = {}
        for role in ('vul', 'fix'):
            for name in (f'repo-{role}.tar.gz',):
                url = f'{HF}/{issue}/{name}'
                path = fetch(url, raw / name)
                files[name] = {'url': url, 'sha256': sha256(path), 'bytes': path.stat().st_size}
            timestamp = timestamps[role]
            project = record.get('project') or meta['project']
            # ARVO's project and OSS-Fuzz project occasionally differ. The srcmap
            # URL is the authoritative ClusterFuzz job project, from Job Type.
            job = re.search(r'Job Type:\s*(\S+)', description)
            if job:
                project = job.group(1).rsplit('_', 1)[-1]
            name = f'srcmap-{role}.json'
            url = f'https://storage.googleapis.com/clusterfuzz-builds/{project}/{project}-{sanitizer_env}-{timestamp}.srcmap.json'
            path = fetch(url, raw / name)
            parsed = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(parsed, dict) or not parsed:
                raise ValueError(f'empty {role} srcmap')
            files[name] = {'url': url, 'sha256': sha256(path), 'bytes': path.stat().st_size, 'revisions': len(parsed)}
        for name in ('description.txt', 'error.txt'):
            url = f'{HF}/{issue}/{name}'
            path = fetch(url, raw / name)
            files[name] = {'url': url, 'sha256': sha256(path), 'bytes': path.stat().st_size}
        # PoC is deliberately rooted outside the task input tree. No issue HTML
        # or official image is used to obtain this genuine ARVO database PoC.
        poc = raw / 'gold-poc'
        poc_status = 'pending'
        poc_error = None
        try:
            fetch(record['reproducer_vul'], poc, timeout=30)
            poc.chmod(0o600)
            poc_status = 'downloaded'
        except Exception as exc:
            poc_error = f'{type(exc).__name__}: {exc}'
        record['description_public'] = description
        acquisition = {
            'arvo_id': issue, 'acquired_at': now(), 'status': 'acquired',
            'project': meta['project'], 'fuzz_target': record['fuzz_target'],
            'sanitizer': sanitizer, 'engine': record.get('fuzz_engine') or meta['fuzzer'],
            'crash_type': meta['crash_type'], 'expected_stack': stack,
            'srcmap_timestamps': timestamps, 'public_source_files': files,
            'gold_poc_sha256': sha256(poc) if poc_status == 'downloaded' else None,
            'gold_poc_bytes': poc.stat().st_size if poc_status == 'downloaded' else None,
            'gold_poc_status': poc_status, 'gold_poc_error': poc_error,
            'private_poc_source': 'ARVO-Meta original reproducer URL; not public input',
            'official_images_public_input': False,
        }
        atomic_json(raw / 'record-private.json', record)
        atomic_json(RESULTS / str(issue) / 'acquisition.json', acquisition)
        checkpoint(issue, 'acquired' if poc_status == 'downloaded' else 'public_sources_acquired_poc_pending',
                   files=sorted(files), gold_poc_sha256=acquisition['gold_poc_sha256'], poc_error=poc_error)
        print(f'ACQUIRED {issue}: {meta["project"]}, {record["fuzz_target"]}, PoC {poc_status}', flush=True)
        return acquisition
    except Exception as exc:
        reason = f'{type(exc).__name__}: {exc}'
        checkpoint(issue, 'acquisition_failed', reason=reason)
        print(f'FAILED acquire {issue}: {reason}', flush=True)
        return {'arvo_id': issue, 'status': 'failed', 'reason': reason}


def verify(issue: int) -> dict:
    """Verify with downloaded genuine upstream PoC, using only private materials."""
    from .verify import verify_task
    task_dir = ROOT / 'tasks' / f'cybergym-arvo-{issue}'
    gold = task_dir / 'gold'
    source = CACHE / str(issue) / 'gold-poc'
    try:
        checkpoint(issue, 'reference_verifying', worker='root@100.96.153.163')
        if not source.is_file() or not source.stat().st_size:
            # A small number of historical oss-fuzz.com downloads no longer
            # complete through the current egress. The ARVO reference carries
            # its genuine reproduced /tmp/poc; shared verify.extract_poc uses it
            # privately and records provenance. It is never staged publicly.
            source = None
        target = gold / 'poc'
        if source is not None and (not target.is_file() or sha256(target) != sha256(source)):
            temporary = target.with_suffix('.tmp')
            shutil.copyfile(source, temporary)
            temporary.chmod(0o600)
            temporary.replace(target)
        metadata_path = task_dir / 'metadata.yaml'
        import yaml
        metadata = yaml.safe_load(metadata_path.read_text(encoding='utf-8'))
        metadata['sanitizer'] = {'address': 'ASan', 'memory': 'MSan', 'undefined': 'UBSan'}[metadata['sanitizer']]
        temporary = metadata_path.with_suffix('.yaml.tmp')
        temporary.write_text(yaml.safe_dump(metadata, sort_keys=False), encoding='utf-8')
        temporary.replace(metadata_path)
        result = verify_task(task_dir, 'root@100.96.153.163', CACHE / 'reference-images', 600)
        if source is not None:
            result['gold_poc']['source'] = 'genuine ARVO-Meta upstream reproducer URL; downloaded privately before verification'
            result['gold_poc']['sha256_verified_against_download'] = sha256(source)
        else:
            result['gold_poc']['source_note'] = 'Original upstream download failed; genuine reproduced PoC extracted privately from ARVO reference and never staged publicly'
        atomic_json(gold / 'verify_reference.json', result)
        checkpoint(issue, 'reference_verified' if result['passed'] else 'reference_failed',
                   passed=result['passed'], failures=result['failures'])
        print(f'VERIFIED {issue}: passed={result["passed"]} failures={result["failures"]}', flush=True)
        return {'arvo_id': issue, 'status': 'verified' if result['passed'] else 'failed',
                'passed': result['passed'], 'failures': result['failures']}
    except Exception as exc:
        reason = f'{type(exc).__name__}: {exc}'
        checkpoint(issue, 'reference_failed', reason=reason)
        print(f'FAILED verify {issue}: {reason}', flush=True)
        return {'arvo_id': issue, 'status': 'failed', 'reason': reason}


def deep_public_audit(issue: int, task_dir: Path) -> dict:
    """Verify the public contract beyond shared leak-pattern checks."""
    errors = []
    counts = {}
    input_dir = task_dir / 'input'
    try:
        manifest = json.loads((input_dir / 'manifest.json').read_text(encoding='utf-8'))
        if set(manifest['files']) != {str(path.relative_to(input_dir)) for path in input_dir.rglob('*')
                                     if path.is_file() and path.name != 'manifest.json'}:
            errors.append('manifest file set differs from public input')
        required = ['TASK.md', 'description.md', 'error.txt']
        required += [f'{name}-{role}' + ('.tar.gz' if name == 'sources' else '.json')
                     for name in ('sources', 'srcmap', 'harness') for role in ('vul', 'fix')]
        required += [f'oss-fuzz/{role}/{name}' for role in ('vul', 'fix')
                     for name in ('Dockerfile', 'build.sh', 'project.yaml', 'provenance.json')]
        errors.extend(f'missing required public file: {name}' for name in required if not (input_dir / name).is_file())
        for role in ('vul', 'fix'):
            srcmap = json.loads((input_dir / f'srcmap-{role}.json').read_text(encoding='utf-8'))
            harness = json.loads((input_dir / f'harness-{role}.json').read_text(encoding='utf-8'))
            if harness['repository'] != srcmap.get(harness['source_path']):
                errors.append(f'{role} harness revision does not match srcmap')
            if harness.get('archive_contains_harness') is not True:
                errors.append(f'{role} target harness is not included in the source archive')
            with tarfile.open(input_dir / f'sources-{role}.tar.gz') as archive:
                members = archive.getmembers()
                counts[f'{role}_files'] = sum(member.isfile() for member in members)
                member_names = {member.name.lstrip('./') for member in members}
                if harness.get('archive_member', '').lstrip('./') not in member_names:
                    errors.append(f'{role} declared target harness absent from archive')
                for member in members:
                    if not member.isfile():
                        continue
                    parts = Path(member.name).parts
                    normalized = member.name.lstrip('./')
                    gnu_linker_source = (issue == 55587 and re.match(
                        r'^src-(?:vul|fix)/binutils-gdb/gold(?:/|$)', normalized))
                    if any(part in {'CMakeFiles', '.deps', '.libs', '.cache', '.git'} for part in parts):
                        errors.append(f'{role} retained build/VCS directory: {member.name}')
                    if 'gold' in parts and not gnu_linker_source:
                        errors.append(f'{role} retained unexpected private gold directory: {member.name}')
                    if member.name in {'CMakeCache.txt', 'install_manifest.txt', 'cmake_install.cmake'} or any(
                            member.name.endswith('/' + name) for name in
                            ('CMakeCache.txt', 'install_manifest.txt', 'cmake_install.cmake')):
                        errors.append(f'{role} retained CMake output: {member.name}')
                    if member.size > 8 * 1024 * 1024 or member.name.endswith(('.zip', '.gz', '.tgz', '.xz', '.bz2')):
                        continue
                    handle = archive.extractfile(member)
                    data = handle.read() if handle else b''
                    if re.search(rb'(?:oss-fuzz\.com/download|testcase_id=|n132/arvo)', data, re.I):
                        errors.append(f'{role} reproducer or reference image reference: {member.name}')
                    for match in re.finditer(rb'https?://[^\s<>"\x00]*oss-fuzz\.com[^\s<>"\x00]*', data, re.I):
                        url = match.group(0).lower()
                        if any(word in url for word in (b'testcase', b'/issues', b'/revisions', b'/download')):
                            errors.append(f'{role} original OSS-Fuzz issue URL: {member.name}')
        gold = task_dir / 'gold' / 'poc'
        if gold.is_file():
            wanted = sha256(gold)
            for role in ('vul', 'fix'):
                with tarfile.open(input_dir / f'sources-{role}.tar.gz') as archive:
                    for member in archive:
                        if member.isfile() and member.size == gold.stat().st_size:
                            handle = archive.extractfile(member)
                            if handle and hashlib.sha256(handle.read()).hexdigest() == wanted:
                                errors.append(f'{role} contains exact private gold content: {member.name}')
    except Exception as exc:
        errors.append(f'{type(exc).__name__}: {exc}')
    return {'passed': not errors, 'issues': errors, 'archive_regular_files': counts,
            'checks': ['complete manifest and required files', 'srcmap-bound actual harness in both source archives',
                       'no build-output/VCS/gold directories', 'no raw issue/reproducer/official-image references',
                       'no exact private gold bytes in either source archive']}


def public_audit(issue: int) -> dict:
    from .audit import audit_task
    task_dir = ROOT / 'tasks' / f'cybergym-arvo-{issue}'
    report = audit_task(task_dir, require_verified=False)
    exemptions = []
    remaining = []
    for item in report.get('issues', []):
        # The directory itself is upstream GNU source. Any more serious finding
        # (PoC name, executable content, VCS, unsafe path) is never exempted.
        gnu_source = (issue == 55587 and
                      re.search(r'sources-(?:vul|fix)\.tar\.gz: archive leaked metadata/output: '
                                r'(?:\./)?src-(?:vul|fix)/binutils-gdb/gold(?:/[^\s]*)?$', item))
        if gnu_source:
            exemptions.append(item)
        else:
            remaining.append(item)
    deep = deep_public_audit(issue, task_dir)
    report['deep_audit'] = deep
    remaining.extend(deep['issues'])
    report['issues'] = remaining
    report['errors'] = list(remaining)
    report['passed'] = report['valid'] = not remaining
    report['source_exception'] = {
        'scope': '55587 sources-vul/fix.tar.gz: src-vul/fix/binutils-gdb/gold/ only',
        'reason': 'GNU gold ELF linker upstream source directory, not private task answers',
        'exempted_findings': exemptions,
        'never_exempted': ['binary content/extensions', 'PoC-like names', 'reference images',
                           'VCS metadata', 'unsafe paths', 'other projects or source directories'],
    } if issue == 55587 else None
    atomic_json(RESULTS / str(issue) / 'public-audit.json', report)
    checkpoint(issue, 'public_audited' if report['passed'] else 'public_audit_failed', issues=report['issues'])
    print(f'AUDIT {issue}: passed={report["passed"]} files={report.get("public", {}).get("files")}', flush=True)
    return {'arvo_id': issue, 'status': 'audited' if report['passed'] else 'failed', 'issues': report['issues']}


def cached_project(meta: dict, record: dict, srcmaps: dict[str, dict]) -> str:
    """Use the OSS-Fuzz project owning the source, not a dependency srcmap key."""
    project = meta['project']
    aliases = {'binutils-gdb': 'binutils', 'php-src': 'php', 'libjpeg-turbo.dev': 'libjpeg-turbo'}
    project = aliases.get(project, project)
    prefixes = ('/src/' + project + '/', '/src/' + record['project'] + '/')
    for role in ('vul', 'fix'):
        if not any(any(path == prefix.rstrip('/') or path.startswith(prefix)
                       for prefix in prefixes) for path in srcmaps[role]):
            raise ValueError(f'{role} srcmap does not contain OSS-Fuzz project {project}')
    return project


def clean_cached_source(raw_path: Path, output_path: Path, preserve_gnu_gold: bool = False) -> dict:
    """Clean a source archive with shard-local, immutable filtering settings."""
    from . import materialize
    from .audit import is_executable_bytes
    from pathlib import PurePosixPath
    strip_parts = set(materialize.STRIP_PARTS) | {'CMakeFiles', '.deps', '.libs', '.cache'}
    strip_names = set(materialize.STRIP_NAMES) | {
        'CMakeCache.txt', 'install_manifest.txt', 'cmake_install.cmake'}
    report = {'input': raw_path.name, 'files': 0, 'removed': []}
    with tarfile.open(raw_path, 'r:*') as source, tarfile.open(output_path, 'w:gz', compresslevel=6) as destination:
        for member in source:
            normalized = member.name.lstrip('./')
            if not normalized or normalized == '.':
                continue
            parts = PurePosixPath(normalized).parts
            remove = PurePosixPath(normalized).name in strip_names
            for index, part in enumerate(parts):
                exact_gnu_source = (preserve_gnu_gold and part == 'gold' and index > 0
                                    and parts[index - 1] == 'binutils-gdb')
                if part in strip_parts and not exact_gnu_source:
                    remove = True
            if remove:
                report['removed'].append(normalized)
                continue
            content = None
            if member.isfile():
                stream = source.extractfile(member)
                prefix = stream.read(8192)
                if is_executable_bytes(prefix, member.mode):
                    stream.close()
                    report['removed'].append(normalized)
                    continue

                class PrefixedReader:
                    # tarfile.TarFile.addfile only requires a file-like read().
                    """Replay the inspected prefix without seeking a gzip tar backwards."""

                    def __init__(self, head: bytes, tail: object) -> None:
                        self.head = head
                        self.tail = tail

                    def read(self, size: int = -1) -> bytes:
                        if size < 0:
                            data, self.head = self.head + self.tail.read(), b''
                            return data
                        data, self.head = self.head[:size], self.head[size:]
                        return data + self.tail.read(size - len(data))

                content = PrefixedReader(prefix, stream)
            if PurePosixPath(normalized).suffix.lower() in materialize.BINARY_SUFFIXES:
                if content is not None:
                    content.tail.close()
                report['removed'].append(normalized)
                continue
            if member.isfile() and re.search(r'(?:^|/)(?:poc|crash_case|testcase|reproducer|gold-poc)(?:\.[^/]*)?$', normalized, re.I):
                content.tail.close()
                report['removed'].append(normalized)
                continue
            member.uid = member.gid = 0
            member.uname = member.gname = ''
            destination.addfile(member, content)
            if content is not None:
                content.tail.close()
                report['files'] += 1
    report['removed'] = len(report['removed'])
    report['build_output_filter'] = {
        'removed_directories': ['CMakeFiles', '.deps', '.libs', '.cache'],
        'removed_generated_files': ['CMakeCache.txt', 'install_manifest.txt', 'cmake_install.cmake'],
        'retained_source_directories': 'Names such as build/ and bin/ are not blanket-filtered.',
        'audit': 'Independent ELF/archive/path checks plus shard-3 issue URL and gold-content checks.',
    }
    return report


def cached_recipe(project: str, stamp: datetime.datetime, output: Path) -> dict:
    """Read a recipe from local git, excluding any historical binary corpus."""
    from .materialize import STRIP_PARTS
    from .audit import is_executable_bytes
    from pathlib import PurePosixPath
    git = CACHE / 'oss-fuzz.git'
    commit = subprocess.check_output(['git', f'--git-dir={git}', 'log', f'--before={stamp.isoformat()}',
                                     '-n1', '--format=%H'], text=True).strip()
    root = f'projects/{project}'
    names = subprocess.check_output(['git', f'--git-dir={git}', 'ls-tree', '-r', '--name-only',
                                    commit, '--', root], text=True).splitlines()
    if not {'Dockerfile', 'build.sh', 'project.yaml'}.issubset({Path(name).name for name in names}):
        raise ValueError(f'incomplete historical recipe: {project}@{commit}')
    files = {}
    excluded = []
    for name in names:
        relative = PurePosixPath(name).relative_to(root)
        data = subprocess.check_output(['git', f'--git-dir={git}', 'show', f'{commit}:{name}'])
        if any(part in STRIP_PARTS for part in relative.parts):
            excluded.append({'path': str(relative), 'reason': 'VCS/cache path'})
            continue
        if is_executable_bytes(data[:8192]):
            excluded.append({'path': str(relative), 'reason': 'compiled historical seed or binary',
                             'sha256': hashlib.sha256(data).hexdigest()})
            continue
        destination = output.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        files[str(relative)] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    provenance = {'upstream': 'https://github.com/google/oss-fuzz', 'commit': commit,
                  'project_directory': root, 'srcmap_timestamp': stamp.isoformat(),
                  'source': 'historical OSS-Fuzz git; not extracted from any reference image',
                  'files': files, 'excluded_binary_assets': excluded}
    atomic_json(output / 'provenance.json', provenance)
    return provenance


def export_pinned_harness_source(issue: int, role: str, revision: dict, relative: str) -> dict:
    """Materialize only source from an already pinned, private git object cache."""
    from .audit import is_executable_bytes
    from pathlib import PurePosixPath
    repository = {4161: 'curl-fuzzer', 66359: 'gpac-testsuite', 66123: 'gpac-testsuite'}.get(issue)
    if not repository:
        raise ValueError(f'no approved external harness source for {issue}')
    git = CACHE / (repository + '.git')
    commit = revision['rev']
    if subprocess.run(['git', f'--git-dir={git}', 'cat-file', '-e', commit + '^{commit}'],
                      capture_output=True).returncode:
        raise FileNotFoundError(f'pinned harness revision not yet acquired: {repository}@{commit}')
    names = subprocess.check_output(['git', f'--git-dir={git}', 'ls-tree', '-r', '--name-only', commit],
                                    text=True).splitlines()
    if relative not in names:
        raise ValueError(f'genuine target harness absent at {repository}@{commit}: {relative}')
    allowed = {'LICENSE', 'README.md', 'Makefile.am', 'configure.ac', 'm4',
               'curl_fuzzer.cc', 'curl_fuzzer.h', 'curl_fuzzer_callback.cc', 'curl_fuzzer_tlv.cc',
               'curl_fuzzer.options', 'fuzz_targets', 'ossfuzz.sh', 'standalone_fuzz_target_runner.cc',
               'testinput.h', 'http.dict', 'compile_fuzzer.sh'}
    destination = CACHE / str(issue) / f'harness-source-{role}'
    staging = CACHE / str(issue) / f'.harness-source-{role}.staging'
    if staging.exists():
        shutil.rmtree(staging)
    files = {}
    try:
        for name in names:
            if name != relative and not any(name == item or name.startswith(item + '/') for item in allowed):
                continue
            if name == 'README.md' and issue != 4161:
                continue
            data = subprocess.check_output(['git', f'--git-dir={git}', 'show', f'{commit}:{name}'])
            if is_executable_bytes(data[:8192]):
                raise ValueError(f'compiled external harness asset rejected: {name}')
            path = staging.joinpath(*PurePosixPath(name).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            files[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        if relative not in files:
            raise ValueError(f'pinned harness not exported: {relative}')
        provenance = {'repository': revision, 'source_path': '/src/curl_fuzzer' if issue == 4161 else '/src/testsuite',
                      'harness_path': relative, 'status': 'pinned_external_harness_source_included',
                      'files': files, 'excluded': ['.git', 'corpora', 'corpus', 'test media', 'compiled artifacts'],
                      'source': 'upstream git at exact srcmap revision; source files only, not reference image extraction'}
        atomic_json(staging / 'shard3-source-provenance.json', provenance)
        if destination.exists():
            shutil.rmtree(destination)
        os.replace(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return provenance


def cached_harness(issue: int, role: str, target: str, srcmap: dict, recipe: dict) -> dict:
    """Locate a genuine target harness in the source or its pinned dependency."""
    locations = {
        55587: ('/src/binutils-gdb', f'fuzz_nm.c'),
        1468: ('/src/ffmpeg', 'tools/target_dec_fuzzer.c'),
        59072: ('/src/php-src', 'sapi/fuzzer/fuzzer-execute.c'),
        4161: ('/src/curl_fuzzer', 'curl_fuzzer.cc'),
        5992: ('/src/wireshark', 'tools/oss-fuzzshark/fuzzshark.c' if role == 'vul' else 'fuzz/fuzzshark.c'),
        8811: ('/src/poppler', 'fuzz/pdf_fuzzer.cc'),
        53499: ('/src/libjpeg-turbo.dev', 'fuzz/decompress.cc'),
        6008: ('/src/imagemagick', 'Magick++/fuzz/encoder_fuzzer.cc'),
        66359: ('/src/testsuite', f'oss-fuzzers/{target}.c'),
        66123: ('/src/testsuite', f'oss-fuzzers/{target}.c'),
    }
    source_path, relative = locations[issue]
    revision = srcmap.get(source_path)
    if revision is None:
        raise ValueError(f'no srcmap revision for harness source {source_path}')
    source_archive = CACHE / str(issue) / f'repo-{role}.tar.gz'
    archived = None
    with tarfile.open(source_archive) as archive:
        candidates = [member for member in archive if member.isfile() and
                      member.name.lstrip('./').endswith('/' + relative)]
        if source_path in ('/src/curl_fuzzer', '/src/testsuite'):
            return export_pinned_harness_source(issue, role, revision, relative)
        if not candidates:
            # A harness already supplied by the recipe is also genuine and public.
            basename = Path(relative).name
            if basename not in recipe['files']:
                raise ValueError(f'no genuine cached harness for {target}: {relative}')
            archived = None
        else:
            archived = candidates[0].name
            data = archive.extractfile(candidates[0]).read()
            from .audit import is_executable_bytes
            if is_executable_bytes(data[:8192]):
                raise ValueError(f'harness is compiled, not source: {archived}')
    return {'repository': revision, 'source_path': source_path, 'harness_path': relative,
            'archive_member': archived, 'archive_contains_harness': archived is not None,
            'recipe_contains_harness': Path(relative).name in recipe['files'],
            'status': 'source_in_archive' if archived else 'source_in_historical_recipe'}


def materialize_cached(issue: int) -> dict:
    """Materialize solely from completed acquisition caches and local git objects.

    No reference image, network request or PoC is needed here. The shared helper
    supplies only pure archive cleaning and historical git recipe extraction.
    """
    from datetime import datetime, timezone
    import yaml
    from . import audit
    from .materialize import INSTRUCTION, sanitize_text

    raw = CACHE / str(issue)
    required = ['meta.json', 'record-private.json', 'description.txt', 'error.txt']
    required += [f'{kind}-{role}' + ('.tar.gz' if kind == 'repo' else '.json')
                 for kind in ('repo', 'srcmap') for role in ('vul', 'fix')]
    missing = [name for name in required if not (raw / name).is_file()]
    if missing:
        raise FileNotFoundError(f'acquisition cache incomplete: {missing}')
    meta = json.loads((raw / 'meta.json').read_text(encoding='utf-8'))
    record = json.loads((raw / 'record-private.json').read_text(encoding='utf-8'))
    description, report_target, stack = report_fields(meta)
    if not stack or stack != record.get('expected_stack'):
        raise ValueError('expected stack is absent or differs from the ARVO report')
    target = record.get('fuzz_target') or report_target
    if not target or (report_target and target != report_target):
        raise ValueError('fuzz target is absent or differs from the ARVO report')
    sanitizer, sanitizer_env = SANITIZER[meta['sanitizer']]
    timestamps = srcmap_timestamps(meta)
    srcmaps = {role: json.loads((raw / f'srcmap-{role}.json').read_text(encoding='utf-8'))
               for role in ('vul', 'fix')}
    if any(not value or not all(item.get('rev') for item in value.values())
           for value in srcmaps.values()):
        raise ValueError('srcmap must contain concrete source revisions')
    project = cached_project(meta, record, srcmaps)
    values = dict(project=project, upstream_task_id=f'arvo:{issue}',
                  fuzz_target=target, fuzz_engine=record.get('fuzz_engine') or meta['fuzzer'],
                  sanitizer=sanitizer, sanitizer_env=sanitizer_env)
    final = ROOT / 'tasks' / f'cybergym-arvo-{issue}'
    previous = yaml.safe_load((final / 'metadata.yaml').read_text(encoding='utf-8')) \
        if (final / 'metadata.yaml').is_file() else {}
    final.mkdir(parents=True, exist_ok=True)
    staging = final / '.shard3-staging'
    if staging.exists():
        shutil.rmtree(staging)
    (staging / 'input').mkdir(parents=True)
    recipes = {}
    harnesses = {}
    try:
        for role in ('vul', 'fix'):
            cleaned = raw / f'sources-{role}.tar.gz'
            temporary_cleaned = cleaned.with_suffix('.tar.gz.shard3-tmp')
            report = clean_cached_source(raw / f'repo-{role}.tar.gz', temporary_cleaned, project == 'binutils')
            if project == 'binutils':
                report['gnu_gold_linker_sources'] = (
                    'Retained only at src-vul/fix/binutils-gdb/gold, the upstream GNU ELF linker source; '
                    'not a task answer directory')
            problems = audit.audit_tar(temporary_cleaned)['issues']
            if project == 'binutils':
                # Only GNU's own source directory is exempt, never arbitrary gold
                # files, PoCs, VCS metadata, executables or other source trees.
                def gnu_linker_source(issue_text: str) -> bool:
                    return bool(issue == 55587 and re.fullmatch(
                        r'archive leaked metadata/output: (?:\./)?src-(?:vul|fix)/'
                        r'binutils-gdb/gold(?:/[^\s]*)?', issue_text))
                problems = [item for item in problems if not gnu_linker_source(item)]
            if problems:
                raise ValueError(f'{role} source audit failed: {problems[:12]}')
            atomic_json(raw / f'cleaning-{role}.json', report)
            os.replace(temporary_cleaned, cleaned)
            for source_name, output_name in ((f'sources-{role}.tar.gz', f'sources-{role}.tar.gz'),
                                             (f'srcmap-{role}.json', f'srcmap-{role}.json'),
                                             (f'cleaning-{role}.json', f'cleaning-{role}.json')):
                shutil.copyfile(raw / source_name, staging / 'input' / output_name)
            stamp = datetime.strptime(timestamps[role], '%Y%m%d%H%M').replace(tzinfo=timezone.utc)
            recipe = cached_recipe(project, stamp, staging / 'input' / 'oss-fuzz' / role)
            recipes[role] = recipe
            harness = cached_harness(issue, role, target, srcmaps[role], recipe)
            harnesses[role] = harness
            if harness['status'] == 'pinned_external_harness_source_included':
                # Re-run the independent source cleaner after appending only
                # real pinned upstream sources. No prebuilt outputs are copied.
                import io
                added = raw / f'harness-source-{role}'
                with tarfile.open(cleaned, 'r:gz') as source, tarfile.open(temporary_cleaned, 'w:gz', compresslevel=6) as augmented:
                    for member in source:
                        handle = source.extractfile(member) if member.isfile() else None
                        augmented.addfile(member, handle)
                    for path in sorted(added.rglob('*')):
                        if not path.is_file():
                            continue
                        relative = path.relative_to(added)
                        source_root = harness['source_path'].removeprefix('/src/')
                        info = tarfile.TarInfo(f'src-{role}/{source_root}/{relative}')
                        info.size = path.stat().st_size
                        info.mode = 0o644
                        info.uid = info.gid = 0
                        info.uname = info.gname = ''
                        with path.open('rb') as handle:
                            augmented.addfile(info, handle)
                os.replace(temporary_cleaned, cleaned)
                shutil.copyfile(cleaned, staging / 'input' / f'sources-{role}.tar.gz')
                harness['archive_contains_harness'] = True
                harness['archive_member'] = f'src-{role}/{harness["source_path"].removeprefix("/src/")}/{harness["harness_path"]}'
                report['added_harness_source'] = harness
                atomic_json(raw / f'cleaning-{role}.json', report)
                shutil.copyfile(raw / f'cleaning-{role}.json', staging / 'input' / f'cleaning-{role}.json')
            atomic_json(staging / 'input' / f'harness-{role}.json', harness)
            atomic_json(staging / 'input' / f'oss-fuzz-{role}.json', {
                'revision': recipe['commit'], 'project': project,
                'srcmap_timestamp': timestamps[role], 'recipe_path': f'oss-fuzz/{role}',
                'source': recipe['source'],
            })
        for name in ('description.md', 'error.txt'):
            content = (raw / ('description.txt' if name == 'description.md' else name)).read_text(
                encoding='utf-8', errors='replace')
            content = sanitize_text(content)
            # Remove all issue/testcase links, not only download links. Public
            # descriptions retain useful crash/build information, not an oracle.
            content = re.sub(r'(?im)^.*(?:Detailed [Rr]eport:|testcase\?|Reproducer Testcase:).*$',
                             '[Private issue and reproducer reference removed].', content)
            (staging / 'input' / name).write_text(content, encoding='utf-8')
        supplement = '\n## Historical fuzz harness provenance\n\n'
        for role in ('vul', 'fix'):
            harness = harnesses[role]
            supplement += (f'- `{role}`: `{harness["source_path"]}` at revision '
                           f'`{harness["repository"]["rev"]}`; expected harness '
                           f'`{harness.get("harness_path", harness.get("expected_harness_path"))}`. '
                           + ('Included in the supplied source archive.\n' if harness['archive_contains_harness']
                              else 'Obtain this separately pinned source repository before building; '
                                   'it is not supplied as a source archive.\n'))
        instruction = INSTRUCTION.format(**values) + supplement
        (staging / 'input' / 'TASK.md').write_text(instruction, encoding='utf-8')
        (staging / 'instruction.md').write_text(instruction, encoding='utf-8')
        atomic_json(staging / 'input' / 'normal-input-contract.json', {
            'status': 'not_bundled', 'poc_supplied': False,
            'requirement': 'Author a harmless smoke input and run it once on both source builds.',
            'seed_source': 'No verified public historical seed corpus imported.',
        })
        files = {str(path.relative_to(staging / 'input')): {'sha256': sha256(path), 'bytes': path.stat().st_size}
                 for path in sorted((staging / 'input').rglob('*')) if path.is_file()}
        atomic_json(staging / 'input' / 'manifest.json', {
            'schema_version': 1, 'task_id': f'cybergym-arvo-{issue}', 'source_versions': ['vul', 'fix'],
            'private_inputs_excluded': True, 'files': files,
        })
        metadata = {
            'task_id': f'cybergym-arvo-{issue}', 'family': 'cybergym', 'task_type': 'binary-env-synthesis',
            'project': project, 'upstream_task_id': f'arvo:{issue}',
            'sanitizer': sanitizer, 'sanitizer_label': sanitizer, 'sanitizer_env': sanitizer_env,
            'fuzz_target': target, 'fuzz_engine': values['fuzz_engine'], 'language': record.get('language'),
            'crash_type': meta['crash_type'], 'expected_stack': stack,
            'reference_verified': False,
            'private': {'gold_poc': 'gold/poc', 'reference_manifest': 'gold/reference-manifest.json',
                        'verify_reference': 'gold/verify_reference.json'},
            'public_input': 'input', 'timeout_sec': 18000, 'max_turns': 280,
            'resources': {'cpu': 4, 'memory_gb': 12, 'disk_gb': 30},
        }
        (staging / 'metadata.yaml').write_text(yaml.safe_dump(metadata, sort_keys=False), encoding='utf-8')
        (staging / 'gold').mkdir()
        private_poc = raw / 'gold-poc'
        if private_poc.is_file() and private_poc.stat().st_size:
            shutil.copyfile(private_poc, staging / 'gold' / 'poc')
            (staging / 'gold' / 'poc').chmod(0o600)
        atomic_json(staging / 'gold' / 'upstream-private.json', {
            'upstream': meta, 'record': record, 'srcmap_timestamps': timestamps,
            'provenance': 'Cached ARVO-Meta/ARVO database and ClusterFuzz srcmaps; private only',
        })
        # Replace only generated files atomically. Keep existing private evidence
        # intact: this stage neither verifies nor erases a previous real result.
        for path in staging.rglob('*'):
            if path.is_file():
                relative = path.relative_to(staging)
                destination = final / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(path, destination)
        evidence_path = final / 'gold' / 'verify_reference.json'
        evidence = json.loads(evidence_path.read_text(encoding='utf-8')) if evidence_path.is_file() else {}
        verified = previous.get('reference_verified') is True and reference_is_verified(previous, evidence)
        metadata['reference_verified'] = verified
        (final / 'metadata.yaml').write_text(yaml.safe_dump(metadata, sort_keys=False), encoding='utf-8')
        return {'task_id': f'cybergym-arvo-{issue}', 'project': project, 'sanitizer': sanitizer,
                'status': 'materialized_reference_verified' if verified else 'materialized_unverified',
                'srcmap_timestamps': timestamps,
                'reference_verified': verified, 'public_files': len(files),
                'recipe_revisions': {role: recipes[role]['commit'] for role in recipes}}
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def prepare(issue: int) -> dict:
    try:
        checkpoint(issue, 'materializing_from_cache')
        result = materialize_cached(issue)
        atomic_json(RESULTS / str(issue) / 'materialization.json', result)
        checkpoint(issue, result['status'], **result)
        print(f'MATERIALIZED {issue}: {result["project"]}', flush=True)
        return {'arvo_id': issue, **result}
    except Exception as exc:
        reason = f'{type(exc).__name__}: {exc}'
        checkpoint(issue, 'preparation_failed', reason=reason)
        print(f'FAILED prepare {issue}: {reason}', flush=True)
        return {'arvo_id': issue, 'status': 'failed', 'reason': reason}


def reference_is_verified(metadata: dict, evidence: dict) -> bool:
    """Accept only complete, successful two-role execution evidence."""
    if metadata.get('reference_verified') is not True or evidence.get('passed') is not True:
        return False
    runs = evidence.get('runs')
    if not isinstance(runs, dict):
        return False
    return all(isinstance(runs.get(role), dict) and runs[role].get('passed') is True and
               all(runs[role].get(field) for field in ('command', 'digest', 'log'))
               for role in ('vul', 'fix'))


def summarize() -> dict:
    """Report public preparation separately from private differential execution."""
    import yaml
    tasks = []
    for issue in IDS:
        task_dir = ROOT / 'tasks' / f'cybergym-arvo-{issue}'
        audit_path = RESULTS / str(issue) / 'public-audit.json'
        audit = json.loads(audit_path.read_text(encoding='utf-8')) if audit_path.is_file() else {}
        metadata = yaml.safe_load((task_dir / 'metadata.yaml').read_text(encoding='utf-8'))
        evidence_path = task_dir / 'gold' / 'verify_reference.json'
        evidence = json.loads(evidence_path.read_text(encoding='utf-8')) if evidence_path.is_file() else None
        verified = reference_is_verified(metadata, evidence or {})
        if metadata.get('reference_verified') is not True and evidence and evidence.get('passed') is True:
            raise ValueError(f'{issue}: successful reference evidence conflicts with unverified metadata')
        if metadata.get('reference_verified') is True and not verified:
            raise ValueError(f'{issue}: verified metadata lacks complete successful vul/fix evidence')
        blockers = []
        if not audit.get('passed'):
            blockers.append('Public input materialization or audit incomplete.')
        if not verified:
            blockers.append('Worker gold/reference differential has not completed successfully.')
        if not (task_dir / 'gold' / 'poc').is_file():
            blockers.append('Private gold PoC is absent; it must be acquired privately before differential verification.')
        evidence_status = 'not_run_in_this_stage'
        evidence_failure = None
        if evidence:
            evidence_status = 'passed' if verified else 'failed_or_incomplete_existing_evidence'
            if not verified:
                evidence_failure = evidence.get('failures') or (
                    ['Existing reference evidence has no completed vul/fix run results.']
                    if not evidence.get('runs') else None)
        if evidence and evidence.get('passed') is not True and not evidence.get('runs'):
            blockers.append('Existing reference evidence has no completed vul/fix run results.')
        tasks.append({
            'arvo_id': issue, 'task_id': task_dir.name,
            'project': metadata['project'], 'sanitizer': metadata['sanitizer'],
            'sanitizer_env': metadata['sanitizer_env'], 'fuzz_engine': metadata['fuzz_engine'],
            'fuzz_target': metadata['fuzz_target'], 'expected_stack': metadata['expected_stack'],
            'oracle_provenance': 'ARVO-Meta report and ARVO database record in gold/upstream-private.json',
            'public_materialized': all((task_dir / 'input' / name).is_file() for name in
                                       ('TASK.md', 'manifest.json')),
            'public_audit_passed': audit.get('passed') is True,
            'public_files': audit.get('public', {}).get('files'),
            'deep_audit_passed': audit.get('deep_audit', {}).get('passed') is True,
            'gold_poc_private_present': (task_dir / 'gold' / 'poc').is_file(),
            'reference_verified': bool(verified), 'reference_evidence_status': evidence_status,
            'reference_evidence_path': str(evidence_path.relative_to(ROOT)) if evidence else None,
            'reference_evidence_failure': evidence_failure,
            'blockers': blockers,
            'status': 'public_ready_reference_unverified' if audit.get('passed') and not verified else
                      ('public_and_reference_verified' if audit.get('passed') and verified else 'public_incomplete'),
        })
    return {
        'schema_version': 1, 'shard': 3, 'updated_at': now(),
        'scope': 'Cache materialization, historical recipe/harness provenance, metadata and public leak audits only.',
        'stage_completed': 'public_materialization_and_audit',
        'counts': {'requested': len(IDS), 'public_ready': sum(t['public_audit_passed'] for t in tasks),
                   'reference_verified': sum(t['reference_verified'] for t in tasks),
                   'private_gold_present': sum(t['gold_poc_private_present'] for t in tasks)},
        'sanitizer_distribution': {label: sum(t['sanitizer'] == label for t in tasks)
                                    for label in ('ASan', 'MSan', 'UBSan')},
        'network': {'redownloaded_primary_sources': False, 'reference_images_pulled': False,
                    'external_harness_sources': 'Only exact curl-fuzzer/GPAC testsuite srcmap revisions were fetched; source files only.'},
        'reference_execution_performed': False,
        'reference_execution_pending': [t['arvo_id'] for t in tasks if not t['reference_verified']],
        'source_cleaning': ['No VCS metadata, ELF/binary output, .o/.a/.so, /out, CMakeFiles, .deps, .libs or .cache.',
                            'GNU gold exemption is only binutils-gdb/gold source in ARVO 55587; binary/PoC findings never exempt.',
                            'curl-fuzzer and GPAC testsuite harness sources are bound to exact srcmap revisions; corpora excluded.'],
        'interfaces': {'task_instruction': 'input/TASK.md', 'runner': '/usr/local/bin/run_poc <path>',
                       'mounted_input': '/tmp/poc', 'labels': ['cdb.cybergym.role=vul', 'cdb.cybergym.role=fix'],
                       'status': 'Documented in task input; no agent-built environment was executed in this stage.'},
        'tasks': tasks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('acquire', 'prepare', 'verify', 'audit'))
    parser.add_argument('--ids', type=lambda text: [int(x) for x in text.split(',')], default=list(IDS))
    args = parser.parse_args()
    if any(issue not in IDS for issue in args.ids):
        parser.error('ID outside shard-3 ownership')
    CACHE.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)
    operation = {'acquire': acquire, 'prepare': prepare, 'verify': verify, 'audit': public_audit}[args.command]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(operation, args.ids))
    atomic_json(RESULTS / f'{args.command}-summary.json', {'updated_at': now(), 'results': results})
    return int(any(result.get('status') == 'failed' for result in results))


if __name__ == '__main__':
    raise SystemExit(main())
