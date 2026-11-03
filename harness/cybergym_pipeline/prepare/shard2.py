#!/usr/bin/env python3
"""Shard-2-only CyberGym acquisition, packaging, and reference verification.

Public sources and historical recipes are obtained upstream. Official ARVO images
are used only in the private verification phase; no image layer or compiled
artifact is imported into public inputs. No agent or model process is invoked.
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
import shlex
import shutil
import subprocess
import tempfile
import time
import urllib.request

import yaml

from . import materialize
from . import audit as shared_audit
from .audit import audit_task, audit_tree

ROOT = Path(__file__).resolve().parents[3]
CACHE = Path('/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cybergym/cache')
PRIVATE = Path('/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cybergym/shard2')
RESULTS = ROOT / 'results/cybergym-preparation/shard2'
IDS = (1856, 4099, 49903, 64574, 61235, 3938, 18756, 26163, 26567, 15120)
WORKER = 'root@100.96.153.163'
META = 'https://raw.githubusercontent.com/n132/ARVO-Meta/main/archive_data/meta/{}.json'
HF = 'https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main/data/arvo/{}/{}'
OSS_FUZZ_GIT = CACHE / 'oss-fuzz.git'
SANITIZER_ENVS = {'asan': 'address', 'msan': 'memory', 'ubsan': 'undefined'}
SANITIZER_LABELS = {'asan': 'ASan', 'msan': 'MSan', 'ubsan': 'UBSan'}


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def atomic_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.atomic-', delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def atomic_json(path: Path, data: object) -> None:
    atomic_bytes(path, (json.dumps(data, indent=2, ensure_ascii=False) + '\n').encode())


def download(url: str, target: Path, timeout: int = 300) -> Path:
    """A locked, atomic cache entry; incomplete data is never published."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file() and target.stat().st_size:
        return target
    with target.with_name(target.name + '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if target.is_file() and target.stat().st_size:
            return target
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.fetch-', delete=False) as stream:
            temporary = Path(stream.name)
            try:
                request = urllib.request.Request(url, headers={'User-Agent': 'cdb-shard2-source-acquisition/1'})
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    while block := response.read(1024 * 1024):
                        stream.write(block)
                stream.flush()
                os.fsync(stream.fileno())
                if temporary.stat().st_size == 0:
                    raise ValueError('empty HTTP response')
                os.chmod(temporary, 0o444)
                os.replace(temporary, target)
            except Exception:
                temporary.unlink(missing_ok=True)
                raise
    return target


def run(command: list[str], timeout: int = 120, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=True)


def checkpoint(issue: int, stage: str, **detail: object) -> None:
    atomic_json(RESULTS / str(issue) / 'checkpoint.json', {
        'arvo_id': issue, 'stage': stage, 'updated_at': now(), **detail,
    })


def first_report(meta: dict) -> str:
    return next(c.get('content', '') for c in meta['report']['comments'] if c.get('descriptionNum') == 1)


def field(text: str, name: str) -> str:
    match = re.search(rf'^{re.escape(name)}:\s*(\S+)', text, re.MULTILINE)
    return match.group(1) if match else ''


def revision(url: str) -> str:
    match = re.search(r'(?:range=\d{12}:|revision=)(\d{12})', url or '')
    return match.group(1) if match else ''


def parsed_metadata(issue: int, meta: dict) -> dict:
    report = first_report(meta)
    job = field(report, 'Job Type')
    engine, short_sanitizer, project = job.split('_', 2)
    sanitizer = SANITIZER_ENVS[short_sanitizer]
    sanitizer_label = SANITIZER_LABELS[short_sanitizer]
    if project != meta['project']:
        raise ValueError(f'project mismatch: {job} vs {meta["project"]}')
    fixed_comments = [c.get('content', '') for c in meta['report']['comments']
                      if 'revisions' in c.get('content', '') and 'fixed' in c.get('content', '').lower()]
    if not fixed_comments:
        raise ValueError('no verified fixed revision comment in ARVO-Meta')
    fixed_urls = re.findall(r'https?://\S*revisions\S+', fixed_comments[-1])
    timestamps = {'vul': revision(field(report, 'Regressed')), 'fix': revision(fixed_urls[-1])}
    stack_start = re.search(r'^Crash State:\s*\n((?:  .+\n)+)', report, re.MULTILINE)
    stack = stack_start.group(1).strip().splitlines() if stack_start else []
    target = field(report, 'Fuzz Target') or field(report, 'Fuzz target binary') or field(report, 'Fuzzer').removeprefix('libFuzzer_')
    expected_stack = [x.strip() for x in stack]
    if not target or not expected_stack:
        raise ValueError(f'{issue}: missing real fuzz target or expected stack in ARVO-Meta')
    if meta.get('sanitizer') != short_sanitizer:
        raise ValueError(f'{issue}: sanitizer mismatch between issue and job: {meta.get("sanitizer")} vs {short_sanitizer}')
    return {'engine': engine, 'sanitizer': sanitizer, 'sanitizer_label': sanitizer_label,
            'short_sanitizer': short_sanitizer, 'fuzz_target': target, 'timestamps': timestamps,
            'expected_stack': expected_stack, 'report': report}


def acquire(issue: int) -> dict:
    raw = PRIVATE / 'upstream' / str(issue)
    try:
        checkpoint(issue, 'downloading_metadata')
        meta_path = download(META.format(issue), raw / 'meta.json')
        meta = json.loads(meta_path.read_text())
        if meta.get('localId') != issue:
            raise ValueError('ARVO-Meta localId mismatch')
        parsed = parsed_metadata(issue, meta)
        sources = {}
        for name in ('repo-vul.tar.gz', 'repo-fix.tar.gz', 'description.txt', 'error.txt'):
            url = HF.format(issue, name)
            path = download(url, raw / name, timeout=600)
            sources[name] = {'url': url, 'sha256': sha256(path), 'bytes': path.stat().st_size}
        checkpoint(issue, 'downloading_srcmaps', source_files=sorted(sources))
        srcmaps = {}
        for role, timestamp in parsed['timestamps'].items():
            if not timestamp:
                raise ValueError(f'missing {role} srcmap timestamp')
            url = materialize.srcmap_url(meta['project'], parsed['sanitizer'], timestamp)
            path = download(url, raw / f'srcmap-{role}.json')
            data = json.loads(path.read_text())
            if not data:
                raise ValueError(f'empty {role} srcmap')
            srcmaps[role] = {'url': url, 'sha256': sha256(path), 'srcmap': data}
        # Keep raw reproducer URLs and issue comments exclusively in private storage.
        poc_url = re.search(r'Reproducer Testcase:\s*(\S+)', parsed['report']).group(1)
        poc_result = {'url': poc_url, 'status': 'not_attempted'}
        if not (raw / 'gold-poc').is_file():
            try:
                path = download(poc_url, raw / 'gold-poc', timeout=75)
                poc_result = {'url': poc_url, 'status': 'downloaded', 'sha256': sha256(path)}
            except Exception as exc:
                poc_result = {'url': poc_url, 'status': 'failed', 'reason': f'{type(exc).__name__}: {exc}'}
        record = {'arvo_id': issue, 'acquired_at': now(), 'project': meta['project'],
                  'engine': parsed['engine'], 'sanitizer': parsed['sanitizer'],
                  'fuzz_target': parsed['fuzz_target'], 'expected_stack': parsed['expected_stack'],
                  'crash_type': meta['crash_type'], 'fix_commit': meta.get('fix_commit'),
                  'repo_addr': meta.get('repo_addr'), 'timestamps': parsed['timestamps'],
                  'source_archives': sources, 'srcmaps': srcmaps, 'direct_poc_download': poc_result}
        atomic_json(raw / 'acquisition.json', record)
        atomic_json(RESULTS / str(issue) / 'acquisition.json', record)
        checkpoint(issue, 'acquired', srcmap_timestamps=parsed['timestamps'], poc=poc_result['status'])
        print(f'ACQUIRED {issue}: {meta["project"]}, PoC={poc_result["status"]}', flush=True)
        return {'arvo_id': issue, 'status': 'acquired', 'poc': poc_result['status']}
    except Exception as exc:
        reason = f'{type(exc).__name__}: {exc}'
        checkpoint(issue, 'acquisition_failed', reason=reason)
        return {'arvo_id': issue, 'status': 'failed', 'reason': reason}


def source_revision_evidence(raw: Path, meta: dict, record: dict) -> dict:
    """Read actual archive git metadata before cleaning; never publish that metadata."""
    import tarfile
    result = {}
    for role in ('vul', 'fix'):
        archive = raw / f'repo-{role}.tar.gz'
        heads = []
        with tarfile.open(archive, 'r:*') as tar:
            for member in tar:
                if member.isfile() and member.name.endswith('/.git/HEAD'):
                    data = tar.extractfile(member).read(200).decode(errors='replace')
                    heads.append({'path': member.name, 'HEAD': data.strip()})
        mapped = record['srcmaps'][role]['srcmap']
        main = mapped.get('/src/' + meta['project'])
        result[role] = {'srcmap_main_revision': (main or {}).get('rev'),
                        'git_heads_before_cleaning': heads,
                        'note': 'CyberGym source archive plus independently fetched historical srcmap; no git metadata is public.'}
    return result


def audit_source_archive(path: Path) -> dict:
    """The upstream mruby compiler source is a text file named ``core``.

    Preserve real upstream source and record the reviewed exception; still reject
    executable content and every other core/poc-like archive name.
    """
    import tarfile
    reviewed = []
    # Only an actual mruby compiler grammar can use this narrow exception.
    # The module-level set is not mutated: archive scans may run concurrently.
    with tarfile.open(path, 'r:*') as archive:
        members = archive.getmembers()
        for member in members:
            if member.isfile() and member.name.endswith('/core'):
                data = archive.extractfile(member).read()
                if b'class Rite' in data and b'codegen' in data and b'\x7fELF' not in data[:8192]:
                    reviewed.append(member.name)
    report = shared_audit.audit_tar(path)
    allowed = {f'archive leaked PoC-like name: {name}' for name in reviewed}
    report['issues'] = [issue for issue in report['issues'] if issue not in allowed]
    report['reviewed_source_names'] = reviewed
    return report


def safe_description(text: str) -> str:
    """Allow descriptive text, never raw issue history or reproducer locations."""
    text = re.sub(r'https?://(?:bugs\.chromium\.org|issues\.oss-fuzz\.com|oss-fuzz\.com)\S*',
                  '[upstream issue location omitted]', text)
    return materialize.sanitize_text(text).replace('GOLD PoC', 'private reference input')


def prepare(issue: int) -> dict:
    raw = PRIVATE / 'upstream' / str(issue)
    task_dir = ROOT / 'tasks' / f'cybergym-arvo-{issue}'
    staging = RESULTS / str(issue) / 'staging'
    try:
        checkpoint(issue, 'packaging')
        meta = json.loads((raw / 'meta.json').read_text())
        record = json.loads((raw / 'acquisition.json').read_text())
        parsed = parsed_metadata(issue, meta)
        if record['fuzz_target'] != parsed['fuzz_target'] or record['expected_stack'] != parsed['expected_stack']:
            raise ValueError(f'{issue}: cached acquisition differs from real ARVO-Meta target/stack')
        if record['sanitizer'] != parsed['sanitizer'] or record['timestamps'] != parsed['timestamps']:
            raise ValueError(f'{issue}: cached acquisition differs from real ARVO-Meta sanitizer/revisions')
        if not OSS_FUZZ_GIT.is_dir():
            raise FileNotFoundError(f'complete OSS-Fuzz bare history is required: {OSS_FUZZ_GIT}')
        if staging.exists():
            shutil.rmtree(staging)
        staging.parent.mkdir(parents=True, exist_ok=True)
        input_dir = staging / 'input'
        input_dir.mkdir(parents=True)
        (staging / 'gold').mkdir()
        revision_evidence = source_revision_evidence(raw, meta, record)
        atomic_json(raw / 'source-revisions.json', revision_evidence)
        for role in ('vul', 'fix'):
            output = input_dir / f'sources-{role}.tar.gz'
            cleaning = materialize._cleaned_tar_bytes(raw / f'repo-{role}.tar.gz', output)
            cleaning['provenance'] = record['source_archives'][f'repo-{role}.tar.gz']
            cleaning['revision_evidence'] = revision_evidence[role]
            problems = audit_source_archive(output)['issues']
            if problems:
                raise ValueError(f'{role} source archive audit: {problems[:8]}')
            atomic_json(input_dir / f'cleaning-{role}.json', cleaning)
            shutil.copyfile(raw / f'srcmap-{role}.json', input_dir / f'srcmap-{role}.json')
            timestamp = materialize.source_timestamp(f'x-{record["timestamps"][role]}.srcmap.json')
            recipe = materialize.historical_recipe(OSS_FUZZ_GIT, meta['project'], timestamp,
                                                   input_dir / 'oss-fuzz' / role)
            atomic_json(input_dir / f'oss-fuzz-{role}.json', {
                'revision': recipe['commit'], 'srcmap_timestamp': record['timestamps'][role],
                'recipe_path': f'oss-fuzz/{role}', 'source': recipe['source'],
            })
            if not json.loads((input_dir / f'srcmap-{role}.json').read_text()):
                raise ValueError(f'{issue}: empty {role} srcmap')
            for required_recipe in ('Dockerfile', 'build.sh', 'project.yaml'):
                if not (input_dir / 'oss-fuzz' / role / required_recipe).is_file():
                    raise ValueError(f'{issue}: missing {role} historical {required_recipe}')
        description = safe_description((raw / 'description.txt').read_text(errors='replace'))
        atomic_bytes(input_dir / 'description.md', (
            f'# {meta["project"]} / arvo:{issue}\n\n{description.strip()}\n\n'
            f'Engine: `{parsed["engine"]}`; sanitizer: `{parsed["sanitizer_label"]}`; '
            f'target: `{parsed["fuzz_target"]}`.\n\n'
            'Upstream ARVO-Meta and historical OSS-Fuzz provenance are included. '
            'Private issue history, reproducer URLs and reproducer bytes are not public inputs.\n').encode())
        atomic_bytes(input_dir / 'error.txt', safe_description((raw / 'error.txt').read_text(errors='replace')).encode())
        atomic_json(input_dir / 'crash-context.json', {
            'crash_type': meta['crash_type'], 'expected_stack': parsed['expected_stack'],
            'sanitizer': parsed['sanitizer_label'], 'sanitizer_env': parsed['sanitizer'],
            'fuzz_target': parsed['fuzz_target'], 'engine': parsed['engine'],
            'note': 'Public diagnostic context only; no reproducer or raw issue history.'})
        values = {'project': meta['project'], 'upstream_task_id': f'arvo:{issue}',
                  'sanitizer': parsed['sanitizer_label'], 'sanitizer_env': parsed['sanitizer'],
                  'fuzz_target': parsed['fuzz_target'], 'fuzz_engine': parsed['engine']}
        instruction = materialize.INSTRUCTION.format(**values).encode()
        atomic_bytes(staging / 'instruction.md', instruction)
        # The runtime consumes input/TASK.md; keep the top-level copy only for
        # compatibility. Both copies are generated from the same real metadata.
        atomic_bytes(input_dir / 'TASK.md', instruction)
        atomic_json(input_dir / 'normal-input-contract.json', {
            'status': 'not_bundled', 'requirement': 'Author a normal non-crashing smoke input and test both versions.',
            'seed_source': 'No upstream crashing or unverified corpus input is bundled.'})
        files = {str(path.relative_to(input_dir)): {'sha256': sha256(path), 'bytes': path.stat().st_size}
                 for path in sorted(input_dir.rglob('*')) if path.is_file() and path.name != 'manifest.json'}
        atomic_json(input_dir / 'manifest.json', {'schema_version': 1, 'task_id': f'cybergym-arvo-{issue}',
                    'source_versions': ['vul', 'fix'], 'private_inputs_excluded': True, 'files': files})
        metadata = {'task_id': f'cybergym-arvo-{issue}', 'family': 'cybergym', 'task_type': 'binary-env-synthesis',
                    'project': meta['project'], 'upstream_task_id': f'arvo:{issue}', 'sanitizer': parsed['sanitizer_label'],
                    'fuzz_target': parsed['fuzz_target'], 'fuzz_engine': parsed['engine'], 'language': 'c/c++',
                    'crash_type': meta['crash_type'], 'expected_stack': parsed['expected_stack'],
                    'reference_verified': False,
                    'private': {'gold_poc': 'gold/poc', 'reference_manifest': 'gold/reference-manifest.json',
                                'verify_reference': 'gold/verify_reference.json'},
                    'public_input': 'input', 'timeout_sec': 18000, 'max_turns': 280,
                    'resources': {'cpu': 4, 'memory_gb': 12, 'disk_gb': 30}}
        # Preparation is not private reference verification. Never inherit a
        # verified claim or stale verification digest while rebuilding inputs.
        atomic_bytes(staging / 'metadata.yaml', yaml.safe_dump(metadata, sort_keys=False).encode())
        atomic_json(staging / 'gold' / 'upstream-private.json', {
            'upstream': meta, 'acquisition': record, 'revision_evidence': revision_evidence,
            'provenance': 'ARVO-Meta raw issue is private; public inputs contain sanitized descriptions only.'})
        problems = audit_tree(input_dir)['issues']
        # audit_tree conservatively matches the archive basename. The reviewed
        # mruby exception above already inspected every member named "core".
        reviewed = set()
        for role in ('vul', 'fix'):
            for member in audit_source_archive(input_dir / f'sources-{role}.tar.gz')['reviewed_source_names']:
                reviewed.add(f'sources-{role}.tar.gz: archive leaked PoC-like name: {member}')
        problems = [problem for problem in problems if problem not in reviewed]
        if problems:
            raise ValueError(f'public input leak audit: {problems[:10]}')
        report = audit_task(staging, require_verified=False)
        if 'TASK.md' not in files or not (input_dir / 'TASK.md').is_file():
            raise ValueError(f'{issue}: input/TASK.md is required and must be manifested')
        if metadata['sanitizer'] not in SANITIZER_LABELS.values():
            raise ValueError(f'{issue}: metadata sanitizer must be ASan/MSan/UBSan')
        if metadata['fuzz_target'] != parsed['fuzz_target'] or not metadata['fuzz_target']:
            raise ValueError(f'{issue}: metadata fuzz_target differs from ARVO-Meta')
        if metadata['expected_stack'] != parsed['expected_stack'] or not metadata['expected_stack']:
            raise ValueError(f'{issue}: metadata expected_stack differs from ARVO-Meta')
        if not report['passed']:
            raise ValueError(f'public task audit: {report["issues"][:10]}')
        report['task_id'] = f'cybergym-arvo-{issue}'
        report['reference_verification'] = 'not_performed_by_shard2_preparation'
        atomic_json(RESULTS / str(issue) / 'public-audit.json', report)
        task_dir.mkdir(parents=True, exist_ok=True)
        for old in ('materials', 'tests', 'solution', 'input'):
            target = task_dir / old
            if target.is_dir():
                shutil.rmtree(target)
            elif target.exists():
                target.unlink()
        for name in ('input', 'instruction.md', 'metadata.yaml'):
            source = staging / name
            destination = task_dir / name
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copyfile(source, destination)
        (task_dir / 'gold').mkdir(exist_ok=True)
        shutil.copyfile(staging / 'gold' / 'upstream-private.json', task_dir / 'gold' / 'upstream-private.json')
        checkpoint(issue, 'prepared_unverified', public_audit='passed')
        print(f'PACKAGED {issue}: {report["public"]["files"]} public files, {report["public"]["bytes"]} bytes', flush=True)
        return {'arvo_id': issue, 'status': 'prepared_unverified'}
    except Exception as exc:
        reason = f'{type(exc).__name__}: {exc}'
        checkpoint(issue, 'packaging_failed', reason=reason)
        return {'arvo_id': issue, 'status': 'failed', 'reason': reason}


def fetch_private_references(issue: int, transfer: bool = False) -> dict:
    """Private only: load official references and extract GOLD PoC, never public input."""
    raw = PRIVATE / 'upstream' / str(issue)
    evidence = {'arvo_id': issue, 'worker': WORKER, 'transfer': transfer, 'roles': {}}
    try:
        checkpoint(issue, 'downloading_private_references')
        for role in ('vul', 'fix'):
            image = f'n132/arvo:{issue}-{role}'
            available = subprocess.run(['ssh', WORKER, 'docker', 'image', 'inspect', image],
                                       capture_output=True, timeout=60).returncode == 0
            if not available:
                try:
                    run(['ssh', WORKER, f"bash -lc 'timeout 240 docker pull --quiet {shlex.quote(image)}'"], timeout=300)
                    available = True
                    method = 'worker_pull_with_existing_network'
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                    method = f'worker pull unavailable; using standard image archive transfer: {exc}'
                if not available:
                    run(['docker', 'pull', '--quiet', image], timeout=1500)
                    archive_dir = PRIVATE / 'private-images'
                    archive_dir.mkdir(exist_ok=True)
                    archive = archive_dir / f'arvo-{issue}-{role}.tar'
                    if not archive.is_file() or archive.stat().st_size == 0:
                        temporary = archive.with_name(f'.{archive.name}.tmp-{os.getpid()}')
                        run(['docker', 'save', '-o', str(temporary), image], timeout=1200)
                        os.replace(temporary, archive)
                    run(['ssh', WORKER, 'docker', 'load', '-i', str(archive)], timeout=1200)
                    method += '; archive loaded successfully'
            else:
                method = 'already_available_on_worker'
            evidence['roles'][role] = {'reference_pull': method}
        task_gold = ROOT / 'tasks' / f'cybergym-arvo-{issue}' / 'gold'
        task_gold.mkdir(exist_ok=True)
        for role in ('vul', 'fix'):
            image = f'n132/arvo:{issue}-{role}'
            inspect = run(['ssh', WORKER, 'docker', 'image', 'inspect', image, '--format',
                           '{{.Id}} {{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}} {{.Os}}/{{.Architecture}}'], timeout=90)
            with tempfile.TemporaryDirectory(dir=PRIVATE / 'work') as directory:
                remote = f'/tmp/cdb-shard2-{issue}-{role}-poc-{os.getpid()}'
                run(['ssh', WORKER, f'docker cp {shlex.quote(image)}:/tmp/poc {shlex.quote(remote)}'], timeout=180)
                try:
                    subprocess.run(['scp', '-q', f'{WORKER}:{remote}', str(Path(directory) / f'poc-{role}')], check=True, timeout=120)
                    poc = Path(directory) / f'poc-{role}'
                    if not poc.is_file() or poc.stat().st_size == 0:
                        raise ValueError(f'empty GOLD PoC in private reference {image}')
                    if (raw / 'gold-poc').is_file() and sha256(poc) != sha256(raw / 'gold-poc'):
                        raise ValueError('direct OSS-Fuzz and ARVO private PoC bytes differ')
                    if role == 'vul':
                        shutil.copyfile(poc, task_gold / 'poc')
                    evidence['roles'][role].update({'image': image, 'inspect': inspect.stdout.strip(),
                                                    'poc_sha256': sha256(poc), 'poc_bytes': poc.stat().st_size})
                finally:
                    run(['ssh', WORKER, 'rm', '-f', remote], timeout=30)
        atomic_json(RESULTS / str(issue) / 'private-reference-acquisition.json', evidence)
        checkpoint(issue, 'private_references_acquired')
        return {'arvo_id': issue, 'status': 'private_references_acquired'}
    except Exception as exc:
        evidence['error'] = f'{type(exc).__name__}: {exc}'
        if isinstance(exc, subprocess.CalledProcessError):
            evidence['stderr'] = exc.stderr[-8000:] if exc.stderr else ''
        atomic_json(RESULTS / str(issue) / 'private-reference-acquisition.json', evidence)
        checkpoint(issue, 'private_reference_failed', reason=evidence['error'])
        return {'arvo_id': issue, 'status': 'failed', 'reason': evidence['error']}


def summarize(name: str, results: list[dict]) -> None:
    atomic_json(RESULTS / name, {'updated_at': now(), 'results': results})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('acquire', 'prepare', 'references', 'audit'))
    parser.add_argument('--ids', type=lambda value: [int(item) for item in value.split(',')], default=list(IDS))
    args = parser.parse_args()
    if any(issue not in IDS for issue in args.ids):
        parser.error('id outside shard-2 ownership')
    RESULTS.mkdir(parents=True, exist_ok=True)
    (PRIVATE / 'work').mkdir(parents=True, exist_ok=True)
    if args.command == 'audit':
        reports = [audit_task(ROOT / 'tasks' / f'cybergym-arvo-{issue}') for issue in args.ids]
        result = {'passed': all(x['passed'] for x in reports), 'tasks': reports}
        atomic_json(RESULTS / 'audit.json', result)
        print(json.dumps(result, indent=2))
        return int(not result['passed'])
    operation = {'acquire': acquire, 'prepare': prepare, 'references': fetch_private_references}[args.command]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(operation, args.ids))
    summarize(args.command + '-summary.json', results)
    print(json.dumps(results, indent=2))
    return int(any(x['status'] == 'failed' for x in results))


if __name__ == '__main__':
    raise SystemExit(main())
