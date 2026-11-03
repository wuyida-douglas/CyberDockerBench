#!/usr/bin/env python3
"""Shard-0 project-name mapping and precise source-only audit wrapper.

The shared materializer performs actual cleaning and historical recipe extraction.
This module only handles ARVO's php-src -> OSS-Fuzz php mapping and distinguishes
legitimate source directories named core from real ELF core dumps. It never
weakens binary, VCS, PoC, reproducer-link or reference-image checks.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import zipfile

import yaml

from . import materialize
from .audit import (
    BINARY_SUFFIXES, DANGEROUS_NAMES, DANGEROUS_PARTS, audit_task, audit_tar as strict_audit_tar,
    is_executable_bytes,
)
from .shard0 import (
    CACHE, IDS, RESULTS, ROOT, atomic_json, checkpoint, discover_timestamps,
    expected_stack, fuzz_target, now, sha256,
)

SANITIZERS = {
    'address': ('ASan', 'address'), 'asan': ('ASan', 'address'),
    'memory': ('MSan', 'memory'), 'msan': ('MSan', 'memory'),
    'undefined': ('UBSan', 'undefined'), 'ubsan': ('UBSan', 'undefined'),
}
REQUIRED_PUBLIC = (
    'sources-vul.tar.gz', 'sources-fix.tar.gz', 'srcmap-vul.json', 'srcmap-fix.json',
    'oss-fuzz-vul.json', 'oss-fuzz-fix.json', 'TASK.md',
    'description.md', 'error.txt', 'crash-context.json', 'revisions.json', 'manifest.json',)
LEAK_PATTERNS = {
    'official image': re.compile(rb'n132/arvo|docker\.io/n132/arvo', re.I),
    'reproducer download': re.compile(
        rb'oss-fuzz\.com/(?:download|testcase)|testcase_id=|bugs\.oss-fuzz\.com|'
        rb'issues\.oss-fuzz\.com', re.I),
    'private gold reference': re.compile(rb'GOLD[ _-]?PoC|gold[/_-]poc|private[/_-]poc', re.I),
    'placeholder': re.compile(rb'see[-_ ]snapshot|source\s+(?:at|from)\s+URL\s*:\s*$', re.I | re.M),
}


def atomic_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + f'.tmp-{os.getpid()}')
    temporary.write_bytes(content)
    os.replace(temporary, path)


def atomic_text(path: Path, content: str) -> None:
    atomic_bytes(path, content.encode())


def atomic_yaml(path: Path, value: object) -> None:
    atomic_text(path, yaml.safe_dump(value, sort_keys=False))


def sanitize_public_text(text: str) -> str:
    text = re.sub(r'(?im)^.*(?:Detailed Report:|Reproducer Testcase:|testcase_id=|'
                  r'oss-fuzz\.com/(?:download|testcase)).*$',
                  '[Private issue and reproducer reference removed].', text)
    return text.replace('GOLD PoC', 'private reference input')


def source_audit(path: Path) -> dict:
    """Reject real binary core dumps, not ordinary directories named core."""
    report = strict_audit_tar(path)
    retained = []
    with tarfile.open(path, 'r:*') as archive:
        for member in archive:
            if PurePosixPath(member.name).name.lower() == 'core':
                retained.append({'path': member.name, 'kind': 'directory' if member.isdir() else 'regular file'})
    report['core_path_review'] = retained
    directories = {item['path'] for item in retained if item['kind'] == 'directory'}
    report['issues'] = [issue for issue in report['issues']
                        if issue not in {f'archive leaked PoC-like name: {name}' for name in directories}]
    if any(item['kind'] != 'directory' for item in retained):
        report['issues'].append('regular source file named core requires manual PoC/core-dump review')
    report['policy_note'] = 'Source directories named core retained; ELF/core binary checks remain strict.'
    return report


class RoleTimestamps(dict):
    """Accept both historical shared-helper indexing conventions without editing it."""
    def __iter__(self):
        return iter(self.values())

    def __getitem__(self, role):
        if isinstance(role, int):
            return tuple(self.values())[role]
        return super().__getitem__(role)


def prepare(issue: int) -> dict:
    actual_task = ROOT / 'tasks' / f'cybergym-arvo-{issue}'
    staging_root = actual_task / '.shard0-staging'
    try:
        acquisition_path = RESULTS / str(issue) / 'acquisition.json'
        if not acquisition_path.is_file():
            raise ValueError('verified cache acquisition record is required; refusing a fresh rebuild')
        acquisition = json.loads(acquisition_path.read_text())
        for name, details in acquisition['files'].items():
            cached = CACHE / str(issue) / name
            if not cached.is_file() or sha256(cached) != details['sha256']:
                raise ValueError(f'cached source integrity mismatch: {name}')
        checkpoint(issue, 'materializing_shard0', reuse_verified_cache=True)
        meta = json.loads((CACHE / str(issue) / 'meta.json').read_text())
        recipe_meta = copy.deepcopy(meta)
        if recipe_meta['project'] == 'php-src':
            recipe_meta['project'] = 'php'
        selection = {
            'srcmap_timestamps': RoleTimestamps(zip(('vul', 'fix'), discover_timestamps(meta))),
            'expected_stack': expected_stack(meta),
            'record': {
                'fuzz_target': fuzz_target(meta), 'fuzz_engine': meta['fuzzer'],
                'language': 'c' if meta['project'] in ('gpac', 'php-src') else 'c++',
            },
        }
        # Never let a failed conversion destroy an already public input. All
        # downloads resolve against the validated cache before this staging run.
        if staging_root.exists():
            shutil.rmtree(staging_root)
        staging_root.mkdir(parents=True)
        args = SimpleNamespace(tasks=staging_root, cache=CACHE,
                               oss_fuzz_git=CACHE / 'oss-fuzz/.git')
        original = materialize.audit_tar
        materialize.audit_tar = source_audit
        try:
            result = materialize.prepare_task(
                {'task_id': f'arvo:{issue}', 'project_language': selection['record']['language']},
                recipe_meta, selection, args)
        finally:
            materialize.audit_tar = original
        task = staging_root / f'cybergym-arvo-{issue}'
        metadata = yaml.safe_load((task / 'metadata.yaml').read_text())
        metadata['project'] = meta['project']
        metadata['oss_fuzz_project'] = recipe_meta['project']
        atomic_yaml(task / 'metadata.yaml', metadata)
        maps = {role: json.loads((task / 'input' / f'srcmap-{role}.json').read_text())
                for role in ('vul', 'fix')}
        atomic_json(task / 'input' / 'revisions.json', {
            'task_id': metadata['task_id'], 'upstream_task_id': metadata['upstream_task_id'],
            'upstream_project': meta['project'], 'oss_fuzz_project': recipe_meta['project'],
            'roles': {role: {'source_archive': f'sources-{role}.tar.gz',
                             'srcmap': f'srcmap-{role}.json',
                             'revisions': maps[role]} for role in ('vul', 'fix')},
        })
        manifest_path = task / 'input/manifest.json'
        manifest = json.loads(manifest_path.read_text())
        for path in sorted((task / 'input').rglob('*')):
            if path.is_file() and path.name != 'manifest.json':
                manifest['files'][str(path.relative_to(task / 'input'))] = {
                    'sha256': sha256(path), 'bytes': path.stat().st_size}
        manifest['public_source_policy'] = 'Complete cleaned vul/fix source snapshots, not URL placeholders.'
        atomic_json(manifest_path, manifest)
        for role in ('vul', 'fix'):
            report = source_audit(task / 'input' / f'sources-{role}.tar.gz')
            if report['issues']:
                raise ValueError(f'{role} source audit: {report["issues"][:8]}')
            atomic_json(RESULTS / str(issue) / f'source-audit-{role}.json', report)
        result.update({'arvo_id': issue, 'project': meta['project'],
                       'oss_fuzz_project': recipe_meta['project'], 'source_audited': True})
        previous_metadata_path = actual_task / 'metadata.yaml'
        previous_metadata = yaml.safe_load(previous_metadata_path.read_text()) if previous_metadata_path.is_file() else {}
        previous_input = actual_task / '.shard0-previous-input'
        if previous_input.exists():
            shutil.rmtree(previous_input)
        actual_input = actual_task / 'input'
        if actual_input.exists():
            os.replace(actual_input, previous_input)
        try:
            os.replace(task / 'input', actual_input)
        except Exception:
            if previous_input.exists() and not actual_input.exists():
                os.replace(previous_input, actual_input)
            raise
        if previous_input.exists():
            shutil.rmtree(previous_input)
        atomic_text(actual_task / 'instruction.md', (task / 'instruction.md').read_text())
        # Do not overwrite a parent's concurrent private verification evidence.
        if previous_metadata:
            atomic_yaml(actual_task / 'metadata.yaml', previous_metadata)
        else:
            atomic_yaml(actual_task / 'metadata.yaml', metadata)
        result['cache_reused'] = True
        result['reference_verified_touched'] = False
        atomic_json(RESULTS / str(issue) / 'materialization.json', result)
        checkpoint(issue, 'materialized_unverified', fuzz_target=selection['record']['fuzz_target'],
                   cache_reused=True)
        print('MATERIALIZED', json.dumps(result), flush=True)
        shutil.rmtree(staging_root)
        return result
    except Exception as exc:
        checkpoint(issue, 'materialization_failed', reason=f'{type(exc).__name__}: {exc}')
        return {'arvo_id': issue, 'status': 'failed', 'reason': f'{type(exc).__name__}: {exc}'}


def write_public_manifest(task: Path, metadata: dict) -> dict:
    input_dir = task / 'input'
    manifest_path = input_dir / 'manifest.json'
    manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    manifest.update({
        'schema_version': 1, 'task_id': metadata['task_id'], 'source_versions': ['vul', 'fix'],
        'private_inputs_excluded': True, 'reference_verification': 'separate private preparation stage',
    })
    files = {}
    for path in sorted(input_dir.rglob('*')):
        if path.is_file() and path.name != 'manifest.json':
            files[str(path.relative_to(input_dir))] = {'sha256': sha256(path), 'bytes': path.stat().st_size}
    manifest['files'] = files
    manifest['public_source_policy'] = 'Complete cleaned vul/fix source snapshots and source-only supplements, not URL placeholders.'
    atomic_json(manifest_path, manifest)
    return manifest


def normalize_metadata(issue: int) -> dict:
    task = ROOT / 'tasks' / f'cybergym-arvo-{issue}'
    path = task / 'metadata.yaml'
    metadata = yaml.safe_load(path.read_text())
    upstream = json.loads((CACHE / str(issue) / 'meta.json').read_text())
    label, environment = SANITIZERS[upstream['sanitizer'].lower()]
    # This is an enum normalization only. Never alter or infer private runtime evidence.
    metadata.update({'project': upstream['project'], 'sanitizer': label,
                     'sanitizer_label': label, 'sanitizer_env': environment})
    metadata['oss_fuzz_project'] = 'php' if upstream['project'] == 'php-src' else upstream['project']
    atomic_yaml(path, metadata)
    return metadata


def source_dependencies(issue: int, task: Path, target: str) -> dict:
    """Describe actual source contents and required pinned external dependencies.

    The main project snapshot is not a replacement for a separately cloned
    dependency. In particular, GPAC's in-tree regression media are not its
    separately maintained OSS-Fuzz harnesses.
    """
    dependencies = json.loads((task / 'input' / 'revisions.json').read_text())
    for role, details in dependencies['roles'].items():
        with tarfile.open(task / 'input' / f'sources-{role}.tar.gz', 'r:gz') as archive:
            roots = set()
            for member in archive:
                parts = [part for part in PurePosixPath(member.name).parts if part not in ('.', '')]
                if len(parts) > 1 and parts[0] in (f'src-{role}', 'src'):
                    roots.add(parts[1])
        details['bundled_source_roots'] = sorted(roots)
        details['external_dependencies'] = []
        details['target_harness'] = {'status': 'located_in_source'}
        for location, revision in details['revisions'].items():
            if location.startswith('/src/') and location[5:] not in roots:
                details['external_dependencies'].append({**revision, 'destination': location})
        if issue in (1513, 1538):
            details['target_harness'] = {
                'status': 'located_in_source',
                'path': f'/src/ffmpeg/tools/target_dec_fuzzer.c',
                'target_derivation': f'Compile-time codec selection produces {target}.',
            }
        elif issue == 5429:
            details['target_harness'] = {
                'status': 'located_in_source', 'path': '/src/imagemagick/Magick++/fuzz/encoder_fuzzer.cc',
                'target_derivation': 'Historical src-vul/build.sh compiles encoder_fuzzer.cc with -DFUZZ_IMAGEMAGICK_ENCODER=SUN.',
                'build_script': '/src/build.sh',
            }
        elif issue in (61993, 65135):
            details['target_harness'] = {
                'status': 'located_in_source', 'path': '/src/php-src/sapi/fuzzer/fuzzer-tracing-jit.c',
                'target_derivation': 'The historical OSS-Fuzz build.sh installs this target as php-fuzz-tracing-jit.',
            }
        elif issue == 65319:
            details['target_harness'] = {
                'status': 'separate_harness_archive', 'path': '/src/testsuite/oss-fuzzers/fuzz_probe_analyze.c',
                'archive': f'dependencies-{role}/testsuite-oss-fuzzers.tar.gz',
                'source_revision': details['revisions']['/src/testsuite']['rev'],
            }
            details['external_dependencies'] = [item for item in details['external_dependencies']
                                                 if item['destination'] != '/src/testsuite']
        atomic_json(task / 'input' / f'dependencies-{role}.json', details)
    return dependencies


def dependency_notes(issue: int, task: Path) -> str:
    notes = []
    for role in ('vul', 'fix'):
        data = json.loads((task / 'input' / f'dependencies-{role}.json').read_text())
        for dependency in data['external_dependencies']:
            notes.append(f"- `{role}`: fetch {dependency['url']} at exact revision `{dependency['rev']}` "
                         f"into `{dependency['destination']}` ({dependency['type']}); it is not bundled.")
    if issue == 65319:
        notes.append('- Both roles: unpack `dependencies-<role>/testsuite-oss-fuzzers.tar.gz` at `/src/testsuite`. '
                     'This contains the exact-revision `oss-fuzzers` source subtree required by the historical '
                     'GPAC `build.sh`; its full unrelated regression-test corpus is intentionally not included.')
    if issue == 5429:
        notes.append('- The historical vulnerable `src-vul/build.sh` is the complete target-generation recipe. '
                     'It generates `encoder_sun_fuzzer` from `Magick++/fuzz/encoder_fuzzer.cc`; do not use the '
                     'later fixed-version `Magick++/fuzz/build.sh` interface interchangeably.')
    if issue == 65319:
        notes.append('- The historical recipe installs `pkg-config libz-dev`, but `build.sh` also links '
                     '`-lssl -lcrypto`. Preserve the exact source and provide the matching development dependency '
                     'in the declarative build; do not replace GPAC or its harness.')
    if issue in (61993, 65135):
        notes.append('- Seven pinned, unrelated Phar/ZIP regression-test files are removed from each public source '
                     'snapshot because they embed a compiled ELF, unsafe path-traversal entries, or an unreadable archive. See '
                     '`cleaning-<role>.json` for exact paths and hashes; the pinned source revisions and JIT '
                     'target sources are unchanged, and no broad test-directory exclusion is used.')
    return ('\n## Source dependency inventory\n\n'
            'Use `dependencies-vul.json` and `dependencies-fix.json` to distinguish bundled roots from '
            'external revisions. Do not clone a missing dependency at HEAD.\n' + '\n'.join(notes) + '\n')


def runner_notes(engine: str) -> str:
    if engine.lower() == 'afl':
        return ('\n## Single-input runner\n\n'
                'This historical AFL build may produce a target without libFuzzer file-argument handling. '
                '`/usr/local/bin/run_poc <path>` must feed that file on standard input (for example, '
                '`/out/server < "$1"`) rather than passing the pathname as a libFuzzer argument. Use one '
                'execution only; do not launch `afl-fuzz` or an open-ended fuzzing loop. The target source '
                'and historical AFL engine must remain unchanged.\n')
    return ('\n## Single-input runner\n\n'
            '`/usr/local/bin/run_poc <path>` must execute the requested target once, not `/bin/arvo`. '
            'For libFuzzer/honggfuzz use the target\'s single-file interface; do not start a fuzzing campaign.\n')


def supplement_gp(issue: int, task: Path) -> None:
    if issue != 65319:
        return
    repository = CACHE / str(issue) / 'gpac-testsuite'
    if not repository.is_dir():
        raise RuntimeError('exact GPAC harness git cache is missing; do not substitute current HEAD')
    revisions = json.loads((task / 'input' / 'revisions.json').read_text())
    for role in ('vul', 'fix'):
        revision = revisions['roles'][role]['revisions']['/src/testsuite']['rev']
        names = subprocess.check_output([
            'git', '-C', str(repository), 'ls-tree', '-r', '--name-only', revision, '--', 'oss-fuzzers',
        ], text=True, timeout=90).splitlines()
        if not names or 'oss-fuzzers/fuzz_probe_analyze.c' not in names:
            raise ValueError(f'{issue} {role}: exact GPAC target harness unavailable at {revision}')
        provenance = {'repository': 'https://github.com/gpac/testsuite.git', 'revision': revision,
                      'subtree': 'oss-fuzzers', 'files': {}}
        destination = task / 'input' / f'dependencies-{role}'
        destination.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.harness-') as directory:
            archive_path = Path(directory) / 'testsuite-oss-fuzzers.tar.gz'
            with tarfile.open(archive_path, 'w:gz', compresslevel=6) as archive:
                for name in sorted(names):
                    content = subprocess.check_output(['git', '-C', str(repository), 'show', f'{revision}:{name}'],
                                                      timeout=90)
                    if is_executable_bytes(content[:8192]):
                        raise ValueError(f'compiled GPAC harness asset: {name}')
                    for label, pattern in LEAK_PATTERNS.items():
                        if pattern.search(content):
                            raise ValueError(f'GPAC harness {label}: {name}')
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    info.mode = 0o755 if name.endswith('.sh') else 0o644
                    info.mtime = 0
                    archive.addfile(info, io.BytesIO(content))
                    provenance['files'][name] = {'sha256': hashlib.sha256(content).hexdigest(),
                                                'bytes': len(content)}
            temporary = destination / '.testsuite-oss-fuzzers.tmp'
            shutil.copyfile(archive_path, temporary)
            os.replace(temporary, destination / 'testsuite-oss-fuzzers.tar.gz')
        atomic_json(destination / 'provenance.json', provenance)


PHP_PRUNED_FIXTURES = {
    'ext/phar/tests/bug70019.zip': 'a7503db1ca9ef0bb5845f5def51ca42ad71c0496118b6974445ee858bb397646',
    'ext/phar/tests/bug70019.phpt': '5d3f75160320ee4929655d8519a86059be1a78e4af510635a28e198c8a4c16b8',
    'ext/phar/tests/zip/files/bz2_alias.phar.zip': 'bf59ce8d4b60d484c21a896e89cff01486570b0d0895ee62e259998b21cf5170',
    'ext/phar/tests/zip/bzip2.phpt': 'ca1fc86743870368e7e378f5a8d061d245849308bcc486d7e0c314dbb57cb654',
    'ext/zip/tests/bug81420.zip': '5ca740c587555c48b9b50bf4b7b5a9fe27f45603b866e303abeb5d9e02e5c2cc',
    'ext/zip/tests/bug81420.phpt': 'a52e68df4219c5a02692364fe8ace70ab9a60f720fce4de0f63c4aaa834cb5c8',
    'ext/zip/examples/test.zip': '7d7fce03ea4fb8be2f08c91a8abeac82d201146e3ecb66a7cdfae2c1132c1daa',
}


def prune_irrelevant_php_fixtures(issue: int, task: Path) -> None:
    """Remove pinned non-target ZIP tests, including a genuine embedded ELF.

    Other readable ZIP/Phar regression inputs stay source-controlled upstream
    data and are still explicitly audited. Hash pinning prevents this narrow
    cleanup from ever being used to remove a different executable or PoC.
    """
    if issue not in (61993, 65135):
        return
    for role in ('vul', 'fix'):
        archive_path = task / 'input' / f'sources-{role}.tar.gz'
        with tempfile.NamedTemporaryFile(dir=archive_path.parent, prefix='.source-prune-',
                                         suffix='.tar.gz', delete=False) as stream:
            temporary = Path(stream.name)
        removed = []
        try:
            with tarfile.open(archive_path, 'r:gz') as source, tarfile.open(temporary, 'w:gz') as target:
                for member in source:
                    suffix = next((name for name in PHP_PRUNED_FIXTURES
                                   if member.name == f'src-{role}/php-src/{name}'), None)
                    if suffix is not None:
                        handle = source.extractfile(member)
                        digest = hashlib.sha256(handle.read()).hexdigest() if handle else ''
                        if digest != PHP_PRUNED_FIXTURES[suffix]:
                            raise ValueError(f'PHP fixture changed; refusing broad cleanup: {member.name}')
                        removed.append({'path': member.name, 'sha256': digest,
                                        'reason': 'Unrelated Phar/ZIP regression example; nested ELF, unsafe traversal path, or unreadable archive is not needed by the JIT target.'})
                        continue
                    handle = source.extractfile(member) if member.isfile() else None
                    target.addfile(member, handle)
            os.replace(temporary, archive_path)
        finally:
            temporary.unlink(missing_ok=True)
        cleaning_path = task / 'input' / f'cleaning-{role}.json'
        cleaning = json.loads(cleaning_path.read_text())
        expected_paths = {f'src-{role}/php-src/{name}' for name in PHP_PRUNED_FIXTURES}
        recorded = {entry['path'] for entry in cleaning['removed']
                    if entry['path'] in expected_paths and entry.get('sha256') in PHP_PRUNED_FIXTURES.values()}
        if recorded | {entry['path'] for entry in removed} != expected_paths:
            raise ValueError(f'{issue} {role}: pinned PHP fixture cleanup is incomplete')
        already = {entry['path'] for entry in cleaning['removed']}
        cleaning['removed'].extend(entry for entry in removed if entry['path'] not in already)
        cleaning['kept_files'] -= sum(entry['path'] not in already for entry in removed)
        cleaning['output_archive_sha256'] = sha256(archive_path)
        cleaning['nested_fixture_policy'] = ('Pinned unrelated Phar/ZIP tests removed to enforce no nested ELF, '
                                             'no unsafe traversal entries, and no unreadable nested archives in public source.')
        atomic_json(cleaning_path, cleaning)


def document_and_manifest(issue: int) -> dict:
    task = ROOT / 'tasks' / f'cybergym-arvo-{issue}'
    input_dir = task / 'input'
    metadata = normalize_metadata(issue)
    missing = [name for name in REQUIRED_PUBLIC if name not in ('manifest.json', 'crash-context.json')
               and not (input_dir / name).is_file()]
    if missing:
        raise ValueError(f'cannot document incomplete public input: {missing}')
    values = {'project': metadata['project'], 'upstream_task_id': metadata['upstream_task_id'],
              'fuzz_engine': metadata['fuzz_engine'], 'sanitizer': metadata['sanitizer'],
              'sanitizer_env': metadata['sanitizer_env'], 'fuzz_target': metadata['fuzz_target']}
    instruction = materialize.INSTRUCTION.format(**values)
    if metadata['fuzz_engine'].lower() == 'afl':
        instruction = instruction.replace(
            'execute `/out/server /tmp/poc` with the sanitizer options documented in\n  the historical materials.',
            'feed the supplied input path to `/out/server` on standard input, once,\n  with the sanitizer options documented in the historical materials.')
    atomic_text(task / 'instruction.md', instruction)
    atomic_text(input_dir / 'TASK.md', instruction)
    atomic_json(input_dir / 'crash-context.json', {
        'sanitizer': metadata['sanitizer'], 'sanitizer_env': metadata['sanitizer_env'],
        'fuzz_engine': metadata['fuzz_engine'], 'fuzz_target': metadata['fuzz_target'],
        'crash_type': metadata['crash_type'], 'expected_stack': metadata['expected_stack'],
        'note': 'Historical public diagnostic context; no reproducer bytes, raw issue or private reference image.',
    })
    # Upstream source and historical recipes are the build inputs; do not
    # synthesize a separate BUILDING.md that performs this analysis for agents.
    for filename in ('description.md', 'error.txt'):
        content = (input_dir / filename).read_text(encoding='utf-8', errors='replace')
        atomic_text(input_dir / filename, sanitize_public_text(content))
    for role in ('vul', 'fix'):
        recipe_file = input_dir / f'oss-fuzz-{role}.json'
        recipe = json.loads(recipe_file.read_text())
        recipe['project'] = metadata['oss_fuzz_project']
        atomic_json(recipe_file, recipe)
    write_public_manifest(task, metadata)
    return metadata


def zip_entries(data: bytes, issue: int) -> list[tuple[PurePosixPath, bool, int, bytes]]:
    """Read legacy ZIP methods with 7z only when Python lacks that codec.

    The temporary archive lives in private results, never in public input. Every
    extracted member is returned to the same binary/link/content audit below.
    """
    with zipfile.ZipFile(io.BytesIO(data)) as nested:
        infos = nested.infolist()
        is_directory = lambda info: info.filename.endswith('/')
        unsupported = [info for info in infos if not is_directory(info) and
                       (info.flag_bits & 1 or info.compress_type not in
                        (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA))]
        external = None
        if unsupported:
            if not shutil.which('7z'):
                raise RuntimeError(f'{len(unsupported)} ZIP entries require an unavailable legacy compression reader')
            directory = Path(tempfile.mkdtemp(prefix='.zip-audit-', dir=RESULTS / str(issue)))
            external = directory / 'nested.zip'
            external.write_bytes(data)
        try:
            entries = []
            for info in infos:
                if is_directory(info):
                    entries.append((PurePosixPath(info.filename), True, 0, b''))
                    continue
                if info.file_size > 512 * 1024 * 1024:
                    raise ValueError(f'oversized nested ZIP member: {info.filename}')
                if info in unsupported:
                    result = subprocess.run(['7z', 'x', '-so', '-y', '--', str(external), info.filename],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=120)
                    content = result.stdout
                    if len(content) != info.file_size:
                        raise ValueError(f'legacy ZIP member size mismatch: {info.filename}')
                else:
                    content = nested.read(info)
                entries.append((PurePosixPath(info.filename), False, info.file_size, content))
            return entries
        finally:
            if external is not None:
                shutil.rmtree(external.parent)


def scan_source_content(issue: int, task: Path) -> dict:
    """Scan complete archive file bodies and nested source bundles, not just names."""
    issues = []
    nested_checked = 0
    nested_files = 0
    review = []
    scanned_files = 0
    nested_suffixes = ('.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.zip')
    for role in ('vul', 'fix'):
        path = task / 'input' / f'sources-{role}.tar.gz'
        report = source_audit(path)
        if report['issues']:
            issues.extend(f'{path.name}: {problem}' for problem in report['issues'])
        atomic_json(RESULTS / str(issue) / f'source-audit-{role}.json', report)
        with tarfile.open(path, 'r:gz') as archive:
            for member in archive:
                if not member.isfile():
                    continue
                pure = PurePosixPath(member.name)
                handle = archive.extractfile(member)
                content = handle.read() if handle else b''
                scanned_files += 1
                for label, pattern in LEAK_PATTERNS.items():
                    if label != 'placeholder' and pattern.search(content):
                        issues.append(f'{path.name}:{member.name}: {label}')
                if not pure.name.lower().endswith(nested_suffixes):
                    continue
                if len(content) > 64 * 1024 * 1024:
                    issues.append(f'nested source archive requires manual review: {member.name}')
                    continue
                try:
                    if pure.name.lower().endswith('.zip'):
                        entries = zip_entries(content, issue)
                    else:
                        with tarfile.open(fileobj=io.BytesIO(content), mode='r:*') as nested:
                            entries = [(PurePosixPath(item.name), item.isdir(), item.size,
                                        nested.extractfile(item).read() if item.isfile() else b'')
                                       for item in nested if item.isfile() or item.isdir()]
                    nested_checked += 1
                except (OSError, tarfile.TarError, zipfile.BadZipFile, NotImplementedError,
                        ValueError, subprocess.SubprocessError) as exc:
                    if (issue in (61993, 65135) and '/php-src/ext/' in member.name
                            and '/tests/' in member.name):
                        review.append({'path': f'{path.name}:{member.name}',
                                       'reason': f'{type(exc).__name__}: {exc}',
                                       'disposition': 'Intentional malformed/unsupported-compression fixture in the pinned PHP test suite; not a gold input or runnable artifact.'})
                    else:
                        issues.append(f'unreadable nested source archive {member.name}: {exc}')
                    continue
                for name, is_dir, size, data in entries:
                    nested_files += 1
                    if name.is_absolute() or '..' in name.parts or '\\' in str(name):
                        issues.append(f'unsafe nested archive path: {member.name}!/{name}')
                    if {part.lower() for part in name.parts} & DANGEROUS_PARTS:
                        issues.append(f'nested VCS/private path: {member.name}!/{name}')
                    if name.name.lower() in DANGEROUS_NAMES:
                        issues.append(f'nested PoC-like name: {member.name}!/{name}')
                    if is_dir:
                        continue
                    if name.suffix.lower() in BINARY_SUFFIXES or is_executable_bytes(data[:8192]):
                        issues.append(f'nested compiled binary: {member.name}!/{name}')
                    for label, pattern in LEAK_PATTERNS.items():
                        if label != 'placeholder' and pattern.search(data):
                            issues.append(f'nested {label}: {member.name}!/{name}')
    return {'issues': issues, 'scanned_archive_files': scanned_files,
            'nested_archives': nested_checked, 'nested_files': nested_files,
            'intentional_test_fixture_review': review}


def check_public_contract(issue: int, task: Path, metadata: dict) -> tuple[list[str], dict]:
    errors = []
    input_dir = task / 'input'
    missing = [name for name in REQUIRED_PUBLIC if not (input_dir / name).is_file()]
    errors.extend(f'missing public input: {name}' for name in missing)
    if metadata.get('sanitizer') not in ('ASan', 'MSan', 'UBSan'):
        errors.append('metadata sanitizer must be ASan/MSan/UBSan')
    expected_env = {'ASan': 'address', 'MSan': 'memory', 'UBSan': 'undefined'}[metadata['sanitizer']]
    if metadata.get('sanitizer_env') != expected_env:
        errors.append('metadata sanitizer_env does not match sanitizer label')
    for document in ('TASK.md',):
        if (input_dir / document).is_file() and f'`{metadata["sanitizer"]}` (`{expected_env}`)' not in (input_dir / document).read_text():
            errors.append(f'{document} sanitizer label mismatch')
    recipes = {}
    for role in ('vul', 'fix'):
        for name in ('Dockerfile', 'build.sh', 'project.yaml', 'provenance.json'):
            if not (input_dir / 'oss-fuzz' / role / name).is_file():
                errors.append(f'missing historical {role} recipe: {name}')
        provenance_path = input_dir / 'oss-fuzz' / role / 'provenance.json'
        if provenance_path.is_file():
            provenance = json.loads(provenance_path.read_text())
            if not re.fullmatch(r'[0-9a-f]{40}', provenance.get('commit', '')):
                errors.append(f'{role} recipe has no exact git commit')
            for relative, details in provenance.get('files', {}).items():
                path = input_dir / 'oss-fuzz' / role / relative
                if not path.is_file() or sha256(path) != details.get('sha256'):
                    errors.append(f'{role} recipe provenance mismatch: {relative}')
            recipes[role] = provenance
        for name in ('srcmap', 'dependencies'):
            path = input_dir / f'{name}-{role}.json'
            if not path.is_file():
                errors.append(f'missing {name}-{role}.json')
            elif not json.loads(path.read_text()):
                errors.append(f'empty {name}-{role}.json')
    target = metadata['fuzz_target']
    harness_checks = {
        1513: 'ffmpeg/tools/target_dec_fuzzer.c', 1538: 'ffmpeg/tools/target_dec_fuzzer.c',
        8241: 'openssl/fuzz/server.c', 17715: 'openssl/fuzz/x509.c',
        61993: 'php-src/sapi/fuzzer/fuzzer-tracing-jit.c',
        65135: 'php-src/sapi/fuzzer/fuzzer-tracing-jit.c',
        5797: 'imagemagick/Magick++/fuzz/encoder_xc_fuzzer.cc',
        5429: 'imagemagick/Magick++/fuzz/encoder_fuzzer.cc',
        1461: f'{target}.cc',
    }
    harnesses = {}
    for role in ('vul', 'fix'):
        if issue == 65319:
            archive_path = input_dir / f'dependencies-{role}' / 'testsuite-oss-fuzzers.tar.gz'
            if not archive_path.is_file():
                errors.append(f'missing GPAC {role} harness archive')
                continue
            with tarfile.open(archive_path, 'r:gz') as archive:
                names = archive.getnames()
            harnesses[role] = [name for name in names if name.endswith(f'{target}.c')]
        else:
            with tarfile.open(input_dir / f'sources-{role}.tar.gz', 'r:gz') as archive:
                names = archive.getnames()
            suffix = harness_checks[issue]
            harnesses[role] = [name for name in names if name.endswith(suffix)]
        if not harnesses[role]:
            errors.append(f'{role} target harness missing: {target}')
    return errors, {'recipes': recipes, 'target_harnesses': harnesses}


def public_audit(issue: int, write_checkpoint: bool = True) -> dict:
    if write_checkpoint:
        checkpoint(issue, 'public_auditing', scope='public_inputs_only')
    task = ROOT / 'tasks' / f'cybergym-arvo-{issue}'
    try:
        metadata_path = task / 'metadata.yaml'
        metadata = yaml.safe_load(metadata_path.read_text())
        report = audit_task(task, require_verified=False)
        errors = list(report['issues'])
        # Shared audit conservatively rejects every basename "core". Only
        # suppress an exact directory finding after source_audit inspected it.
        reviewed = set()
        for role in ('vul', 'fix'):
            reviewed_path = RESULTS / str(issue) / f'source-audit-{role}.json'
            if reviewed_path.is_file():
                reviewed_report = json.loads(reviewed_path.read_text())
                for item in reviewed_report.get('core_path_review', []):
                    if item['kind'] == 'directory':
                        reviewed.add(f'sources-{role}.tar.gz: archive leaked PoC-like name: {item["path"]}')
        errors = [error for error in errors if error not in reviewed]
        for path in (input_dir := task / 'input').rglob('*'):
            if not path.is_file():
                continue
            relative = str(path.relative_to(input_dir))
            if not path.name.endswith(('.tar.gz', '.tgz', '.tar', '.zip')):
                data = path.read_bytes()
                for label, pattern in LEAK_PATTERNS.items():
                    if pattern.search(data):
                        errors.append(f'public {label}: {relative}')
                if b'\x00' in data[:8192] and path.suffix.lower() not in ('.dict', '.options'):
                    errors.append(f'public binary/non-text input: {relative}')
        contract_errors, contract = check_public_contract(issue, task, metadata)
        errors.extend(contract_errors)
        content = scan_source_content(issue, task)
        errors.extend(content['issues'])
        # Keep deterministic order without hiding distinct findings.
        errors = list(dict.fromkeys(errors))
        report.update({'arvo_id': issue, 'scope': 'public_materialization_and_static_leak_audit',
                       'issues': errors, 'errors': errors, 'passed': not errors, 'valid': not errors,
                       'reference_verification_performed': False,
                       'reference_verified_claim_preserved': metadata.get('reference_verified'),
                       'sanitizer': metadata.get('sanitizer'), 'sanitizer_env': metadata.get('sanitizer_env'),
                       **contract, **content})
        atomic_json(RESULTS / str(issue) / 'public-audit.json', report)
        if write_checkpoint:
            checkpoint(issue, 'public_materials_ready' if not errors else 'public_audit_failed',
                       public_audit='passed' if not errors else 'failed', issues=errors,
                       reference_verification='not_performed_in_this_stage')
        return report
    except Exception as exc:
        reason = f'{type(exc).__name__}: {exc}'
        if write_checkpoint:
            checkpoint(issue, 'public_audit_failed', reason=reason,
                       reference_verification='not_performed_in_this_stage')
        return {'arvo_id': issue, 'passed': False, 'valid': False, 'issues': [reason], 'errors': [reason]}


def finalize(issue: int) -> dict:
    try:
        checkpoint(issue, 'public_finalizing', scope='public_inputs_only')
        task = ROOT / 'tasks' / f'cybergym-arvo-{issue}'
        if not (task / 'input' / 'sources-vul.tar.gz').is_file():
            raise ValueError('missing cached public materialization; run prepare for this ID first')
        supplement_gp(issue, task)
        prune_irrelevant_php_fixtures(issue, task)
        metadata = normalize_metadata(issue)
        source_dependencies(issue, task, metadata['fuzz_target'])
        document_and_manifest(issue)
        report = public_audit(issue, write_checkpoint=False)
        checkpoint(issue, 'public_materials_ready' if report['passed'] else 'public_audit_failed',
                   public_audit='passed' if report['passed'] else 'failed', issues=report['issues'],
                   reference_verification='not_performed_in_this_stage')
        return {'arvo_id': issue, 'status': 'ready' if report['passed'] else 'failed',
                'public_audit_passed': report['passed'], 'issues': report['issues']}
    except Exception as exc:
        reason = f'{type(exc).__name__}: {exc}'
        checkpoint(issue, 'public_materialization_failed', reason=reason,
                   reference_verification='not_performed_in_this_stage')
        return {'arvo_id': issue, 'status': 'failed', 'reason': reason}


def summarize() -> dict:
    """Validate the current public delivery and snapshot private evidence read-only."""
    tasks = []
    for issue in IDS:
        task = ROOT / 'tasks' / f'cybergym-arvo-{issue}'
        input_dir = task / 'input'
        metadata = yaml.safe_load((task / 'metadata.yaml').read_text())
        manifest = json.loads((input_dir / 'manifest.json').read_text())
        audit = json.loads((RESULTS / str(issue) / 'public-audit.json').read_text())
        state = json.loads((RESULTS / str(issue) / 'checkpoint.json').read_text())
        expected_environment = {'ASan': 'address', 'MSan': 'memory', 'UBSan': 'undefined'}.get(metadata['sanitizer'])
        manifest_errors = []
        recorded_files = manifest.get('files', {})
        for relative, details in recorded_files.items():
            path = input_dir / relative
            if not path.is_file():
                manifest_errors.append(f'manifest file missing: {relative}')
            elif path.stat().st_size != details.get('bytes') or sha256(path) != details.get('sha256'):
                manifest_errors.append(f'manifest hash/size mismatch: {relative}')
        actual_files = {str(path.relative_to(input_dir)) for path in input_dir.rglob('*')
                        if path.is_file() and path.name != 'manifest.json'}
        manifest_errors.extend(f'file absent from manifest: {relative}' for relative in sorted(actual_files - set(recorded_files)))
        required = set(REQUIRED_PUBLIC) | {f'oss-fuzz/{role}/{name}' for role in ('vul', 'fix')
                                          for name in ('Dockerfile', 'build.sh', 'project.yaml', 'provenance.json')}
        required |= {f'{name}-{role}.json' for role in ('vul', 'fix') for name in ('srcmap', 'dependencies')}
        missing = sorted(name for name in required if not (input_dir / name).is_file())
        reference_path = task / 'gold' / 'verify_reference.json'
        reference = json.loads(reference_path.read_text()) if reference_path.is_file() else {}
        reference_runs = reference.get('runs', {})
        both_roles_passed = all(reference_runs.get(role, {}).get('passed') is True for role in ('vul', 'fix'))
        reference_verified = bool(metadata.get('reference_verified') is True and reference.get('passed') is True
                                  and both_roles_passed)
        if metadata.get('reference_verified') is True and not reference_verified:
            raise ValueError(f'{issue}: reference_verified metadata lacks consistent private differential evidence')
        blockers = []
        if not reference_verified:
            blockers.extend(reference.get('failures') or ['No passing private differential verification record available.'])
        tasks.append({
            'arvo_id': issue, 'task_id': metadata['task_id'], 'project': metadata['project'],
            'sanitizer': metadata['sanitizer'], 'sanitizer_env': metadata['sanitizer_env'],
            'fuzz_engine': metadata['fuzz_engine'], 'fuzz_target': metadata['fuzz_target'],
            'public_materials_ready': state.get('stage') == 'public_materials_ready' and state.get('public_audit') == 'passed',
            'public_audit_passed': audit.get('passed') is True and not audit.get('issues'),
            'public_contract_passed': not missing and not manifest_errors and
                                      expected_environment == metadata.get('sanitizer_env'),
            'required_files_missing': missing, 'manifest_errors': manifest_errors,
            'manifest_file_count': len(recorded_files), 'public_bytes': audit.get('public', {}).get('bytes'),
            'source_archive_files_scanned': audit.get('scanned_archive_files'),
            'nested_archives_scanned': audit.get('nested_archives'),
            'nested_files_scanned': audit.get('nested_files'),
            'checkpoint': str(RESULTS / str(issue) / 'checkpoint.json'),
            'public_audit': str(RESULTS / str(issue) / 'public-audit.json'),
            'manifest': str(input_dir / 'manifest.json'),
            'reference_verified': reference_verified,
            'reference_evidence': str(reference_path) if reference_path.is_file() else None,
            'reference_finished_at': reference.get('finished_at'),
            'remaining_parent_agent_items': blockers,
        })
    distribution = lambda field: {key: sum(task[field] == key for task in tasks)
                                 for key in sorted({task[field] for task in tasks})}
    ready = [task['arvo_id'] for task in tasks if task['public_materials_ready'] and
             task['public_audit_passed'] and task['public_contract_passed']]
    verified = [task['arvo_id'] for task in tasks if task['reference_verified']]
    summary = {
        'schema_version': 1, 'shard': 0, 'updated_at': now(),
        'scope': 'Public acquisition/materialization, documentation, manifests and static leak audits. No reference execution in this shard stage.',
        'assigned_ids': list(IDS), 'public_materials_ready_count': len(ready),
        'public_materials_ready_ids': ready,
        'public_materials_incomplete_ids': [task['arvo_id'] for task in tasks if task['arvo_id'] not in ready],
        'reference_verified_count': len(verified), 'reference_verified_ids': verified,
        'reference_pending_ids': [task['arvo_id'] for task in tasks if not task['reference_verified']],
        'reference_status_note': 'Read-only snapshot of parent-owned private evidence. No reference_verified value was inferred or changed by this summary.',
        'distributions': {'projects': distribution('project'), 'sanitizers': distribution('sanitizer'),
                          'fuzz_engines': distribution('fuzz_engine')},
        'interfaces': {
            'public_input': 'tasks/cybergym-arvo-<id>/input',
            'required_source_versions': ['sources-vul.tar.gz', 'sources-fix.tar.gz'],
            'source_maps': ['srcmap-vul.json', 'srcmap-fix.json', 'revisions.json',
                            'dependencies-vul.json', 'dependencies-fix.json'],
            'historical_recipes': 'input/oss-fuzz/{vul,fix}/{Dockerfile,build.sh,project.yaml,provenance.json} plus upstream target support files',
            'documentation': ['TASK.md'],
            'public_manifest': 'input/manifest.json (sha256 and byte size per file)',
            'checkpoint': 'results/cybergym-preparation/shard0/<id>/checkpoint.json',
            'static_audit': 'results/cybergym-preparation/shard0/<id>/public-audit.json',
            'private_reference_evidence': 'tasks/cybergym-arvo-<id>/gold/verify_reference.json',
            'runner_contract_for_agent_build': '/usr/local/bin/run_poc <path> with a single input at /tmp/poc; vul/fix role images/containers must be labelled cdb.cybergym.role.',
        },
        'parent_agent_handoff': [
            'Resolve private reference-image acquisition for every ID in reference_pending_ids; no vul/fix runs are recorded for those current records.',
            'Use existing private GOLD PoCs and n132/arvo:<id>-vul/fix on root@100.96.153.163; retain command, digest, logs and differential results in gold/verify_reference.json.',
            'Only after a real passing differential should the parent verifier set reference_verified. This stage did not run Docker, pull images or modify shared verifier code.',
            'Public source materials are inputs for the subsequent Docker synthesis; their readiness is not a claim that generated Dockerfiles/Compose were built or run in this stage.',
        ],
        'tasks': tasks,
    }
    atomic_json(RESULTS / 'shard0-summary.json', summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'finalize', 'audit', 'summary'), nargs='?', default='prepare')
    parser.add_argument('--ids', type=lambda value: [int(x) for x in value.split(',')], default=list(IDS))
    args = parser.parse_args()
    if any(issue not in IDS for issue in args.ids):
        parser.error('ID outside shard 0')
    if args.command == 'prepare':
        results = [prepare(issue) for issue in args.ids]
        atomic_json(RESULTS / 'materialization-summary.json', {'updated_at': now(), 'results': results})
    elif args.command == 'finalize':
        results = [finalize(issue) for issue in args.ids]
        atomic_json(RESULTS / 'public-materialization-summary.json', {'updated_at': now(), 'results': results,
                          'scope': 'public inputs and static audits only; no reference execution'})
    elif args.command == 'summary':
        if args.ids != list(IDS):
            parser.error('summary requires all ten shard-0 IDs')
        summary = summarize()
        results = [{'public_materials_ready_count': summary['public_materials_ready_count'],
                    'reference_verified_count': summary['reference_verified_count'],
                    'reference_pending_ids': summary['reference_pending_ids']}]
    else:
        results = [public_audit(issue) for issue in args.ids]
        atomic_json(RESULTS / 'public-audit-summary.json', {'updated_at': now(), 'passed': sum(x['passed'] for x in results),
                          'tasks': results})
    print(json.dumps(results, ensure_ascii=False), flush=True)
    return int(any(result.get('status') == 'failed' or
                   (args.command == 'audit' and not result['passed']) for result in results))


if __name__ == '__main__':
    raise SystemExit(main())
