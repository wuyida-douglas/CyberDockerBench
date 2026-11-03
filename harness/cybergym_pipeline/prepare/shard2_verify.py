#!/usr/bin/env python3
"""Shard-2 private ARVO oracle differential on the designated worker.

No public task input and no solver/model process is used. Official images are
exclusively private oracle materials. At most one task (two image pulls) is in
flight; every result, including infrastructure failure, is checkpointed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import uuid

from . import verify
from .shard2 import IDS, PRIVATE, RESULTS, ROOT, WORKER, atomic_json, checkpoint, now

SANITIZER = {'asan': 'ASan', 'msan': 'MSan', 'ubsan': 'UBSan',
             'address': 'ASan', 'memory': 'MSan', 'undefined': 'UBSan'}


def crash_type_observed(text: str, expected: str) -> bool:
    lowered = expected.lower()
    if lowered.startswith(('unknown', 'segv on unknown address')):
        # A raw SEGV needs a separate check below; an UNKNOWN ARVO crash label
        # alone is not a sufficiently specific crash-type assertion.
        return 'SEGV' in text if lowered.startswith('segv') else verify.crash_type_observed(text, expected)
    if lowered.startswith('incorrect-function-pointer-type'):
        return 'incorrect function type' in text.lower() or 'incorrect-function-pointer-type' in text.lower()
    return verify.crash_type_observed(text, expected)


def stack_observed(text: str, issue: int, expected: list[str]) -> tuple[dict, dict]:
    direct = verify.stack_observed(text, expected)
    aliases = {}
    # ARVO-Meta records DEDUP symbols from a different Clang symbolization.
    # Match only the exact observed frame plus its original source location for
    # this task; record this as an alias rather than claiming a literal match.
    if issue == 1856:
        candidates = {
            'int OT::SortedArrayOf<OT::GlyphID, OT::IntType<unsigned short, 2u> >::bsearch<un':
                ('bsearch<unsigned int>', '/src/harfbuzz/src/./hb-open-type-private.hh:1055:11'),
            'OT::CoverageFormat1::get_coverage':
                ('get_coverage', '/src/harfbuzz/src/./hb-ot-layout-common-private.hh:692:24'),
        }
        for frame, parts in candidates.items():
            if frame in expected:
                matched = any(all(part in line for part in parts) for line in text.splitlines())
                aliases[frame] = {'matched': matched, 'observed_frame_and_source': list(parts),
                                  'reason': 'equivalent Clang symbolization of the original ARVO DEDUP frame'}
    return direct, aliases


def run_oracle(issue: int, role: str, metadata: dict, logs: Path) -> dict:
    image = f'n132/arvo:{issue}-{role}'
    name = f'cdb-shard2-arvo-{issue}-{role}-{uuid.uuid4().hex[:8]}'
    command = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15', WORKER,
               'docker', 'run', '--rm', '--network', 'none', '--name', name,
               '--label', 'cdb.cybergym.shard=2', '--label', 'cdb.cybergym.reference=official',
               '--label', f'cdb.cybergym.role={role}', '--entrypoint', '/bin/arvo',
               '-v', f'{ROOT}/tasks/cybergym-arvo-{issue}/gold/poc:/tmp/poc:ro', image]
    result = verify.command_result(command, logs / f'reference-{role}.log', timeout=600)
    text = (logs / f'reference-{role}.log').read_text(errors='replace')
    sanitizer = SANITIZER.get(str(metadata['sanitizer']).lower(), metadata['sanitizer'])
    sanitizer_found = verify.sanitizer_observed(text, sanitizer)
    any_sanitizer = bool(verify.GENERIC_SANITIZER.search(text))
    crash_found = crash_type_observed(text, metadata['crash_type'])
    direct, aliases = stack_observed(text, issue, metadata['expected_stack'])
    stack_found = all(direct.get(frame) or aliases.get(frame, {}).get('matched')
                      for frame in metadata['expected_stack'])
    if role == 'vul':
        passed = sanitizer_found and crash_found and stack_found and not result['timed_out']
    else:
        passed = not any_sanitizer and not result['timed_out'] and result['return_code'] == 0
    if result['timed_out']:
        verify.command_result(command[:command.index('docker')] + ['docker', 'rm', '-f', name],
                              logs / f'reference-{role}-timeout-cleanup.log', timeout=60)
    result.update({'image': image, 'role': role, 'expected_sanitizer': sanitizer,
                   'expected_sanitizer_observed': sanitizer_found,
                   'any_sanitizer_observed': any_sanitizer, 'crash_type_observed': crash_found,
                   'expected_stack_observed': direct, 'expected_stack_aliases': aliases,
                   'all_expected_frames_accounted_for': stack_found, 'passed': passed})
    return result


def check_gold_pair(issue: int, task: Path, logs: Path) -> dict:
    destination = task / 'gold' / 'poc-fix-check'
    destination.unlink(missing_ok=True)
    details = verify.extract_poc(f'n132/arvo:{issue}-fix', destination, WORKER, logs)
    vulnerable_hash = hashlib.sha256((task / 'gold' / 'poc').read_bytes()).hexdigest()
    destination.unlink(missing_ok=True)
    record = {'arvo_id': issue, 'vul_sha256': vulnerable_hash, 'fix_sha256': details['sha256'],
              'identical': vulnerable_hash == details['sha256'], 'bytes': details['bytes']}
    atomic_json(task / 'gold' / 'poc-pair-verification.json', record)
    atomic_json(RESULTS / str(issue) / 'poc-pair-verification.json', record)
    if not record['identical']:
        raise ValueError(f'{issue}: private vul/fix reproducer bytes differ')
    return record


def retain_reference_labels(issue: int) -> dict:
    """Keep stopped role-labelled oracle containers, never public build images."""
    retained = {}
    for role in ('vul', 'fix'):
        source = f'n132/arvo:{issue}-{role}'
        name = f'cdb-shard2-arvo-{issue}-reference-{role}'
        target = f'cdb-cybergym-shard2/arvo-{issue}-reference:{role}'
        existing = subprocess.run(['ssh', '-o', 'BatchMode=yes', WORKER, 'docker', 'container', 'inspect',
                                   '--format', '{{json .Config.Labels}}', name], text=True,
                                  capture_output=True, timeout=60)
        if existing.returncode == 0:
            if json.loads(existing.stdout or '{}').get('cdb.cybergym.shard') != '2':
                raise RuntimeError(f'{name} exists but is not owned by shard 2')
            subprocess.run(['ssh', WORKER, 'docker', 'rm', '-f', name], check=True, timeout=60)
        script = (f'docker create --name {shlex.quote(name)} --label cdb.cybergym.shard=2 '
                  f'--label cdb.cybergym.reference=official --label cdb.cybergym.role={role} {shlex.quote(source)} && '
                  f'docker commit --change {shlex.quote("LABEL cdb.cybergym.shard=2 cdb.cybergym.reference=official cdb.cybergym.role=" + role)} '
                  f'{shlex.quote(name)} {shlex.quote(target)}')
        result = subprocess.run(['ssh', '-o', 'BatchMode=yes', WORKER, script],
                                text=True, capture_output=True, timeout=120)
        if result.returncode:
            raise RuntimeError(f'cannot retain {source}: {result.stderr[-2000:]}')
        inspect = subprocess.run(['ssh', WORKER, 'docker', 'image', 'inspect', target,
                                  '--format', '{{.Id}} {{json .Config.Labels}}'],
                                 text=True, capture_output=True, check=True, timeout=60)
        retained[role] = {'image': target, 'container': name, 'inspect': inspect.stdout.strip(),
                          'private_reference_only': True}
    atomic_json(RESULTS / str(issue) / 'retained-reference-images.json', retained)
    return retained


def verify_one(issue: int) -> dict:
    import yaml
    task = ROOT / 'tasks' / f'cybergym-arvo-{issue}'
    gold = task / 'gold'
    logs = gold / 'reference-logs'
    logs.mkdir(parents=True, exist_ok=True)
    evidence_path = gold / 'verify_reference.json'
    evidence = {'schema_version': 1, 'task_id': task.name, 'upstream_task_id': f'arvo:{issue}',
                'started_at': now(), 'worker': WORKER, 'passed': False, 'reference_verified': False,
                'official_images_public_input': False, 'gold_poc_public_input': False,
                'images': {}, 'runs': {}, 'failures': []}
    try:
        checkpoint(issue, 'verifying_private_reference', worker=WORKER)
        atomic_json(evidence_path, evidence)
        metadata = yaml.safe_load((task / 'metadata.yaml').read_text())
        archive = PRIVATE / 'reference-images' / str(issue)
        archive.mkdir(parents=True, exist_ok=True)
        # Sequential here: other shards share the registry. The acquisition
        # phase uses two workers; a retry never starts additional downloads.
        for role in ('vul', 'fix'):
            details = verify.pull_reference(f'n132/arvo:{issue}-{role}', WORKER, archive, logs, attempts=1)
            evidence['images'][role] = details
            atomic_json(evidence_path, evidence)
        if not (gold / 'poc').is_file():
            evidence['gold_poc'] = verify.extract_poc(f'n132/arvo:{issue}-vul', gold / 'poc', WORKER, logs)
        else:
            evidence['gold_poc'] = {'path': str(gold / 'poc'), 'sha256': verify.digest_file(gold / 'poc'),
                                    'bytes': (gold / 'poc').stat().st_size,
                                    'source': 'private PoC checkpoint extracted from official ARVO /tmp/poc'}
        evidence['gold_poc_sha256'] = evidence['gold_poc']['sha256']
        evidence['gold_poc_bytes'] = evidence['gold_poc']['bytes']
        evidence['gold_poc_pair'] = check_gold_pair(issue, task, logs)
        for role in ('vul', 'fix'):
            run = run_oracle(issue, role, metadata, logs)
            image = evidence['images'][role]
            run['digest'] = image.get('official_manifest_digest') or image.get('digest') or image['config_id']
            run['config_id'] = image['config_id']
            evidence['runs'][role] = run
            atomic_json(evidence_path, evidence)
        expected_stack_complete = all(run['all_expected_frames_accounted_for']
                                      for run in [evidence['runs']['vul']])
        evidence['passed'] = all(run['passed'] for run in evidence['runs'].values())
        evidence['reference_verified'] = evidence['passed']
        evidence['expected_stack_literal_complete'] = all(evidence['runs']['vul']['expected_stack_observed'].values())
        evidence['expected_stack_equivalence_complete'] = expected_stack_complete
        if not expected_stack_complete:
            evidence['failures'].append('one or more expected frames are absent from the observed vulnerable report')
        evidence['finished_at'] = now()
        metadata['reference_verified'] = evidence['passed']
        metadata['reference_verification'] = {'verified_at': now(), 'worker': WORKER,
                                              'evidence': 'gold/verify_reference.json',
                                              'image_digests': {role: run['digest'] for role, run in evidence['runs'].items()}}
        (task / 'metadata.yaml').write_text(yaml.safe_dump(metadata, sort_keys=False))
        if evidence['passed']:
            retained = retain_reference_labels(issue)
            evidence['retained_private_reference_images'] = retained
            atomic_json(gold / 'reference-manifest.json', {
                'schema_version': 1, 'task_id': task.name,
                'public_input_policy': 'Private oracle only; no official image or PoC is staged.',
                'gold_poc': {'path': 'gold/poc', 'sha256': evidence['gold_poc_sha256'],
                             'bytes': evidence['gold_poc_bytes']},
                'gold_poc_pair': evidence['gold_poc_pair'], 'reference_images': evidence['images'],
                'retained_private_reference_images': retained, 'verification': 'gold/verify_reference.json',
                'logs': 'gold/reference-logs', 'verification_worker': WORKER,
                'raw_upstream_metadata': 'gold/upstream-private.json'})
        atomic_json(evidence_path, evidence)
        atomic_json(RESULTS / str(issue) / 'verify_reference.json', evidence)
        checkpoint(issue, 'reference_verified' if evidence['passed'] else 'reference_failed',
                   passed=evidence['passed'], failures=evidence['failures'])
        return {'arvo_id': issue, 'status': 'reference_verified' if evidence['passed'] else 'reference_failed',
                'passed': evidence['passed'], 'failures': evidence['failures'],
                'runs': {role: {'passed': run['passed'], 'return_code': run['return_code'],
                                'sanitizer': run['expected_sanitizer_observed'],
                                'crash_type': run['crash_type_observed'],
                                'stack': run['all_expected_frames_accounted_for']}
                         for role, run in evidence['runs'].items()}}
    except Exception as exc:
        evidence['failures'].append(f'{type(exc).__name__}: {exc}')
        evidence['finished_at'] = now()
        atomic_json(evidence_path, evidence)
        atomic_json(RESULTS / str(issue) / 'verify_reference.json', evidence)
        checkpoint(issue, 'reference_verification_error', reason=evidence['failures'][-1])
        return {'arvo_id': issue, 'status': 'reference_verification_error', 'passed': False,
                'reason': evidence['failures'][-1]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ids', type=lambda value: [int(item) for item in value.split(',')], default=list(IDS))
    args = parser.parse_args()
    if any(issue not in IDS for issue in args.ids):
        parser.error('id outside shard-2 ownership')
    results = []
    for issue in args.ids:
        result = verify_one(issue)
        results.append(result)
        print(json.dumps(result), flush=True)
        atomic_json(RESULTS / 'reference-summary.json', {
            'worker': WORKER, 'updated_at': now(), 'requested_ids': args.ids,
            'passed': sum(result['passed'] for result in results), 'results': results})
    return int(any(not result['passed'] for result in results))


if __name__ == '__main__':
    raise SystemExit(main())
