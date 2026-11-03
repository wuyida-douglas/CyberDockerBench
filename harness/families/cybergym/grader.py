"""Grade only an agent's frozen CyberGym source delivery.

This mirrors CVE-Factory's grading contract: the declarative project is built
once in a clean sandbox, the public debugging PoC is copied into the rebuilt
containers, and the vulnerable/fixed differential is checked against the task
metadata. A passing source rebuild plus differential is reward 1. Running
images are not exported or graded again.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping

import yaml

from harness.docker_sandbox import DockerSandbox
from harness.staging import stage_delivery


class _Failure(Exception):
    def __init__(self, failure_class: str, stage: str, message: str,
                 status: str | None = None):
        super().__init__(message)
        self.failure_class = failure_class
        self.stage = stage
        self.status = status or ('failed' if failure_class == 'agent_semantic' else 'error')


NETWORK_RE = re.compile(
    r'(temporary failure in name resolution|could not resolve|dns.*failed|'
    r'i/o timeout|tls handshake timeout|connection timed out|proxyconnect|'
    r'network is unreachable|no route to host|connection reset by peer|'
    r'failed to (?:fetch|pull).*(?:timeout|registry|proxy)|toomanyrequests|rate limit|'
    r'(?:registry|proxy).*(?:502|503|504|unavailable)|'
    r'failed to do request:\s*head\s+"https?://[^"\s]+":\s*(?:bad gateway|'
    r'502 bad gateway|503 service unavailable|504 gateway time-?out))',
    re.IGNORECASE | re.DOTALL,
)
PIPELINE_RE = re.compile(
    r'(cannot connect to the docker daemon|docker daemon.*(?:error|failed)|'
    r'no space left on device|overlay2.*(?:failed|error)|'
    r'permission denied.*docker\.sock)',
    re.IGNORECASE | re.DOTALL,
)
# A build killed while pulling base layers ends mid-download: the output tail
# is buildkit layer progress with no ERROR/CANCELED step. That is a registry
# or proxy stall, never agent code (arvo-1461 r1: one layer pinned at
# 16.78MB/54.83MB for 1598s, killed with rc=137 and no error line).
PULL_PROGRESS_RE = re.compile(
    r'sha256:[0-9a-f]{12,}\s+[\d.]+\s*[KMGT]?i?B\s*/\s*[\d.]+\s*[KMGT]?i?B\s+\d+(?:\.\d+)?s')
BUILD_FAILURE_MARK_RE = re.compile(r'\b(ERROR|CANCELED)\b')


def _tail(value: Any, limit: int = 12000) -> str:
    return str(value or '')[-limit:]


def _output(cp: Any) -> str:
    return _tail((getattr(cp, 'stdout', '') or '') + (getattr(cp, 'stderr', '') or ''))


def _command_evidence(cp: Any) -> dict[str, Any]:
    return {
        'returncode': getattr(cp, 'returncode', None),
        'output_tail': _output(cp),
    }


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n',
                         encoding='utf-8')
    os.replace(temporary, path)


def _infra_failure(stage: str, message: str, output: str = '',
                   default: str = 'pipeline') -> _Failure:
    text = output or message
    if NETWORK_RE.search(text):
        classification = 'network'
    elif PIPELINE_RE.search(text):
        classification = 'pipeline'
    elif (default == 'agent_semantic' and PULL_PROGRESS_RE.search(text)
          and not BUILD_FAILURE_MARK_RE.search(text)):
        # Killed mid-pull with no build-step error: registry/proxy stall.
        classification = 'network'
    else:
        classification = default
    return _Failure(classification, stage, message)


def _load_metadata(task_path: Path) -> Mapping[str, Any]:
    path = task_path / 'metadata.yaml'
    if not path.is_file():
        raise _Failure('pipeline', 'metadata', f'missing {path}')
    metadata = yaml.safe_load(path.read_text(encoding='utf-8'))
    if not isinstance(metadata, dict):
        raise _Failure('pipeline', 'metadata', f'{path} must contain a mapping')
    return metadata


def _labels(service: Mapping[str, Any]) -> dict[str, str]:
    raw = service.get('labels') or {}
    if isinstance(raw, dict):
        return {str(key): str(value) for key, value in raw.items()}
    result: dict[str, str] = {}
    if isinstance(raw, list):
        for item in raw:
            key, separator, value = str(item).partition('=')
            result[key] = value if separator else ''
    return result


def _validate_delivery(task_path: Path, delivery: Path) -> dict[str, Any]:
    # A completed agent workspace may be graded directly before bundle export.
    # Its missing required files are a model verdict, not an export outage.
    source = delivery / 'source' if (delivery / 'source').is_dir() else delivery
    required = ['docker-compose.yaml', 'Dockerfile', 'smoke.sh']
    missing = [name for name in required if not (source / name).is_file()]
    if missing:
        raise _Failure('agent_semantic', 'delivery',
                       'missing agent delivery files: ' + ', '.join(missing))
    try:
        compose = yaml.safe_load((source / 'docker-compose.yaml').read_text(encoding='utf-8'))
        services = compose.get('services', {}) if isinstance(compose, dict) else {}
        for role in ('vul', 'fix'):
            service = services.get(role)
            if not isinstance(service, dict):
                raise _Failure('agent_semantic', 'delivery', f'compose service {role} is missing')
            labels = _labels(service)
            if labels.get('cdb.cybergym.role') != role:
                raise _Failure('agent_semantic', 'delivery',
                               f'compose service {role} lacks its exact cdb.cybergym.role label')
    except _Failure:
        raise
    except (OSError, yaml.YAMLError) as exc:
        raise _Failure('pipeline', 'delivery', str(exc)) from exc
    return {
        'success': True,
        'source': str(source),
        'inventories': ['bundle.json', 'source-inventory.json'],
    }


def _resolve_roles(services: Mapping[str, Any]) -> tuple[str, str]:
    roles: dict[str, str] = {}
    for name, raw in services.items():
        service = raw if isinstance(raw, dict) else {}
        role = _labels(service).get('cdb.cybergym.role')
        if role in ('vul', 'fix'):
            if role in roles:
                raise _Failure('agent_semantic', 'delivery',
                               f'ambiguous {role} role containers: {roles[role]} and {name}')
            roles[role] = name
    if set(roles) != {'vul', 'fix'}:
        raise _Failure('agent_semantic', 'delivery',
                       f'exactly one labelled container for each vul/fix is required; got {sorted(roles)}')
    return roles['vul'], roles['fix']


def _crash_tokens(value: str) -> list[str]:
    """Lowercase words, with digits dropped so ``READ 4`` and ``index 96`` compare."""
    return [tok for tok in re.sub(r'[^a-z0-9]+', ' ', value.lower()).split()
            if tok and not tok.isdigit()]


def _is_segv_family(value: str) -> bool:
    """OSS-Fuzz deadly-signal labels and sanitizer SEGV text are one family.

    OSS-Fuzz writes ``UNKNOWN READ`` / ``UNKNOWN WRITE`` for a wild access;
    sanitizers print ``SEGV on unknown address`` with ``READ memory access``
    (arvo-15120: label ``UNKNOWN READ``, UBSan printed ``SEGV``).
    """
    lowered = value.lower()
    return 'segv' in lowered or lowered.strip().startswith('unknown')


def _crash_category_matches(expected: str, observed: str | None) -> bool:
    """OSS-Fuzz labels and sanitizer text are the same bug written two ways.

    ``Heap-use-after-free READ 4`` is the label; AddressSanitizer prints
    ``heap-use-after-free``. ``Index-out-of-bounds`` is the label; UBSan prints
    ``index 96 out of bounds for type ...``.
    """
    if not expected or not observed:
        return False
    if _is_segv_family(expected) and _is_segv_family(observed):
        return True
    exp, obs = _crash_tokens(expected), _crash_tokens(observed)
    if not exp or not obs:
        return False
    if exp == obs or (len(obs) >= len(exp) and obs[:len(exp)] == exp):
        return True
    if len(exp) >= len(obs) and exp[:len(obs)] == obs:
        return True
    pending = iter(obs)
    return all(word in pending for word in exp)


def _full_output(execution: Any) -> str:
    """Whole captured output for matching; the 12k tail is only for records.

    Frame and sanitizer matching against a truncated tail is unsound: long
    reports (libFuzzer banner + main stack + allocation stack + shadow dump)
    push the crash-site frames out of the window (arvo-42481640 r1 lost its
    top main-stack frames this way).
    """
    return (getattr(execution, 'stdout', '') or '') + (getattr(execution, 'stderr', '') or '')


def _classify(execution: Any, sanitizer: str, require_vulnerable: bool,
              expected_crash_type: str = '', expected_stack: list[str] | None = None) -> dict[str, Any]:
    output = _full_output(execution)
    sanitizer_lower = sanitizer.lower()
    if sanitizer_lower == 'asan':
        sanitizer_lower = 'address'
    elif sanitizer_lower == 'msan':
        sanitizer_lower = 'memory'
    elif sanitizer_lower == 'ubsan':
        sanitizer_lower = 'undefined'
    patterns = {
        'address': re.compile(r'(?:ERROR|SUMMARY):\s*AddressSanitizer:\s*(detected memory leaks|[^\s]+)'),
        'memory': re.compile(r'WARNING:\s*MemorySanitizer:\s*([^\s]+)'),
        # UBSan reports UB as ``runtime error:`` but a deadly signal as
        # ``ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address``
        # (arvo-15120); accept both spellings.
        'undefined': re.compile(
            r'\bruntime error:\s*([^\n]+)|'
            r'(?:ERROR|SUMMARY):\s*UndefinedBehaviorSanitizer:\s*([^\s]+)'),
    }
    pattern = patterns.get(sanitizer_lower)
    match = pattern.search(output) if pattern else None
    crash_type = None
    if match:
        crash_type = next((g.strip() for g in match.groups() if g), None)
    leak_only = bool(match and ('memory leaks' in crash_type or 'leaksanitizer' in output.lower()))
    error = None
    if require_vulnerable:
        if not match:
            error = 'vulnerable GOLD PoC did not emit the expected sanitizer diagnostic'
        elif execution.returncode == 0 and not expected_stack:
            error = 'vulnerable sanitizer process unexpectedly exited zero'
        elif leak_only:
            error = 'leak-only report is not the requested vulnerability'
        elif expected_crash_type and not _crash_category_matches(expected_crash_type, crash_type):
            error = f'sanitizer crash category does not match expectation: {expected_crash_type}'
        # Crash frames belong to the vulnerable run. A fixed build that exits
        # cleanly does not print them; requiring them there rejects a good fix.
        if expected_stack:
            # Toolchains differ on template bracket whitespace ("> >" vs
            # ">>"), so fall back to whitespace-insensitive matching.
            compact_output = re.sub(r'\s+', '', output)
            missing = []
            for frame in expected_stack:
                if frame in output or re.sub(r'\s+', '', frame) in compact_output:
                    continue
                # A symbolizer may omit a class/namespace qualifier. Match
                # only an actual stack-frame function token, not arbitrary
                # prose or a sanitizer category. Keep the majority bar below.
                terminal = frame.rsplit('::', 1)[-1].split('<', 1)[0]
                if '::' in frame and re.search(
                        r'^\s*#\d+\s+\S+\s+in\s+' + re.escape(terminal)
                        + r'(?:<|\(|\s|$)', output, re.MULTILINE):
                    continue
                missing.append(frame)
            matched = len(expected_stack) - len(missing)
            # Demanglers may drop class qualifiers (``hb_array_t<...>::copy``
            # printed as bare ``copy``) and inlining removes middle frames
            # (arvo-42481371: identical file:line at every level, 3 of 6
            # symbols absent). Requiring every symbol is unsound; requiring
            # none is no check. Keep a majority bar, at least two frames.
            if len(expected_stack) >= 3:
                frames_ok = matched >= max(2, -(-len(expected_stack) // 2))
            else:
                frames_ok = matched == len(expected_stack)
            if not frames_ok:
                error = (error + '; ' if error else '') + (
                    f'expected application frames absent ({matched}/{len(expected_stack)} matched): '
                    + ', '.join(missing))
    return {
        'sanitizer_found': bool(match),
        'sanitizer': sanitizer if match else None,
        'crash_type': crash_type,
        'stack': expected_stack[0] if expected_stack else None,
        'leak_only': leak_only,
        'execution_error': error,
    }


def _execute(docker, container: str, argv: list[str], timeout: int = 60) -> Any:
    return docker(['exec', container, *argv], timeout=timeout)


def _stage_poc_where_inner_docker_can_read(workspace: Path, poc: Path) -> Path:
    """Copy the public PoC onto the sandbox workspace bind.

    The inner dockerd lstats the ``docker cp`` source inside the grade
    sandbox. That sandbox bind-mounts its workspace and does not mount
    ``/mnt/shared-storage-user``, so a direct copy of the task-tree PoC
    fails with ``lstat /mnt/shared-storage-user: no such file or directory``.
    """
    if not poc.is_file() or poc.stat().st_size == 0:
        raise _Failure('pipeline', 'delivery', f'public PoC is missing or empty: {poc}')
    destination = workspace / 'grade-poc'
    destination.write_bytes(poc.read_bytes())
    return destination


def _push_poc(docker, container: str, poc: Path, destination: str = '/tmp/poc') -> None:
    cp = docker(['cp', str(poc), f'{container}:{destination}'], timeout=120)
    if cp.returncode:
        # The delivery may already provide the same public input at the
        # destination (e.g. its own read-only bind mount, which docker cp
        # cannot overwrite).  That is not a defect when the bytes in place
        # are exactly the supplied PoC.
        want = hashlib.sha256(poc.read_bytes()).hexdigest()
        check = docker(['exec', container, 'sha256sum', destination], timeout=60)
        if check.returncode == 0 and (check.stdout or '').split()[:1] == [want]:
            return
        raise _infra_failure('push_poc', f'cannot copy PoC to {container}: ' + _output(cp), _output(cp))


def _check_pair(docker, roles: Mapping[str, str], poc: Path, metadata: Mapping[str, Any],
                timeout: int = 60) -> dict[str, Any]:
    if set(roles) != {'vul', 'fix'}:
        raise _Failure('agent_semantic', 'delivery', f'exactly one vul/fix pair is required; got {sorted(roles)}')
    if not poc.is_file() or poc.stat().st_size == 0:
        raise _Failure('pipeline', 'delivery', f'public PoC is missing or empty: {poc}')
    poc_sha = hashlib.sha256(poc.read_bytes()).hexdigest()
    results: dict[str, Any] = {'poc_sha256': poc_sha, 'roles': {}}
    sanitizer = str(metadata.get('sanitizer', 'address'))
    expected_stack = metadata.get('expected_stack') or []
    if isinstance(expected_stack, str):
        expected_stack = [expected_stack]
    for role, service in roles.items():
        container = service
        _push_poc(docker, container, poc)
        execution = _execute(docker, container, ['/usr/local/bin/run_poc', '/tmp/poc'], timeout)
        verdict = _classify(execution, sanitizer, require_vulnerable=(role == 'vul'),
                            expected_crash_type=str(metadata.get('crash_type', '')),
                            expected_stack=expected_stack)
        results['roles'][role] = {
            'container': container,
            'target_path': '/out/' + str(metadata.get('fuzz_target', '')),
            'target': asdict_execution(execution),
            'verdict': verdict,
        }
    vul = results['roles']['vul']['verdict']
    fix = results['roles']['fix']['verdict']
    fixed_execution = results['roles']['fix']['target']
    passed = (vul['sanitizer_found'] and not vul['execution_error']
              and not fix['sanitizer_found'] and fix['execution_error'] is None
              and fixed_execution['returncode'] == 0)
    if not fix['sanitizer_found'] and fixed_execution['returncode'] != 0:
        results['roles']['fix']['verdict']['execution_error'] = (
            f'fixed environment exited {fixed_execution["returncode"]} without a sanitizer report')
        passed = False
    results.update(passed=passed, reward=int(passed),
                   failure_stage=None if passed else 'gold_differential')
    return results


def asdict_execution(execution: Any) -> dict[str, Any]:
    return {
        'returncode': getattr(execution, 'returncode', None),
        'output_tail': _output(execution),
    }


class _Environment:
    """One disposable sandbox and one Compose project inside that sandbox."""

    def __init__(self, task_id: str, out_dir: Path, delivery: Path, kind: str,
                 keep_data: bool):
        self.delivery = delivery
        self.kind = kind
        self.keep_data = keep_data
        unique = f'{time.time_ns()}-{os.getpid()}'
        runtime_root = out_dir / 'grader-runtime' / f'{kind}-{unique}'
        runtime_root.mkdir(parents=True, exist_ok=False)
        sandbox_id = f'{task_id}-{kind}-{unique}'
        safe_task = re.sub(r'[^a-zA-Z0-9_.-]+', '-', task_id)[:48].strip('-.') or 'task'
        # Stable per-task docker-data name: with CDB_LOCAL_DOCKER_DATA=1 the
        # inner daemon's images survive re-grades of this task (only the
        # --no-cache compile reruns), and CDB_STORAGE_DRIVER=overlay2 becomes
        # legal on the host's xfs/ext4 root.
        self.sandbox = DockerSandbox(task_id=sandbox_id, runtime_root=runtime_root,
                                     docker_data_name=f'grade-{safe_task}-{kind}')
        digest = hashlib.sha256(str(runtime_root).encode()).hexdigest()[:12]
        self.project = f'cdb-{safe_task}-{kind}-{digest}'
        self.staged = self.sandbox.workspace / kind
        self.compose_file = self.staged / 'docker-compose.yaml'
        self.base = ['compose', '-p', self.project,
                     '--project-directory', str(self.staged),
                     '-f', str(self.compose_file)]
        self.config: dict[str, Any] = {}
        self.roles: tuple[str, str] | None = None
        self._closed = False

    def docker(self, args: list[str], timeout: int = 120) -> Any:
        return self.sandbox.docker(args, timeout=timeout)

    def compose(self, args: list[str], timeout: int = 120) -> Any:
        return self.docker([*self.base, *args], timeout=timeout)

    def _stage(self, source: Path) -> None:
        self.sandbox.start()
        stage_delivery(source, self.staged)

    def start_source(self) -> None:
        self._stage(self.delivery / 'source')

    def read_config(self, *, preserve_test_contract: bool = False) -> dict[str, Any]:
        cp = self.compose(['config'], timeout=90)
        if cp.returncode:
            raise _Failure('agent_semantic', f'{self.kind}_config',
                           'Compose config failed: ' + _output(cp))
        try:
            value = yaml.safe_load(cp.stdout)
        except yaml.YAMLError as exc:
            raise _Failure('grader', f'{self.kind}_config',
                           f'cannot parse Compose config output: {exc}') from exc
        if not isinstance(value, dict) or not isinstance(value.get('services'), dict):
            raise _Failure('agent_semantic', f'{self.kind}_config',
                           'Compose config has no services mapping')
        self.config = value
        if not preserve_test_contract:
            self.roles = _resolve_roles(value['services'])
        return value

    def build_and_up(self) -> tuple[dict[str, Any], dict[str, Any]]:
        self.read_config()
        build = self.compose(['build', '--no-cache'], timeout=3600)
        build_evidence = {'success': build.returncode == 0, **_command_evidence(build)}
        up_evidence: dict[str, Any] = {'success': False, 'skipped': True}
        if build.returncode == 0:
            # vfs container creation copies the whole image rootfs per service;
            # multi-GB sanitizer images need far more than 300s before any
            # healthcheck can even start (59072 r5 died here after a clean build).
            up = self.compose(['up', '-d', '--wait', '--wait-timeout', '120'], timeout=1800)
            up_evidence = {'success': up.returncode == 0, **_command_evidence(up)}
        return build_evidence, up_evidence

    def container(self, service: str) -> str:
        cp = self.compose(['ps', '-q', service], timeout=45)
        ids = (cp.stdout or '').split()
        if cp.returncode or len(ids) != 1:
            raise _Failure('agent_semantic', f'{self.kind}_contract',
                           f'expected one running container for {service}: ' + _output(cp))
        return ids[0]

    def run_smoke(self, service: str) -> dict[str, Any]:
        container = self.container(service)
        # Probe with -f, not -x. The script is invoked explicitly, so a 0644
        # smoke.sh must not fall through to the host-side fallback. Prefer
        # bash: `set -o pipefail` is valid there and dash rejects it.
        cp = self.docker(['exec', container, 'sh', '-c',
                          'run_smoke() { '
                          'if command -v bash >/dev/null 2>&1; then exec bash "$1"; '
                          'else exec sh "$1"; fi; '
                          '}; '
                          'if [ -f /smoke.sh ]; then run_smoke /smoke.sh; '
                          'elif [ -f /workspace/smoke.sh ]; then run_smoke /workspace/smoke.sh; '
                          'elif [ -f ./smoke.sh ]; then run_smoke ./smoke.sh; '
                          'else echo "smoke.sh not found" >&2; exit 2; fi'], timeout=300)
        if cp.returncode == 2 and 'smoke.sh not found' in _output(cp):
            # The contract places smoke.sh at the delivery root and never said
            # where it runs; a host-side Compose-level script is a legitimate
            # reading (arvo-59072 r7 was misjudged agent_semantic before this
            # fallback). Run the delivery-root script from the sandbox against
            # the already-running project.
            host = self.sandbox.exec(
                ['sh', '-c',
                 'if command -v bash >/dev/null 2>&1; then exec bash smoke.sh; '
                 'else exec sh smoke.sh; fi'],
                timeout=300, workdir=str(self.staged),
                extra_env={'COMPOSE_PROJECT_NAME': self.project},
                log_operation=f'{self.kind}-smoke-host')
            return {'success': host.returncode == 0, 'host_side': True,
                    **_command_evidence(host)}
        return {'success': cp.returncode == 0, **_command_evidence(cp)}

    def run_differential(self, poc: Path, metadata: Mapping[str, Any]) -> dict[str, Any]:
        if self.roles is None:
            raise _Failure('grader', f'{self.kind}_contract',
                           'Compose config was not rendered before differential')
        vul_service, fix_service = self.roles
        containers = {
            'vul': self.container(vul_service),
            'fix': self.container(fix_service),
        }
        visible = _stage_poc_where_inner_docker_can_read(self.sandbox.workspace, poc)
        return _check_pair(self.docker, containers, visible, metadata)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.sandbox.stop(remove_data=not self.keep_data)



def grade(task_path: Path | str, out_dir: Path | str, delivery_dir: Path | str,
          keep_data: bool = False) -> dict[str, Any]:
    """Grade a frozen declarative source delivery.

    ``out_dir`` is the task's own result directory (not its parent).  Semantic
    failures return ``status=failed``; export and infrastructure errors return
    ``status=error`` and are never relabelled as agent semantic failures.
    """
    task_path = Path(task_path)
    out_dir = Path(out_dir).resolve()
    delivery = Path(delivery_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()
    record: dict[str, Any] = {
        'task_id': task_path.name,
        'delivery': str(delivery),
        'reward': 0,
        'status': 'running',
        'failure_class': None,
        'failure_stage': None,
        'checks': {},
        'started_at': time.strftime('%Y-%m-%dT%H:%M:%S%z', time.localtime(started)),
    }

    def checkpoint() -> None:
        _write_json(out_dir / 'result.json', record)

    def fail(failure: _Failure) -> None:
        record['status'] = failure.status
        record['failure_class'] = failure.failure_class
        record['failure_stage'] = failure.stage
        record['error'] = str(failure)

    environment: _Environment | None = None
    current_stage = 'delivery'
    try:
        record['checks']['delivery'] = _validate_delivery(task_path, delivery)
        checkpoint()

        metadata = _load_metadata(task_path)
        poc = task_path / 'input' / 'poc'
        if not poc.is_file():
            poc = task_path / 'gold' / 'poc'
        if not poc.is_file():
            raise _Failure('pipeline', 'delivery', f'public PoC missing: {poc}')

        environment = _Environment(task_path.name, out_dir, delivery, 'source', keep_data)
        current_stage = 'source_sandbox'
        try:
            environment.start_source()
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            raise _infra_failure('source_sandbox', f'cannot start/stage source sandbox: {exc}',
                                 str(exc)) from exc
        current_stage = 'source_build'
        build, up = environment.build_and_up()
        record['checks']['source'] = {'build': build, 'up': up, 'clean_sandbox': True}
        current_stage = 'source_up'
        if not build['success']:
            raise _infra_failure('source_build', 'source Compose build failed: ' +
                                 build['output_tail'], build['output_tail'],
                                 default='agent_semantic')
        if not up['success']:
            raise _infra_failure('source_up', 'source Compose up/health failed: ' +
                                 up['output_tail'], up['output_tail'],
                                 default='agent_semantic')
        environment.read_config(preserve_test_contract=True)
        checkpoint()

        vul_service, fix_service = environment.roles
        record['checks']['source']['contract'] = {
            'vul': vul_service, 'fix': fix_service,
        }

        current_stage = 'smoke'
        smoke_vul = environment.run_smoke(vul_service)
        smoke_fix = environment.run_smoke(fix_service)
        record['checks']['smoke'] = {
            'vul': smoke_vul,
            'fix': smoke_fix,
        }
        if not smoke_vul['success'] or not smoke_fix['success']:
            raise _Failure('agent_semantic', 'smoke',
                           'smoke.sh must pass on both vul and fix')

        current_stage = 'differential'
        differential = environment.run_differential(poc, metadata)
        record['checks']['differential'] = differential
        if not differential['passed']:
            raise _Failure('agent_semantic', 'differential',
                           'GOLD PoC differential failed')

        environment.close()
        environment = None

        record['reward'] = 1
        record['status'] = 'passed'
        record['failure_class'] = None
        record['failure_stage'] = None
    except _Failure as exc:
        fail(exc)
    except (subprocess.TimeoutExpired, RuntimeError, OSError) as exc:
        fail(_infra_failure(current_stage, f'{exc.__class__.__name__}: {exc}',
                            str(exc), default='pipeline'))
    except Exception as exc:
        fail(_Failure('grader', 'grader', f'{exc.__class__.__name__}: {exc}'))
    finally:
        if environment is not None:
            try:
                environment.close()
            except Exception as exc:
                record['checks']['cleanup'] = {'success': False, 'error': str(exc)}
                if record['reward']:
                    record['reward'] = 0
                    record['status'] = 'error'
                    record['failure_class'] = 'pipeline'
                    record['failure_stage'] = 'cleanup'
                    record['error'] = f'cannot clean grading sandbox: {exc}'
        record['duration_sec'] = round(time.time() - started, 3)
        record['finished_at'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
        checkpoint()
    return record
