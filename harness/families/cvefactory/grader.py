"""Grade only an agent's frozen CVE-Factory delivery.

The task package is used only for its public task id.  In particular this module
never resolves ``gold``, ``solution``, official tests, or an input archive.  The
declarative project is built once in a clean sandbox, patched in place, restarted,
and retested.  A passing source differential is reward 1.  Running images are
not exported or graded again.
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


TEST_NAMES = ('test_func.py', 'test_vuln.py')
TEST_ROOT = '/tmp/cdb-tests'
SOLUTION_ROOT = '/tmp/cdb-solution'
NETWORK_RE = re.compile(
    r'(temporary failure in name resolution|could not resolve|dns.*failed|'
    r'i/o timeout|tls handshake timeout|connection timed out|proxyconnect|'
    r'network is unreachable|no route to host|connection reset by peer|'
    r'failed to (?:fetch|pull).*(?:timeout|registry|proxy)|toomanyrequests|rate limit|'
    r'(?:registry|proxy).*(?:502|503|504|unavailable))',
    re.IGNORECASE | re.DOTALL,
)
PIPELINE_RE = re.compile(
    r'(cannot connect to the docker daemon|docker daemon.*(?:error|failed)|'
    r'no space left on device|overlay2.*(?:failed|error)|'
    r'permission denied.*docker\.sock)',
    re.IGNORECASE | re.DOTALL,
)
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


class _Failure(Exception):
    def __init__(self, failure_class: str, stage: str, message: str,
                 status: str | None = None):
        super().__init__(message)
        self.failure_class = failure_class
        self.stage = stage
        self.status = status or ('failed' if failure_class == 'agent_semantic' else 'error')


def _infra_failure(stage: str, message: str, output: str = '',
                   default: str = 'pipeline') -> _Failure:
    text = output or message
    if NETWORK_RE.search(text):
        classification = 'network'
    elif PIPELINE_RE.search(text):
        classification = 'pipeline'
    else:
        classification = default
    return _Failure(classification, stage, message)


def _validate_compose_contract(config: Mapping[str, Any], failure_class: str,
                               stage: str) -> tuple[str, str, str | None]:
    """Resolve the agent's declared test entrypoint from a rendered Compose."""
    services = config.get('services', {})
    if not isinstance(services, dict) or 'client' not in services:
        raise _Failure(failure_class, stage,
                       'Compose must contain the primary application service client')
    selected = 'client'
    command: str | None = None
    for name, raw_service in services.items():
        service = raw_service if isinstance(raw_service, dict) else {}
        labels = _labels(service)
        requested = labels.get('cdb.test_service')
        if requested:
            if requested not in services:
                raise _Failure(failure_class, stage,
                               f'cdb.test_service names an unknown service: {requested}')
            if selected != 'client' and selected != requested:
                raise _Failure(failure_class, stage,
                               'conflicting cdb.test_service labels')
            selected = requested
        if 'cdb.test_command' in labels:
            # Compose config preserves $$ so its output remains re-parseable;
            # the actual container label (and sh -c input) contains one $.
            candidate = labels['cdb.test_command'].replace('$$', '$')
            if command is not None and command != candidate:
                raise _Failure(failure_class, stage,
                               'conflicting cdb.test_command labels')
            command = candidate
    if command is not None and not command.strip():
        raise _Failure(failure_class, stage, 'cdb.test_command must not be empty')
    return 'client', selected, command



def _safe_tree(root: Path, forbidden: Path) -> None:
    """A frozen package may have internal links, never links to private files."""
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f'not a regular frozen directory: {root}')
    resolved = root.resolve()
    for path in root.rglob('*'):
        if path.is_symlink():
            try:
                link_target = os.readlink(path)
            except OSError as exc:
                raise ValueError(f'cannot read frozen symlink: {path}') from exc
            # The controller's debug alias is not part of the project. Old
            # bundles may still contain it after the log was moved away.
            if Path(link_target).name == 'cli-debug.log':
                continue
            try:
                target = path.resolve(strict=True)
            except FileNotFoundError as exc:
                raise ValueError(f'frozen symlink is dangling: {path} -> {link_target}') from exc
            if path.readlink().is_absolute() or not target.is_relative_to(resolved):
                raise ValueError(f'frozen symlink escapes its package: {path}')
            if target == forbidden or forbidden in target.parents:
                raise ValueError(f'frozen symlink refers to the private task package: {path}')
        elif not path.is_file() and not path.is_dir():
            raise ValueError(f'unsupported special file in frozen package: {path}')


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _validate_delivery(task_path: Path, delivery: Path) -> dict[str, Any]:
    """Validate only frozen agent material; never search for an oracle fallback."""
    task = task_path.resolve()
    if not delivery.is_dir() or delivery.is_symlink():
        raise _Failure('pipeline', 'delivery', f'frozen delivery is not a directory: {delivery}')
    resolved = delivery.resolve()
    if resolved == task or task in resolved.parents or resolved in task.parents:
        raise _Failure('pipeline', 'delivery',
                       'delivery must be a frozen results package, not a task/private path')
    source = delivery / 'source'
    try:
        _safe_tree(source, task)
        for name in ('bundle.json', 'source-inventory.json'):
            path = delivery / name
            if not _regular_file(path):
                raise ValueError(f'missing frozen inventory: {name}')
            value = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(value, dict):
                raise ValueError(f'{name} must contain a JSON object')
        required = [source / 'docker-compose.yaml', source / 'solution.sh',
                    source / 'tests' / 'run-tests.sh']
        required.extend(source / 'tests' / name for name in TEST_NAMES)
        missing = [str(path.relative_to(delivery)) for path in required
                   if not _regular_file(path)]
        if missing:
            raise _Failure('agent_semantic', 'delivery',
                           'missing agent delivery files: ' + ', '.join(missing))
    except _Failure:
        raise
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        raise _Failure('pipeline', 'delivery', str(exc)) from exc
    return {
        'success': True,
        'source': str(source),
        'inventories': ['bundle.json', 'source-inventory.json'],
        'official_oracle_used': False,
    }


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


def _phase_failure(phase: str, result: Mapping[str, Any]) -> str:
    code = (result.get('script') or {}).get('returncode')
    if result.get('custom_command'):
        return f'{phase} test command exited {code}'
    return f'sh /tmp/cdb-tests/run-tests.sh {phase} exited {code}'


def _test_phase(vulnerable: Mapping[str, Any], fixed: Mapping[str, Any]) -> dict[str, Any]:
    """Both phases are accepted from run-tests.sh's own exit code.

    The vulnerable script exits 0 when functional checks pass and the
    vulnerability check fails as required. The fixed script exits 0 when both
    pass. The grader does not start a second runner.
    """
    vulnerable_ok = bool(vulnerable.get('runner_succeeded'))
    fixed_ok = bool(fixed.get('runner_succeeded'))
    return {
        'p2p': {
            'vulnerable': vulnerable_ok,
            'fixed': fixed_ok,
            'success': vulnerable_ok and fixed_ok,
        },
        'f2p': {
            'vulnerable_assertion_failed': vulnerable_ok,
            'fixed': fixed_ok,
            'success': vulnerable_ok and fixed_ok,
        },
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
        self.sandbox = DockerSandbox(task_id=sandbox_id, runtime_root=runtime_root)
        digest = hashlib.sha256(str(runtime_root).encode()).hexdigest()[:12]
        safe_task = re.sub(r'[^a-zA-Z0-9_.-]+', '-', task_id)[:48].strip('-.') or 'task'
        self.project = f'cdb-{safe_task}-{kind}-{digest}'
        self.staged = self.sandbox.workspace / kind
        self.test_source = self.staged / 'tests'
        # Keep solution assets out of any writable application bind. The inner
        # daemon can only docker-cp paths mounted into its outer sandbox.
        self.solution_source = self.sandbox.workspace / 'solution-source'
        self.compose_file = self.staged / 'docker-compose.yaml'
        self.base = ['compose', '-p', self.project,
                     '--project-directory', str(self.staged),
                     '-f', str(self.compose_file)]
        self.config: dict[str, Any] = {}
        self.test_contract: tuple[str, str, str | None] | None = None
        self._closed = False

    def docker(self, args: list[str], timeout: int = 120) -> Any:
        return self.sandbox.docker(args, timeout=timeout)

    def compose(self, args: list[str], timeout: int = 120) -> Any:
        return self.docker([*self.base, *args], timeout=timeout)

    def _stage(self, source: Path) -> None:
        # start() creates the same-path workspace mount before Compose reads it.
        self.sandbox.start()
        stage_delivery(source, self.staged)
        stage_delivery(source, self.solution_source)

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
        failure_class = 'agent_semantic'
        if not preserve_test_contract:
            self.test_contract = _validate_compose_contract(
                value, failure_class, f'{self.kind}_contract')
        return value

    def build_and_up(self) -> tuple[dict[str, Any], dict[str, Any]]:
        self.read_config()
        build = self.compose(['build', '--no-cache'], timeout=3600)
        build_evidence = {'success': build.returncode == 0, **_command_evidence(build)}
        up_evidence: dict[str, Any] = {'success': False, 'skipped': True}
        if build.returncode == 0:
            up = self.compose(['up', '-d', '--wait', '--wait-timeout', '120'], timeout=300)
            up_evidence = {'success': up.returncode == 0, **_command_evidence(up)}
        return build_evidence, up_evidence

    def contract(self) -> tuple[str, str, str | None]:
        if self.test_contract is None:
            raise _Failure('grader', f'{self.kind}_contract',
                           'Compose config was not rendered before contract selection')
        return self.test_contract

    def container(self, service: str) -> str:
        cp = self.compose(['ps', '-q', service], timeout=45)
        ids = (cp.stdout or '').split()
        failure_class = 'agent_semantic'
        if cp.returncode or len(ids) != 1:
            raise _Failure(failure_class, f'{self.kind}_contract',
                           f'expected one running container for {service}: ' + _output(cp))
        return ids[0]

    def inject_tests(self, container: str) -> None:
        # A bind mount at this path would make rm delete the project's own tests.
        # Run the cleanup as root: the agent may have left root-owned files
        # under TEST_ROOT (e.g. __pycache__ from a root-run pytest), and the
        # container's default user cannot remove those. chmod 777 keeps the
        # directory writable for whichever user the tests later run as.
        prepare = self.docker(['exec', '-u', '0', container, 'sh', '-c',
                               'mounted=0; '
                               'while read -r _ mp _; do '
                               f'[ "$mp" = {TEST_ROOT} ] && mounted=1; '
                               'done < /proc/mounts; '
                               'if [ "$mounted" = 1 ]; then '
                               f'echo "refusing to replace bind-mounted {TEST_ROOT}" >&2; '
                               'exit 42; '
                               'fi; '
                               f'rm -rf {TEST_ROOT} && mkdir -p {TEST_ROOT} '
                               f'&& chmod 777 {TEST_ROOT}'], timeout=30)
        if prepare.returncode == 42:
            failure_class = 'agent_semantic'
            raise _Failure(failure_class, f'{self.kind}_test_injection',
                           f'{TEST_ROOT} is a bind mount; the grader replaces that '
                           'directory and will not delete a mounted project tree')
        if prepare.returncode:
            raise _infra_failure(f'{self.kind}_test_injection',
                                 'cannot prepare test directory: ' + _output(prepare),
                                 _output(prepare))
        cp = self.docker(['cp', str(self.test_source) + '/.',
                          f'{container}:{TEST_ROOT}'], timeout=120)
        if cp.returncode:
            raise _infra_failure(f'{self.kind}_test_injection',
                                 'cannot copy frozen agent tests: ' + _output(cp), _output(cp))

    def run_tests(self, test_service: str, custom_command: str | None,
                  phase: str) -> dict[str, Any]:
        if phase not in ('vulnerable', 'fixed'):
            raise ValueError(f'unknown test phase: {phase}')
        container = self.container(test_service)
        self.inject_tests(container)
        # The optional state is explicit for run-tests.sh; custom commands keep
        # their exact argv but see CDB_TEST_PHASE for their own runner call.
        base = ['exec', '-e', f'CDB_TEST_PHASE={phase}', '--workdir', TEST_ROOT, container]
        if custom_command is None:
            script_command = [*base, 'sh', f'{TEST_ROOT}/run-tests.sh', phase]
        else:
            script_command = [*base, 'sh', '-c', custom_command]
        script = self.docker(script_command, timeout=900)
        success = script.returncode == 0
        return {
            'success': success,
            'runner_succeeded': success,
            'test_service': test_service,
            'custom_command': custom_command,
            'script': {'command': script_command, **_command_evidence(script)},
            'expected': f'{phase} test command exits 0',
            'dependencies_installed_by_grader': False,
            'tests_modified_by_grader': False,
        }

    def apply_solution(self) -> dict[str, Any]:
        client = self.container('client')
        prepare = self.docker(['exec', client, 'sh', '-c',
                               f'rm -rf {SOLUTION_ROOT} && mkdir -p {SOLUTION_ROOT}'], timeout=30)
        if prepare.returncode:
            raise _infra_failure('solution', 'cannot prepare solution directory: ' +
                                 _output(prepare), _output(prepare))
        # This is a separately staged frozen copy: application bind mounts
        # cannot mutate it. Nothing goes to /app or into a rebuilt image.
        cp = self.docker(['cp', str(self.solution_source) + '/.',
                          f'{client}:{SOLUTION_ROOT}'], timeout=300)
        if cp.returncode:
            raise _infra_failure('solution', 'cannot copy solution assets: ' +
                                 _output(cp), _output(cp))
        run = self.docker(['exec', '--user', 'root', '--workdir', SOLUTION_ROOT, client,
                           'sh', f'{SOLUTION_ROOT}/solution.sh'], timeout=900)
        return {'success': run.returncode == 0, **_command_evidence(run),
                'working_directory': SOLUTION_ROOT}

    def restart_client(self) -> dict[str, Any]:
        client = self.container('client')
        restarted = self.docker(['restart', client], timeout=120)
        evidence: dict[str, Any] = {
            'success': restarted.returncode == 0,
            'client_container': client,
            'rebuild_performed': False,
            'restart': _command_evidence(restarted),
        }
        if restarted.returncode:
            if (self.docker(['inspect', '--format', '{{.State.Running}}', client],
                            timeout=30).stdout or '').strip() == 'true':
                raise _Failure('agent_semantic', 'restart',
                               'solution replaced the running client container: ' +
                               _output(restarted))
            if re.search(r'no such (?:container|object)', _output(restarted), re.I):
                raise _Failure('agent_semantic', 'restart',
                               'solution removed the client container: ' + _output(restarted))
            raise _infra_failure('restart', 'docker restart client failed: ' +
                                 _output(restarted), _output(restarted))
        deadline = time.monotonic() + 120
        while True:
            state = self.docker(['inspect', '--format',
                                 '{{if .State.Health}}{{.State.Health.Status}}'
                                 '{{else}}{{.State.Status}}{{end}}', client], timeout=30)
            value = (state.stdout or '').strip()
            evidence['health'] = {'returncode': state.returncode, 'state': value,
                                  'output_tail': _output(state)}
            if state.returncode == 0 and value in ('healthy', 'running'):
                evidence['success'] = True
                return evidence
            if state.returncode or value in ('unhealthy', 'dead', 'exited', 'removing'):
                evidence['success'] = False
                return evidence
            if time.monotonic() >= deadline:
                evidence['success'] = False
                evidence['health']['error'] = 'health check timed out'
                return evidence
            time.sleep(1)

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
        # An up health check may wait for a sidecar. Preserve the source's test
        # selection while inspecting the final rendered service configuration.
        environment.read_config(preserve_test_contract=True)
        checkpoint()
        client, tester, command = environment.contract()
        record['checks']['source']['contract'] = {
            'client': client, 'test_service': tester, 'custom_command': command,
        }
        # read_config precedes build for early validation, while test evidence is
        # always vulnerable -> solution -> restart -> fixed in this one sandbox.
        current_stage = 'vulnerable'
        vulnerable = environment.run_tests(tester, command, 'vulnerable')
        record['checks']['vulnerable'] = vulnerable
        checkpoint()
        if not vulnerable['success']:
            raise _Failure('agent_semantic', 'vulnerable',
                           _phase_failure('vulnerable', vulnerable))

        current_stage = 'solution'
        client_before_patch = environment.container('client')
        solution = environment.apply_solution()
        solution['client_before_patch'] = client_before_patch
        record['checks']['solution'] = solution
        checkpoint()
        if environment.container('client') != client_before_patch:
            raise _Failure('agent_semantic', 'solution',
                           'solution.sh must patch client in place, not replace its container')
        if not solution['success']:
            raise _Failure('agent_semantic', 'solution', 'solution.sh returned non-zero')

        current_stage = 'restart'
        restart = environment.restart_client()
        record['checks']['restart'] = restart
        checkpoint()
        if not restart['success']:
            raise _Failure('agent_semantic', 'restart',
                           'client is not running and healthy after solution.sh')

        # This is the same running environment; no rebuild or reset occurs.
        current_stage = 'fixed'
        fixed = environment.run_tests(tester, command, 'fixed')
        record['checks']['fixed'] = fixed
        record['checks']['differential'] = _test_phase(vulnerable, fixed)
        checkpoint()
        if not fixed['success']:
            raise _Failure('agent_semantic', 'fixed',
                           _phase_failure('fixed', fixed))
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
