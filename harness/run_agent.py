"""Run one Claude Code session in one all-in-one DockerSandbox.

This is deliberately an agent runner, not a grader.  It stages public input,
starts the ordinary DinD sandbox, optionally runs network/source preflight, and
exports the complete workspace and live application environment after the
session.  A later controller can judge the frozen bundle.

Usage (the results directory is this task's directory, not a batch root)::

    python3 harness/run_agent.py --task tasks/cvefactory-cve-2014-1944 \
        --results results/agent-cve-2014-1944 --model <endpoint-model-alias> \
        --max-turns 50 --timeout 18000

Model credentials come from ANTHROPIC_BASE_URL and ANTHROPIC_AUTH_TOKEN.
``run-factory-eval.sh`` assigns both before starting this process.  They are passed
only to the Claude process.
``--preflight-only`` never reads credentials and never launches a model.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from harness.compact_trace import TrajectoryWriter  # noqa: E402
from harness.docker_sandbox import DockerSandbox  # noqa: E402

if TYPE_CHECKING:
    from harness.task_api import TaskSpec

# Single-task defaults are edited here, not supplied through CDB_* variables.
DEFAULT_MODEL = 'glm-5.3'
DEFAULT_MAX_TURNS = 50
DEFAULT_TIMEOUT = 18000
GENERIC_PREFLIGHT = True
PLUGIN_SOURCE = ROOT / 'harness' / 'agent_plugins' / 'internal-network'
PLUGIN_TARGET = '/opt/cdb-network-plugin'
REQUIRED_DELIVERABLES = (
    'docker-compose.yaml', 'solution.sh',
    'tests/test_func.py', 'tests/test_vuln.py', 'tests/run-tests.sh',
)
MODEL_ENV_KEYS = ('ANTHROPIC_BASE_URL', 'ANTHROPIC_AUTH_TOKEN')
SENSITIVE_KEYS = frozenset({
    'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY', 'CDB_MODEL_CREDENTIALS',
})
PRINT_LOCK = threading.Lock()
_SECRET_VALUES: set[str] = set()


# This is the complete public task contract.  In particular, it does not ask
# for an archive, a source reset, a patched-image rebuild, or an export action.
TASK_PROMPT = r'''# Task: reproduce and fix a vulnerability in an ordinary container project

You are working in a fresh, ordinary Docker sandbox as the `agent` user. Your
current directory is the project workspace and is the only project directory
you need. Work autonomously: do not ask for confirmation and do not wait for an
interactive prompt. Use the normal Claude Code tools and normal shell/Docker
commands to investigate, write files, build, run, and debug.

Before any `docker pull`, `docker build`, `docker compose build`, or package
install, read and follow `/opt/cdb-network-plugin/skills/kkrepo-network/SKILL.md`;
it is mounted read-only in this sandbox.

## Public input and source freedom

- `CVE.md` describes the requested vulnerability.
- `src/` is an initial, mutable, non-authoritative source snapshot. It may be
  incomplete, inconsistent, or missing build materials. Inspect it and freely
  modify, replace, or supplement it with the real upstream project/version.
  You may use `git clone`, `git fetch`, `curl`, `wget`, package managers, and
  other ordinary source/dependency retrieval commands. Do not treat the initial
  tree as read-only or as the only allowed source. Never reset, restore, or
  replace your final work with the initial tree.
- Keep the requested upstream project and vulnerability semantics. Do not
  substitute an unrelated application or simulate vulnerability output.
- Private environments, private task data, reference solutions, hidden tests,
  host Docker sockets, host caches, and other tasks are not allowed. Use only
  the ordinary containers and Docker daemon in this sandbox. The task file
  points at the network/mirror Skill once; follow it before the first
  `docker pull`, `docker build`, `docker compose build`, or package install.
  `docker build` does not inherit this shell's proxy: pass proxy build args
  and rewrite package sources in the Dockerfile before the first install.
  Do not leave `apt-get` or `pip` pointed at the public Debian, Ubuntu, or
  PyPI hosts inside a build: mirror settings must be baked into the
  Dockerfile or Compose file, because grading rebuilds without this
  sandbox's network plugin mount.

## Required project deliverables

A successful build, a container commit, or a verbal
description alone is not a delivery. At minimum provide:

1. `docker-compose.yaml` at the workspace root, plus every Dockerfile needed by
   its build contexts. Use `docker compose --project-name "$COMPOSE_PROJECT_NAME"`
   for every application operation; this prevents cross-run resource conflicts.
   The application service must be named `client`. Include every build context,
   configuration, startup script, sidecar, and dependency needed by that
   project. Keep the real source in the project/build context; do not create a
   separate special `/app` copy for grading or depend on an `/app` export.
   Declare a Compose `healthcheck` for every service that needs warm-up before
   it can serve real requests (database initialization, seeding, migrations,
   fixture or chain loading). The grader starts the project with
   `docker compose up -d --wait` and runs the tests as soon as that command
   returns; a service without a healthcheck counts as ready the moment its
   process starts, so tests can begin before your seed data exists.
2. `solution.sh`, for applicable fix tasks. The controller copies the project to
   `/tmp/cdb-solution` inside `client`, then executes
   `sh /tmp/cdb-solution/solution.sh` as root with that working directory. It runs
   **inside `client`, not on the sandbox host**. Do not use `docker`, `sudo`, host
   paths, or host workspace mounts; use POSIX sh and dependencies declared in the
   client image. The script must actually patch the application; printing `fixed`
   or returning zero is not proof. Do not require a patched-image rebuild, an
   injected source archive, or a second application copy. The final environment
   you leave running must be the vulnerable, unpatched baseline, not a fixed leftover.
3. `tests/test_func.py`: meaningful functional tests that pass in both the
   vulnerable and fixed states.
4. `tests/test_vuln.py`: a meaningful vulnerability test that fails on the
   vulnerable baseline and passes after `solution.sh` and the client restart.
5. `tests/run-tests.sh`: the POSIX-sh test entry point (no Bash assumption).
   Accept an optional
   `vulnerable|fixed` argument (defaulting to `vulnerable`), always run the
   functional tests first, and then run the vulnerability test with the
   appropriate expected failure/pass behavior for the selected state. The
   script's exit code is the only signal the grader reads, so do not hide a
   failure behind exit code 0. Tests normally execute under `client`.
   To use a separate tester, declare `cdb.test_service=<service>` as a Compose
   label on that tester. For a custom runner, `cdb.test_command=<shell-command>`
   is passed to `sh -c` with `CDB_TEST_PHASE=vulnerable|fixed`; forward that
   phase to `run-tests.sh`. Test services and dependencies belong to the same
   exported Compose topology.

These tests are the only judgment materials for this task; there is no private
answer test to discover or invoke. The controller does not grade during your
session. Do not weaken tests merely to make them pass, and do not write a script
that only prints success without executing the assertions.

## Build, test, and finish

Make the project actually run, not just build. The only test location is
`/tmp/cdb-tests` inside the test service. The grader deletes that directory and
copies the frozen `tests/` into it, then runs
`sh /tmp/cdb-tests/run-tests.sh vulnerable` and, after the fix,
`sh /tmp/cdb-tests/run-tests.sh fixed`. Do not bind-mount the workspace
`tests/` directory, or anything else, onto `/tmp/cdb-tests`. A mount there
would make that deletion remove the project tests. To rehearse the same
command, copy `tests/` into the container at `/tmp/cdb-tests` and run it
there, for example:

    docker compose --project-name "$COMPOSE_PROJECT_NAME" cp tests client:/tmp/cdb-tests
    docker compose --project-name "$COMPOSE_PROJECT_NAME" exec -T client sh /tmp/cdb-tests/run-tests.sh vulnerable

After applying the fix through the prescribed root-in-client `solution.sh` and
restarting `client`, run the same entry point with `fixed`. Test dependencies
and fixtures must be built into the client/test image; do not rely on a host-side
virtualenv or on this Skill/an external judge installing them later.
The grader evaluates in exactly this order: `run-tests.sh vulnerable`,
`solution.sh` as root inside `client`, `docker restart client`, then
`run-tests.sh fixed`. A restart is not a rebuild: the container filesystem and
any database files persist, but processes start over and PID numbering resets.
Write tests that survive that restart: do not use a PID, a boot timestamp, or
any per-boot value as a uniqueness source, and do not assume rows or files
written during the vulnerable phase were wiped. The grader
accepts a phase only when that test command exits 0. By default the command is
`sh /tmp/cdb-tests/run-tests.sh vulnerable` or
`sh /tmp/cdb-tests/run-tests.sh fixed`. If you set `cdb.test_command`, the
grader runs that shell command instead, with `CDB_TEST_PHASE` set to the same
phase, and accepts the phase when that command exits 0. It does not run the
test files itself and does not install test tools. Use the
real project source and runtime, with no separate `/app` source copy.

You may freely install debugging tools, inspect logs, use `docker exec`, and
restart services while developing. Those actions are not the delivery. The
controller copies this workspace and, in a new sandbox, runs
`docker compose build --no-cache` from the Dockerfiles and Compose file. It
does not keep the containers you leave running, the sandbox host's installed
packages, or files that exist only inside a container.

- Put every package, compiler, interpreter, and test tool the application or
  `solution.sh` needs into the client Dockerfile (`apt-get`, `pip`, `npm`, and
  so on). `pip install` or `apt-get install` on this sandbox host does not
  enter `client` and is not copied. The same install done with `docker exec`
  is discarded on rebuild unless that command is also in the Dockerfile.
  Write file changes that the rebuilt application must contain into the
  Dockerfile or into project files that the Dockerfile copies; do not leave
  them only in the running container.
- In a Dockerfile, `COPY` and `ADD` sources are relative paths inside the
  build context, which is this workspace. `COPY app /opt/app` is valid: `app`
  is a workspace directory and `/opt/app` is a path inside the image.
  `COPY /tmp/app /opt/app` is not: an absolute source does not read the
  sandbox path `/tmp/app`.
- A Compose bind must use a relative path inside this workspace, for example
  `./app:/opt/app`. The left side is a project file; the right side is where
  the container sees it. Do not bind-mount an absolute path, `/tmp`,
  `/home/agent`, or any directory outside this workspace. This sandbox can see
  those directories, but the grader's workspace has a different absolute path
  and an outside bind is rejected before grading.
- A volume written as `dbdata:/var/lib/mysql` is a private disk named `dbdata`,
  not a `dbdata/` directory in this workspace. Rows inserted while you debug
  live only on that disk. Rebuild creates a new empty disk and does not copy
  those rows. Put data the tests need into the image, for example
  `COPY seed.sql /docker-entrypoint-initdb.d/seed.sql`, or into a workspace
  file mounted with a relative bind such as `./seed:/docker-entrypoint-initdb.d`.
  Do not use `tmpfs`. Its contents are not saved, and the moved environment
  is rejected.
- Do not perform an export, commit, grading, or submission action.
'''


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact_text(value: Any) -> str:
    """Remove known credentials from every human- or machine-readable log."""
    text = str(value)
    for secret in sorted(_SECRET_VALUES, key=len, reverse=True):
        if secret:
            text = text.replace(secret, '<redacted>')
    for key in sorted(SENSITIVE_KEYS):
        # Covers shell diagnostics such as KEY=value without recording values.
        text = re.sub(rf'({re.escape(key)}\s*=\s*)[^\s,;]+',
                      rf'\1<redacted>', text, flags=re.IGNORECASE)
    return text


def redact_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if str(key).upper() in SENSITIVE_KEYS:
                result[key] = '<redacted>'
            else:
                result[key] = redact_value(item)
        return result
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def write_json(path: Path, value: Mapping[str, Any] | list[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(redact_value(value), ensure_ascii=False,
                                   indent=2, default=str) + '\n', encoding='utf-8')
    os.replace(temporary, path)


def emit(console_path: Path, message: str) -> None:
    line = f'[{time.strftime("%H:%M:%S")}] {redact_text(message)}'
    with PRINT_LOCK:
        print(line, flush=True)
        with console_path.open('a', encoding='utf-8') as handle:
            handle.write(line + '\n')


def redact_file(path: Path) -> None:
    if path.is_file() and not path.is_symlink():
        path.write_text(redact_text(path.read_text(encoding='utf-8', errors='replace')),
                        encoding='utf-8')


def _make_workspace_mutable(workspace: Path) -> None:
    from harness.families.cvefactory.workspace import make_workspace_mutable
    make_workspace_mutable(workspace)



def prepare_public_workspace(task: 'TaskSpec', workspace: Path) -> None:
    """Stage only public inputs using the selected family's own contract."""
    from harness.registry import FamilyRegistry
    from harness.task_api import PrepareRequest

    if workspace.exists():
        raise FileExistsError(f'refusing to replace existing workspace: {workspace}')
    plugin = FamilyRegistry().create(task.family)
    errors = plugin.validate_task(task)
    if errors:
        raise TaskInputFailure(f'{task.task_id}: invalid public input: {errors}')
    plugin.prepare_workspace(PrepareRequest(task, workspace))
    if task.family == 'cvefactory':
        # Keep the richer single-task CVE contract as well as the family contract.
        (workspace / 'TASK.md').write_text(TASK_PROMPT, encoding='utf-8')
    _make_workspace_mutable(workspace)


def load_model_environment(environ: Mapping[str, str] | None = None
                           ) -> tuple[dict[str, str], dict[str, Any]]:
    """Read the endpoint assigned by run-factory-eval.sh and inherited by this process."""
    environment = os.environ if environ is None else environ
    credentials: dict[str, str] = {}
    missing = []
    for key in MODEL_ENV_KEYS:
        value = environment.get(key, '').strip()
        if value:
            credentials[key] = value
            _SECRET_VALUES.add(value)
        else:
            missing.append(key)
    if missing:
        raise RuntimeError(
            'model run requires ANTHROPIC_BASE_URL and ANTHROPIC_AUTH_TOKEN '
            f'from run-factory-eval.sh; missing {", ".join(missing)}')
    for key, value in environment.items():
        if key.startswith(('ANTHROPIC_', 'CLAUDE_')) and key not in credentials and value:
            credentials[key] = value
    return credentials, {
        'source': 'run-factory-eval.sh',
        'keys': list(credentials),
        'values': '<redacted>',
    }


class PipelineFailure(RuntimeError):
    failure_category = 'pipeline'


class NetworkFailure(PipelineFailure):
    failure_category = 'network'


def _tail(value: Any, limit: int = 4000) -> str:
    return str(value or '')[-limit:]


# Each sandbox has a private image store, so a base-image pull is a full
# download. Twenty of those at once share the worker proxy and some miss the
# old 240s deadline. A few pulls at a time leave enough bandwidth to finish.
REGISTRY_PULL_SLOTS = 3
REGISTRY_PULL_TIMEOUT_SEC = 900


class _RegistryPullSlot:
    """Hold one of a few host-local locks for the duration of a registry pull."""

    def __init__(self) -> None:
        root = Path(os.environ.get('CDB_DOCKER_DATA_ROOT', '/var/tmp'))
        self.directory = root / 'registry-pull-slots'
        self.handle: Any = None

    def __enter__(self) -> '_RegistryPullSlot':
        self.directory.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + 3600
        while True:
            for index in range(REGISTRY_PULL_SLOTS):
                handle = (self.directory / f'slot-{index}').open('a+')
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    handle.close()
                    continue
                self.handle = handle
                return self
            if time.monotonic() >= deadline:
                raise NetworkFailure('timed out waiting for a registry pull slot')
            time.sleep(1)

    def __exit__(self, *args: Any) -> None:
        if self.handle is not None:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
            self.handle = None


def _preflight_step(steps: list[dict[str, Any]], out_dir: Path, name: str,
                    cp: subprocess.CompletedProcess | BaseException, category: str = 'network',
                    required: bool = True) -> bool:
    """Record timeouts and probe errors before applying the required/optional policy."""
    if isinstance(cp, BaseException):
        timed_out = isinstance(cp, subprocess.TimeoutExpired)
        step = {
            'name': name, 'returncode': 124 if timed_out else 1,
            'error_type': type(cp).__name__,
            'stdout_tail': _tail(getattr(cp, 'stdout', None)),
            'stderr_tail': _tail(getattr(cp, 'stderr', None) or str(cp)),
            **({'timeout_sec': cp.timeout} if timed_out else {}),
        }
    else:
        step = {
            'name': name, 'returncode': cp.returncode,
            'stdout_tail': _tail(cp.stdout), 'stderr_tail': _tail(cp.stderr),
        }
    steps.append(step)
    # Heartbeats make partial failures diagnosable while a preflight is running.
    write_json(out_dir / 'preflight.json', {'success': False, 'steps': steps})
    if step['returncode'] and required:
        error = (f'preflight {name} failed with exit {step["returncode"]}: '
                 f'{step["stderr_tail"] or step["stdout_tail"]}')
        if category == 'network':
            raise NetworkFailure(error)
        raise PipelineFailure(error)
    return step['returncode'] == 0


def _streaming_preflight(sandbox: DockerSandbox, script: str) -> subprocess.CompletedProcess:
    """Exercise the same streaming exec used by Claude, with a hard deadline."""
    process = sandbox.popen(
        ['bash', '-lc', script], user='agent', workdir=str(sandbox.workspace),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        _terminate_agent(sandbox, process)
        stdout, stderr = process.communicate(timeout=30)
        return subprocess.CompletedProcess(['bash', '-lc', '<build-preflight>'], 124,
                                          stdout, stderr)
    return subprocess.CompletedProcess(['bash', '-lc', '<build-preflight>'],
                                      process.returncode, stdout, stderr)


def run_preflight(sandbox: DockerSandbox, out_dir: Path, *,
                  require_task: bool = True) -> dict[str, Any]:
    """Preserve probe timeouts in the step report instead of losing their evidence."""
    steps: list[dict[str, Any]] = []
    try:
        return _run_preflight_probes(sandbox, out_dir, require_task=require_task, steps=steps)
    except (OSError, subprocess.SubprocessError) as exc:
        name = 'probe-timeout' if isinstance(exc, subprocess.TimeoutExpired) else 'probe-os-error'
        category = 'network' if isinstance(exc, subprocess.TimeoutExpired) else 'pipeline'
        _preflight_step(steps, out_dir, name, exc, category=category)
        raise AssertionError('required preflight failure must raise') from exc


def _run_preflight_probes(sandbox: DockerSandbox, out_dir: Path, *,
                          require_task: bool,
                          steps: list[dict[str, Any]]) -> dict[str, Any]:
    """Exercise real source/package downloads and a network-using Docker build.

    No model credentials are read or forwarded. All downloads use ordinary
    sandbox proxy variables, with bounded curl/pip timeouts. kkRepo must stay
    direct; internal services must not be routed through an external proxy.
    """
    if require_task:
        _preflight_step(steps, out_dir, 'mutable-public-source',
                        sandbox.exec(['bash', '-c', 'test -w src && test -w TASK.md && test ! -e gold && test ! -e solution'],
                                     user='agent', workdir=str(sandbox.workspace)), category='pipeline')
    else:
        _preflight_step(steps, out_dir, 'mutable-preflight-workspace',
                        sandbox.exec(['test', '-w', '/workspace'],
                                     user='agent', workdir=str(sandbox.workspace)), category='pipeline')
    _preflight_step(steps, out_dir, 'package-install',
                    sandbox.exec(['bash', '-lc',
                        'work=$(mktemp -d /tmp/cdb-pip.XXXXXX) && trap \'rm -rf "$work"\' EXIT && '
                        'python3 -m pip install --disable-pip-version-check --retries 1 --timeout 30 '
                        '--target "$work/site" wheel && PYTHONPATH="$work/site" python3 -c "import wheel"'],
                        timeout=240, user='agent', workdir=str(sandbox.workspace)))
    _preflight_step(steps, out_dir, 'docker-daemon',
                    sandbox.docker(['info', '--format', '{{.ServerVersion}}'], timeout=45),
                    category='pipeline')
    source_script = r'''set -Eeuo pipefail
work=$(mktemp -d /tmp/cdb-source-preflight.XXXXXX)
trap 'rm -rf "$work"' EXIT
git clone --depth 1 https://github.com/octocat/Hello-World.git "$work/source"
test -s "$work/source/README"
curl --fail --silent --show-error --connect-timeout 10 --max-time 45 \
  https://example.com/ -o "$work/index.html"
test -s "$work/index.html"
curl --noproxy '*' --fail --silent --show-error --connect-timeout 10 --max-time 30 \
  http://100.102.49.114:19091/repository/debian/dists/stable/Release -o "$work/debian-release"
grep -q '^Codename:' "$work/debian-release"
curl --fail --silent --show-error --connect-timeout 10 --max-time 45 \
  https://raw.githubusercontent.com/octocat/Hello-World/master/README -o "$work/raw-source"
test -s "$work/raw-source"
'''
    _preflight_step(steps, out_dir, 'external-source-kkrepo-and-network',
                    sandbox.exec(['bash', '-lc', source_script], timeout=240,
                                 user='agent', workdir=str(sandbox.workspace)))
    # The slot is on the worker, around the inner pull. It does not change
    # what is checked: this sandbox must still obtain the image itself.
    with _RegistryPullSlot():
        _preflight_step(steps, out_dir, 'registry-pull',
                        sandbox.docker(['pull', 'python:3.11-slim'],
                                       timeout=REGISTRY_PULL_TIMEOUT_SEC))
    container_probe = ['python3', '-c',
                       'import urllib.request; '
                       'r=urllib.request.urlopen("https://example.com/", timeout=20); '
                       'assert r.status == 200']
    direct = _preflight_step(steps, out_dir, 'container-network-direct-diagnostic',
                             sandbox.docker(['run', '--rm', 'python:3.11-slim',
                                             *container_probe], timeout=45), required=False)
    proxy_env = {key: os.environ[key] for key in (
        'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy')
        if os.environ.get(key)}
    proxy_args = [item for key, value in proxy_env.items() for item in ('-e', f'{key}={value}')]
    if proxy_env:
        _preflight_step(steps, out_dir, 'container-network-explicit-deployment-config',
                        sandbox.docker(['run', '--rm', *proxy_args, 'python:3.11-slim',
                                        *container_probe], timeout=60))
    elif not direct:
        raise NetworkFailure('container has neither direct HTTPS nor a deployment HTTP proxy')
    build_script = r'''set -Eeuo pipefail
work=$(mktemp -d /tmp/cdb-build-preflight.XXXXXX)
project=cdb-preflight-$(basename "$work" | tr '.[:upper:]' '-[:lower:]')
cleanup() {
    docker compose -p "$project" -f "$work/docker-compose.yaml" down --volumes --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
cat >"$work/Dockerfile" <<'DOCKERFILE'
FROM python:3.11-slim
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG http_proxy
ARG https_proxy
ARG no_proxy
RUN python3 -m pip install --no-cache-dir --disable-pip-version-check \
    --retries 1 --timeout 30 six==1.17.0
RUN python3 -c "import six; assert six.__version__ == '1.17.0'"
DOCKERFILE
cat >"$work/docker-compose.yaml" <<'COMPOSE'
services:
  client:
    build:
      context: .
      network: host
      args:
        HTTP_PROXY: ${HTTP_PROXY:-}
        HTTPS_PROXY: ${HTTPS_PROXY:-}
        NO_PROXY: ${NO_PROXY:-}
        http_proxy: ${http_proxy:-}
        https_proxy: ${https_proxy:-}
        no_proxy: ${no_proxy:-}
COMPOSE
# stdin/stdout/stderr are streamed through the same scoped exec as Claude.
docker compose --progress plain -p "$project" -f "$work/docker-compose.yaml" build --no-cache
docker compose -p "$project" -f "$work/docker-compose.yaml" config --format json \
    | python3 -c 'import json,sys; c=json.load(sys.stdin); assert c["services"]["client"]["build"]["dockerfile"] == "Dockerfile"'
'''
    try:
        build = _streaming_preflight(sandbox, build_script)
    except (OSError, subprocess.SubprocessError) as exc:
        build = subprocess.CompletedProcess(['streaming-build-preflight'], 1, '', str(exc))
    _preflight_step(steps, out_dir, 'docker-build-network-and-streaming', build)
    result = {'success': True, 'steps': steps}
    write_json(out_dir / 'preflight.json', result)
    return result


def export_bundle(sandbox: DockerSandbox, destination: Path) -> Any:
    """Freeze the declarative source. Running containers are not exported."""
    from harness.bundle import export_bundle as bundle_export
    project = getattr(sandbox, 'compose_project', 'cdb-' + sandbox.task_id)
    return bundle_export(sandbox, destination, project=project)


def build_agent_command(model: str, max_turns: int) -> list[str]:
    from harness.claude_session import claude_command
    prompt = ('Read TASK.md in the current directory and follow it exactly. '
              'Before any docker pull, docker build, or package install, read '
              'and follow /opt/cdb-network-plugin/skills/kkrepo-network/SKILL.md. '
              'Leave the declarative project in the vulnerable baseline requested '
              'by TASK.md; any local application run is for debugging only and is not graded. '
              'Work autonomously; do not ask for confirmation.')
    return claude_command(prompt, model, max_turns, debug_file='cli-debug.log')


def _terminate_agent(sandbox: DockerSandbox, process: subprocess.Popen) -> None:
    # Target only this Claude exec's dedicated process group, never daemon PID 1
    # or an unrelated controller command running as the same UID.
    token = getattr(process, 'cdb_exec_token', None)
    if token:
        try:
            sandbox.kill_exec(token)
        except Exception:
            pass
    try:
        process.kill()
    except Exception:
        pass
    try:
        process.wait(timeout=30)
    except Exception:
        pass


def stream_agent(sandbox: DockerSandbox, cmd: list[str], out_dir: Path,
                 timeout_sec: int, extra_env: dict[str, str],
                 console_path: Path | None = None,
                 max_turns: int | None = None) -> subprocess.Popen:
    """Stream JSONL and enforce the deadline and complete-session turn budget."""
    from harness.claude_session import TurnBudget
    budget = TurnBudget(max_turns) if max_turns is not None else None
    process = sandbox.popen(
        cmd, user='agent', workdir=str(sandbox.workspace), extra_env=extra_env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:
        _terminate_agent(sandbox, process)
        raise RuntimeError('Claude process did not provide stdout/stderr pipes')
    stdout_path = out_dir / 'agent_stdout.jsonl'
    stderr_path = out_dir / 'agent_stderr.log'
    trajectory_path = out_dir / 'trajectory.jsonl'
    console_path = console_path or out_dir / 'console.log'

    with stdout_path.open('w', encoding='utf-8') as stdout_file, \
            stderr_path.open('w', encoding='utf-8') as stderr_file, \
            TrajectoryWriter(trajectory_path, out_dir / 'trajectory.md',
                             out_dir / 'trail.jsonl') as trajectory:
        def drain_stderr() -> None:
            for chunk in process.stderr:
                stderr_file.write(redact_text(chunk))
                stderr_file.flush()

        def drain_stdout() -> None:
            for line in process.stdout:
                stdout_file.write(redact_text(line))
                stdout_file.flush()
                try:
                    event = json.loads(line)
                except (json.JSONDecodeError, TypeError):
                    continue
                event = redact_value(event)
                if isinstance(event, dict):
                    event['observed_at'] = utc_now()
                    trajectory.write(event)
                    message = event.get('message', {})
                    if event.get('type') == 'assistant' and isinstance(message, dict):
                        for item in message.get('content', []):
                            if isinstance(item, dict) and item.get('type') == 'tool_use':
                                emit(console_path, f'[tool] {item.get("name", "?")}')
                    elif event.get('type') == 'result':
                        emit(console_path, f'[agent-result] turns={event.get("num_turns")} '
                                          f'error={event.get("is_error")}')
                    if budget is not None and budget.observe(event):
                        setattr(process, 'cdb_turn_limit', budget.turns)
                        emit(console_path, f'[agent-max-turns] turns={budget.turns}')
                        _terminate_agent(sandbox, process)

        threads = [threading.Thread(target=drain_stdout, daemon=True),
                   threading.Thread(target=drain_stderr, daemon=True)]
        for thread in threads:
            thread.start()
        try:
            waited = process.wait(timeout=timeout_sec)
            if process.returncode is None and isinstance(waited, int):
                process.returncode = waited
        except subprocess.TimeoutExpired:
            _terminate_agent(sandbox, process)
            raise
        except BaseException:
            # Also freeze on controller interruption or a streaming failure;
            # never export while Claude may still be writing the project.
            _terminate_agent(sandbox, process)
            raise
        finally:
            for thread in threads:
                thread.join(timeout=30)
    return process


def _remove_debug_symlinks(workspace: Path) -> None:
    """Drop Claude's `latest` alias before its target log is moved out."""
    if not workspace.is_dir():
        return
    links = []
    for path in workspace.rglob('*'):
        if not path.is_symlink():
            continue
        try:
            target_name = Path(os.readlink(path)).name
        except OSError:
            continue
        if target_name == 'cli-debug.log':
            links.append(path)
    for path in links:
        path.unlink(missing_ok=True)


def _finalize_debug_log(sandbox: DockerSandbox, out_dir: Path) -> None:
    _remove_debug_symlinks(sandbox.workspace)
    source = sandbox.workspace / 'cli-debug.log'
    destination = out_dir / 'cli-debug.log'
    if source.is_file() and not source.is_symlink():
        shutil.move(str(source), str(destination))
    elif source.is_symlink():
        source.unlink()
    destination.touch(exist_ok=True)
    redact_file(destination)


def _deliverables(workspace: Path, family: str = 'cvefactory') -> tuple[dict[str, int], list[str]]:
    from harness.registry import FamilyRegistry

    files: dict[str, int] = {}
    missing: list[str] = []
    required = FamilyRegistry().create(family).required_deliverables
    for name in required:
        path = workspace / name
        if path.is_file() and not path.is_symlink():
            files[name] = path.stat().st_size
        else:
            missing.append(name)
    return files, missing


def _record_agent_result(record: dict[str, Any], out_dir: Path,
                         process: subprocess.Popen) -> None:
    result_event = None
    trajectory = out_dir / 'trajectory.jsonl'
    if trajectory.is_file():
        for line in trajectory.read_text(encoding='utf-8', errors='replace').splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get('type') == 'result':
                result_event = event
    agent = record['agent']
    turn_limit = getattr(process, 'cdb_turn_limit', None)
    agent['returncode'] = process.returncode
    agent['num_turns'] = turn_limit or 0
    if turn_limit is not None:
        agent['status'] = 'max_turns'
        agent['is_error'] = True
        agent['subtype'] = 'error_max_turns'
        agent['error'] = f'complete-session assistant turn budget reached: {turn_limit}'
        return
    if result_event is not None:
        agent['num_turns'] = result_event.get('num_turns', 0)
        agent['is_error'] = bool(result_event.get('is_error', False))
        agent['result'] = str(result_event.get('result', ''))[:8000]
        agent['subtype'] = result_event.get('subtype')
    else:
        agent['is_error'] = True
        agent['error'] = 'Claude produced no stream-json result event'
        agent['subtype'] = None
    if result_event is None or process.returncode != 0 or agent['is_error']:
        if result_event and result_event.get('subtype') == 'error_max_turns':
            agent['status'] = 'max_turns'
        else:
            agent['status'] = 'error'
        if not agent.get('error'):
            agent['error'] = (str(result_event.get('result', ''))[:2000]
                              if result_event else agent['error'])
    else:
        agent['status'] = 'completed'


def _set_phase(record: dict[str, Any], out_dir: Path, phase: str) -> None:
    record['phase'] = phase
    record['pipeline']['phase'] = phase
    record['timestamps'][phase + '_at'] = utc_now()
    write_json(out_dir / 'result.json', record)


def _set_pipeline_exception(record: dict[str, Any], exc: BaseException,
                            phase: str) -> None:
    category = getattr(exc, 'failure_category', 'pipeline')
    if category not in {'pipeline', 'network', 'export'}:
        category = 'pipeline'
    record['pipeline'].update({
        'status': 'failed', 'phase': 'failed', 'failed_phase': phase,
        'failure_category': category,
        'exception': {
            'type': type(exc).__name__, 'message': redact_text(exc),
            'traceback': redact_text(''.join(traceback.format_exception(
                type(exc), exc, exc.__traceback__))),
        },
    })
    record['failure_category'] = category
    record['error'] = redact_text(f'{type(exc).__name__}: {exc}')


def _container_record(sandbox: DockerSandbox, task_id: str) -> dict[str, Any]:
    labels = {
        'cyberdockerbench.runtime': 'all-in-one-dind-v2',
        'cyberdockerbench.task': task_id,
        'cyberdockerbench.role': 'sandbox',
    }
    return {'name': sandbox.container, 'role': 'sandbox', 'labels': labels}


def _archive_previous_attempt(out_dir: Path) -> None:
    """Keep a failed attempt's files, then leave the results directory empty enough to rerun.

    The batch puts a preflight or API failure back on the queue in the same
    directory. The previous workspace has to move aside or the next attempt
    refuses to stage public inputs.
    """
    if not (out_dir / 'workspace').exists():
        return
    index = 1
    while (out_dir / f'failed-attempt-{index:02d}').exists():
        index += 1
    destination = out_dir / f'failed-attempt-{index:02d}'
    destination.mkdir()
    for child in list(out_dir.iterdir()):
        if child.name == destination.name or child.name == '.batch.lock':
            continue
        if child.name.startswith('failed-attempt-'):
            continue
        child.rename(destination / child.name)


def run_one(task_dir: Path | str, results_dir: Path | str,
            model: str = DEFAULT_MODEL, max_turns: int = DEFAULT_MAX_TURNS,
            timeout_sec: int = DEFAULT_TIMEOUT, preflight_only: bool = False) -> dict[str, Any]:
    """Run exactly one task; return a redacted execution record, never a reward."""
    from harness.task_api import TaskSpec

    started = time.monotonic()
    task = TaskSpec.load(Path(task_dir))
    out_dir = Path(results_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    _archive_previous_attempt(out_dir)
    if (out_dir / 'result.json').exists():
        raise FileExistsError(f'result already exists; use a new --results directory: {out_dir}')
    console_path = out_dir / 'console.log'
    console_path.touch(exist_ok=True)
    for artifact in ('trajectory.jsonl', 'trajectory.md', 'cli-debug.log',
                     'agent_stdout.jsonl', 'agent_stderr.log'):
        (out_dir / artifact).touch(exist_ok=True)
    sandbox = DockerSandbox(task_id=task.task_id, runtime_root=out_dir)
    record: dict[str, Any] = {
        'schema_version': 2,
        'task_id': task.task_id, 'family': task.family, 'task_type': task.task_type,
        'status': 'running', 'phase': 'prepare', 'failure_category': None,
        'model': None if preflight_only else model,
        'preflight_only': preflight_only,
        'launch': {'max_turns': max_turns, 'timeout_sec': timeout_sec,
                   'preflight_only': preflight_only},
        'agent': {
            'name': 'claude-code', 'status': 'not_started', 'returncode': None,
            'num_turns': None, 'is_error': None, 'result': '', 'error': None,
            'started_at': None, 'finished_at': None,
        },
        'pipeline': {
            'status': 'running', 'phase': 'prepare', 'failure_category': None,
            'exception': None, 'started_at': utc_now(), 'finished_at': None,
        },
        'attempts': {'sandbox_start': 0, 'preflight': 0, 'agent': 0,
                     'bundle_export': 0, 'stop': 0},
        'containers': [_container_record(sandbox, task.task_id)],
        'container_labels': {sandbox.container: _container_record(sandbox, task.task_id)['labels']},
        'export': {'status': 'pending', 'path': str(out_dir / 'bundle')},
        'grading': {'status': 'not_run', 'reason': 'run_agent only collects agent artifacts'},
        'timestamps': {'started_at': utc_now()},
        'elapsed_sec': 0,
    }
    write_json(out_dir / 'result.json', record)
    emit(console_path, f'prepared runner task={task.task_id} results={out_dir}')
    sandbox_started = False
    start_attempted = False
    debug_finalized = False
    phase = 'prepare'

    try:
        prepare_public_workspace(task, sandbox.workspace)
        if not (PLUGIN_SOURCE / 'skills').is_dir():
            raise PipelineFailure(f'network plugin is missing skills: {PLUGIN_SOURCE}')
        sandbox.agent_plugin(str(PLUGIN_SOURCE), PLUGIN_TARGET)
        write_json(out_dir / 'task.json', {
            'task_id': task.task_id, 'family': task.family, 'task_type': task.task_type,
            'metadata': dict(task.metadata),
            'public_workspace': str(sandbox.workspace),
            'public_inputs': [path.name for path in sandbox.workspace.iterdir()],
            'launch': record['launch'], 'model': record['model'],
        })
        if not preflight_only:
            credentials, credential_info = load_model_environment()
            record['model_credentials'] = credential_info
        else:
            credentials = {}
            record['agent']['status'] = 'skipped'
            record['model_credentials'] = {'source': 'not used by --preflight-only',
                                           'keys': [], 'values': '<redacted>'}
        write_json(out_dir / 'result.json', record)

        phase = 'sandbox_start'
        record['attempts']['sandbox_start'] += 1
        _set_phase(record, out_dir, phase)
        start_attempted = True
        sandbox.start()
        sandbox_started = True
        record['sandbox_image'] = {
            'reference': sandbox.image_reference,
            'image_id': sandbox.image_id,
        }
        write_json(out_dir / 'result.json', record)
        emit(console_path, f'sandbox ready container={sandbox.container}')

        phase = 'preflight'
        record['attempts']['preflight'] += 1
        _set_phase(record, out_dir, phase)
        record['preflight'] = (run_preflight(sandbox, out_dir)
                               if GENERIC_PREFLIGHT else {'success': True, 'steps': []})
        write_json(out_dir / 'result.json', record)

        if preflight_only:
            emit(console_path, 'preflight-only complete; Claude was not launched')
        else:
            if not record['preflight'].get('success'):
                raise NetworkFailure('source/network preflight did not pass; model was not launched')
            phase = 'agent'
            record['attempts']['agent'] += 1
            record['agent']['status'] = 'running'
            record['agent']['started_at'] = utc_now()
            from harness.claude_session import with_claude_retries
            cmd = build_agent_command(model, max_turns)
            record['agent']['command'] = cmd
            _set_phase(record, out_dir, phase)
            emit(console_path, 'starting native Claude Code session')
            try:
                process = stream_agent(sandbox, cmd, out_dir, timeout_sec,
                                       with_claude_retries({
                                           'HOME': '/home/agent', **credentials,
                                       }), console_path=console_path, max_turns=max_turns)
                _record_agent_result(record, out_dir, process)
            except subprocess.TimeoutExpired:
                # A session deadline is a bounded agent attempt, not a broken
                # grader or API. The stopped session's real delivery is graded
                # normally; its timeout remains explicit in agent-result.json.
                record['agent']['status'] = 'timeout'
                record['agent']['error'] = f'agent session exceeded {timeout_sec}s'
                record['failure_category'] = 'agent_semantic'
            except Exception:
                record['agent']['status'] = 'error'
                raise
            finally:
                record['agent']['finished_at'] = utc_now()
                _finalize_debug_log(sandbox, out_dir)
                debug_finalized = True
            files, missing = _deliverables(sandbox.workspace, task.family)
            record['deliverables'] = files
            record['missing_deliverables'] = missing
            if missing and record['agent']['status'] == 'completed':
                record['agent']['status'] = 'incomplete'
                record['agent']['error'] = 'missing required deliverables: ' + ', '.join(missing)
                record['error'] = record['agent']['error']
            if record['agent']['status'] != 'completed':
                # A normal CLI failure/turn limit/incomplete delivery is a
                # semantic outcome, not a Python pipeline exception.
                record['failure_category'] = 'agent_semantic'
            emit(console_path, f'agent session ended status={record["agent"]["status"]}')
    except Exception as exc:
        _set_pipeline_exception(record, exc, phase)
        emit(console_path, f'pipeline exception during {phase}: {type(exc).__name__}: {exc}')
    finally:
        missing = record.get('missing_deliverables', [])
        if not debug_finalized and sandbox_started and phase == 'agent':
            try:
                _finalize_debug_log(sandbox, out_dir)
            except Exception as exc:
                record.setdefault('cleanup_errors', []).append(redact_text(str(exc)))
        # Collection is intentionally unconditional after a started sandbox,
        # including agent timeout/error and preflight failure.  No grader runs.
        if missing:
            # Contract omissions belong to the submitted application, not to the
            # snapshot machinery. A genuine exception freezing present files is
            # still an export failure below.
            record['export'].update({
                'status': 'skipped_missing_deliverables',
                'missing': missing,
                'error': record['agent']['error'],
                'finished_at': utc_now(),
            })
            emit(console_path, 'delivery not exported: ' + record['agent']['error'])
        elif sandbox_started and not preflight_only and record.get('preflight', {}).get('success'):
            phase = 'export'
            record['attempts']['bundle_export'] += 1
            _set_phase(record, out_dir, phase)
            try:
                from harness.registry import FamilyRegistry
                exported = FamilyRegistry().create(task.family).export(
                    sandbox, out_dir / 'bundle')
                record['export'].update({'status': 'completed', 'finished_at': utc_now()})
                if isinstance(exported, (Mapping, list, str, int, float, bool)) or exported is None:
                    record['export']['result'] = exported
                else:
                    record['export']['result'] = str(exported)
                emit(console_path, 'delivery exported')
            except Exception as exc:
                if not getattr(exc, 'failure_category', None):
                    exc.failure_category = 'export'
                record['export'].update({
                    'status': 'error', 'finished_at': utc_now(),
                    'error': redact_text(f'{type(exc).__name__}: {exc}'),
                    'traceback': redact_text(''.join(traceback.format_exception(
                        type(exc), exc, exc.__traceback__))),
                })
                if record['pipeline']['status'] != 'failed':
                    _set_pipeline_exception(record, exc, phase)
                emit(console_path, f'bundle export failed: {type(exc).__name__}: {exc}')
        else:
            record['export']['status'] = 'not_started' if preflight_only else 'not_started_no_application'

        if start_attempted:
            record['attempts']['stop'] += 1
            try:
                sandbox.stop(remove_data=True)
            except Exception as exc:
                record.setdefault('cleanup_errors', []).append({
                    'type': type(exc).__name__, 'message': redact_text(str(exc)),
                    'traceback': redact_text(''.join(traceback.format_exception(
                        type(exc), exc, exc.__traceback__))),
                })
                if record['pipeline']['status'] != 'failed':
                    _set_pipeline_exception(record, exc, 'stop')

        if record['pipeline']['status'] != 'failed':
            record['pipeline']['status'] = 'succeeded'
            record['pipeline']['phase'] = 'complete'
            record['status'] = 'completed'
        else:
            record['status'] = 'error'
        record['phase'] = 'complete'
        record['pipeline']['finished_at'] = utc_now()
        record['timestamps']['finished_at'] = utc_now()
        record['elapsed_sec'] = round(time.monotonic() - started, 3)
        for path in (console_path, out_dir / 'agent_stdout.jsonl',
                     out_dir / 'agent_stderr.log', out_dir / 'trajectory.jsonl',
                     out_dir / 'trajectory.md', out_dir / 'cli-debug.log'):
            try:
                redact_file(path)
            except OSError:
                pass
        write_json(out_dir / 'result.json', record)
        emit(console_path, f'finished status={record["status"]} '
                          f'pipeline={record["pipeline"]["status"]} '
                          f'agent={record["agent"]["status"]}')
    return record


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--task', required=True,
                        help='actual task directory containing metadata.yaml and public input/')
    parser.add_argument('--results', required=True,
                        help='new directory for this one task result and bundle')
    parser.add_argument('--model', default=DEFAULT_MODEL,
                        required=not DEFAULT_MODEL,
                        help='model alias supported by the configured endpoint')
    parser.add_argument('--max-turns', type=int, default=DEFAULT_MAX_TURNS)
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help='Claude session timeout in seconds')
    parser.add_argument('--preflight-only', action='store_true',
                        help='run sandbox network/source checks and export without launching Claude')
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_turns < 1:
        parser.error('--max-turns must be positive')
    if args.timeout < 1:
        parser.error('--timeout must be positive')
    try:
        record = run_one(Path(args.task), Path(args.results), model=args.model,
                         max_turns=args.max_turns, timeout_sec=args.timeout,
                         preflight_only=args.preflight_only)
    except Exception as exc:
        print(redact_text(f'run_agent: {type(exc).__name__}: {exc}'), file=sys.stderr)
        return 1
    return 0 if record['pipeline']['status'] == 'succeeded' else 1


if __name__ == '__main__':
    raise SystemExit(main())
