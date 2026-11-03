"""One isolated, all-in-one DinD sandbox per task or grading run.

The controller starts exactly one privileged outer container. Its private
``dockerd`` and the unprivileged Claude Code process share /workspace and
/var/run/docker.sock. The host Docker socket and private task directories are
never exposed to the agent. Snapshot/export is a controller operation.
"""
from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import time
import uuid

from harness.registry_mirror import apply_mirror, direct_registry_hosts
from dataclasses import dataclass, field
from pathlib import Path

from harness.storage import (
    remove_owner_marker,
    validate_storage_root,
    write_owner_marker,
)

SANDBOX_IMAGE = os.environ.get('CDB_SANDBOX_IMAGE', 'cdb-sandbox:28')
ADDRESS_LEASES = 256
# Same occupancy rule as exploit-from-git's factory IPAM. A subnet stays
# taken while Docker still has a network on it. A lease is also kept for this
# long when its network is not visible yet: the lease is written before
# `docker network create`, and during that window inspect says the container
# is missing.
LEASE_GRACE_SECONDS = 600
SANDBOX_LABEL = 'cyberdockerbench.runtime=all-in-one-dind-v2'
SENSITIVE_KEYS = frozenset({
    'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_API_KEY', 'CDB_MODEL_CREDENTIALS',
})


def run(cmd: list[str], timeout: int = 120, env: dict | None = None,
        input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, env=env, input=input_text)


def run_riding_out_daemon_churn(cmd: list[str], timeout: int = 30,
                                attempts: int = 6, sleep_s: int = 10
                                ) -> subprocess.CompletedProcess:
    """Retry timeout-only failures from a churning daemon.

    After a multi-GB vfs/overlay tree is removed, dockerd keeps answering
    cheap queries (`docker info`) while name lookups (`docker inspect`)
    stall past 30s until deferred deletion drains (59072 r6 died here one
    minute after the previous grade's cleanup). Definitive answers — found,
    not-found, real errors — return immediately; only timeouts are retried.
    """
    for attempt in range(attempts):
        try:
            return run(cmd, timeout=timeout)
        except subprocess.TimeoutExpired:
            if attempt == attempts - 1:
                raise
            time.sleep(sleep_s)


def safe_name(value: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_.-]+', '-', value).strip('-.')[:64]


def tail(value: str | None, limit: int = 6000) -> str:
    return (value or '')[-limit:]


# Live kkRepo entry on wuyida-01. The dev machine's DHCP address changes
# across reboots; keep legacy addresses in DIRECT_MIRROR_HOSTS so stale
# NO_PROXY entries keep working, and put the live one in KKREPO_HOST.
KKREPO_HOST = '100.102.49.114'
DIRECT_MIRROR_HOSTS = ('100.102.49.113', KKREPO_HOST)


def _with_direct_hosts(no_proxy: str) -> str:
    """kkRepo/package-mirror traffic must never leave through the egress
    proxy: the cluster squid cannot reach these hosts (502), only direct
    or the site jump proxy can. Guarantee them in NO_PROXY regardless of
    the caller's environment."""
    parts = [part for part in (no_proxy or '').split(',') if part]
    for host in (*DIRECT_MIRROR_HOSTS, *direct_registry_hosts()):
        if host not in parts:
            parts.append(host)
    return ','.join(parts)


class SandboxError(RuntimeError):
    """Sandbox startup, daemon or controller failure, not an agent failure."""


def address_ranges(index: int) -> tuple[str, str, str]:
    """One exclusive outer /24 and one exclusive inner /20 for a live sandbox.

    The outer range is attached only to that sandbox's bridge on the worker.
    The inner range is the private dockerd pool and never leaves that sandbox.
    Indexes 0..255 do not overlap, so concurrent tasks do not share a subnet.
    """
    if not isinstance(index, int) or not 0 <= index < ADDRESS_LEASES:
        raise ValueError(f'sandbox address index out of range: {index}')
    outer = f'10.200.{index}.0/24'
    gateway = f'10.200.{index}.1'
    second = 160 + index // 16
    third = (index % 16) * 16
    inner = f'10.{second}.{third}.0/20'
    return outer, gateway, inner


def _lease_directory(data_root: Path) -> Path:
    directory = Path(data_root) / 'address-leases'
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _container_state(name: str) -> bool | None:
    from harness.storage import _container_exists
    return _container_exists(name)


def _as_networks(values) -> list[ipaddress.IPv4Network]:
    found: list[ipaddress.IPv4Network] = []
    for item in values or []:
        if isinstance(item, ipaddress.IPv4Network):
            found.append(item)
            continue
        try:
            net = ipaddress.ip_network(str(item).strip(), strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            found.append(net)
    return found


def docker_occupied_subnets() -> list[ipaddress.IPv4Network]:
    """Every IPv4 subnet Docker has already handed out on this daemon."""
    try:
        listed = run(['docker', 'network', 'ls', '-q'], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if listed.returncode != 0 or not (listed.stdout or '').strip():
        return []
    ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    if not ids:
        return []
    try:
        inspected = run(
            ['docker', 'network', 'inspect', *ids, '--format',
             '{{range .IPAM.Config}}{{.Subnet}} {{end}}'],
            timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if inspected.returncode != 0:
        return []
    return _as_networks((inspected.stdout or '').split())


def _subnet_taken(subnet: str, occupied: list[ipaddress.IPv4Network]) -> bool:
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False
    return any(net.overlaps(other) for other in occupied)


def _lease_holds(index: int, payload: dict, occupied: list[ipaddress.IPv4Network],
                 exists, now: float) -> bool:
    """A lease stays until Docker has dropped its subnet and the grace has passed."""
    outer, _gateway, _inner = address_ranges(index)
    if _subnet_taken(outer, occupied):
        return True
    owner = payload.get('container')
    present = exists(owner) if isinstance(owner, str) and owner else False
    if present is not False:
        return True
    try:
        age = now - float(payload.get('created_at'))
    except (TypeError, ValueError):
        age = LEASE_GRACE_SECONDS
    return age < LEASE_GRACE_SECONDS


def acquire_address_lease(data_root: Path, container: str,
                          container_exists=None, occupied_subnets=None) -> int:
    """Reserve the lowest index whose /24 Docker is not already using."""
    exists = container_exists or _container_state
    occupied = (_as_networks(occupied_subnets) if occupied_subnets is not None
                else docker_occupied_subnets())
    now = time.time()
    directory = _lease_directory(data_root)
    with (directory / '.lock').open('a+') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            used: set[int] = set()
            for path in directory.glob('*.lease'):
                try:
                    index = int(path.stem)
                    payload = json.loads(path.read_text(encoding='utf-8'))
                except (OSError, ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(payload, dict) or not 0 <= index < ADDRESS_LEASES:
                    continue
                if _lease_holds(index, payload, occupied, exists, now):
                    used.add(index)
                    continue
                path.unlink(missing_ok=True)
            for index in range(ADDRESS_LEASES):
                if index in used:
                    continue
                outer, _gateway, _inner = address_ranges(index)
                if _subnet_taken(outer, occupied):
                    continue
                lease = directory / f'{index}.lease'
                lease.write_text(json.dumps({
                    'index': index, 'container': container, 'created_at': time.time(),
                }), encoding='utf-8')
                return index
            raise SandboxError(
                f'all {ADDRESS_LEASES} sandbox network ranges are in use')
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def sweep_finished_sandboxes(data_root: Path | None = None) -> dict[str, list]:
    """Remove this bench's stopped sandboxes and the bridges they still hold.

    Running sandboxes are left alone. The shared sandbox image is not deleted:
    inner images live in the per-sandbox data directory and disappear with it.
    """
    report: dict[str, list] = {'containers': [], 'networks': [], 'leases': [], 'errors': []}
    for status in ('exited', 'dead', 'created'):
        listed = run(['docker', 'ps', '-aq', '--filter', f'label={SANDBOX_LABEL}',
                      '--filter', f'status={status}'], timeout=30)
        if listed.returncode:
            report['errors'].append(tail(listed.stderr, 500))
            continue
        for container_id in listed.stdout.split():
            removed = run(['docker', 'rm', '-f', container_id], timeout=60)
            if removed.returncode:
                report['errors'].append(tail(removed.stderr, 500))
            else:
                report['containers'].append(container_id)
    listed = run(['docker', 'network', 'ls', '-q', '--filter', f'label={SANDBOX_LABEL}'],
                 timeout=30)
    if listed.returncode:
        report['errors'].append(tail(listed.stderr, 500))
    else:
        for network_id in listed.stdout.split():
            inspected = run(['docker', 'network', 'inspect', network_id], timeout=30)
            try:
                payload = json.loads(inspected.stdout) if inspected.returncode == 0 else []
            except json.JSONDecodeError:
                payload = []
            containers = (payload[0].get('Containers') or {}) if payload else {'unknown': True}
            if containers:
                continue
            removed = run(['docker', 'network', 'rm', network_id], timeout=30)
            if removed.returncode:
                report['errors'].append(tail(removed.stderr, 500))
            else:
                report['networks'].append(network_id)
    if data_root is not None:
        directory = Path(data_root) / 'address-leases'
        if directory.is_dir():
            occupied = docker_occupied_subnets()
            now = time.time()
            for path in directory.glob('*.lease'):
                try:
                    index = int(path.stem)
                    payload = json.loads(path.read_text(encoding='utf-8'))
                except (OSError, ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(payload, dict) or not 0 <= index < ADDRESS_LEASES:
                    continue
                if _lease_holds(index, payload, occupied, _container_state, now):
                    continue
                owner = payload.get('container')
                if isinstance(owner, str):
                    release_address_lease(data_root, owner)
                    report['leases'].append(owner)
    return report


def release_address_lease(data_root: Path, container: str) -> None:
    directory = Path(data_root) / 'address-leases'
    if not directory.is_dir():
        return
    lock_path = directory / '.lock'
    with lock_path.open('a+') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            for path in directory.glob('*.lease'):
                try:
                    payload = json.loads(path.read_text(encoding='utf-8'))
                except (OSError, ValueError, json.JSONDecodeError):
                    continue
                if payload.get('container') == container:
                    path.unlink(missing_ok=True)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


@dataclass
class DockerSandbox:
    task_id: str
    runtime_root: Path
    name: str = ''
    container: str = ''
    # Optional stable name for the local docker-data dir. Re-grades of the
    # same task share the dir, so base images and pulled layers survive and
    # only --no-cache compile steps rerun. Named dirs are never rmtree'd by
    # stop(); sweep them explicitly via harness.storage cleanup.
    docker_data_name: str = ''
    workspace: Path = field(init=False)
    env: dict[str, str] = field(init=False)
    network: str = field(init=False)
    agent_plugin_mounts: list[tuple[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.runtime_root = Path(self.runtime_root).resolve()
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(str(self.runtime_root).encode()).hexdigest()[:12]
        self.name = self.name or f'cdb-{safe_name(self.task_id)[:48]}-{digest}'
        # Callers may provide a stable, attempt-specific name. Only the
        # generated task-based fallback needs a path-derived collision guard.
        if not self.container:
            self.container = self.name
        self.compose_project = f'cdb-{safe_name(self.task_id)[:36]}-{digest[:8]}'
        self.workspace = self.runtime_root / 'workspace'
        self.network = self.name + '-net'
        # Docker's local metadata database needs mmap; shared task storage may
        # reject it. Each attempt owns exactly one local directory or volume.
        self.local_docker_data = os.environ.get('CDB_LOCAL_DOCKER_DATA', '') == '1'
        self.docker_data_root = Path(os.environ.get('CDB_DOCKER_DATA_ROOT', '/var/tmp'))
        if self.local_docker_data:
            if not self.docker_data_root.is_absolute():
                raise ValueError('CDB_DOCKER_DATA_ROOT must be an absolute local directory')
            self.docker_data_root = self.docker_data_root.resolve()
        if self.docker_data_name:
            self.docker_data_name = safe_name(self.docker_data_name)
            if not self.docker_data_name:
                raise ValueError('docker_data_name sanitizes to empty')
            if not self.docker_data_name.startswith('cdb-'):
                self.docker_data_name = 'cdb-' + self.docker_data_name
        self.docker_data = self.docker_data_root / (
            (self.docker_data_name or self.name) + '-docker-data')
        self.env = dict(os.environ)
        self.env.pop('DOCKER_HOST', None)
        self.env.pop('DOCKER_CONTEXT', None)
        self.env['DOCKER_BUILDKIT'] = '1'
        self.env['COMPOSE_DOCKER_CLI_BUILD'] = '1'
        self.image_reference = SANDBOX_IMAGE
        self.image_id = ''
        self.address_index: int | None = None

    def _log(self, operation: str, args: list[str], cp: subprocess.CompletedProcess) -> None:
        record = {
            'operation': operation,
            'args': [redact_argument(value) for value in args],
            'returncode': cp.returncode,
            'stdout_tail': tail(cp.stdout),
            'stderr_tail': tail(cp.stderr),
        }
        # The batch runner may archive agent-runtime/ into detail/ while a
        # peer task is still cleaning up its sandbox. Logging must never
        # crash that cleanup (nor the whole batch).
        try:
            self.runtime_root.mkdir(parents=True, exist_ok=True)
            with (self.runtime_root / 'docker-commands.log').open('a') as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + '\n')
        except OSError:
            pass

    def docker(self, args: list[str], timeout: int = 120,
               input_text: str | None = None) -> subprocess.CompletedProcess:
        """Run a Docker CLI against this task's internal daemon only."""
        cp = self.exec(['docker', *args], timeout=timeout,
                       input_text=input_text, log_operation='internal-docker')
        return cp

    def _exec_command(self, args: list[str], token: str, *, user: str | None = None,
                      workdir: str | None = None,
                      extra_env: dict[str, str] | None = None) -> list[str]:
        command = ['docker', 'exec', '-i']
        if user:
            command += ['--user', user]
        if workdir:
            command += ['--workdir', workdir]
        forwarded = {'COMPOSE_PROJECT_NAME': self.compose_project}
        if user == 'agent':
            forwarded['HOME'] = '/home/agent'
        forwarded.update(extra_env or {})
        for key, value in forwarded.items():
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
                raise ValueError(f'invalid environment name: {key!r}')
            command += ['-e', f'{key}={value}']
        command += [self.container, 'cdb-exec', token, *args]
        return command

    def exec(self, args: list[str], timeout: int = 120, *, user: str | None = None,
             workdir: str | None = None, input_text: str | None = None,
             log_operation: str = 'exec',
             extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        token = uuid.uuid4().hex
        command = self._exec_command(args, token, user=user, workdir=workdir,
                                     extra_env=extra_env)
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=self.env,
                                   start_new_session=True)
        timed_out = False
        try:
            stdout, stderr = process.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self.kill_exec(token)
            try:
                stdout, stderr = process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=10)
        cp = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
        self._log(log_operation, args, cp)
        if timed_out:
            raise subprocess.TimeoutExpired(args, timeout,
                                            output=stdout, stderr=stderr)
        return cp

    def kill_exec(self, token: str) -> None:
        if not re.fullmatch(r'[0-9a-f]{32}', token):
            raise ValueError('invalid controller exec token')
        run(['docker', 'exec', '--user', 'root', self.container,
             'cdb-kill-exec', token], timeout=30, env=self.env)

    def popen(self, args: list[str], *, user: str | None = None,
              workdir: str | None = None, extra_env: dict[str, str] | None = None,
              stdout=None, stderr=None):
        """Stream one controller-managed process inside the existing sandbox."""
        token = uuid.uuid4().hex
        command = self._exec_command(args, token, user=user, workdir=workdir,
                                     extra_env=extra_env)
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr,
                                   text=True, env=self.env, start_new_session=True)
        process.cdb_exec_token = token
        return process

    def stop_exec(self, process: subprocess.Popen) -> None:
        """Stop only one streaming exec, never the sandbox's dockerd/PID 1."""
        token = getattr(process, 'cdb_exec_token', None)
        if token:
            try:
                self.kill_exec(token)
            except (OSError, subprocess.SubprocessError):
                pass
        if process.poll() is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired as exc:
            raise SandboxError('scoped exec did not stop within 30 seconds') from exc

    def agent_plugin(self, source: str, target: str) -> None:
        source_path, target_path = Path(source).resolve(), Path(target)
        if (not source_path.is_dir() or not target_path.is_absolute()
                or target_path.name in ('', '.', '..')):
            raise ValueError(f'invalid read-only plugin mount: {source} -> {target}')
        self.agent_plugin_mounts.append((str(source_path), str(target_path)))

    def _await_docker_disk_headroom(self) -> None:
        """VFS-backed nested builds transiently multiply image size several
        times over. Wait for concurrent grades to drain when the host docker
        filesystem runs low, and fail as a pipeline (not agent) error if the
        headroom never arrives instead of letting builds die mid-extract."""
        roots: list[str] = []
        try:
            cp = subprocess.run(['docker', 'info', '-f', '{{.DockerRootDir}}'],
                                capture_output=True, text=True, timeout=30)
            if cp.returncode == 0 and cp.stdout.strip():
                roots.append(cp.stdout.strip())
        except Exception:
            pass
        if self.local_docker_data:
            roots.append(str(self.docker_data_root))
        if not roots:
            return
        min_free = float(os.environ.get('CDB_GRADE_MIN_FREE_GB', '60'))
        wait_s = float(os.environ.get('CDB_GRADE_DISK_WAIT_S', '2700'))
        deadline = time.monotonic() + wait_s
        announced = False
        while True:
            lowest = min(shutil.disk_usage(root).free for root in roots) / (1024 ** 3)
            if lowest >= min_free:
                return
            if not announced:
                self._log('disk-headroom-wait', roots,
                          subprocess.CompletedProcess(args=[], returncode=0,
                                                      stdout=f'{lowest:.1f}G free < {min_free:.0f}G required',
                                                      stderr=''))
                announced = True
            if time.monotonic() >= deadline:
                raise SandboxError(
                    f'docker disk headroom too low: {lowest:.1f}G free < {min_free:.0f}G '
                    f'after waiting {wait_s:.0f}s (roots: {", ".join(roots)})')
            time.sleep(60)

    def start(self) -> None:
        self._await_docker_disk_headroom()
        self._start_args = [
            '--storage-driver=' + os.environ.get('CDB_STORAGE_DRIVER', 'vfs'),
            '--dns=' + os.environ.get('CDB_DIND_DNS', '169.254.20.10'),
        ]
        if self._start_args[0] not in ('--storage-driver=overlay2', '--storage-driver=vfs'):
            raise ValueError('CDB_STORAGE_DRIVER must be overlay2 or vfs')
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.workspace.chmod(0o777)
        if self.local_docker_data:
            validate_storage_root(
                self.docker_data_root,
                float(os.environ.get('CDB_MIN_FREE_GIB', '0')),
            )
            self.docker_data.mkdir(parents=True, exist_ok=True)
        # Same-path bind is essential: relative Compose bind paths must resolve
        # to identical content in the outer container and its private daemon.
        # The lease is controller state on the worker. It is not written into
        # the workspace or the agent prompt. dockerd still needs its own pool
        # in daemon.json, so `docker info` inside this sandbox can show it.
        self.address_index = acquire_address_lease(self.docker_data_root, self.container)
        outer_subnet, outer_gateway, inner_pool = address_ranges(self.address_index)
        config = {
            'default-address-pools': [
                {'base': inner_pool, 'size': 24},
            ],
        }
        apply_mirror(config)
        daemon_file = self.runtime_root / 'docker-daemon.json'
        (self.runtime_root / 'docker-proxy.conf').touch()
        proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy') or os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
        if proxy:
            no_proxy = _with_direct_hosts(
                os.environ.get('NO_PROXY', os.environ.get('no_proxy', 'localhost,127.0.0.1,::1')))
            # These settings affect only the private daemon's registry requests,
            # not application containers. Mirror and internal traffic stay direct.
            (self.runtime_root / 'docker-proxy.conf').write_text(
                f'Environment=HTTP_PROXY={proxy}\n'
                f'Environment=HTTPS_PROXY={proxy}\n'
                f'Environment=NO_PROXY={no_proxy}\n')
        daemon_file.write_text(json.dumps(config, indent=2) + '\n')
        # Idempotent setup is restricted to resources owned by this attempt.
        image = run_riding_out_daemon_churn(
            ['docker', 'image', 'inspect', '--format', '{{.Id}}', SANDBOX_IMAGE], timeout=30)
        if image.returncode or not image.stdout.strip():
            release_address_lease(self.docker_data_root, self.container)
            raise SandboxError(f'sandbox image is unavailable: {SANDBOX_IMAGE}: {tail(image.stderr)}')
        self.image_id = image.stdout.strip()
        existing = run_riding_out_daemon_churn(
            ['docker', 'inspect', '-f', '{{.Id}}', self.container], timeout=30)
        if existing.returncode == 0:
            release_address_lease(self.docker_data_root, self.container)
            raise SandboxError(f'sandbox already exists: {self.container}; use a new attempt')
        if not run_riding_out_daemon_churn(
                ['docker', 'network', 'inspect', self.network], timeout=30).returncode:
            release_address_lease(self.docker_data_root, self.container)
            raise SandboxError(f'sandbox network already exists: {self.network}')
        if self.local_docker_data:
            write_owner_marker(
                self.docker_data,
                task_id=self.task_id,
                sandbox_name=self.name,
                container=self.container,
                runtime_root=self.runtime_root,
            )
        cp = run(['docker', 'network', 'create', '--driver', 'bridge',
                  '--subnet', outer_subnet, '--gateway', outer_gateway,
                  '--label', SANDBOX_LABEL,
                  '--label', f'cyberdockerbench.sandbox={self.container}',
                  self.network], timeout=45)
        if cp.returncode:
            self.stop(remove_data=True)
            raise SandboxError(f'cannot create sandbox network: {tail(cp.stderr)}')
        try:
            command = [
                'docker', 'run', '-d', '--name', self.container,
                '--privileged', '--cgroupns=private', '--network', self.network,
                '--label', SANDBOX_LABEL,
                '--label', f'cyberdockerbench.task={self.task_id}',
                '--label', 'cyberdockerbench.role=sandbox',
                '--stop-timeout', '120',
                '-v', f'{self.docker_data if self.local_docker_data else self.name + "-docker"}:/var/lib/docker',
                '-v', f'{self.workspace}:{self.workspace}',
                '-v', f'{daemon_file}:/etc/docker/daemon.json:ro',
                '-v', f'{self.runtime_root / "docker-proxy.conf"}:/etc/docker/daemon-proxy.conf:ro',
                '-e', 'DOCKER_TLS_CERTDIR=',
                '-e', 'DOCKER_HOST=unix:///var/run/docker.sock',
            ]
            # A local named home is outside the deliverable. Model credentials
            # are only injected into the later Claude exec, never dockerd/apps.
            command += ['-v', f'{self.name}-home:/home/agent']
            for source, target in self.agent_plugin_mounts:
                command += ['-v', f'{source}:{target}:ro']
            for key in ('CDB_DIND_MTU', 'HTTP_PROXY', 'HTTPS_PROXY',
                        'http_proxy', 'https_proxy', 'NO_PROXY', 'no_proxy'):
                value = os.environ.get(key)
                if value:
                    if key in ('NO_PROXY', 'no_proxy'):
                        value = _with_direct_hosts(value)
                    command += ['-e', f'{key}={value}']
            command += [SANDBOX_IMAGE, 'dockerd', *self._start_args]
            cp = run(command, timeout=90)
            if cp.returncode:
                raise SandboxError(f'cannot start all-in-one sandbox: {tail(cp.stderr)}')
            # Upgrade helpers in an already-versioned image; new images carry
            # the identical files. Entrypoint initialization already creates
            # the root-owned sticky token directory before any agent exec.
            for helper in ('cdb-exec', 'cdb-kill-exec', 'docker-kkrepo'):
                # The image may not contain the current helper yet; bootstrap
                # over host docker cp before the first managed cdb-exec call.
                helper_path = Path(__file__).parent / 'agent_image' / helper
                cp = run(['docker', 'cp', str(helper_path),
                          f'{self.container}:/usr/local/bin/{helper}'],
                         timeout=60, env=self.env)
                if cp.returncode:
                    raise SandboxError('cannot install sandbox exec helper: ' + tail(cp.stderr))
            helper_cp = run(['docker', 'exec', '--user', 'root', self.container,
                             'chmod', '0755', '/usr/local/bin/cdb-exec',
                             '/usr/local/bin/cdb-kill-exec'], timeout=30)
            if helper_cp.returncode:
                raise SandboxError('cannot install sandbox exec helpers: ' + tail(helper_cp.stderr))
            helper_cp = run(['docker', 'exec', '--user', 'root', self.container,
                             'cp', '/usr/local/bin/docker', '/usr/local/bin/docker-real'], timeout=30)
            if helper_cp.returncode:
                raise SandboxError('cannot preserve real Docker CLI: ' + tail(helper_cp.stderr))
            helper_cp = run(['docker', 'exec', '--user', 'root', self.container,
                             'cp', '/usr/local/bin/docker-kkrepo', '/usr/local/bin/docker'],
                             timeout=30)
            if helper_cp.returncode:
                raise SandboxError('cannot install kkRepo Docker adapter: ' + tail(helper_cp.stderr))
            # Baked apt sources may point at any stale wuyida-01 kkRepo IP
            # (the dev machine's DHCP address changes across reboots). Rewrite
            # whatever 100.102.49.x:19091 they carry to the live entry so
            # agent apt installs do not depend on image rebuild timing.
            run(['docker', 'exec', '--user', 'root', self.container,
                 'bash', '-c',
                 "grep -rlsE '100\\.102\\.49\\.[0-9]+:19091' /etc/apt/ 2>/dev/null"
                 f" | xargs -r sed -i -E 's|100\\.102\\.49\\.[0-9]+:19091|{KKREPO_HOST}:19091|g'"],
                timeout=30)
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                cp = self.docker(['info', '--format', '{{.ServerVersion}}'], timeout=15)
                if cp.returncode == 0:
                    probe = self.exec(['bash', '-c',
                        'id agent >/dev/null && docker compose version && docker buildx version'],
                        timeout=30)
                    if probe.returncode == 0:
                        self.runtime_contract = self.inspect_contract()
                        return
                time.sleep(2)
            logs = run(['docker', 'logs', self.container], timeout=30)
            raise SandboxError('private dockerd not ready: ' + tail(logs.stderr + logs.stdout))
        except Exception as start_error:
            try:
                self.stop(remove_data=True)
            except Exception as cleanup_error:
                raise SandboxError(f'{start_error}; sandbox cleanup also failed: '
                                   f'{cleanup_error}') from start_error
            raise

    def inspect_contract(self) -> dict:
        """Verify the real outer mounts and private daemon, not just CLI health."""
        inspected = self._host(['inspect', self.container], timeout=30)
        if inspected.returncode:
            raise SandboxError('cannot inspect sandbox: ' + tail(inspected.stderr))
        try:
            outer = json.loads(inspected.stdout)[0]
        except (json.JSONDecodeError, IndexError, TypeError) as exc:
            raise SandboxError('invalid sandbox inspection JSON') from exc
        host_config = outer.get('HostConfig', {})
        if (not host_config.get('Privileged')
                or host_config.get('NetworkMode') != self.network):
            raise SandboxError('sandbox privilege/network contract violated')
        if any(Path(source).resolve() in (Path('/var/run/docker.sock'), Path('/run/docker.sock'))
               or any(part.lower() in ('gold', 'private') for part in Path(target).parts)
               for source, target in self.agent_plugin_mounts):
            raise SandboxError('forbidden plugin source or private mount target')
        allowed = {
            str(self.workspace): (str(self.workspace), True),
            '/var/lib/docker': (str(self.docker_data) if self.local_docker_data
                                else self.name + '-docker', True),
            '/home/agent': (self.name + '-home', True),
            '/etc/docker/daemon.json': (str(self.runtime_root / 'docker-daemon.json'), False),
            '/etc/docker/daemon-proxy.conf': (str(self.runtime_root / 'docker-proxy.conf'), False),
            **{target: (source, False) for source, target in self.agent_plugin_mounts},
        }
        mounts = outer.get('Mounts', [])
        actual = {mount.get('Destination'): mount for mount in mounts}
        if set(actual) != set(allowed):
            raise SandboxError('unexpected or missing sandbox mounts: '
                               + str(sorted(set(actual) ^ set(allowed))))
        for destination, (source, writable) in allowed.items():
            mount = actual[destination]
            if mount.get('RW') is not writable:
                raise SandboxError(f'unexpected mount access: {destination}')
            identity = mount.get('Source') if mount.get('Type') == 'bind' else mount.get('Name')
            if identity != source or mount.get('Type') not in ('bind', 'volume'):
                raise SandboxError(f'unexpected mount source: {destination}')
            if destination in ('/var/run/docker.sock', '/run/docker.sock'):
                raise SandboxError('host Docker socket must never be mounted')
        daemon = self.docker(['info', '--format', '{{json .}}'], timeout=30)
        if daemon.returncode:
            raise SandboxError('cannot inspect private Docker daemon: ' + tail(daemon.stderr))
        try:
            inner = json.loads(daemon.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxError('invalid private Docker daemon inspection JSON') from exc
        expected_driver = os.environ.get('CDB_STORAGE_DRIVER', 'vfs')
        expected_dns = os.environ.get('CDB_DIND_DNS', '169.254.20.10')
        daemon_argv = (outer.get('Path'), *(outer.get('Args') or []))
        expected = {'DockerRootDir': '/var/lib/docker', 'Driver': expected_driver,
                    'Name': outer.get('Config', {}).get('Hostname'),
                    'DNS': '--dns=' + expected_dns}
        actual = {'DockerRootDir': inner.get('DockerRootDir'), 'Driver': inner.get('Driver'),
                  'Name': inner.get('Name'), 'DNS': daemon_argv}
        mismatches = {key: {'expected': value, 'actual': actual[key]}
                      for key, value in expected.items()
                      if (actual[key] != value if key != 'DNS'
                          else value not in actual[key])}
        if mismatches:
            raise SandboxError('private Docker root/driver/name/DNS contract violated: '
                               + json.dumps(mismatches, ensure_ascii=False))
        if inner.get('Driver') == 'overlay2' and not self.local_docker_data:
            raise SandboxError('overlay2 requires an explicitly configured local data root')
        agent = self.exec(['bash', '-c',
            'test "$(id -u)" = 1000 && id -nG | tr " " "\\n" | grep -qx docker && '
            'test -S /var/run/docker.sock && test -w /var/run/docker.sock && '
            'test -z "${ANTHROPIC_AUTH_TOKEN:-}${ANTHROPIC_API_KEY:-}"'],
            user='agent', timeout=30)
        if agent.returncode:
            raise SandboxError('agent identity/private socket/model isolation violated')
        for _, target in self.agent_plugin_mounts:
            plugin = self.exec(['bash', '-c',
                f'test -r {target}/skills/kkrepo-network/SKILL.md && '
                f'! touch {target}/.cdb-write-probe 2>/dev/null'],
                user='agent', timeout=30)
            if plugin.returncode:
                raise SandboxError(f'network plugin must be readable and read-only: {target}')
        mtu = os.environ.get('CDB_DIND_MTU')
        actual_mtu = None
        if mtu:
            bridge = self.docker(['network', 'inspect', 'bridge',
                                  '--format', '{{json .Options}}'], timeout=30)
            if bridge.returncode:
                raise SandboxError('cannot inspect private Docker bridge: ' + tail(bridge.stderr))
            try:
                options = json.loads(bridge.stdout)
            except json.JSONDecodeError as exc:
                raise SandboxError('invalid private Docker bridge inspection JSON') from exc
            actual_mtu = options.get('com.docker.network.driver.mtu')
            if str(actual_mtu) != str(mtu):
                raise SandboxError(f'private Docker MTU mismatch: expected {mtu}, got {actual_mtu}')
        return {'image_id': outer.get('Image'), 'container_id': outer.get('Id'),
                'docker_root': inner.get('DockerRootDir'), 'storage_driver': inner.get('Driver'),
                'dns': expected_dns, 'mtu': actual_mtu,
                'agent_uid': 1000, 'host_docker_socket_mounted': False,
                'read_only_plugins': [target for _, target in self.agent_plugin_mounts]}

    def _host(self, args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
        cp = run(['docker', *args], timeout=timeout, env=self.env)
        self._log('host-docker', args, cp)
        return cp

    def copy_in(self, source: Path, container_path: str) -> None:
        source = Path(source).resolve()
        target = Path(container_path)
        if source.is_dir():
            temporary = source.parent / ('.cdb-input-' + uuid.uuid4().hex + '.tar')
            with tarfile.open(temporary, 'w') as archive:
                for child in sorted(source.iterdir(), key=lambda p: p.name):
                    archive.add(child, arcname=child.name, recursive=True)
            destination = '/var/tmp/cdb-input-' + uuid.uuid4().hex + '.tar'
            self.exec(['mkdir', '-p', '--', str(target)], timeout=120)
            self._copy_archive_in(temporary, destination)
            try:
                cp = self.exec(['python3', '-c', _EXTRACT_SCRIPT, destination,
                                str(target), 'directory'], timeout=1800)
                if cp.returncode:
                    raise SandboxError(f'extract directory into sandbox failed: {tail(cp.stderr)}')
            finally:
                temporary.unlink(missing_ok=True)
                self.exec(['rm', '-f', '--', destination], timeout=60)
        else:
            # docker cp does not create missing parent directories for a file.
            cp = self.exec(['mkdir', '-p', '--', str(target.parent)], timeout=120)
            if cp.returncode:
                raise SandboxError(f'create destination directory failed: {tail(cp.stderr)}')
            # A plain source file is not a Docker-produced tar archive. Docker
            # cp preserves its type, mode and ownership at the exact target;
            # only directory inputs need the checked archive extractor above.
            cp = run(['docker', 'cp', str(source),
                      f'{self.container}:{container_path}'], timeout=1800, env=self.env)
            self._log('copy-file-in', [str(source), container_path], cp)
            if cp.returncode:
                raise SandboxError(f'copy file into sandbox failed: {tail(cp.stderr)}')
        # A workspace copy must be mutable by agent UID 1000. Do not apply
        # workspace ownership to snapshot data under /var/tmp.
        if str(target) == str(self.workspace) or self.workspace in target.parents:
            cp = run(['docker', 'exec', '--user', 'root', self.container,
                      'chown', '-R', '1000:1000', container_path],
                     timeout=1800, env=self.env)
            if cp.returncode:
                raise SandboxError(f'cannot make workspace writable: {tail(cp.stderr)}')

    def _copy_archive_in(self, source: Path, destination: str) -> None:
        cp = run(['docker', 'cp', str(source), f'{self.container}:{destination}'],
                 timeout=1800, env=self.env)
        if cp.returncode:
            raise SandboxError(f'copy into sandbox failed: {tail(cp.stderr)}')

    def copy_out(self, container_path: str, destination: Path) -> None:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Inner container IDs belong only to this sandbox's private daemon.
        # Absolute paths, in contrast, name files in the outer sandbox itself.
        if container_path.startswith('/'):
            cp = run(['docker', 'cp', f'{self.container}:{container_path}',
                      str(destination)], timeout=1800, env=self.env)
            if cp.returncode:
                raise SandboxError(f'copy out of sandbox failed: {tail(cp.stderr)}')
            return
        if not re.fullmatch(r'[0-9a-f]{12,64}:/.*', container_path):
            raise SandboxError(f'invalid sandbox copy source: {container_path}')
        remote = '/var/tmp/cdb-copy-' + uuid.uuid4().hex + '.tar'
        directory = container_path.endswith('/.')
        # Without an explicit '-', docker cp treats a destination ending in
        # .tar as a directory, not as an archive. That used to add an unwanted
        # cdb-copy-*.tar directory below every exported mount.
        cp = self.exec(['sh', '-c', 'exec docker cp "$1" - > "$2"', 'cdb-copy',
                        container_path, remote], timeout=1800)
        if cp.returncode:
            raise SandboxError(f'copy out of sandbox failed: {tail(cp.stderr)}')
        remote_destination = '/var/tmp/cdb-copy-destination-' + uuid.uuid4().hex
        try:
            # The host destination may be outside the workspace bind and thus
            # invisible to the outer sandbox. Extract the archive where Docker
            # wrote it, then transport only the checked result to the host.
            cp = self.exec(['python3', '-c', _EXTRACT_SCRIPT, remote,
                            remote_destination, 'directory' if directory else 'file'],
                           timeout=1800)
            if cp.returncode:
                raise SandboxError(f'extract copied mount failed: {tail(cp.stderr)}')
            if directory:
                destination.mkdir(parents=True, exist_ok=True)
            cp = run(['docker', 'cp', f'{self.container}:{remote_destination}' +
                      ('/.' if directory else ''), str(destination)], timeout=1800, env=self.env)
            if cp.returncode:
                raise SandboxError(f'copy out of sandbox failed: {tail(cp.stderr)}')
        finally:
            self.exec(['rm', '-rf', '--', remote, remote_destination], timeout=60)

    def stop(self, remove_data: bool = False) -> None:
        errors = []
        for args, timeout in [(['rm', '-f', self.container], 150),
                              (['network', 'rm', self.network], 45)]:
            cp = self._host(args, timeout=timeout)
            if cp.returncode and not re.search(r'no such|not found', cp.stderr, re.I):
                errors.append(tail(cp.stderr, 1000))
        if remove_data:
            for volume in (self.name + '-docker', self.name + '-home'):
                cp = self._host(['volume', 'rm', volume], timeout=120)
                if cp.returncode and not re.search(r'no such|not found', cp.stderr, re.I):
                    errors.append(tail(cp.stderr, 1000))
        if remove_data and self.local_docker_data:
            # Never resolve or recursively remove an unexpected/symlinked path.
            if self.docker_data_name:
                # Named cache: shared across re-grades, so keep the data and
                # only drop our ownership marker.
                try:
                    remove_owner_marker(self.docker_data)
                except OSError as exc:
                    errors.append(f'cannot remove Docker-data owner marker: {exc}')
            elif (self.docker_data.is_dir() and not self.docker_data.is_symlink()
                    and self.docker_data.parent == self.docker_data_root
                    and self.docker_data.name == self.name + '-docker-data'):
                shutil.rmtree(self.docker_data)
            elif self.docker_data.exists() or self.docker_data.is_symlink():
                errors.append('refusing to clean an unexpected local docker-data path')
            if not self.docker_data.exists() and not self.docker_data.is_symlink():
                try:
                    remove_owner_marker(self.docker_data)
                except OSError as exc:
                    errors.append(f'cannot remove Docker-data owner marker: {exc}')
        try:
            release_address_lease(self.docker_data_root, self.container)
        except OSError as exc:
            errors.append(f'cannot release sandbox network range: {exc}')
        if errors:
            raise SandboxError('sandbox cleanup failed: ' + '; '.join(errors))


_EXTRACT_SCRIPT = r'''import os, shutil, sys, tarfile
from pathlib import Path, PurePosixPath
archive_path, destination, kind = sys.argv[1:]
root = Path(destination)
directories = []
def relative(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts:
        raise RuntimeError('archive path traversal: ' + name)
    return Path(*(part for part in path.parts if part != '.'))
with tarfile.open(archive_path, 'r:') as archive:
    if kind == 'file':
        members = archive.getmembers()
        if len(members) != 1 or not members[0].isfile():
            raise RuntimeError('expected one regular file in Docker archive')
        root.parent.mkdir(parents=True, exist_ok=True)
        with archive.extractfile(members[0]) as source, root.open('wb') as output:
            shutil.copyfileobj(source, output)
        member = members[0]
        os.chown(root, member.uid, member.gid)
        root.chmod(member.mode & 0o7777)
        os.utime(root, (member.mtime, member.mtime))
    else:
        root.mkdir(parents=True, exist_ok=True)
        for member in archive:
            rel = relative(member.name)
            if str(rel) == '.':
                continue
            target = root / rel
            if not target.parent.resolve(strict=False).is_relative_to(root.resolve()):
                raise RuntimeError('archive destination traversal')
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                directories.append((target, member))
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                link = Path(member.linkname)
                candidate = link if link.is_absolute() else target.parent / link
                if not candidate.resolve(strict=False).is_relative_to(root.resolve()):
                    raise RuntimeError('archive symlink escapes mount')
                target.symlink_to(member.linkname)
            elif member.isfile() or member.islnk():
                if member.islnk():
                    relative(member.linkname)
                with archive.extractfile(member) as source, target.open('wb') as output:
                    shutil.copyfileobj(source, output)
            else:
                raise RuntimeError('special file in mount archive')
            if not member.issym():
                os.chown(target, member.uid, member.gid, follow_symlinks=False)
                target.chmod(member.mode & 0o7777)
                os.utime(target, (member.mtime, member.mtime))
for target, member in reversed(directories):
    os.chown(target, member.uid, member.gid)
    target.chmod(member.mode & 0o7777)
    os.utime(target, (member.mtime, member.mtime))
'''


def redact_argument(value: str) -> str:
    for key in SENSITIVE_KEYS:
        if value.startswith(key + '='):
            return key + '=<redacted>'
    return value
