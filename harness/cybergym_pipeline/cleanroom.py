"""Controller-owned, disposable Docker daemon for untrusted frozen submissions.

No host socket, agent cache or previous result volume is exposed to the build.
The submission and private oracle mounts are read-only. This class is deliberately
separate from the interactive agent runtime.
"""
from __future__ import annotations

import json
import os
import secrets
import shlex
import shutil
import subprocess
import threading
from pathlib import Path

from harness.registry_mirror import apply_mirror, direct_registry_hosts


def _cleanroom_daemon_config() -> dict:
    """Preserve caller-provided egress without modifying the shared daemon."""
    environment = os.environ
    no_proxy = ','.join(dict.fromkeys(filter(None, (
        environment.get('NO_PROXY', ''), environment.get('no_proxy', ''),
        'localhost,127.0.0.1,vul,fix,100.102.49.113,100.102.49.114',
        *direct_registry_hosts()))))
    proxies = {key: environment[key] for key in
               ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy') if environment.get(key)}
    config = {'proxies': {
        'http-proxy': proxies.get('HTTP_PROXY') or proxies.get('http_proxy', ''),
        'https-proxy': proxies.get('HTTPS_PROXY') or proxies.get('https_proxy', ''),
        'no-proxy': no_proxy,
    }} if proxies else {}
    apply_mirror(config)
    return config


class DockerFailure(RuntimeError):
    def __init__(self, command: list[str], result: subprocess.CompletedProcess):
        self.command, self.result = command, result
        output = ((result.stdout or '') + (result.stderr or ''))[-8000:]
        super().__init__(f'{shlex.join(command)} exited {result.returncode}: {output}')


class HostDocker:
    def run(self, argv, timeout=600, env=None, input=None, log_path=None, **kwargs):
        command = ['docker', *map(str, argv)]
        environment = {**os.environ, **(env or {})}
        if log_path:
            Path(log_path).parent.mkdir(parents=True, exist_ok=True)
            with Path(log_path).open('a') as log:
                log.write('$ ' + shlex.join(command) + '\n')
                log.flush()
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                        stdin=subprocess.DEVNULL if input is None else None,
                                        input=input, text=True, timeout=timeout, env=environment)
                # Preserve concise failure evidence in the return object.
                with Path(log_path).open('rb') as saved:
                    saved.seek(max(0, Path(log_path).stat().st_size - 65536))
                    result.stdout = saved.read().decode(errors='replace')
            return result
        return subprocess.run(command, capture_output=True, text=True, input=input,
                              timeout=timeout, env=environment)

    def run_bytes(self, argv, timeout=600, env=None, **kwargs):
        return subprocess.run(['docker', *map(str, argv)], capture_output=True, text=False,
                              timeout=timeout, env={**os.environ, **(env or {})})

    def success(self, argv, **kwargs):
        result = self.run(argv, **kwargs)
        if result.returncode:
            raise DockerFailure(['docker', *argv], result)
        return result


class CleanRoom:
    """One disposable privileged daemon, with isolated bridge and no host data."""

    def __init__(self, attempt: str, output: Path, submission: Path, private: Path,
                 image: str = 'docker:28-dind', host: HostDocker | None = None,
                 docker_root: Path | None = None):
        self.attempt = ''.join(c if c.isalnum() or c in '-_' else '-' for c in attempt)
        self.name = 'cdb-cg-grade-' + self.attempt + '-' + secrets.token_hex(4)
        self.output, self.private = output, private
        self.submission = Path(submission).resolve()
        self.image, self.host = image, host or HostDocker()
        self.docker_root = docker_root
        self.started = False
        self.log = output / 'cleanroom-daemon.log'
        self.daemon_config = output / 'daemon.json'
        self.docker_env = {}

    def start(self, timeout=120):
        if self.started:
            return
        self.output.mkdir(parents=True, exist_ok=True)
        self.daemon_config.write_text(json.dumps(_cleanroom_daemon_config()) + '\n')
        self.daemon_config.chmod(0o600)
        self.docker_env = {}
        argv = ['run', '-d', '--name', self.name, '--privileged', '--cgroupns=host',
                '--label', 'cdb.owner=cybergym-grader', '--label', f'cdb.attempt_id={self.attempt}',
                '--tmpfs', '/tmp', '--tmpfs', '/run', '--entrypoint', 'dockerd-entrypoint.sh',
                '-v', f'{self.daemon_config.resolve()}:/etc/docker/daemon.json:ro',
                '-v', f'{self.submission.resolve()}:/submission:ro',
                '-v', f'{self.private.resolve()}:/private:ro',
                '-v', f'{self.output.resolve()}:/evidence',
                # A DinD bind source must resolve to the same host directory.
                # Preserve the absolute runtime-copy path inside the outer
                # clean-room as well as exposing its evidence at /evidence.
                '-v', f'{self.output.resolve()}:{self.output.resolve()}']
        if self.docker_root:
            self.docker_root.mkdir(parents=True, exist_ok=True)
            argv += ['-v', f'{self.docker_root.resolve()}:/var/lib/docker']
        driver = os.environ.get('CYBERGYM_CLEANROOM_STORAGE_DRIVER', 'overlay2')
        if driver not in {'overlay2', 'fuse-overlayfs', 'vfs'}:
            raise ValueError('CYBERGYM_CLEANROOM_STORAGE_DRIVER must be overlay2, fuse-overlayfs or vfs')
        argv += [self.image, '--host=unix:///var/run/docker.sock', '--storage-driver=' + driver]
        self.host.success(argv, timeout=120, log_path=self.output / 'daemon-create.log')
        self.started = True
        # Do not expose the host's HTTP_PROXY to the nested daemon.
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.run(['info', '--format', '{{json .ServerVersion}}'], timeout=15)
            if result.returncode == 0:
                return
            time.sleep(1)
        raise RuntimeError(f'clean Docker daemon not ready; see {self.output / "dind.log"}')

    def run(self, argv, **kwargs):
        return self.host.run(['exec', '-i', self.name, 'docker', *map(str, argv)], **kwargs)

    def run_bytes(self, argv, **kwargs):
        return self.host.run_bytes(['exec', '-i', self.name, 'docker', *map(str, argv)], **kwargs)

    def success(self, argv, **kwargs):
        result = self.run(argv, **kwargs)
        if result.returncode:
            raise DockerFailure(['cleanroom-docker', *argv], result)
        return result

    def exec(self, target: str, argv: list[str], timeout=60):
        return self.run(['exec', target, *argv], timeout=timeout)

    def compose(self, argv: list[str], timeout=1800, compose_file: str = '/submission/docker-compose.yaml'):
        return self.success(['compose', '-f', compose_file,
                             '--project-name', 'cg' + secrets.token_hex(8), *argv],
                            timeout=timeout, log_path=self.output / 'source-compose.log')

    def stop(self):
        if self.started:
            self.host.run(['rm', '-f', '-v', self.name], timeout=180)
            self.started = False
        if self.docker_root and self.docker_root.exists():
            shutil.rmtree(self.docker_root, ignore_errors=True)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()
