"""One ordinary-Claude, single-container DinD sandbox for CyberGym.

The controller talks to the *host* Docker daemon only to manage the outer
container. Every ``Sandbox.docker()`` call talks to the attempt's inner daemon
through ``/var/run/docker.sock``. No host socket is mounted.

Only non-sensitive environment is inherited by the outer container/dockerd.
Anthropic and other model credentials are retained by the controller and
forwarded by name only to the later Claude ``docker exec``.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from harness.claude_session import PLUGIN_DIR, with_claude_retries
from harness.registry_mirror import apply_mirror, direct_registry_hosts
from harness.compact_trace import TrajectoryWriter

IMAGE = "cdb-cybergym-sandbox:28.5.2-v2"
AGENT_USER = "agent"
# Inner dockerd data-root base. /var/tmp works on any machine; on the worker
# on-worker.sh points this at /nvme (xfs) so the inner daemon can use kernel
# overlay2 instead of fuse-overlayfs on the container's overlayfs root.
DOCKER_ROOT_BASE = Path(os.environ.get("CYBERGYM_DOCKER_ROOT_BASE", "/var/tmp/cybergym-docker"))
# Repo copy of the image's entrypoint, bind-mounted over the baked script so
# image rebuilds are not required for init changes.
SANDBOX_INIT = Path(__file__).resolve().parents[1] / "sandbox" / "sandbox-init"
KKREPO_DOCKER = Path(__file__).resolve().parents[2] / "agent_image" / "docker-kkrepo"
# Live kkRepo entry on wuyida-01; the dev machine's DHCP address changes
# across reboots. Keep legacy addresses in DIRECT_HOSTS, live one in KKREPO_HOST.
KKREPO_HOST = "100.102.49.114"
DIRECT_HOSTS = (
    "100.102.49.113",
    KKREPO_HOST,
    "pkg.pjlab.org.cn",
    "localhost",
    "127.0.0.1",
    "::1",
    "client",
    "db",
    "target",
    "player",
    "attacker",
)
SENSITIVE_NAMES = frozenset({
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CDB_MODEL_CREDENTIALS",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
})
SENSITIVE_PARTS = ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY")
PROXY_NAMES = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "all_proxy",
)
CONFIG_NAMES = frozenset({
    "CYBERGYM_SANDBOX_IMAGE",
    "CYBERGYM_NETWORK_PLUGIN",
    "CYBERGYM_REGISTRY_MIRROR",
})


class SandboxError(RuntimeError):
    """A controller/runtime failure, rather than a task or model failure."""


class SandboxTimeout(SandboxError):
    """An exec timed out; its process group was killed, not the inner dockerd."""


@dataclass(frozen=True)
class ClaudeResult:
    """A completed non-interactive Claude invocation."""

    returncode: int
    timed_out: bool
    duration_sec: float
    log_path: Path
    stderr_path: Path
    num_turns: int = 0
    turn_limit_reached: bool = False

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.turn_limit_reached

    def as_dict(self) -> dict[str, object]:
        return {'returncode': self.returncode, 'timed_out': self.timed_out,
                'num_turns': self.num_turns, 'turn_limit_reached': self.turn_limit_reached,
                'duration_sec': self.duration_sec, 'success': self.success,
                'log_path': str(self.log_path), 'stderr_path': str(self.stderr_path)}


def safe_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value):
        raise ValueError(f"{label} must be 1-80 safe filename characters")
    return value


def is_sensitive(name: str) -> bool:
    upper = name.upper()
    return upper in SENSITIVE_NAMES or any(part in upper for part in SENSITIVE_PARTS)


def merge_no_proxy(env: dict[str, str]) -> str:
    """Preserve both cases of NO_PROXY and append required direct endpoints."""
    values: list[str] = []
    for key in ("NO_PROXY", "no_proxy"):
        values.extend(item.strip() for item in env.get(key, "").split(","))
    values.extend(item.strip() for item in env.get("CYBERGYM_EXTRA_NO_PROXY", "").split(","))
    values.extend(DIRECT_HOSTS)
    values.extend(direct_registry_hosts(env))
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return ",".join(result)


def tail(value: str | bytes | None, limit: int = 6000) -> str:
    if isinstance(value, bytes):
        return value[-limit:].decode('utf-8', 'replace')
    return (value or "")[-limit:]


def redact_arg(value: str) -> str:
    if "=" in value:
        key, _ = value.split("=", 1)
        if is_sensitive(key):
            return key + "=<redacted>"
    return value


def controller_run(args: list[str], timeout: int = 120,
                   extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run the host CLI without forwarding host DOCKER_HOST/DOCKER_CONTEXT."""
    env = dict(os.environ)
    env.pop("DOCKER_HOST", None)
    env.pop("DOCKER_CONTEXT", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)


class Sandbox:
    """An isolated attempt owned by one dedicated worker.

    ``workspace`` and ``docker_root`` must be absolute. ``docker_root`` must be
    exactly ``DOCKER_ROOT_BASE/<task>--<attempt>`` on a local filesystem;
    overlay-on-GPFS is rejected. ``DOCKER_ROOT_BASE`` defaults to
    ``/var/tmp/cybergym-docker`` and is overridden by
    ``CYBERGYM_DOCKER_ROOT_BASE`` (on-worker.sh points it at /nvme xfs, where
    the inner dockerd can use kernel overlay2). The workspace is bind-mounted
    at the identical absolute path so Docker daemon bind resolution agrees
    with the agent view.

    ``env`` augments the controller environment. Sensitive values are withheld
    from container creation and used only by ``run_claude``. ``start`` never
    launches Claude and ``run_claude`` never stops the sandbox, leaving the live
    environment available for the parent controller's snapshot.
    """

    def __init__(
        self,
        task_id: str,
        attempt_id: str,
        workspace: str | Path,
        runtime_root: str | Path,
        docker_root: str | Path,
        env: dict[str, str] | None = None,
    ) -> None:
        self.task_id = safe_id(task_id, "task_id")
        self.attempt_id = safe_id(attempt_id, "attempt_id")
        self.workspace = self._absolute(workspace, "workspace")
        self.runtime_root = self._absolute(runtime_root, "runtime_root")
        self.docker_root = self._absolute(docker_root, "docker_root")
        # The root must stay a direct child of the local base and be unique per
        # task+attempt: concurrent attempts share the worker's attempt_id.
        expected_name = f"{self.task_id}--{self.attempt_id}"
        if self.docker_root.parent != DOCKER_ROOT_BASE or self.docker_root.name not in {
                self.attempt_id, expected_name}:
            raise ValueError(
                f"docker_root must be {DOCKER_ROOT_BASE}/{expected_name}; shared/GPFS storage is forbidden")
        digest = hashlib.sha256(f"{task_id}\0{attempt_id}".encode()).hexdigest()[:12]
        task_part = re.sub(r"[^a-z0-9_.-]+", "-", task_id.lower()).strip("-.")[:36]
        self.name = f"cdb-cybergym-{task_part}-{attempt_id[:24]}-{digest}"
        self.container = self.name
        self.network = self.name + "-net"
        self.runtime_id = digest
        self.home = self.runtime_root / "agent-home"
        self.daemon_config = self.runtime_root / "docker-daemon.json"
        self._config = dict(os.environ)
        self._apply_runtime_settings(env or {})

    def _apply_runtime_settings(self, env: dict[str, str]) -> None:
        """Apply trusted controller settings without serializing them to argv.

        The worker sends runtime configuration over stdin before any container
        starts. Recalculate the public outer and process-only Claude environments
        together; credentials must never enter the outer container configuration.
        """
        if not isinstance(env, dict) or any(not isinstance(key, str) or not isinstance(value, str)
                                           for key, value in env.items()):
            raise ValueError("runtime settings must be a string mapping")
        self._config.update(env)
        explicit_env = set(env)
        self.image = self._config.get("CYBERGYM_SANDBOX_IMAGE", IMAGE)
        self._claude_env = {
            key: value for key, value in self._config.items()
            if key.startswith(("ANTHROPIC_", "CLAUDE_")) or is_sensitive(key)
        }
        self._claude_env.pop("CYBERGYM_SANDBOX_IMAGE", None)
        self._claude_env = with_claude_retries(self._claude_env)
        for key in {"GIT_SSL_CAINFO", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"}:
            if key in explicit_env and key in self._config:
                self._claude_env[key] = self._config[key]
        self._outer_env = {
            key: value for key, value in self._config.items()
            if not is_sensitive(key)
            and not key.startswith(("ANTHROPIC_", "CLAUDE_"))
            and key not in CONFIG_NAMES
            and key not in {
                "HOME", "PATH", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
                "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "USER", "LOGNAME",
            }
            and (key in PROXY_NAMES or key in {
                "NO_PROXY", "no_proxy", "CYBERGYM_EXTRA_NO_PROXY",
                "CYBERGYM_DIND_MTU", "CYBERGYM_GIT_SMOKE_URL",
                "GIT_SSL_CAINFO", "CURL_CA_BUNDLE", "SSL_CERT_FILE",
            } or key in explicit_env)
        }
        no_proxy = merge_no_proxy(self._config)
        self._outer_env["NO_PROXY"] = no_proxy
        self._outer_env["no_proxy"] = no_proxy
        self._outer_env["DOCKER_HOST"] = "unix:///var/run/docker.sock"
        self._outer_env["DOCKER_CONFIG"] = "/home/agent/.docker"
        self._outer_env["DOCKER_BUILDKIT"] = "1"
        self._outer_env["COMPOSE_DOCKER_CLI_BUILD"] = "1"
        self._started = False
        self._created_container = False
        self._created_network = False
        self._cleanup_log_written = False
        self._resource_errors: list[str] = []
        self.image_id = ""

    @staticmethod
    def _absolute(value: str | Path, label: str) -> Path:
        path = Path(value)
        if not path.is_absolute():
            raise ValueError(f"{label} must be absolute")
        return path.resolve()

    def _validate_local_root(self) -> None:
        DOCKER_ROOT_BASE.mkdir(parents=True, exist_ok=True)
        if DOCKER_ROOT_BASE.resolve() != DOCKER_ROOT_BASE:
            raise SandboxError(f"{DOCKER_ROOT_BASE} must not be a symlink")
        self.docker_root.mkdir(parents=True, exist_ok=True)
        resolved = self.docker_root.resolve()
        if resolved != self.docker_root or resolved.parent != DOCKER_ROOT_BASE:
            raise SandboxError(f"docker_root must be a direct, non-symlink child of {DOCKER_ROOT_BASE}")
        mount = self._mount_for(resolved)
        remote_types = {"nfs", "nfs4", "cifs", "smbfs", "gpfs", "glusterfs", "lustre", "9p", "ceph"}
        if mount and (mount[0] in remote_types or mount[0].startswith("fuse.")):
            raise SandboxError(f"docker_root filesystem is not local: {mount[0]}")
        if Path(mount[1] if mount else "").is_relative_to("/mnt/shared-storage-user"):
            raise SandboxError("docker_root cannot be on shared storage")

    @staticmethod
    def _mount_for(path: Path) -> tuple[str, str] | None:
        """Return (filesystem type, mount point) for the deepest known mount."""
        best: tuple[int, str, str] | None = None
        try:
            lines = Path("/proc/self/mountinfo").read_text().splitlines()
        except OSError:
            return None
        for line in lines:
            try:
                left, right = line.split(" - ", 1)
                mount_point = Path(left.split()[4].replace("\\040", " "))
                fs_type = right.split()[0]
                path.relative_to(mount_point)
            except (ValueError, IndexError):
                continue
            depth = len(mount_point.parts)
            if best is None or depth > best[0]:
                best = (depth, fs_type, str(mount_point))
        return (best[1], best[2]) if best else None

    @property
    def _labels(self) -> dict[str, str]:
        return {
            "cyberdockerbench.runtime": "cybergym-single-dind-v1",
            "cyberdockerbench.cybergym.runtime-id": self.runtime_id,
            "cyberdockerbench.cybergym.task": self.task_id,
            "cyberdockerbench.cybergym.attempt": self.attempt_id,
            "cyberdockerbench.role": "sandbox",
        }

    def _label_args(self) -> list[str]:
        return [item for key, value in self._labels.items() for item in ("--label", f"{key}={value}")]

    def _log(self, operation: str, args: list[str], cp: subprocess.CompletedProcess) -> None:
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        record = {
            "operation": operation,
            "args": [redact_arg(value) for value in args],
            "returncode": cp.returncode,
            "stdout_tail": tail(cp.stdout),
            "stderr_tail": tail(cp.stderr),
        }
        with (self.runtime_root / "commands.jsonl").open("a") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _host(self, args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
        cp = controller_run(args, timeout=timeout)
        self._log("host-docker", args, cp)
        return cp

    def _exec_args(
        self,
        args: list[str],
        user: str | None,
        extra_env: dict[str, str] | None,
        token: str,
    ) -> tuple[list[str], dict[str, str]]:
        if not args:
            raise ValueError("exec args cannot be empty")
        user = user or AGENT_USER
        forwarded = dict(extra_env or {})
        for key in forwarded:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                raise ValueError(f"invalid environment name: {key!r}")
        if user == AGENT_USER:
            forwarded.setdefault("HOME", "/home/agent")
            forwarded.setdefault("DOCKER_CONFIG", "/home/agent/.docker")
            forwarded.setdefault("DOCKER_HOST", "unix:///var/run/docker.sock")
        command = ["docker", "exec", "-i", "--user", user, "--workdir", str(self.workspace)]
        # Values travel in the controller process environment, not argv/logs.
        command.extend(item for key in forwarded for item in ("-e", key))
        command.extend([self.container, "cybergym-exec", token, *args])
        return command, forwarded

    def _start_exec(
        self,
        args: list[str],
        user: str | None,
        extra_env: dict[str, str] | None,
        stdout,
        stderr,
        text: bool = True,
    ) -> tuple[subprocess.Popen, str, list[str]]:
        token = uuid.uuid4().hex
        command, forwarded = self._exec_args(args, user, extra_env, token)
        env = dict(os.environ)
        env.pop("DOCKER_HOST", None)
        env.pop("DOCKER_CONTEXT", None)
        env.update(forwarded)
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            text=text, env=env, start_new_session=True, bufsize=1,
        )
        return process, token, command

    def _kill_exec(self, token: str) -> None:
        # This only targets a new session created by cybergym-exec. PID 1 and
        # dockerd are deliberately not part of that session.
        self._host(["docker", "exec", "--user", "root", self.container,
                    "cybergym-kill", token], timeout=30)

    def exec(
        self,
        args: list[str],
        user: str | None = None,
        timeout: int = 120,
        extra_env: dict[str, str] | None = None,
        stream: bool = False,
        binary: bool = False,
    ):
        """Execute in the outer container, defaulting to agent and workspace.

        With ``stream=True``, return a text Popen with piped stdout/stderr. Its
        caller is responsible for reading both streams. Otherwise return a
        CompletedProcess. On timeout the inner command's own process group is
        terminated before raising ``SandboxTimeout``; DinD remains alive.
        """
        if not self._started:
            raise SandboxError("sandbox is not started")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        stdout = subprocess.PIPE
        process, token, command = self._start_exec(args, user, extra_env, stdout, subprocess.PIPE,
                                                   text=not binary)
        process._cybergym_token = token  # type: ignore[attr-defined]
        process.cybergym_timed_out = False  # type: ignore[attr-defined]
        if stream:
            def expire_stream() -> None:
                if process.poll() is None:
                    process.cybergym_timed_out = True  # type: ignore[attr-defined]
                    try:
                        self._kill_exec(token)
                    finally:
                        if process.poll() is None:
                            process.kill()

            timer = threading.Timer(timeout, expire_stream)
            timer.daemon = True
            timer.start()
            process._cybergym_timeout_timer = timer  # type: ignore[attr-defined]
            return process
        timed_out = False
        try:
            out, err = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill_exec(token)
            try:
                out, err = process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                out, err = process.communicate(timeout=10)
        cp = subprocess.CompletedProcess(command, process.returncode, out, err)
        self._log("exec", args, cp)
        if timed_out:
            raise SandboxTimeout(f"exec timed out after {timeout}s; command killed, sandbox retained: {args[0]}")
        return cp

    def docker(self, args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
        """Run Docker CLI as agent against this attempt's inner daemon only."""
        return self.exec(["docker", *args], user=AGENT_USER, timeout=timeout)

    def _prepare_workspace(self) -> None:
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.home.mkdir(parents=True, exist_ok=True)
        # The input owner has already made a public working copy. This pass only
        # grants the sandbox UID access; it never follows symlinks outside it.
        if os.geteuid() == 0:
            for root, dirs, files in os.walk(self.workspace, followlinks=False):
                for name in [".", *dirs, *files]:
                    path = Path(root) / name
                    try:
                        os.chown(path, 1000, 1000, follow_symlinks=False)
                    except (PermissionError, FileNotFoundError):
                        pass
            os.chown(self.home, 1000, 1000)
        self.workspace.chmod(0o777)

    def _reclaim_stale(self, kind: str, name: str, inspect_stdout: str) -> None:
        """Remove a leftover from a crashed previous run of this exact
        task/attempt. Resource names are deterministic per task/attempt, so a
        name collision is either an orphan from a killed run (safe to remove:
        stopped container or network with no attached containers) or a live
        duplicate (still refused). Foreign-labelled resources are refused."""
        try:
            info = json.loads(inspect_stdout)[0]
        except (ValueError, IndexError):
            raise SandboxError(f"refusing to reuse existing {kind}: {name} (unreadable inspect output)")
        labels = info.get("Labels") or (info.get("Config") or {}).get("Labels") or {}
        if any(labels.get(key) != value for key, value in self._labels.items()):
            raise SandboxError(f"refusing to reuse foreign {kind}: {name}")
        if kind == "container":
            if (info.get("State") or {}).get("Running"):
                raise SandboxError(f"refusing to reuse live sandbox: {name}")
            rm_args = ["docker", "rm", "-f", name]
        else:
            if info.get("Containers"):
                raise SandboxError(f"refusing to reuse network with attached containers: {name}")
            rm_args = ["docker", "network", "rm", name]
        cp = self._host(rm_args, timeout=60)
        if cp.returncode:
            raise SandboxError(f"cannot reclaim stale {kind} {name}: {tail(cp.stderr)}")
        self._log("reclaim-stale", rm_args, cp)

    def start(self) -> None:
        if self._started:
            raise SandboxError("sandbox already started")
        if not SANDBOX_INIT.is_file():
            raise SandboxError(f"sandbox-init missing: {SANDBOX_INIT}")
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        self._validate_local_root()
        self._prepare_workspace()
        for kind, name in (("container", self.container), ("network", self.network)):
            cp = self._host(["docker", kind, "inspect", name], timeout=30)
            if cp.returncode == 0:
                self._reclaim_stale(kind, name, cp.stdout)
            else:
                self._resource_errors.append(tail(cp.stderr, 500))
        config: dict[str, object] = {
            "default-address-pools": [
                {"base": "10.160.0.0/12", "size": 24},
                {"base": "172.30.0.0/16", "size": 24},
            ]
        }
        apply_mirror(config, self._config)
        # Dockerd does not inherit the outer container's environment. Package
        # mirrors cannot pull a FROM image, so configure only this attempt's
        # private daemon with the already-supplied egress settings. The file
        # lives outside the workspace, is never part of a submission, and no
        # value is logged or passed as a command-line argument.
        proxies = {key: self._config[key] for key in PROXY_NAMES if self._config.get(key)}
        if proxies:
            config["proxies"] = {
                "http-proxy": proxies.get("HTTP_PROXY") or proxies.get("http_proxy", ""),
                "https-proxy": proxies.get("HTTPS_PROXY") or proxies.get("https_proxy", ""),
                "no-proxy": merge_no_proxy(self._config),
            }
        self.daemon_config.write_text(json.dumps(config, indent=2) + "\n")
        self.daemon_config.chmod(0o600)
        cp = self._host([
            "docker", "network", "create", "--driver", "bridge", *self._label_args(), self.network,
        ], timeout=45)
        if cp.returncode:
            raise SandboxError(f"cannot create isolated bridge: {tail(cp.stderr)}")
        self._created_network = True
        try:
            command = [
                "docker", "run", "-d", "--name", self.container,
                "--privileged", "--cgroupns=private", "--network", self.network,
                *self._label_args(), "--stop-timeout", "30",
                "--tmpfs", "/run:rw,nosuid,nodev,mode=755",
                "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777",
                "-v", f"{self.docker_root}:{self.docker_root}:rw",
                "-v", f"{self.workspace}:{self.workspace}:rw",
                # The public contract says ``/workspace``. Keep the long
                # GPFS path for daemon-side bind resolution, but make the
                # documented path the same directory rather than an unrelated
                # tmpfs directory that disappears on export.
                "-v", f"{self.workspace}:/workspace:rw",
                "-v", f"{self.home}:/home/agent:rw",
                "-v", f"{self.daemon_config}:/etc/docker/daemon.json:ro",
                "-v", f"{SANDBOX_INIT}:/usr/local/bin/cybergym-sandbox-init:ro",
                "-e", "CYBERGYM_DOCKER_ROOT=" + str(self.docker_root),
                "-e", "CYBERGYM_DOCKER_ROOT_BASE=" + str(DOCKER_ROOT_BASE),
                "-e", "DOCKER_TLS_CERTDIR=",
            ]
            plugin = self._config.get("CYBERGYM_NETWORK_PLUGIN")
            if plugin:
                plugin_path = Path(plugin).resolve()
                if not (plugin_path / ".claude-plugin" / "plugin.json").is_file() or not (plugin_path / "skills").is_dir():
                    raise ValueError("CYBERGYM_NETWORK_PLUGIN must be a valid Claude plugin")
                # Same directory at the current path and the path already
                # written into existing task instructions.
                command += ["-v", f"{plugin_path}:{PLUGIN_DIR}:ro",
                            "-v", f"{plugin_path}:/opt/cybergym-network:ro"]
            for key, value in self._outer_env.items():
                # Secrets were excluded at construction; model configuration is
                # not present in docker inspect, dockerd, or application env.
                command += ["-e", f"{key}={value}"]
            command.append(self.image)
            cp = self._host(command, timeout=120)
            if cp.returncode:
                raise SandboxError(f"cannot start CyberGym sandbox: {tail(cp.stderr)}")
            self._created_container = True
            # Baked apt sources may point at any stale wuyida-01 kkRepo IP
            # (the dev machine's DHCP address changes across reboots). Rewrite
            # whatever 100.102.49.x:19091 they carry to the live entry so
            # agent apt installs and the preflight apt-download check do not
            # depend on image rebuild timing.
            self._rewrite_stale_apt_sources()
            for source, target, mode in (
                    (KKREPO_DOCKER, "/usr/local/bin/docker-kkrepo", "0755"),):
                cp = self._host(["docker", "cp", str(source), f"{self.container}:{target}"], timeout=30)
                if cp.returncode:
                    raise SandboxError(f"cannot install kkRepo Docker adapter: {tail(cp.stderr)}")
                cp = self._host(["docker", "exec", "--user", "root", self.container,
                                 "chmod", mode, target], timeout=30)
                if cp.returncode:
                    raise SandboxError(f"cannot enable kkRepo Docker adapter: {tail(cp.stderr)}")
            cp = self._host(["docker", "exec", "--user", "root", self.container,
                             "cp", "/usr/local/bin/docker", "/usr/local/bin/docker-real"], timeout=30)
            if cp.returncode:
                raise SandboxError(f"cannot preserve real Docker CLI: {tail(cp.stderr)}")
            cp = self._host(["docker", "exec", "--user", "root", self.container,
                             "cp", "/usr/local/bin/docker-kkrepo", "/usr/local/bin/docker"], timeout=30)
            if cp.returncode:
                raise SandboxError(f"cannot activate kkRepo Docker adapter: {tail(cp.stderr)}")
            deadline = time.monotonic() + 180
            last_error = ""
            while time.monotonic() < deadline:
                probe = self._host([
                    "docker", "exec", "--user", AGENT_USER, "--workdir", str(self.workspace),
                    "-e", "HOME=/home/agent", "-e", "DOCKER_CONFIG=/home/agent/.docker",
                    self.container, "bash", "--noprofile", "--norc", "-c",
                    "test \"$(id -u)\" = 1000 && docker info --format '{{.ServerVersion}}' "
                    "&& docker compose version && docker buildx version && claude --version",
                ], timeout=25)
                if probe.returncode == 0:
                    self._started = True
                    self._log("start-ready", [self.container], probe)
                    self._assert_isolation()
                    return
                last_error = tail(probe.stderr + probe.stdout)
                state = self._host([
                    "docker", "inspect", "--format", "{{json .State}}", self.container,
                ], timeout=15)
                if state.returncode == 0:
                    container_state = json.loads(state.stdout)
                    if not container_state.get("Running"):
                        logs = self._host(["docker", "logs", self.container], timeout=30)
                        (self.runtime_root / "startup-logs.txt").write_text(logs.stdout + logs.stderr)
                        raise SandboxError(
                            f"outer sandbox exited ({container_state.get('ExitCode')}): "
                            + tail(logs.stdout + logs.stderr)
                        )
                time.sleep(2)
            logs = self._host(["docker", "logs", self.container], timeout=30)
            (self.runtime_root / "startup-logs.txt").write_text(logs.stdout + logs.stderr)
            raise SandboxError("inner dockerd not ready: " + tail(last_error + logs.stdout + logs.stderr))
        except Exception:
            if not self._created_container:
                self.stop(remove_data=True)
            raise

    def _rewrite_stale_apt_sources(self) -> None:
        script = (
            "grep -rlsE '100\\.102\\.49\\.[0-9]+:19091' /etc/apt/ 2>/dev/null"
            f" | xargs -r sed -i -E 's|100\\.102\\.49\\.[0-9]+:19091|{KKREPO_HOST}:19091|g'"
        )
        for _ in range(5):
            cp = self._host(["docker", "exec", "--user", "root", self.container,
                             "bash", "--noprofile", "--norc", "-c", script], timeout=30)
            if cp.returncode == 0:
                return
            time.sleep(2)
        self._resource_errors.append(f"apt sources rewrite to {KKREPO_HOST} failed: "
                                     + tail(cp.stderr, 300))

    def ensure(self) -> None:
        """Start this attempt, or reattach its labeled container."""
        if self._started:
            return
        if self.probe()["exists"]:
            try:
                self.attach()
            except SandboxError:
                # attach() authenticates the owned container/network before
                # its isolation probe. Do not leak that partial attachment
                # into start(), or a retry mistakes itself for a duplicate.
                self._started = False
                self._created_container = False
                self._created_network = False
            else:
                return
        self.start()

    def probe(self) -> dict:
        cp = self._host(["docker", "container", "inspect", self.container], timeout=30)
        return {"exists": cp.returncode == 0, "name": self.container}

    def attach(self) -> None:
        """Reattach an owned, running attempt after a controller restart.

        The attempt identity is authenticated by host-side Docker labels before
        marking the sandbox started; a random same-named container is rejected.
        """
        cp = self._host(["docker", "inspect", self.container], timeout=30)
        if cp.returncode:
            raise SandboxError(f"cannot reattach sandbox {self.container}: {tail(cp.stderr)}")
        info = json.loads(cp.stdout)[0]
        self._created_container = True
        labels = info.get("Config", {}).get("Labels", {})
        if any(labels.get(key) != value for key, value in self._labels.items()):
            raise SandboxError("existing sandbox does not belong to this exact task/attempt")
        if not info.get("State", {}).get("Running"):
            raise SandboxError("owned sandbox is not running; inspect or remove it before retrying")
        network = self._host(["docker", "network", "inspect", self.network], timeout=30)
        if network.returncode:
            raise SandboxError(f"cannot reattach sandbox network: {tail(network.stderr)}")
        network_info = json.loads(network.stdout)[0]
        if any(network_info.get("Labels", {}).get(key) != value for key, value in self._labels.items()):
            raise SandboxError("existing network does not belong to this exact task/attempt")
        self._created_container = self._created_network = self._started = True
        self._assert_isolation()

    def _assert_isolation(self) -> None:
        cp = self._host(["docker", "inspect", self.container], timeout=30)
        if cp.returncode:
            raise SandboxError("cannot inspect new sandbox")
        info = json.loads(cp.stdout)[0]
        host_config = info.get("HostConfig", {})
        if host_config.get("NetworkMode") == "host" or not host_config.get("Privileged"):
            raise SandboxError("sandbox network/privilege contract violated")
        binds = host_config.get("Binds") or []
        for bind in binds:
            source = bind.split(":", 1)[0]
            if source in {"/var/run/docker.sock", "/run/docker.sock"}:
                raise SandboxError(f"forbidden host mount: {source}")
        allowed = {str(self.workspace), str(self.docker_root), str(self.home),
                   str(self.daemon_config), str(SANDBOX_INIT)}
        plugin = self._config.get("CYBERGYM_NETWORK_PLUGIN")
        if plugin:
            allowed.add(str(Path(plugin).resolve()))
            plugin_mount = next((mount for mount in info.get("Mounts", [])
                                 if mount.get("Destination") == PLUGIN_DIR), None)
            if not plugin_mount or plugin_mount.get("RW") is not False:
                raise SandboxError("network plugin must be mounted read-only")
        actual = {mount.get("Source") for mount in info.get("Mounts", [])}
        if not actual <= allowed:
            raise SandboxError(f"unexpected sandbox mounts: {sorted(actual - allowed)}")
        for mount in info.get("Mounts", []):
            source, destination = mount.get("Source", ""), mount.get("Destination", "")
            if "gold" in {part.lower() for part in Path(destination).parts}:
                raise SandboxError(f"private gold mount is forbidden: {destination}")
            if source.startswith("/mnt/shared-storage") and source not in allowed:
                raise SandboxError(f"unapproved shared-storage mount: {source}")
        if {str(self.workspace), str(self.docker_root), str(self.home)} - actual:
            raise SandboxError("workspace, docker data-root or agent home is not mounted")
        self.image_id = info.get("Image", "")
        if not self.image_id:
            raise SandboxError("sandbox image ID is missing")
        outer = self._host([
            "docker", "ps", "-a", "--filter", f"label=cyberdockerbench.cybergym.runtime-id={self.runtime_id}",
            "--format", "{{.Names}}",
        ], timeout=30)
        names = [name for name in outer.stdout.splitlines() if name]
        if outer.returncode or names != [self.container]:
            raise SandboxError(f"attempt must own exactly one outer container: {names or outer.stderr}")
        inner = self.docker(["info", "--format", "{{json .}}"], timeout=30)
        if inner.returncode:
            raise SandboxError("agent cannot access the attempt's inner daemon")
        inner_info = json.loads(inner.stdout)
        if inner_info.get("DockerRootDir") != str(self.docker_root):
            raise SandboxError("inner dockerd uses an unexpected data-root")
        metadata = {
            "task_id": self.task_id,
            "attempt_id": self.attempt_id,
            "image": self.image,
            "image_id": self.image_id,
            "container_id": info.get("Id"),
            "container": self.container,
            "network": self.network,
            "network_id": info.get("NetworkSettings", {}).get("Networks", {}).get(self.network, {}).get("NetworkID"),
            "docker_root": str(self.docker_root),
            "workspace": str(self.workspace),
            "inner_server_version": inner_info.get("ServerVersion"),
            "storage_driver": inner_info.get("Driver"),
            "agent_uid": 1000,
            "outer_container_count": len(names),
            "host_socket_mounted": False,
            "private_mounts": [],
        }
        (self.runtime_root / "runtime.json").write_text(json.dumps(metadata, indent=2) + "\n")

    def _api_probe(self) -> dict[str, object]:
        base = self._claude_env.get("ANTHROPIC_BASE_URL", "")
        if not base:
            return {"status": "skipped", "reason": "ANTHROPIC_BASE_URL not configured"}
        parsed = urlsplit(base if "://" in base else "https://" + base)
        if not parsed.hostname or parsed.scheme not in {"http", "https"}:
            raise SandboxError("ANTHROPIC_BASE_URL must be an HTTP(S) URL with a hostname")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        timeout = 10
        # Execute from the agent network namespace so proxy/DNS behavior matches
        # Claude. This is TCP/TLS only: no /v1/messages, credentials or model.
        script = '''import socket, ssl, sys
host, port, secure = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1"
with socket.create_connection((host, port), timeout=10) as connection:
    if secure:
        context = ssl.create_default_context()
        with context.wrap_socket(connection, server_hostname=host) as tls:
            print(tls.version())
'''
        cp = self.exec(["python3", "-c", script, parsed.hostname, str(port),
                        "1" if parsed.scheme == "https" else "0"], timeout=20)
        if cp.returncode:
            raise OSError(tail(cp.stderr + cp.stdout, 1000))
        return {
            "status": "passed", "host": parsed.hostname, "port": port,
            "tls": cp.stdout.strip() if parsed.scheme == "https" else False,
        }

    def freeze(self, output: str | Path) -> dict[str, object]:
        """Freeze only the declarative source project as the graded delivery.

        ``output`` is the frozen submission root. It contains source/,
        bundle.json and source-inventory.json. Running containers are not
        part of the graded delivery.
        """
        from harness.bundle import export_bundle
        destination = Path(output).resolve()
        if destination == self.workspace or destination.is_relative_to(self.workspace):
            raise ValueError('frozen delivery must be outside the mutable agent workspace')
        destination.parent.mkdir(parents=True, exist_ok=True)
        report = export_bundle(self, destination, project=self.name)
        return report

    def preflight(self, check_api: bool = True) -> dict[str, object]:
        """Run real Docker/network smoke checks without invoking a paid model."""
        cp = self.exec([
            "python3", "/usr/local/lib/cybergym/preflight.py", str(self.workspace),
        ], timeout=900)
        try:
            report = json.loads(cp.stdout)
        except json.JSONDecodeError as exc:
            report = {"ok": False, "error": "invalid preflight JSON",
                      "stdout_tail": tail(cp.stdout), "stderr_tail": tail(cp.stderr)}
            (self.runtime_root / "preflight.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2) + "\n")
            raise SandboxError("preflight returned invalid JSON: " + tail(cp.stdout + cp.stderr)) from exc
        if check_api:
            try:
                report["api"] = self._api_probe()
            except (OSError, ValueError, ssl.SSLError) as exc:
                report["api"] = {"status": "failed", "error": str(exc)}
                report["ok"] = False
        report["outer_returncode"] = cp.returncode
        report["check_api"] = check_api
        if not check_api:
            report["api"] = {"status": "skipped", "reason": "check_api=False"}
        report["model_invoked"] = False
        report["claude_cli"] = {
            "default_tools": "--tools" not in self.claude_args("preflight", "unused", 1),
            "empty_mcp": True,
            "session_started": False,
            "argument_contract": "unit-test plus installed CLI --help inspection",
        }
        runtime_metadata = self.runtime_root / "runtime.json"
        if runtime_metadata.exists():
            report["runtime"] = json.loads(runtime_metadata.read_text())
        (self.runtime_root / "preflight.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        if cp.returncode or not report.get("ok"):
            raise SandboxError("preflight failed; see " + str(self.runtime_root / "preflight.json"))
        return report

    def claude_args(self, prompt: str, model: str, max_turns: int) -> list[str]:
        """Build the ordinary Claude command without starting a model session."""
        from harness.claude_session import claude_command
        return claude_command(prompt, model, max_turns,
                              debug_file="/home/agent/claude-debug.log")

    def run_claude(
        self,
        prompt: str,
        model: str,
        timeout_sec: int,
        max_turns: int,
        log_path: str | Path,
        view_dir: str | Path | None = None,
    ) -> ClaudeResult:
        """Run one ordinary Claude Code session and stream JSONL to ``log_path``.

        There is intentionally no ``--tools`` whitelist. MCP is constrained to
        an explicit empty configuration, user/project settings are disabled,
        and the optional network plugin is mounted read-only at container start.
        """
        if not prompt or not model or max_turns <= 0 or timeout_sec <= 0:
            raise ValueError("prompt/model must be nonempty and timeout/max_turns positive")
        log_path = Path(log_path)
        if not log_path.is_absolute():
            log_path = self.runtime_root / log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path = log_path.with_name(log_path.name + ".stderr")
        args = self.claude_args(prompt, model, max_turns)
        from harness.claude_session import TurnBudget
        budget = TurnBudget(max_turns)
        # No stop/finally cleanup here: the parent snapshot controller owns the
        # still-running sandbox after normal exit, error, or timeout.
        process, token, _ = self._start_exec(
            args, AGENT_USER, self._claude_env, subprocess.PIPE, subprocess.PIPE,
        )
        started = time.monotonic()
        state = {"timed_out": False}

        def expire() -> None:
            if process.poll() is None:
                state["timed_out"] = True
                self._kill_exec(token)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()

        timer = threading.Timer(timeout_sec, expire)
        timer.daemon = True
        timer.start()
        try:
            with log_path.open("w", encoding="utf-8") as output, stderr_path.open("w", encoding="utf-8") as errors:
                def drain_stderr() -> None:
                    assert process.stderr is not None
                    for chunk in process.stderr:
                        errors.write(chunk)
                        errors.flush()

                reader = threading.Thread(target=drain_stderr, daemon=True)
                reader.start()
                assert process.stdout is not None
                # Raw stream stays in log_path. The human Markdown view and the
                # tools-only trail go to view_dir when the batch wants them one
                # level up, beside the task directory rather than among the logs.
                view = Path(view_dir) if view_dir else log_path.parent
                view.mkdir(parents=True, exist_ok=True)
                with TrajectoryWriter(None, view / "trajectory.md",
                                      view / "trail.jsonl") as trace:
                    for line in process.stdout:
                        output.write(line)
                        output.flush()
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(event, dict) and "timestamp" not in event:
                            event["observed_at"] = datetime.now(timezone.utc).isoformat()
                        trace.write(event)
                        if budget.observe(event):
                            self._kill_exec(token)
                            break
                try:
                    # EOF and process exit are separate. A descendant can keep
                    # a pipe open after Claude's process group was killed.
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                reader.join(timeout=10)
        finally:
            timer.cancel()
        debug_path = self.home / "claude-debug.log"
        if debug_path.exists():
            shutil.copy2(debug_path, log_path.with_name("claude-debug.log"))
        return ClaudeResult(
            returncode=process.returncode,
            timed_out=state["timed_out"],
            duration_sec=time.monotonic() - started,
            log_path=log_path,
            stderr_path=stderr_path,
            num_turns=budget.turns,
            turn_limit_reached=budget.turns >= max_turns,
        )

    def stop(self, remove_data: bool = False) -> None:
        """Remove only this attempt's outer container and bridge.

        The workspace is retained. ``remove_data`` additionally removes the
        local inner data-root and disposable Claude home. It is never called by
        ``run_claude`` itself.
        """
        errors: list[str] = []
        removed_container = not self._created_container
        removed_network = not self._created_network
        if self._created_container:
            cp = self._host(["docker", "rm", "-f", self.container], timeout=90)
            if cp.returncode and "No such container" in cp.stderr:
                cp.returncode = 0
            if cp.returncode:
                errors.append("container: " + tail(cp.stderr))
            else:
                self._created_container = False
                removed_container = True
        if self._created_network and not self._created_container:
            cp = self._host(["docker", "network", "rm", self.network], timeout=45)
            if cp.returncode and "No such network" in cp.stderr:
                cp.returncode = 0
            if cp.returncode:
                errors.append("network: " + tail(cp.stderr))
            else:
                self._created_network = False
                removed_network = True
        self._started = False
        if remove_data and not self._created_container:
            for path in (self.docker_root, self.home):
                try:
                    shutil.rmtree(path)
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    errors.append(f"data {path}: {exc}")
        cleanup = {
            "container": self.container,
            "network": self.network,
            "container_removed": removed_container,
            "network_removed": removed_network,
            "remove_data": remove_data,
            "data_removed": remove_data and not self._created_container and not any(
                item.startswith("data ") for item in errors),
            "errors": errors,
        }
        (self.runtime_root / "cleanup.json").write_text(json.dumps(cleanup, indent=2) + "\n")
        self._cleanup_log_written = True
        if errors:
            raise SandboxError("sandbox cleanup failed: " + "; ".join(errors))
