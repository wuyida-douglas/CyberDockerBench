#!/usr/bin/env python3
"""In-sandbox, no-model integration preflight for the CyberGym runtime."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

NAME = "cybergym-smoke-" + uuid.uuid4().hex[:12]
IMAGE = NAME + ":built"
COMMITTED = NAME + ":committed"
COMPOSE_PROJECT = NAME.replace("_", "-")
VOLUME = COMPOSE_PROJECT + "_state"
report: dict[str, object] = {"ok": False, "image": IMAGE, "checks": []}


def record(name: str, command: list[str], started: float, cp: subprocess.CompletedProcess) -> None:
    entry = {
        "name": name,
        "ok": cp.returncode == 0,
        "duration_sec": round(time.monotonic() - started, 3),
        "command": command,
        "returncode": cp.returncode,
        "stdout_tail": (cp.stdout or "")[-1500:],
        "stderr_tail": (cp.stderr or "")[-1500:],
    }
    report["checks"].append(entry)  # type: ignore[union-attr]
    if cp.returncode:
        raise RuntimeError(f"{name} failed ({cp.returncode}): {entry['stderr_tail']}")


def run(name: str, command: list[str], *, timeout: int = 120, cwd: Path | None = None,
        expected: str | None = None) -> subprocess.CompletedProcess:
    started = time.monotonic()
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, cwd=cwd, env=env, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    cp = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    record(name, command, started, cp)
    if expected is not None and expected not in cp.stdout:
        raise RuntimeError(f"{name}: expected {expected!r}, got {cp.stdout[-500:]!r}")
    return cp


def network_step(name, function) -> None:
    """Record network failures but continue the independent Docker checks."""
    try:
        function()
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
        report.setdefault("network_failures", []).append({"name": name, "error": str(exc)})


def main(workspace: Path) -> int:
    token = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix=".cybergym-preflight-", dir=workspace) as temporary:
        root = Path(temporary)
        bind = root / "bind"
        bind.mkdir()
        (bind / "same-path.txt").write_text("same-path-" + token + "\n")
        (root / "marker.txt").write_text("built-" + token + "\n")
        (root / "Dockerfile").write_text(
            "FROM alpine:3.20\n"
            "COPY marker.txt /etc/cybergym-marker\n"
            "RUN test \"$(cat /etc/cybergym-marker)\" = \"built-" + token + "\"\n"
        )
        compose = root / "compose.yaml"
        compose.write_text(f'''services:
  writer:
    image: {IMAGE}
    command: ["sh", "-c", "printf volume-ok > /state/value; printf bind-ok > /bind/from-inner; exec sleep 300"]
    volumes:
      - state:/state
      - {str(bind)}:/bind
  reader:
    image: {IMAGE}
    depends_on:
      - writer
    command: ["sh", "-c", "i=0; while [ ! -f /state/value ]; do i=$((i+1)); test $i -lt 30; sleep 1; done; exec sleep 300"]
    volumes:
      - state:/state
      - {str(bind)}:/bind
volumes:
  state: {{}}
''')
        compose_started = False
        bootstrap_archive = os.environ.get("CYBERGYM_SMOKE_BASE_IMAGE_ARCHIVE", "")
        try:
            if bootstrap_archive:
                archive = Path(bootstrap_archive).resolve()
                archive.relative_to(workspace)
                run("offline-public-base-load", ["docker", "image", "load", "--input", str(archive)], timeout=120)
                report["base_bootstrap"] = {"source": "explicit public smoke archive", "tag": "alpine:3.20"}
            run("ordinary-agent-and-socket", ["bash", "-c",
                "test \"$(id -u)\" = 1000 && id -nG | tr ' ' '\\n' | grep -qx docker && "
                "test -S /var/run/docker.sock && test -w /var/run/docker.sock && "
                "docker info --format '{{.ServerVersion}}'"])
            run("ordinary-device-access", ["bash", "-c",
                "test -r /dev/null && test -w /dev/null && "
                "docker buildx version >/dev/null && docker compose version >/dev/null"])
            run("docker-cli-plugins", ["bash", "-c",
                "docker --version && docker compose version && docker buildx version"])
            run("claude-help-no-api", ["bash", "-c",
                "claude --version && claude --help | grep -q -- '--strict-mcp-config' && "
                "claude --help | grep -q -- '--permission-prompts' && "
                "claude --help | grep -q -- '--output-format' && "
                "claude --help | grep -q -- '--plugin-dir'"])
            # No Claude session is started: CLI argument construction is checked
            # by the controller unit tests and recorded in preflight.json.
            run("no-private-material", ["bash", "-c",
                "for path in /gold /tasks /app; "
                "do test ! -e \"$path\" || { echo \"exposed: $path\"; exit 1; }; done; "
                "test ! -e /mnt/shared-storage-user/datafactory-share/wuyida/cyberdockerbench/tasks; "
                "test ! -e /mnt/shared-storage-user/datafactory-share/wuyida/cyberdockerbench/harness; "
                "test ! -e /mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cyberdockerbench/cybergym/downloads; "
                "test ! -e /mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cyberdockerbench/cybergym/final-reference; "
                "test -z \"${ANTHROPIC_AUTH_TOKEN:-}${ANTHROPIC_API_KEY:-}\""])
            plugin = Path("/opt/cdb-network-plugin")
            if plugin.exists():
                run("optional-network-plugin-read-only", ["bash", "-c",
                    "test -r /opt/cdb-network-plugin/skills/kkrepo-network/SKILL.md && "
                    "! touch /opt/cdb-network-plugin/.write-probe 2>/dev/null"])
            run("outer-dns", ["getent", "hosts", "registry-1.docker.io"])
            network_step("apt", lambda: (
                run("apt-update-small", ["sudo", "-n", "apt-get", "update",
                    "-o", "Acquire::Retries=1",
                    "-o", "Acquire::http::Timeout=15",
                    "-o", "Acquire::https::Timeout=15"], timeout=180),
                run("apt-download-small", ["apt-get", "download", "ca-certificates"],
                    timeout=120, cwd=root),
            ))
            network_step("git", lambda: run("git-public-connectivity", [
                "git", "-c", "http.connectTimeout=15", "ls-remote",
                os.environ.get("CYBERGYM_GIT_SMOKE_URL", "https://github.com/octocat/Hello-World.git"),
                "HEAD"], timeout=45))
            if bootstrap_archive:
                report.setdefault("network_failures", []).append({
                    "name": "registry",
                    "error": "external registry probe intentionally skipped; explicit public base archive used",
                })
            else:
                network_step("registry", lambda: run("registry-pull-small", [
                    "docker", "pull", "alpine:3.20"], timeout=240))
            run("docker-build", ["docker", "build", "--network=none", "--pull=false",
                "--tag", IMAGE, "."], timeout=240, cwd=root)
            run("buildx-build", ["docker", "buildx", "build", "--builder", "default",
                "--network=none", "--pull=false", "--load", "--tag", IMAGE, "."], timeout=240, cwd=root)
            run("same-path-bind-run", ["docker", "run", "--rm", "-v", f"{bind}:/bind:ro",
                IMAGE, "cat", "/bind/same-path.txt"], expected="same-path-" + token)
            network_step("inner-dns", lambda: run("inner-container-dns", [
                "docker", "run", "--rm", IMAGE, "getent", "hosts", "registry-1.docker.io"]))
            run("compose-config", ["docker", "compose", "-p", COMPOSE_PROJECT,
                "-f", str(compose), "config", "--quiet"])
            run("compose-up-two-services", ["docker", "compose", "-p", COMPOSE_PROJECT,
                "-f", str(compose), "up", "-d", "--wait"], timeout=120)
            compose_started = True
            container = run("compose-container-id", ["docker", "compose", "-p", COMPOSE_PROJECT,
                "-f", str(compose), "ps", "-q", "writer"]).stdout.strip()
            if not container:
                raise RuntimeError("compose writer has no container ID")
            run("docker-exec", ["docker", "exec", container, "cat", "/state/value"],
                expected="volume-ok")
            run("docker-cp", ["docker", "cp", str(bind / "same-path.txt"), container + ":/tmp/copied"])
            run("docker-cp-verify", ["docker", "exec", container, "cat", "/tmp/copied"],
                expected="same-path-" + token)
            if (bind / "from-inner").read_text().strip() != "bind-ok":
                raise RuntimeError("Compose same-path bind did not update outer file")
            run("docker-commit", ["docker", "commit", container, COMMITTED], timeout=120)
            run("docker-volume-inspect", ["docker", "volume", "inspect", VOLUME])
            run("docker-volume-content", ["docker", "run", "--rm", "-v", VOLUME + ":/state:ro",
                IMAGE, "cat", "/state/value"], expected="volume-ok")
            run("docker-committed-run", ["docker", "run", "--rm", COMMITTED,
                "cat", "/etc/cybergym-marker"], expected="built-" + token)
            report["ok"] = not report.get("network_failures")
            report["docker_ok"] = True
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
            report["error"] = str(exc)
            report["docker_ok"] = False
        finally:
            report["resources"] = {
                "compose_project": COMPOSE_PROJECT,
                "images": [COMMITTED, IMAGE],
                "volume": VOLUME,
            }
            # Only resources with this random, preflight-owned project/name.
            for command in (
                ["docker", "compose", "-p", COMPOSE_PROJECT, "-f", str(compose), "down", "-v"],
                ["docker", "image", "rm", "-f", COMMITTED, IMAGE],
            ):
                try:
                    cp = subprocess.run(command, capture_output=True, text=True, timeout=90)
                    if cp.returncode and (compose_started or "image" in command):
                        report.setdefault("cleanup_warnings", []).append(cp.stderr[-1000:])  # type: ignore[union-attr]
                except (OSError, subprocess.TimeoutExpired) as exc:
                    report.setdefault("cleanup_warnings", []).append(str(exc))  # type: ignore[union-attr]
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: preflight.py /absolute/workspace")
    raise SystemExit(main(Path(sys.argv[1]).resolve()))
