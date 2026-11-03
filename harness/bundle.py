"""Freeze a declarative source tree for a clean rebuild.

This module deliberately talks to a small DockerSandbox duck type.  It does
not import the old DockerSandbox (or the exploit-from-git orchestrator).
The delivery root is ``out_dir / 'delivery'``. The controller calls this only
after the interactive session has ended. Running containers are not exported.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

BUNDLE_SCHEMA = 1
_DEFAULT_TIMEOUT = 120
# Claude's own debug log. The runner moves this file out of the workspace and
# deletes the `latest` alias; export skips whichever copy is still here. A
# directory or project file that merely contains "log" in its name is kept.
_HARNESS_DEBUG_LOG = "cli-debug.log"
_EXCLUSION_RULES = (
    "regular file named cli-debug.log",
    "symlink whose target is cli-debug.log",
)
_SENSITIVE_SETTING = re.compile(
    r"(?:ANTHROPIC_(?:AUTH_TOKEN|API_KEY)|OPENAI_API_KEY|"
    r"(?:API|AUTH|ACCESS)[_-]?(?:KEY|TOKEN|SECRET)|"
    r"CLAUDE_(?:API_KEY|AUTH_TOKEN)|MODEL_(?:API_KEY|AUTH_TOKEN))$",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?:sk-(?:ant-)?[A-Za-z0-9_-]{12,}|"
    r"(?:api[_-]?(?:key|token)|auth[_-]?token|access[_-]?token)"
    r"\s*[:=]\s*[^\s,;]+)",
    re.IGNORECASE,
)
_REDacted = "<redacted: model API credential removed>"


class PipelineError(RuntimeError):
    """Base error for export failures."""


class ExportError(PipelineError):
    """The application was not completely and safely exportable."""


def _error(kind: type[PipelineError], message: str) -> PipelineError:
    return kind(message)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _result_text(cp: Any, name: str) -> str:
    return _text(getattr(cp, name, "") or "")


def _check(cp: Any, operation: str, *, error: type[PipelineError] = ExportError) -> Any:
    if int(getattr(cp, "returncode", 1) or 0) != 0:
        detail = (_result_text(cp, "stderr") or _result_text(cp, "stdout"))[-3000:]
        raise _error(error, f"{operation} failed: {detail.strip() or 'no diagnostic'}")
    return cp


def _docker(sandbox: Any, args: Sequence[str], *, timeout: int = _DEFAULT_TIMEOUT,
            error: type[PipelineError] = ExportError) -> Any:
    # Do not turn a command into a string: sandbox.docker executes this list
    # against the inner daemon, and arbitrary Compose names remain arguments.
    argv = [str(arg) for arg in args]
    try:
        cp = sandbox.docker(argv, timeout=timeout)
    except TypeError:
        # A small convenience for older duck-typed test doubles; the actual
        # sandbox API has keyword timeout.
        cp = sandbox.docker(argv, timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise _error(error, f"docker {argv[0] if argv else ''} failed: {exc}") from exc
    return _check(cp, "docker " + shlex.join(argv[:4]), error=error)


def _json_output(cp: Any, operation: str, *, error: type[PipelineError] = ExportError) -> Any:
    text = _result_text(cp, "stdout").strip()
    try:
        return json.loads(text)
    except (TypeError, ValueError) as exc:
        raise _error(error, f"{operation} returned invalid JSON: {text[-500:]}") from exc


def _absolute(value: Path | str, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ExportError(f"{label} must be absolute, got {path}")
    return path.resolve()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _safe_relative(value: str | Path) -> Path:
    rel = Path(value)
    if rel.is_absolute() or not rel.parts or any(part in ("", ".", "..") for part in rel.parts):
        raise ExportError(f"unsafe bundle-relative path: {value!r}")
    return rel


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def _symlink_target(link: Path) -> str:
    try:
        return os.readlink(link)
    except OSError as exc:
        raise ExportError(f"cannot read symlink {link}: {exc}") from exc


def _check_source_symlink(link: Path, workspace: Path) -> str:
    target = _symlink_target(link)
    candidate = Path(target) if os.path.isabs(target) else link.parent / target
    resolved = candidate.resolve(strict=False)
    if not _inside(resolved, workspace):
        raise ExportError(f"workspace symlink escapes its root: {link} -> {target}")
    return target


def _excluded(path: Path, workspace: Path, output: Path) -> bool:
    """Skip the export directory itself and Claude's debug log.

    Filename and directory-name skips have deleted real project files
    (a vendored ``log/`` package, a ``runtime/`` mount). Caches, ``.git``,
    ``.env``, ``.npmrc`` and ``*.log`` stay in the tree the grader rebuilds.
    """
    del workspace
    if _inside(path, output):
        return True
    try:
        info = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        try:
            return Path(os.readlink(path)).name == _HARNESS_DEBUG_LOG
        except OSError:
            return False
    return stat.S_ISREG(info.st_mode) and path.name == _HARNESS_DEBUG_LOG


def _scan_source(workspace: Path, output: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    excluded: list[str] = []
    pending: list[Path] = []
    try:
        children = sorted(workspace.iterdir(), key=lambda p: p.name)
    except OSError as exc:
        raise ExportError(f"cannot enumerate workspace {workspace}: {exc}") from exc
    for child in children:
        if _excluded(child, workspace, output):
            excluded.append(str(child.relative_to(workspace)))
            continue
        pending.append(child)
    while pending:
        path = pending.pop()
        if _excluded(path, workspace, output):
            excluded.append(str(path.relative_to(workspace)))
            continue
        try:
            info = path.lstat()
        except OSError as exc:
            raise ExportError(f"cannot stat workspace entry {path}: {exc}") from exc
        rel = str(path.relative_to(workspace))
        if stat.S_ISLNK(info.st_mode):
            # Claude writes `latest` -> cli-debug.log in the workspace. The runner
            # then moves that log out, so freezing the alias leaves a dangling
            # absolute link that the grader cannot open.
            try:
                link_target = os.readlink(path)
            except OSError as exc:
                raise ExportError(f"cannot read symlink {path}: {exc}") from exc
            if Path(link_target).name == 'cli-debug.log':
                excluded.append(rel)
                continue
            _check_source_symlink(path, workspace)
            rows.append({"path": rel, "type": "symlink", "target": link_target,
                         "mode": stat.S_IMODE(info.st_mode)})
        elif stat.S_ISDIR(info.st_mode):
            rows.append({"path": rel, "type": "directory", "mode": stat.S_IMODE(info.st_mode)})
            pending.extend(sorted(path.iterdir(), key=lambda p: p.name, reverse=True))
        elif stat.S_ISREG(info.st_mode):
            rows.append({"path": rel, "type": "file", "mode": stat.S_IMODE(info.st_mode),
                         "size": info.st_size})
        else:
            raise ExportError(f"non-deliverable workspace entry {rel}: not a regular file/dir/symlink")
    rows.sort(key=lambda row: row["path"])
    return rows, sorted(set(excluded))


def _copy_source_file(path: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with path.open("rb") as source, destination.open("wb") as target:
        shutil.copyfileobj(source, target, length=1024 * 1024)
    shutil.copystat(path, destination, follow_symlinks=False)


def _freeze_source(workspace: Path, output: Path) -> dict[str, Any]:
    if not workspace.is_dir():
        raise ExportError(f"workspace is not a directory: {workspace}")
    entries, excluded = _scan_source(workspace, output)
    source_root = output / "source"
    source_root.mkdir(parents=True)
    for row in entries:
        rel = _safe_relative(row["path"])
        original = workspace / rel
        target = source_root / rel
        if row["type"] == "directory":
            target.mkdir(parents=True, exist_ok=True)
            os.chmod(target, row["mode"])
        elif row["type"] == "symlink":
            # Revalidate immediately before creating the link.  No source path
            # is ever dereferenced by the copy loop.
            _check_source_symlink(original, workspace)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(row["target"])
        else:
            _copy_source_file(original, target)
    # The scan's path/type/mode/size rows exist only to copy the tree.
    # Nothing reads them after export, so they are not written into the inventory.
    return {"schema_version": BUNDLE_SCHEMA, "root": ".",
            "exclusions": list(_EXCLUSION_RULES),
            "excluded_paths": excluded,
            "file_count": sum(row["type"] == "file" for row in entries)}


def _compose_parts(sandbox: Any, compose: str, project: str) -> list[str]:
    return ["compose", "-f", compose, "-p", project]


def _compose_config(sandbox: Any, compose: str, project: str) -> dict[str, Any]:
    cp = _docker(sandbox, [*_compose_parts(sandbox, compose, project),
                          "config", "--format", "json"])
    config = _json_output(cp, "docker compose config")
    if not isinstance(config, dict) or not isinstance(config.get("services"), dict):
        raise ExportError("compose config does not contain a services mapping")
    return config


def _validate_source_closure(config: Mapping[str, Any], compose: str,
                             workspace: Path) -> None:
    """Check declared build/bind/config inputs against the frozen workspace.

    The full tree is already frozen; this check finds agent declarations which
    point outside it instead of silently exporting a different live container.
    Runtime-generated or absolute paths inside a container are not host inputs.
    """
    compose_path = Path(compose)
    compose_directory = compose_path.parent

    def require(value: Any, description: str) -> None:
        if not isinstance(value, str) or not value:
            raise ExportError(f'invalid {description} path: {value!r}')
        # config --format json preserves unresolved variables. Check their
        # textual location first: '/$WORKSPACE/src' is a valid absolute path,
        # even though it does not start with the literal workspace prefix.
        candidate = Path(os.path.expandvars(value)).expanduser()
        if not candidate.is_absolute():
            candidate = compose_directory / candidate
        if not _inside(candidate, workspace):
            try:
                candidate.resolve(strict=False).relative_to(workspace.resolve())
            except ValueError as exc:
                raise ExportError(
                    f'{description} {value!r} is outside the declarative workspace') from exc
        if not candidate.exists() and not candidate.is_symlink():
            raise ExportError(f'declared {description} is missing: {value!r}')

    for name, raw_service in config.get('services', {}).items():
        service = raw_service if isinstance(raw_service, dict) else {}
        build = service.get('build')
        if isinstance(build, str):
            require(build, f'{name} build context')
        elif isinstance(build, Mapping):
            require(build.get('context', '.'), f'{name} build context')
            dockerfile = build.get('dockerfile')
            if dockerfile:
                context = Path(str(build.get('context', '.')))
                if not context.is_absolute():
                    context = compose_directory / context
                require(str(context / str(dockerfile)), f'{name} Dockerfile')
            for extra in build.get('additional_contexts') or {}:
                require(extra, f'{name} additional build context')
        for mount in service.get('volumes') or []:
            if isinstance(mount, Mapping) and mount.get('type') == 'bind':
                require(mount.get('source'), f'{name} bind')
        env_files = service.get('env_file') or []
        if isinstance(env_files, (str, Mapping)):
            env_files = [env_files]
        for env_file in env_files:
            value = env_file.get('path') if isinstance(env_file, Mapping) else env_file
            require(value, f'{name} env_file')
        for section in ('configs', 'secrets'):
            for item in service.get(section) or []:
                if isinstance(item, Mapping) and item.get('source'):
                    definition = (config.get(section) or {}).get(item['source'], {})
                    if isinstance(definition, Mapping) and definition.get('file'):
                        require(definition['file'], f'{name} {section}')


def _clean_for_inventory(value: Any, key: str = "") -> Any:
    if isinstance(value, Mapping):
        return {str(k): _clean_for_inventory(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean_for_inventory(v, key) for v in value]
    if isinstance(value, str):
        if _SENSITIVE_SETTING.search(key):
            return _REDacted
        return _SECRET_VALUE.sub("<redacted-credential>", value)
    return value


def export_bundle(sandbox: Any, out_dir: Path | str, *, project: str,
                  compose_path: Path | str | None = None) -> dict[str, Any]:
    """Freeze the declarative project into ``out_dir/delivery``.

    ``project`` is the original Compose project.  ``compose_path`` defaults to
    ``sandbox.workspace / 'docker-compose.yaml'`` and is interpreted in the
    outer sandbox.      Only the workspace tree is copied.  Running containers and committed
    images are not part of that tree.  Named-volume bytes are not either:
    grading rebuilds the project and creates those disks empty.  The copy
    skips Claude's ``cli-debug.log`` and a symlink to it, and it does not
    copy the delivery directory into itself.  Other workspace files are kept,
    including caches, ``.git``, ``.env`` and files whose names end in ``.log``.
    The inventory records a file count.  It does not hash file contents, and
    no SHA256SUMS file is written.  No partial delivery is accepted.
    """
    if not project or not isinstance(project, str) or any(c.isspace() for c in project):
        raise ExportError("project must be a non-empty Compose project name without whitespace")
    output = _absolute(out_dir, "out_dir") / "delivery"
    if output.exists() or output.is_symlink():
        raise ExportError(f"refusing to overwrite existing delivery: {output}")
    workspace_value = getattr(sandbox, "workspace", None)
    if workspace_value is None:
        raise ExportError("sandbox.workspace is required")
    workspace = _absolute(workspace_value, "sandbox.workspace")
    if _inside(output, workspace):
        # It is explicitly excluded from the freeze; this also permits the
        # common runtime/results directory layout.
        pass
    compose = str(compose_path or (workspace / "docker-compose.yaml"))
    if not compose.startswith("/"):
        raise ExportError("compose_path must be absolute inside the sandbox")
    if Path(compose).name not in ("docker-compose.yaml", "docker-compose.yml", "compose.yaml", "compose.yml"):
        # Allow custom names, but reject an accidental directory early.
        if Path(compose).suffix not in (".yaml", ".yml"):
            raise ExportError("compose_path must name a YAML Compose file")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    complete = False
    try:
        source_inventory = _freeze_source(workspace, output)
        config = _compose_config(sandbox, compose, project)
        _validate_source_closure(config, compose, workspace)
        task_id = str(getattr(sandbox, "task_id", "task"))
        source_inventory.update({
            "task_id": task_id, "project": project,
            "compose_file": "source/" + str(Path(compose).relative_to(workspace)) if _inside(Path(compose), workspace) else "source/docker-compose.yaml",
            "declared_services": list(config["services"]),
            "compose_config": _clean_for_inventory(config),
        })
        _write_json(output / "bundle.json", {
            "schema_version": BUNDLE_SCHEMA,
            "task_id": task_id,
            "project": project,
            "source": "source",
            "inventories": ["source-inventory.json"],
        })
        result = source_inventory
        _write_json(output / "source-inventory.json", source_inventory)
        complete = True
        return result
    except PipelineError:
        raise
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ExportError(f"bundle export failed: {exc}") from exc
    finally:
        if not complete:
            # A partial package is not a valid fallback.  Keep the error
            # actionable while avoiding accidental later use of that package.
            shutil.rmtree(output, ignore_errors=True)



__all__ = ["PipelineError", "ExportError", "export_bundle"]
