"""Static public-input and leak audit for CyberGym source-only tasks.

The audit never treats a successful HTTP fetch or a patch as solvability.
Reference verification is a separate private operation. ``audit_task`` accepts
both a task directory and the shared TaskSpec for compatibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import stat
import tarfile
from pathlib import Path, PurePosixPath

import yaml

from harness.cybergym_pipeline.prepare.verify import (
    GENERIC_SANITIZER, crash_type_observed, digest_file, sanitizer_observed, stack_observed,
)
from harness.task_api import TaskSpec

TEXT_SUFFIXES = {".md", ".txt", ".json", ".yaml", ".yml", ".sh", ".diff", ".patch"}
DANGEROUS_PARTS = {".git", ".svn", ".hg", "private"}
# The task-level input/poc is the deliberate public reproducer in CyberGym.
# Keep rejecting reproducer-like artifacts inside the pristine source archives.
DANGEROUS_NAMES = {"crash_case", "poc", "testcase", "reproducer", "reproducer.bin", "gold-poc"}
# Names such as binutils-gdb/gold, mruby-compiler/core, and ImageMagick's
# documentation core are legitimate source paths. Only exact compiled output
# directories and actual binary/reproducer contents are prohibited.
BINARY_SUFFIXES = {".a", ".o", ".so", ".dll", ".dylib", ".exe", ".class", ".jar", ".pyc"}
LEAK_PATTERNS = {
    "official_reference_image": re.compile(rb"(?:n132/arvo|docker\.io/n132/arvo)"),
    "private_store_path": re.compile(rb"shared-storage-gpfs2[^\s\x00]*cyberdockerbench"),
    "raw_reproducer_url": re.compile(rb"(?:oss-fuzz\.com/download|testcase_id=)"),
    "gold_poc": re.compile(rb"(?:GOLD[ _-]?PoC|gold[/_-]poc|private[/_-]poc)"),
}
PROVENANCE_FILES = {
    "input/sources-vul.tar.gz", "input/sources-fix.tar.gz",
    "input/srcmap-vul.json", "input/srcmap-fix.json",
    "input/oss-fuzz-vul.json", "input/oss-fuzz-fix.json",
    "input/description.md", "input/error.txt",
    # Legacy tasks may still carry NETWORKING.md; new tasks keep it in TASK.md.
    "input/NETWORKING.md", "input/manifest.json", "instruction.md", "metadata.yaml",
}


def is_executable_bytes(data: bytes, mode: int = 0) -> bool:
    """Reject compiled binaries, not text scripts or normal seed corpus bytes."""
    if data.startswith((b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
                        b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"!<arch>\n")):
        return True
    return bool(mode & stat.S_IXUSR and data.startswith(b"\0"))


def audit_tar(path: Path, max_files: int = 150_000) -> dict:
    issues: list[str] = []
    try:
        with tarfile.open(path, "r:*") as archive:
            members = archive.getmembers()
            if len(members) > max_files:
                issues.append(f"archive exceeds {max_files} members")
            for member in members:
                pure = PurePosixPath(member.name)
                if pure.is_absolute() or ".." in pure.parts or "\\" in member.name or "\x00" in member.name:
                    issues.append(f"unsafe archive path: {member.name!r}")
                if {part.lower() for part in pure.parts} & DANGEROUS_PARTS:
                    issues.append(f"archive leaked metadata/output: {member.name}")
                if pure.name.lower() in DANGEROUS_NAMES:
                    issues.append(f"archive leaked PoC-like name: {member.name}")
                if member.issym() or member.islnk():
                    issues.append(f"archive link requires removal: {member.name}")
                if not member.isfile():
                    continue
                if pure.suffix.lower() in BINARY_SUFFIXES:
                    issues.append(f"archive binary extension: {member.name}")
                if member.size > 512 * 1024 * 1024:
                    issues.append(f"oversized source member: {member.name}")
                handle = archive.extractfile(member)
                if handle is not None and is_executable_bytes(handle.read(8192), member.mode):
                    issues.append(f"archive executable content: {member.name}")
    except (OSError, tarfile.TarError) as exc:
        issues.append(f"unreadable source archive: {exc}")
    return {"path": str(path), "issues": issues}


def audit_tree(input_dir: Path) -> dict:
    issues: list[str] = []
    file_count = total_bytes = 0
    if input_dir.is_symlink() or not input_dir.is_dir():
        return {"issues": ["input must be a real directory"], "files": 0, "bytes": 0}
    for path in input_dir.rglob("*"):
        relative = path.relative_to(input_dir)
        if path.is_symlink():
            issues.append(f"public input symlink: {relative}")
            continue
        if any(part.lower() in DANGEROUS_PARTS for part in relative.parts):
            issues.append(f"public input metadata/output: {relative}")
        if path.name.lower() in DANGEROUS_NAMES and relative.as_posix() != "poc":
            issues.append(f"public input PoC-like name: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            issues.append(f"non-regular public input: {relative}")
            continue
        file_count += 1
        total_bytes += path.stat().st_size
        if path.suffix.lower() in BINARY_SUFFIXES:
            issues.append(f"public binary extension: {relative}")
        with path.open("rb") as handle:
            data = handle.read(1024 * 1024)
        if is_executable_bytes(data, path.stat().st_mode):
            issues.append(f"public binary content: {relative}")
        if path.name.endswith((".tar.gz", ".tgz", ".tar")):
            issues.extend(f"{relative}: {item}" for item in audit_tar(path)["issues"])
        else:
            for label, pattern in LEAK_PATTERNS.items():
                if pattern.search(data):
                    issues.append(f"public {label}: {relative}")
    return {"issues": issues, "files": file_count, "bytes": total_bytes}


def audit_reference(task_dir: Path, metadata: dict, evidence: dict) -> list[str]:
    """Independently recheck recorded official-reference evidence and log bytes."""
    errors: list[str] = []
    if evidence.get("reference_verified") is not True:
        errors.append("private reference evidence lacks reference_verified=true")
    issue = str(metadata.get("upstream_task_id", ""))
    if evidence.get("upstream_task_id") != issue:
        errors.append("reference evidence upstream_task_id mismatch")
    poc = task_dir / "gold" / "poc"
    if not poc.is_file() or not poc.stat().st_size:
        errors.append("private GOLD PoC missing or empty")
    else:
        expected_poc_sha = evidence.get("gold_poc_sha256") or (evidence.get("gold_poc") or {}).get("sha256")
        if not expected_poc_sha or digest_file(poc) != expected_poc_sha:
            errors.append("private GOLD PoC digest differs from reference evidence")
    for role in ("vul", "fix"):
        result = (evidence.get("runs") or {}).get(role) or {}
        image = (evidence.get("images") or {}).get(role) or {}
        expected_image = f"n132/arvo:{issue.split(':')[-1]}-{role}"
        if image.get("image") != expected_image:
            errors.append(f"{role} reference image identity mismatch")
        if not image.get("rootfs_layers") or not result.get("digest"):
            errors.append(f"{role} reference image runtime identity missing")
        if result.get("passed") is not True:
            errors.append(f"{role} reference run did not pass")
            continue
        command = result.get("command")
        if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
            errors.append(f"{role} evidence does not record an official /tmp/poc run")
        elif (task_dir / "gold" / "poc").is_file():
            errors.extend(audit_reference_command(command, role, task_dir / "gold" / "poc",
                                                 expected_image=expected_image))
        if (not isinstance(command, list) or not all(isinstance(item, str) for item in command)
                or result.get("command_text") != shlex.join(command)):
            errors.append(f"{role} evidence command_text does not match the executed command")
        log_name = result.get("log")
        if not isinstance(log_name, str) or Path(log_name).name != log_name:
            errors.append(f"{role} reference log path is not a safe basename")
            continue
        log = task_dir / "gold" / "reference-logs" / log_name
        if not log.is_file() or digest_file(log) != result.get("log_sha256"):
            errors.append(f"{role} reference log missing or digest mismatch")
            continue
        text = log.read_text(encoding="utf-8", errors="replace")
        if role == "vul":
            if not sanitizer_observed(text, str(metadata.get("sanitizer", ""))):
                errors.append("vulnerable reference log lacks expected sanitizer")
            if not crash_type_observed(text, str(metadata.get("crash_type", ""))):
                errors.append("vulnerable reference log lacks expected crash type")
            frames = stack_observed(text, metadata.get("expected_stack") or [])
            if not all(frames.values()):
                errors.append(f"vulnerable reference log misses expected stack: {[key for key, value in frames.items() if not value]}")
            if result.get("timed_out"):
                errors.append("vulnerable reference run timed out")
        elif result.get("return_code") != 0 or result.get("timed_out"):
            errors.append("fixed reference did not exit normally with code 0")
        elif GENERIC_SANITIZER.search(text):
            errors.append("fixed reference log contains an unexpected sanitizer report")
    return errors


def audit_reference_command(command: list[str], role: str, poc: Path,
                            expected_image: str) -> list[str]:
    """Validate the exact worker invocation without executing a remote shell.

    Legacy evidence has OpenSSH's remote command split into argv elements;
    current evidence correctly sends it as one shell-quoted string. Both map
    to the same actual ssh/docker execution and are checked structurally.
    """
    errors: list[str] = []
    if len(command) < 5 or command[0] != "ssh" or "join" in command:
        return [f"{role} official verification was not a supported direct worker invocation"]
    try:
        if command[-1].startswith("docker "):
            worker_args = command[1:-1]
            docker_args = shlex.split(command[-1])
        else:
            remote = command.index("docker", 1)
            worker_args = command[1:remote]
            docker_args = command[remote:]
    except (ValueError, TypeError) as exc:
        return [f"{role} official verification command is not valid: {exc}"]
    if ("BatchMode=yes" not in worker_args or
            any(item in {"sh", "bash", "sh -c", "bash -c"} for item in worker_args)):
        errors.append(f"{role} official verification did not use noninteractive direct ssh")
    if (len(docker_args) < 8 or docker_args[:5] != ["docker", "run", "--rm", "--network", "none"]
            or docker_args[-2:] != [expected_image, "arvo"]):
        errors.append(f"{role} official verification did not invoke the expected isolated docker run")
    try:
        index = docker_args.index("-v")
        bind = docker_args[index + 1]
        source, marker, destination = bind.rpartition(":/tmp/poc:ro")
        if not marker:
            raise ValueError("PoC mount has the wrong destination")
        if (not Path(source).is_absolute()
                or Path(source).resolve() != poc.resolve()):
            errors.append(f"{role} reference did not mount the exact private GOLD PoC")
    except (ValueError, IndexError):
        errors.append(f"{role} reference lacks a read-only private GOLD PoC mount")
    return errors


def audit_task(task: Path | object, require_verified: bool = True, **kwargs) -> dict:
    if "require_reference" in kwargs:
        require_verified = kwargs["require_reference"]
    task_spec = None if isinstance(task, (Path, str)) else task
    task_dir = Path(task) if task_spec is None else Path(task.path)
    metadata_path = task_dir / "metadata.yaml"
    errors: list[str] = []
    warnings: list[str] = []
    if not metadata_path.is_file():
        return {"task_id": task_dir.name, "passed": False, "valid": False,
                "issues": ["missing metadata.yaml"], "errors": ["missing metadata.yaml"], "warnings": []}
    metadata = task_spec.metadata if task_spec is not None and hasattr(task_spec, "metadata") else yaml.safe_load(metadata_path.read_text(encoding="utf-8"))
    for field in ("family", "task_type", "project", "upstream_task_id", "sanitizer",
                  "fuzz_target", "crash_type", "expected_stack", "private"):
        if field not in metadata:
            errors.append(f"missing metadata field: {field}")
    if metadata.get("family") != "cybergym":
        errors.append("family must be cybergym")
    if metadata.get("task_type") != "binary-env-synthesis":
        errors.append("task_type must be binary-env-synthesis")
    if metadata.get("reference_verified") is not True and require_verified:
        errors.append("reference verification has not passed")
    if not metadata.get("expected_stack") and not (
            metadata.get("sanitizer") in {'MSan', 'msan', 'memory'} and
            metadata.get("stack_evidence_optional") is True):
        errors.append("expected_stack must contain frames, or explicit stackless MSan evidence")
    private = metadata.get("private") or {}
    for field in ("gold_poc", "reference_manifest", "verify_reference"):
        value = private.get(field)
        if not isinstance(value, str) or not value.startswith("gold/") or ".." in Path(value).parts:
            errors.append(f"private.{field} must be a task-relative gold path")
    public = audit_tree(task_dir / "input")
    errors.extend(public.pop("issues"))
    for required in sorted(PROVENANCE_FILES):
        if not (task_dir / required).is_file():
            errors.append(f"missing public input: {required}")
    manifest_path = task_dir / "input/manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = manifest.get("files", {})
        if not isinstance(entries, dict):
            errors.append("manifest.files must be a mapping")
        else:
            for relative, expected in entries.items():
                path = task_dir / "input" / relative
                if not path.is_file():
                    errors.append(f"manifest missing file: {relative}")
                    continue
                if hashlib.sha256(path.read_bytes()).hexdigest() != expected.get("sha256"):
                    errors.append(f"manifest digest mismatch: {relative}")
            absent = {str(path.relative_to(task_dir / "input"))
                      for path in (task_dir / "input").rglob("*") if path.is_file()
                      } - set(entries) - {"manifest.json"}
            if absent:
                errors.append(f"files missing from manifest: {sorted(absent)[:12]}")
    verify_path = task_dir / private.get("verify_reference", "gold/verify_reference.json")
    if require_verified:
        if not verify_path.is_file():
            errors.append("private reference verification evidence missing")
        else:
            evidence = json.loads(verify_path.read_text(encoding="utf-8"))
            if evidence.get("passed") is not True:
                errors.append("private reference evidence did not pass")
            for role in ("vul", "fix"):
                result = (evidence.get("runs") or {}).get(role) or {}
                if not result.get("command") or not result.get("digest") or not result.get("log"):
                    errors.append(f"incomplete {role} reference evidence")
            errors.extend(audit_reference(task_dir, metadata, evidence))
    return {
        "task_id": task_dir.name, "passed": not errors, "valid": not errors,
        "issues": errors, "errors": errors, "warnings": warnings, "public": public,
        "policy": {
            "reference_images": "private verification only; never agent input",
            "gold_poc": "private gold only; never staged",
            "raw_issue": "private upstream metadata only; sanitized description/error are public",
            "source_archives": "source-only, no VCS metadata, /out or compiled outputs",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tasks", type=Path, nargs="+")
    parser.add_argument("--allow-unverified", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    reports = [audit_task(path, require_verified=not args.allow_unverified) for path in args.tasks]
    result = {"passed": all(report["passed"] for report in reports), "tasks": reports}
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
