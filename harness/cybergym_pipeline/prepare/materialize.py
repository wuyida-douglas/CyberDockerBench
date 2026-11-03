"""Materialize source-only, dual-version CyberGym task inputs.

The original CyberGym archives are downloaded from their public dataset. The
importer independently adds historical OSS-Fuzz recipes and srcmaps, and never
copies a Dockerfile or compiled artifact out of an ARVO reference image.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import yaml

from .audit import audit_tar, audit_task, is_executable_bytes

ROOT = Path(__file__).resolve().parents[3]
HF = "https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main"
SOURCE_SUFFIXES = (".tar.gz", ".tgz", ".tar")
STRIP_PARTS = {".git", ".hg", ".svn", "__pycache__"}
STRIP_NAMES = {"poc", "poc.bin", "crash_case", "testcase", "reproducer"}
BINARY_SUFFIXES = {".o", ".a", ".so", ".dll", ".dylib", ".exe", ".pyc", ".class", ".jar"}
INSTRUCTION = """# Rebuild a dual-version OSS-Fuzz sanitizer environment

Project: **{project}**. Upstream task: **{upstream_task_id}**.
This is an environment-synthesis task, not a vulnerability-discovery or PoC-generation task.

Before any `docker pull`, `docker build`, package install or `git` download, read and follow
`/opt/cdb-network-plugin/skills/kkrepo-network/SKILL.md`; it is mounted read-only in this sandbox.

## Deliverables in `/workspace`

Write every deliverable at the `/workspace` root. When your session ends the
evaluator freezes `/workspace` and grades the frozen copy only; content left in
scratch directories, containers or anywhere else does not count. Missing any
required file fails the task before any build is attempted.

Required files (hard checks):

1. `Dockerfile`: the complete declarative build for both versions, from the
   supplied vulnerable and fixed source trees and the corresponding historical
   OSS-Fuzz materials. Do not download or use prebuilt ARVO/CyberGym reference
   images or binaries.
2. `docker-compose.yaml`: two services named `vul` and `fix`, each with its own
   `build:` section and the exact label `cdb.cybergym.role=vul` /
   `cdb.cybergym.role=fix`. The evaluator rebuilds both services from this
   file; images and containers left running are not graded.
3. `smoke.sh`: a scripted check that runs one meaningful self-written smoke
   input (placed at `/tmp/smoke`) against a built image, with the expected
   clean result documented. The smoke input is not a reproducer. Running a
   seed once is a valid smoke test; do not run open-ended fuzzing. The script
   may either run inside each container (as `/smoke.sh`, invoked with
   `docker exec`) or run from the delivery root against the running Compose
   project; the evaluator accepts both forms. Inside a container the evaluator
   uses bash when the image has bash, and `sh` otherwise, so `set -o pipefail`
   is valid.
4. `/usr/local/bin/run_poc` inside each image: accepts exactly one input path
   and runs the specified fuzz target on it. The supplied debugging input is
   `poc` at the workspace root. Start each service with a harmless long-lived
   command such as `sleep infinity`. Keep the container running; the evaluator
   invokes `run_poc` with `docker exec` after copying the same input to `/tmp/poc`.

How the evaluator verifies your delivery:

- Presence: the frozen copy must contain `Dockerfile`, `docker-compose.yaml`
  and `smoke.sh`, and the compose services must carry the exact role labels.
- Rebuild: it runs `docker compose build` from the frozen files alone, in a
  clean sandbox without your caches or running containers. Anything the build
  needs must therefore live in `/workspace`: extra scripts only when your
  Dockerfile references them (a top-level `build.sh` is NOT required
  otherwise), pinned base images, fetched archives with recorded digests. The
  historical OSS-Fuzz `build.sh` is already supplied under `oss-fuzz/`; COPY it
  from there and do not rewrite it at the workspace root. No `latest`
  dependency versions when an exact historical revision or artifact is
  provided. `.env` is copied with the rest of the workspace. Do not put model
  API credentials in it. Compose values can live in `.env` or in
  `docker-compose.yaml`. A named volume such as `dbdata:/var/lib/mysql` is an
  empty disk on the clean rebuild. Data the image needs must be created in the
  Dockerfile, for example `COPY seed /opt/seed`, or mounted from a relative
  workspace path such as `./seed:/opt/seed`. Do not use `tmpfs`.
- Run: it executes your `smoke.sh` on both roles, then invokes `run_poc
  /tmp/poc` on both services as described in the Contract. For `smoke.sh` the
  evaluator first looks inside each container (`/smoke.sh` via `docker exec`,
  with bash when the image has bash). If it is not baked into the image, it
  runs the delivery-root `smoke.sh` from the sandbox with `COMPOSE_PROJECT_NAME`
  set to the grading project, so a host-side script that uses `docker compose`
  against the already-running services also works. Both sides must exit 0.
  Document the exact build/run/smoke commands you used in comments or a short
  note at the workspace root.

## Contract

- Engine: `{fuzz_engine}`; sanitizer: `{sanitizer}` (`{sanitizer_env}`); target:
  `{fuzz_target}`; architecture: `x86_64`.
- Use `/src`, `/out`, `/work` with the OSS-Fuzz conventions. The runner should
  execute `/out/{fuzz_target} /tmp/poc` with the sanitizer options documented in
  the historical materials. Do not use the reference `/bin/arvo` implementation.
- Both versions must build from their respective `sources-*.tar.gz`, not by merely
  applying a patch to an already-built binary. Use `srcmap-*.json` for dependency
  revisions and the two OSS-Fuzz recipe bundles for their respective history.
- Preserve the fuzz harness and build recipe; do not manufacture a crash input,
  guess a fix, or replace the task with a stand-alone reproducer program.
- A normal input should complete without a sanitizer report on both versions.
  The supplied `poc` is the genuine upstream reproducer. After your own build,
  `vul` must print a real sanitizer diagnostic of this bug class, and `fix`
  must exit 0 on the same input without a sanitizer error. The grader matches
  the diagnostic by words (`index 96 out of bounds` is `Index-out-of-bounds`).
  It looks for the vulnerable function names only in the crashing `vul` output.

## Supplied inputs

- `sources-vul.tar.gz` and `sources-fix.tar.gz`: cleaned source and bundled source
  dependencies, with VCS metadata, `/out`, compiled binaries and PoCs removed.
- `srcmap-vul.json` and `srcmap-fix.json`: actual historical source revisions,
  not placeholders. Use the appropriate map with each source snapshot.
- `oss-fuzz/`: original historical `Dockerfile`, `build.sh`, `project.yaml` and
  fuzz harness/recipe assets, including revision provenance and SHA-256 digests.
  These are upstream OSS-Fuzz history, not files extracted from reference images.
- `description.md`, `error.txt`: sanitized vulnerability and sanitizer information.
- `poc`: the genuine upstream reproducer bytes, provided for debugging and final
  verification.
- `manifest.json`: integrity inventory for the supplied files.
- Normal seeds are included only when available and their provenance is recorded.

Read the upstream source and OSS-Fuzz recipes yourself before choosing base
images and dependency mirrors. Network use must remain declarative and
reproducible; no answer service or reference image access is allowed.

## Network scope and historical-build constraints

Use exact source/dependency revisions from the supplied srcmaps and historical
OSS-Fuzz recipes. Network is needed only to obtain declared source, base images,
and packages, never to retrieve a reference solution, prebuilt fuzz target, issue
reproducer or external evaluator. Docker daemon access to base registries is a
separate infrastructure concern from package-manager mirrors.

Do not switch operating-system releases or disable TLS/signature verification to
work around a missing historical package. Record unavailable exact dependencies
in your build notes rather than silently replacing them with current software.
"""
def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    kwargs.setdefault("check", True)
    return subprocess.run(command, **kwargs)


def parse_sanitizer(value: str) -> tuple[str, str]:
    return {
        "asan": ("ASan", "address"),
        "msan": ("MSan", "memory"),
        "ubsan": ("UBSan", "undefined"),
        "address": ("ASan", "address"),
        "memory": ("MSan", "memory"),
        "undefined": ("UBSan", "undefined"),
    }[value]


def sanitize_text(text: str) -> str:
    text = re.sub(r"https?://[^\s)]+(?:download|testcase|reproducer)[^\s)]*", "[private upstream reproducer removed]", text, flags=re.I)
    text = re.sub(r"Reproducer Testcase:.*", "Reproducer: private evaluator input.", text, flags=re.I)
    text = re.sub(r"https?://\S*testcase_id=\S*", "[private reproducer URL removed]", text, flags=re.I)
    return text.replace("GOLD PoC", "private reference input")


def source_timestamp(srcmap_name: str) -> datetime:
    match = re.search(r"-(\d{12})\.srcmap\.json$", srcmap_name)
    if not match:
        raise ValueError(f"unrecognized srcmap timestamp: {srcmap_name}")
    return datetime.strptime(match.group(1), "%Y%m%d%H%M").replace(tzinfo=timezone.utc)


def srcmap_url(project: str, sanitizer: str, timestamp: str) -> str:
    return f"https://storage.googleapis.com/clusterfuzz-builds/{project}/{project}-{sanitizer}-{timestamp}.srcmap.json"


def discover_timestamps(upstream: dict) -> tuple[str, str]:
    text = json.dumps(upstream)
    pattern = r"https?://oss-fuzz\.com/revisions\?[^\s\"\\]+"
    urls = re.findall(pattern, text)
    vulnerable = fixed = None
    for url in urls:
        range_match = re.search(r"range=\d{12}:(\d{12})", url)
        if not range_match:
            continue
        timestamp = range_match.group(1)
        if "Regressed:" in text[max(0, text.find(url) - 40):text.find(url)]:
            vulnerable = timestamp
        if "Fixed:" in text[max(0, text.find(url) - 40):text.find(url)]:
            fixed = timestamp
    if not vulnerable or not fixed:
        # Prefer explicitly named fields from the new upstream issue metadata.
        for key, value in upstream.items():
            if key == "regressed":
                vulnerable = re.search(r"(?:range=\d{12}:|revision=)(\d{12})", str(value)).group(1)
            if key == "verified_fixed":
                fixed = re.search(r"(?:range=\d{12}:|revision=)(\d{12})", str(value)).group(1)
    if not vulnerable or not fixed:
        raise ValueError("upstream issue does not contain vulnerable/fixed srcmap revisions")
    return vulnerable, fixed


def _cleaned_tar_bytes(raw_path: Path, output_path: Path) -> dict:
    """Stream a safe source archive while retaining its original root layout."""
    removed: list[dict] = []
    kept = 0
    seen: set[str] = set()
    with tarfile.open(raw_path, "r:*") as source, tarfile.open(output_path, "w:gz", compresslevel=6) as target:
        for member in source:
            pure = PurePosixPath(member.name)
            if pure.is_absolute() or ".." in pure.parts or "\x00" in member.name or "\\" in member.name:
                raise ValueError(f"unsafe source archive path: {member.name}")
            if member.name in seen:
                raise ValueError(f"duplicate archive member: {member.name}")
            seen.add(member.name)
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                removed.append({"path": member.name, "reason": "link or non-regular archive entry"})
                continue
            reason = None
            if any(part in STRIP_PARTS for part in pure.parts) or (len(pure.parts) > 1 and pure.parts[1] == "out"):
                reason = "VCS metadata or root compiled output directory"
            elif pure.name in STRIP_NAMES or pure.name.startswith(("poc.", "reproducer.")):
                reason = "possible reproducer"
            elif pure.suffix.lower() in BINARY_SUFFIXES:
                reason = "compiled binary/library suffix"
            if reason:
                removed.append({"path": member.name, "reason": reason})
                continue
            if member.isdir():
                target.addfile(member)
                continue
            handle = source.extractfile(member)
            data = handle.read() if handle else b""
            if is_executable_bytes(data[:8192], member.mode):
                removed.append({"path": member.name, "reason": "compiled executable content"})
                continue
            if any(pattern.search(data) for pattern in (
                re.compile(rb"oss-fuzz\.com/download[^\s\x00]*testcase_id="),
                re.compile(rb"n132/arvo"),
            )):
                removed.append({"path": member.name, "reason": "reference-image or reproducer URL content"})
                continue
            info = tarfile.TarInfo(member.name)
            info.size = len(data)
            info.mode = member.mode & 0o777
            info.mtime = member.mtime
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            target.addfile(info, io.BytesIO(data))
            kept += 1
    return {
        "source_archive_sha256": sha256(raw_path),
        "output_archive_sha256": sha256(output_path),
        "source_format": "CyberGym public source archive; independently cleaned",
        "kept_files": kept,
        "removed": removed,
        "policy": "No VCS metadata, /out, compiled outputs, symlinks, reference images or reproducers.",
    }


def historical_recipe(oss_fuzz_git: Path, project: str, timestamp: datetime, output: Path) -> dict:
    stamp = timestamp.isoformat().replace("+00:00", "Z")
    commit = subprocess.check_output([
        "git", f"--git-dir={oss_fuzz_git}", "log", f"--before={stamp}",
        "-n1", "--format=%H",
    ], text=True).strip()
    if not commit:
        raise ValueError(f"no OSS-Fuzz history at {stamp}")
    files: dict[str, str] = {}
    for root in (f"projects/{project}", f"targets/{project}"):
        result = subprocess.run([
            "git", f"--git-dir={oss_fuzz_git}", "ls-tree", "-r", "--name-only", commit, "--", root,
        ], text=True, capture_output=True, check=True)
        names = [line for line in result.stdout.splitlines() if line]
        if names:
            break
    required = {"Dockerfile", "build.sh", "project.yaml"}
    basenames = {PurePosixPath(name).name for name in names}
    if not required.issubset(basenames):
        raise ValueError(f"incomplete OSS-Fuzz recipe {project}@{commit}: missing {required - basenames}")
    output.mkdir(parents=True, exist_ok=True)
    for name in names:
        data = subprocess.check_output(["git", f"--git-dir={oss_fuzz_git}", "show", f"{commit}:{name}"])
        relative = PurePosixPath(name).relative_to(root)
        if any(part in STRIP_PARTS for part in relative.parts):
            continue
        if is_executable_bytes(data[:8192]):
            raise ValueError(f"unexpected compiled recipe asset: {name}")
        destination = output.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        files[str(relative)] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    provenance = {
        "upstream": "https://github.com/google/oss-fuzz",
        "commit": commit,
        "project_directory": root,
        "srcmap_timestamp": timestamp.isoformat(),
        "source": "historical OSS-Fuzz git; not extracted from any reference image",
        "files": files,
    }
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    return provenance


def fetch(url: str, output: Path, attempts: int = 4) -> None:
    if output.is_file() and output.stat().st_size:
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".part")
    run(["curl", "-fL", "--retry", str(attempts), "--retry-all-errors", "--connect-timeout", "20",
         "--max-time", "900", url, "-o", str(temporary)])
    temporary.replace(output)


def sanitize_cleaning_report(report: dict) -> dict:
    """Remove private extraction details from cached or newly written evidence."""
    report.pop("source_export_evidence", None)
    return report


def sanitize_public_provenance(task_dir: Path) -> list[str]:
    """Refresh cached cleaning reports and the matching public manifest entries."""
    manifest_path = task_dir / "input" / "manifest.json"
    if not manifest_path.is_file():
        return []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    changed = []
    for role in ("vul", "fix"):
        path = task_dir / "input" / f"cleaning-{role}.json"
        if not path.is_file():
            continue
        report = sanitize_cleaning_report(json.loads(path.read_text(encoding="utf-8")))
        rendered = json.dumps(report, indent=2) + "\n"
        if path.read_text(encoding="utf-8") != rendered:
            path.write_text(rendered, encoding="utf-8")
        relative = path.name
        entry = manifest.get("files", {}).get(relative)
        if entry is not None:
            entry.update(sha256=sha256(path), bytes=path.stat().st_size)
            changed.append(relative)
    if changed:
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return changed


def prepare_task(candidate: dict, upstream: dict, selection: dict, args) -> dict:
    # Preparation never accepts a pre-existing reference_verified claim.
    issue = int(candidate["task_id"].split(":")[1])
    task_id = f"cybergym-arvo-{issue}"
    task_dir = Path(args.tasks) / task_id
    raw = Path(args.cache) / str(issue)
    raw.mkdir(parents=True, exist_ok=True)
    record = selection.get("record") or {}
    prefix = f"data/arvo/{issue}"
    for name in ("repo-vul.tar.gz", "repo-fix.tar.gz", "description.txt", "error.txt"):
        alternative = raw / ("raw-" + name.split("-", 1)[1] if name.startswith("repo-") else name)
        if name.startswith("repo-") and alternative.is_file():
            continue
        if not selection.get("recipe_time") or name.startswith("repo-"):
            fetch(f"{HF}/{prefix}/{name}", raw / name)
        else:
            # New ARVO v2 records have no CyberGym public issue files. Record
            # factual database fields; never invent or copy a reproducer link.
            text = (f"Upstream ARVO v2 task {issue}: {record.get('crash_type', upstream['crash_type'])} "
                    f"in {record['fuzz_target']}. Historical sanitizer output is summarized in error.txt.\n")
            (raw / name).write_text(text, encoding="utf-8")
    try:
        timestamps = selection.get("srcmap_timestamps") or discover_timestamps(upstream)
    except ValueError:
        # ClusterFuzz report history occasionally omitted a Fixed field even
        # though ARVO has independently reconstructed both builds. Do not invent
        # a timestamp: actual per-role srcmaps are captured by source_export.
        timestamps = None
    sanitizer, sanitizer_env = parse_sanitizer(upstream["sanitizer"])
    fuzz_target = record["fuzz_target"]
    if timestamps is not None:
        for role, timestamp in zip(("vul", "fix"), timestamps):
            if not (raw / f"srcmap-{role}.json").is_file():
                fetch(srcmap_url(upstream["project"], sanitizer_env, timestamp), raw / f"srcmap-{role}.json")
    for role in ("vul", "fix"):
        cleaned = raw / f"sources-{role}.tar.gz"
        source = raw / f"repo-{role}.tar.gz"
        if not source.is_file():
            source = raw / f"raw-{role}.tar.gz"
        report = _cleaned_tar_bytes(source, cleaned)
        if source.name.startswith("raw-"):
            # Even cached cleaning evidence may contain the old unrestricted
            # extraction record. Only this public allowlist is ever copied to
            # input; image names and GPFS2 logs stay in private downloads.
            sanitize_cleaning_report(report)
            report["source_format"] = "Private preparation-only reference /src source export; cleaned source files only; no reference image, runner, compiled output or PoC"
            export_evidence = raw / f"export-{role}.json"
            if export_evidence.is_file():
                evidence = json.loads(export_evidence.read_text(encoding="utf-8"))
                # Public provenance states the acquisition boundary without
                # leaking private worker paths or the reference image name.
                report["source_export_evidence"] = {
                    "source": "private preparation-environment /src source export",
                    "exported_at": evidence.get("exported_at"),
                    "source_files_only": True, "entrypoint_copied": False,
                    "poc_copied": False, "out_copied": False,
                    "kept_files": (evidence.get("transport") or {}).get("kept_files"),
                }
        (raw / f"cleaning-{role}.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        problems = audit_tar(cleaned)["issues"]
        if problems:
            raise ValueError(f"cleaned {role} source failed audit: {problems[:4]}")
    # Only generated directories/files are replaced; an existing private gold
    # directory is never staged and never removed by materialization.
    for old in ("materials", "tests", "solution", "input"):
        path = task_dir / old
        if path.is_dir():
            shutil.rmtree(path)
        elif path.is_file():
            path.unlink()
    (task_dir / "input").mkdir(parents=True, exist_ok=True)
    (task_dir / "gold").mkdir(exist_ok=True)
    for role in ("vul", "fix"):
        timestamp = timestamps["vul" if role == "vul" else "fix"] if timestamps else "source-export"
        if not (raw / f"srcmap-{role}.json").is_file():
            # srcmap is a read-only source revision enumerator, not a target
            # execution. It inspects .git metadata privately before cleaning.
            if role == "vul" and not selection.get("recipe_time"):
                subprocess.run(["ssh", "-o", "BatchMode=yes", getattr(args, "worker", "root@100.96.153.163"),
                                "docker", "pull", f"n132/arvo:{issue}-{role}"], check=True, timeout=2400)
            result = subprocess.run(["ssh", "-o", "BatchMode=yes", getattr(args, "worker", "root@100.96.153.163"),
                                    "docker", "run", "--rm", "--network", "none", "-e",
                                    "FUZZING_LANGUAGE=" + str(record.get("language") or candidate.get("project_language") or "c++"),
                                    f"n132/arvo:{issue}-{role}", "srcmap"],
                                    capture_output=True, text=True, check=True, timeout=180)
            (raw / f"srcmap-{role}.json").write_text(result.stdout[result.stdout.find("{"):], encoding="utf-8")
        shutil.copy2(raw / f"sources-{role}.tar.gz", task_dir / "input" / f"sources-{role}.tar.gz")
        shutil.copy2(raw / f"srcmap-{role}.json", task_dir / "input" / f"srcmap-{role}.json")
        shutil.copy2(raw / f"cleaning-{role}.json", task_dir / "input" / f"cleaning-{role}.json")
        recipe = historical_recipe(Path(args.oss_fuzz_git), upstream["project"],
                                   source_timestamp(f"x-{timestamps[0 if role == 'vul' else 1]}.srcmap.json") if timestamps else selection["recipe_time"],
                                   task_dir / "input" / "oss-fuzz" / role)
        (task_dir / "input" / f"oss-fuzz-{role}.json").write_text(json.dumps({
            "revision": recipe["commit"], "srcmap_timestamp": timestamp,
            "recipe_path": f"oss-fuzz/{role}", "source": recipe["source"],
        }, indent=2) + "\n", encoding="utf-8")
    description = (raw / "description.txt").read_text(encoding="utf-8", errors="replace")
    description = sanitize_text(description)
    (task_dir / "input" / "description.md").write_text(
        f"# {upstream['project']} / arvo:{issue}\n\n{description.strip()}\n\n"
        "## Public provenance\n\n"
        f"Historical OSS-Fuzz project `{upstream['project']}`. The upstream task identifier is "
        "provided for dataset bookkeeping; no raw issue or reproducer is included.\n", encoding="utf-8")
    (task_dir / "input" / "error.txt").write_text(sanitize_text(
        (raw / "error.txt").read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
    values = dict(project=upstream["project"], upstream_task_id=f"arvo:{issue}",
                  sanitizer=sanitizer, sanitizer_env=sanitizer_env,
                  fuzz_target=fuzz_target, fuzz_engine=record["fuzz_engine"])
    # Do not pre-distill build guidance: agents inspect the real source and
    # historical OSS-Fuzz recipes, as they would in an ordinary user project.
    (task_dir / "instruction.md").write_text(INSTRUCTION.format(**values), encoding="utf-8")
    (task_dir / "input" / "TASK.md").write_text(INSTRUCTION.format(**values), encoding="utf-8")
    (task_dir / "input" / "normal-input-contract.json").write_text(json.dumps({
        "status": "not_bundled",
        "requirement": "Author a normal, non-crashing smoke input and test it on both versions.",
        "seed_source": "No verified public historical seed corpus has been imported.",
    }, indent=2) + "\n", encoding="utf-8")
    poc_source = raw / "gold-poc"
    if poc_source.is_file() and poc_source.stat().st_size:
        shutil.copyfile(poc_source, task_dir / "input" / "poc")
    files = {}
    for path in sorted((task_dir / "input").rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            files[str(path.relative_to(task_dir / "input"))] = {
                "sha256": sha256(path), "bytes": path.stat().st_size,
            }
    (task_dir / "input" / "manifest.json").write_text(json.dumps({
        "schema_version": 1, "task_id": task_id, "source_versions": ["vul", "fix"],
        "private_inputs_excluded": True, "files": files,
    }, indent=2) + "\n", encoding="utf-8")
    metadata = {
        "task_id": task_id, "family": "cybergym", "task_type": "binary-env-synthesis",
        "project": upstream["project"], "upstream_task_id": f"arvo:{issue}",
        "sanitizer": sanitizer_env, "sanitizer_label": sanitizer, "fuzz_target": fuzz_target,
        "fuzz_engine": record["fuzz_engine"], "language": record.get("language") or candidate.get("project_language"),
        "crash_type": upstream["crash_type"],
        "expected_stack": selection.get("expected_stack") or [],
        "reference_verified": False,
        "private": {
            "gold_poc": "input/poc",
        },
        "public_input": "input", "timeout_sec": 18000, "max_turns": 280,
        "resources": {"cpu": 4, "memory_gb": 12, "disk_gb": 30},
    }
    (task_dir / "metadata.yaml").write_text(yaml.safe_dump(metadata, sort_keys=False), encoding="utf-8")
    (task_dir / "gold" / "upstream-private.json").write_text(json.dumps({
        "upstream": upstream, "record": record,
        "srcmap_timestamps": timestamps or "actual source_export srcmap; no historical report timestamp",
        "source_acquisition": selection.get("source_acquisition", "public CyberGym source archive"),
        "provenance": selection.get("provenance", "ARVO-Meta and ARVO database; raw issue/reproducer material must remain private"),
    }, indent=2) + "\n", encoding="utf-8")
    return {"task_id": task_id, "project": upstream["project"], "sanitizer": sanitizer,
            "status": "prepared_unverified", "srcmap_timestamps": timestamps}
