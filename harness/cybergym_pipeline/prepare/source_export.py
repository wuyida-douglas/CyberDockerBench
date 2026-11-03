"""Private acquisition of source/build assets from already cached ARVO images.

This is a preparation fallback when a public source archive is unavailable.
Only /src is copied. /out, /tmp/poc, /bin/arvo, toolchain directories, issue
links, git metadata and all binaries are excluded before any public packaging.
No image archive is streamed into public task inputs.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import gzip
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .audit import audit_tar

WORKER = "root@100.96.153.163"
STRIP_PARTS = {".git", ".hg", ".svn", "__pycache__"}
STRIP_NAMES = {"poc", "poc.bin", "crash_case", "testcase", "reproducer"}
BINARY_SUFFIXES = {".o", ".a", ".so", ".dll", ".dylib", ".exe", ".pyc", ".class", ".jar"}


def stream_source(prefix: list[str], container: str, archive_path: Path, log: Path) -> dict:
    """Stream /src directly into a clean tar.gz; never spool .git or binaries.

    The transport tar contains exactly the original /src file tree. Metadata is
    normalized only after Docker has produced it. Links and special entries are
    deliberately excluded rather than followed or dereferenced.
    """
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    temporary = archive_path.with_suffix(archive_path.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    process = subprocess.Popen([*prefix, "docker", "cp", f"{container}:/src/.", "-"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    kept = removed = 0
    try:
        assert process.stdout is not None
        with tarfile.open(fileobj=process.stdout, mode="r|*") as source, \
                tarfile.open(temporary, "w:gz", compresslevel=4) as target:
            for member in source:
                relative = member.name
                if relative.startswith("./"):
                    relative = relative[2:]
                if relative == "src":
                    relative = "."
                elif relative.startswith("src/"):
                    relative = relative[4:]
                if not relative or relative == ".":
                    continue
                pure = Path(relative)
                parts = pure.parts
                if pure.is_absolute() or ".." in parts or "\\" in relative:
                    raise ValueError(f"unsafe source archive path: {member.name}")
                if any(part in STRIP_PARTS for part in parts) or parts[0] == "out":
                    removed += 1
                    continue
                if relative == "Dockerfile":
                    removed += 1
                    continue
                if pure.name in STRIP_NAMES or pure.name.startswith(("poc.", "reproducer.")):
                    removed += 1
                    continue
                if pure.suffix.lower() in BINARY_SUFFIXES or member.issym() or member.islnk():
                    removed += 1
                    continue
                if not (member.isfile() or member.isdir()):
                    removed += 1
                    continue
                if member.isdir():
                    info = tarfile.TarInfo("src/" + relative)
                    info.type = tarfile.DIRTYPE
                    info.mode = member.mode & 0o777
                    info.mtime = member.mtime
                    info.uid = info.gid = 0
                    target.addfile(info)
                    continue
                handle = source.extractfile(member)
                data = handle.read() if handle else b""
                if data.startswith(b"\x7fELF") or data.startswith(b"MZ"):
                    removed += 1
                    continue
                if b"oss-fuzz.com/download" in data and b"testcase_id=" in data or b"n132/arvo" in data:
                    removed += 1
                    continue
                info = tarfile.TarInfo("src/" + relative)
                info.size = len(data)
                info.mode = member.mode & 0o777
                info.mtime = member.mtime
                info.uid = info.gid = 0
                target.addfile(info, io.BytesIO(data))
                kept += 1
        assert process.stderr is not None
        stderr = process.stderr.read().decode("utf-8", "replace")
        code = process.wait(timeout=120)
        log.write_text(stderr, encoding="utf-8")
        if code:
            raise RuntimeError(f"source tar stream failed ({code}): {stderr[-500:]}")
        if not kept:
            raise RuntimeError("source tar stream has no regular files")
        temporary.replace(archive_path)
    except Exception:
        process.kill()
        process.wait()
        temporary.unlink(missing_ok=True)
        raise
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    return {"kept_files": kept, "removed_entries": removed,
            "duration_seconds": round(time.monotonic() - started, 3),
            "log": str(log), "archive": str(archive_path)}


def command(command: list[str], log: Path, timeout=3600) -> dict:
    started = time.monotonic()
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as handle:
        handle.write("$ " + shlex.join(command) + "\n")
        handle.flush()
        try:
            result = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT, timeout=timeout)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
    return {"command": command, "return_code": code, "duration_seconds": round(time.monotonic() - started, 3),
            "log": str(log)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ids", nargs="+", type=int)
    parser.add_argument("--store", type=Path,
                        default=Path("/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cyberdockerbench/cybergym/downloads"))
    parser.add_argument("--worker", default=WORKER)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--force", action="store_true", help="regenerate archives using the current cleaning policy")
    args = parser.parse_args()

    def export(issue: int) -> dict:
        destination = args.store / str(issue)
        destination.mkdir(parents=True, exist_ok=True)
        logs = destination / "source-export-logs"
        name = f"cdb-cybergym-source-{issue}-{uuid.uuid4().hex[:8]}"
        prefix = ["ssh", "-o", "BatchMode=yes", args.worker]
        image = f"n132/arvo:{issue}-vul"
        record = {"upstream_task_id": f"arvo:{issue}", "started_at": datetime.now(timezone.utc).isoformat(),
                  "image": image, "scope": "/src only; no /out, /tmp, runner or toolchain", "roles": {}}
        for role in ("vul", "fix"):
            # Do not redownload an already-exported complete role. Check the
            # compressed archive and private acquisition evidence on resume.
            if not args.force and (destination / f"raw-{role}.tar.gz").is_file() and (destination / f"export-{role}.json").is_file():
                record["roles"][role] = {"status": "cached"}
                continue
            image = f"n132/arvo:{issue}-{role}"
            container = name + "-" + role
            try:
                inspect = command([*prefix, shlex.join(["docker", "image", "inspect", "--format",
                                   "{{json .RepoDigests}} {{.Id}}", image])], logs / f"{role}-inspect.log", timeout=90)
                if inspect["return_code"]:
                    raise RuntimeError(f"reference source image not cached: {image}")
                # Create without running a fuzzer or any project build script.
                create = command([*prefix, "docker", "create", "--network", "none", "--name", container, image],
                                  logs / f"{role}-create.log", timeout=120)
                if create["return_code"]:
                    raise RuntimeError(f"cannot create source container {image}")
                # Stream only source files. A raw /src copy can include tens of
                # GB of .git objects and duplicate compressed archives on disk.
                archive_path = destination / f"raw-{role}.tar.gz"
                transport = stream_source(prefix, container, archive_path, logs / f"{role}-copy.log")
                report = {"source": "docker cp <reference>:/src/. -; filtered source tar stream; no execution during export",
                          "reference": image, "exported_at": datetime.now(timezone.utc).isoformat(),
                          "entrypoint_copied": False, "poc_copied": False, "out_copied": False,
                          "private_source_export_fallback": True,
                          "private_extraction_log_directory": str(logs), "transport": transport}
                (destination / f"export-{role}.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
                record["roles"][role] = {"status": "exported", "archive": str(archive_path), **transport}
            except Exception as exc:
                record["roles"][role] = {"status": "failed", "error": str(exc)}
            finally:
                command([*prefix, "docker", "rm", "-f", container], logs / f"{role}-cleanup.log", timeout=120)
        (destination / "source-export.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        print(f"[source-export] {issue}: {record['roles']}", flush=True)
        return record

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        records = list(pool.map(export, args.ids))
    return 0 if all(all(item["status"] in {"cached", "exported"} for item in record["roles"].values())
                    for record in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
