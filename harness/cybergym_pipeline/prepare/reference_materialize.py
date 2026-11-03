"""Materialize newer ARVO records from preparation-only, cleaned source exports.

These records are absent from the legacy ARVO-Meta repository. The ARVO v2
sqlite database is their metadata authority. Source archives must already have
been produced by ``source_export.py``; this command never runs a project build,
exports an image, or exposes its PoC to the public task input.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import email.utils
import json
import re
import sqlite3
import subprocess
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .materialize import prepare_task
from .prepare import DEFAULT_STORE, ROOT, stack_from_output

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|(?:\^\[\[[AB])+")


def patch_time(record: dict, cache: Path) -> datetime:
    """Read the actual public patch's author date, never substitute today."""
    commit = str(record.get("fix_commit") or "").strip()
    repository = str(record.get("repo_addr") or "").strip()
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit) or not repository.startswith("https://github.com/"):
        raise ValueError("a GitHub fix_commit and repo_addr are required for historical recipe selection")
    destination = cache / "patch-header.txt"
    if not destination.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        url = repository + "/commit/" + commit + ".patch"
        request = urllib.request.Request(url, headers={"User-Agent": "cdb-source-history/1"})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(1024 * 1024)
        if b"\nDate:" not in data and not data.startswith("Date:"):
            raise ValueError(f"no actual patch author date: {url}")
        temporary = destination.with_suffix(".tmp")
        temporary.write_bytes(data)
        temporary.replace(destination)
    for line in destination.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("Date:"):
            parsed = email.utils.parsedate_to_datetime(line[5:].strip())
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    raise ValueError("actual patch contains no author date")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ids", nargs="+", type=int)
    parser.add_argument("--store", type=Path, default=DEFAULT_STORE)
    parser.add_argument("--tasks", type=Path, default=ROOT / "tasks")
    parser.add_argument("--concurrency", type=int, default=3)
    args = parser.parse_args(argv)
    with sqlite3.connect(f"file:{args.store / 'upstream/arvo.db'}?immutable=1", uri=True) as database:
        database.row_factory = sqlite3.Row
        records = {}
        for issue in args.ids:
            row = database.execute("SELECT * FROM arvo WHERE localId=?", (issue,)).fetchone()
            if row is not None:
                records[issue] = dict(row)

    def one(issue: int) -> dict:
        try:
            raw = args.store / "downloads" / str(issue)
            if issue not in records:
                raise ValueError("no exact ARVO v2 record; legacy mappings are not valid for these IDs")
            record = records[issue]
            if not record["reproduced"] or not record["patch_located"]:
                raise ValueError("record has not been reproduced with a located patch")
            for role in ("vul", "fix"):
                archive = raw / f"raw-{role}.tar.gz"
                evidence = raw / f"export-{role}.json"
                if not archive.is_file() or not archive.stat().st_size or not evidence.is_file():
                    raise ValueError(f"complete cleaned {role} source export is required first")
            project = ANSI.sub("", record["project"]).strip()
            target = ANSI.sub("", record["fuzz_target"]).strip()
            target = re.sub(r"^(?:\^\[[AB])+", "", target).strip()
            if not target or not re.fullmatch(r"[A-Za-z0-9_.+:-]+", target):
                raise ValueError(f"invalid fuzz target after stripping terminal controls: {target!r}")
            upstream = {"project": project, "sanitizer": record["sanitizer"],
                        "crash_type": record["crash_type"], "localId": issue,
                        "source": "ARVO v2 sqlite record; legacy ARVO-Meta has no entry for this ID"}
            candidate = {"task_id": f"arvo:{issue}", "project": project,
                         "project_language": record.get("language")}
            frames = stack_from_output(record.get("crash_output") or "")
            if not frames:
                raise ValueError("ARVO crash output has no expected application stack")
            timestamp = patch_time(record, raw)
            selection = {"record": {**record, "project": project, "fuzz_target": target},
                         "expected_stack": frames, "recipe_time": timestamp,
                         "source_acquisition": "Private preparation-only source export from official ARVO /src; source files only, no image/runner/output/PoC",
                         "provenance": "ARVO v2 database and public historical OSS-Fuzz git; source export provenance is recorded in cleaning-vul/fix.json"}
            args_for_prepare = argparse.Namespace(
                tasks=args.tasks, cache=args.store / "downloads",
                oss_fuzz_git=args.store / "upstream/oss-fuzz.git",
                worker="root@100.96.153.163")
            result = prepare_task(candidate, upstream, selection, args_for_prepare)
            result["recipe_before"] = timestamp.isoformat()
            result["source_export"] = True
            (args.tasks / result["task_id"] / "gold" / "preparation-record.json").write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(result), flush=True)
            return result
        except Exception as exc:
            result = {"task_id": f"cybergym-arvo-{issue}", "status": "prepare_failed",
                      "error": f"{type(exc).__name__}: {exc}"}
            print(json.dumps(result), flush=True)
            return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        results = list(pool.map(one, args.ids))
    return 0 if all(item["status"] != "prepare_failed" for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
