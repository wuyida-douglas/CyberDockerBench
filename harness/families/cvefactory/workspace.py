"""Public-input staging for CVE-Factory.

This module deliberately knows nothing about reference solutions, frozen grading
packages, input archives, or source restoration.  The task directory is private;
only its ``input`` directory and the public instruction are copied to an agent.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path


TASK_CONTRACT = """# CVE-Factory: reproduce and fix the vulnerability

Use the public vulnerability description and source in this workspace. Build a
real, reproducible vulnerable application and provide a minimal fix that keeps
its intended functionality working.

## Source completion and network freedom

The initial `src/` is a mutable starting point, not a read-only or complete
reference. It may be incomplete or inconsistent. Inspect its actual code and
versions; freely `git clone`, `git fetch`, download official archives, install
system/language dependencies, and add or replace missing implementation. Use
ordinary networking and your own Dockerfile/Compose. Before any image build
or package install, read and follow the kkrepo-network Skill at
`/opt/cdb-network-plugin/skills/kkrepo-network/SKILL.md`.
Preserve the described project and vulnerability semantics; do not switch to an
unrelated project or fabricate vulnerability results. The grader uses your final
project and never restores
or compares it against the initial `src/`.

## Required delivery

Write the complete declarative project in this workspace. It must include:

1. `docker-compose.yaml` and every Dockerfile, build context, configuration file,
   script, bind-mount asset, and other file needed to build and run the complete
   application. The primary application service must be named `client`. Keep the
   Compose file at the workspace root. Always invoke Compose with the injected
   project identity: `docker compose --project-name "$COMPOSE_PROJECT_NAME" ...`;
   do not use a different project name for the final application.
2. `solution.sh`, which changes the already-running vulnerable environment from
   vulnerable to fixed. It may use files delivered with the project, but must not
   depend on this grader, another task, or an undeclared tool. The controller copies
   the whole project to `/tmp/cdb-solution` inside `client`, then executes
   `sh /tmp/cdb-solution/solution.sh` as root with that working directory. It runs
   **inside `client`, not on the sandbox host**: do not use `docker`, `sudo`, a host
   path, or a host-mounted workspace. Use POSIX sh and dependencies declared in the
   `client` image. The script must actually change the vulnerable application;
   printing `fixed` or returning zero is not evidence of a successful patch.
   To rehearse the same contract, copy the project to that directory with Compose
   exec/cp, execute it as root inside `client`, restart `client`, and run `fixed`
   tests. Afterwards restore the declared vulnerable baseline and leave it running.
3. `tests/test_func.py`, `tests/test_vuln.py`, and `tests/run-tests.sh`, plus all
   fixtures and test dependencies. Functional tests must pass before and after
   the fix. The vulnerability test must execute a real vulnerability assertion
   that fails before the fix and passes after it. The grader reads only the
   test command's exit code. For `vulnerable`, exit 0 only when the functional
   tests passed and the vulnerability assertion failed. For `fixed`, exit 0
   only when both passed. A collection error, missing dependency, skipped test,
   or printed success must not exit 0.

The only test location inside the test service is `/tmp/cdb-tests`. The grader
deletes that directory and copies the frozen `tests/` there before running
`sh /tmp/cdb-tests/run-tests.sh vulnerable` and, after the fix,
`sh /tmp/cdb-tests/run-tests.sh fixed`. Do not bind-mount the workspace `tests/`
directory, or anything else, onto `/tmp/cdb-tests`; that deletion would remove
the mounted project files. To rehearse, copy `tests/` into the container at
`/tmp/cdb-tests` and run the same command.

The default test service is `client`. To use a dedicated tester, give its Compose
service the label `cdb.test_service=<service-name>`. The optional
`cdb.test_command=<shell-command>` label replaces the invocation of
`sh /tmp/cdb-tests/run-tests.sh vulnerable|fixed`. The grader runs that command
with `CDB_TEST_PHASE=vulnerable|fixed` and accepts the phase when it exits 0.
It does not run the test files again. Declare the test runtime and every test
dependency in a Dockerfile/Compose image or the tester service. Build every
interpreter, virtualenv, package, and test tool into the service image. The
grader does not install dependencies or copy a host-side virtualenv.

## Final state and evaluation

Finish with a declarative project that rebuilds the vulnerable application.
Do not leave `solution.sh` applied inside the files that the rebuild uses, and
do not perform an export, commit, or submission action. The controller freezes
this workspace after the session.

The controller builds that project in a new, clean Docker environment, brings it
up with `docker compose up -d --wait`, runs `run-tests.sh vulnerable`, applies
`solution.sh` inside that same client, restarts `client` with `docker restart`,
waits for its healthcheck, and runs `run-tests.sh fixed`. Declare a Compose
`healthcheck` for every service that needs warm-up (database initialization,
seeding, migrations, fixture or chain loading): without one the service counts
as ready the moment its process starts, and tests can begin before your data
exists. A restart is not a rebuild: the container filesystem and database files
persist, but processes start over and PID numbering resets, so tests must not
use a PID, a boot timestamp, or any per-boot value as a uniqueness source, and
must not assume rows or files written during the vulnerable phase were wiped.
It never rebuilds a patched image. Containers left running in this session are
not graded.

All runtime services, initial data, test assets, and test dependencies must be
represented in the declarative project. The controller copies this workspace
and rebuilds it with `docker compose build --no-cache`. It does not keep the
containers left running, packages installed on the sandbox host, or files that
exist only inside a container.

- Put every package, compiler, interpreter, and test tool into the client
  Dockerfile. `pip install` or `apt-get install` on the sandbox host is not
  inside `client` and is not copied. An install done only with `docker exec`
  is discarded unless the same command is in the Dockerfile.
- `COPY` and `ADD` sources are relative paths inside this workspace.
  `COPY app /opt/app` is valid. `COPY /tmp/app /opt/app` does not read the
  sandbox path `/tmp/app`.
- Compose binds must use a relative path inside this workspace, for example
  `./app:/opt/app`. Do not bind-mount an absolute path, `/tmp`, `/home/agent`,
  or any directory outside this workspace. An outside bind is rejected before
  grading.
- A volume written as `dbdata:/var/lib/mysql` is a private disk, not a
  directory in this workspace. Rows inserted while you debug live only on that
  disk. Rebuild creates a new empty disk and does not copy those rows. Put data
  the tests need into the image, for example
  `COPY seed.sql /docker-entrypoint-initdb.d/seed.sql`, or into a workspace
  file mounted with a relative bind such as `./seed:/docker-entrypoint-initdb.d`.
  Do not use `tmpfs`; the moved environment is rejected.

The application is not required to live in `/app`; use the paths appropriate
for the application. Do not read or use reference solutions, private tests,
other tasks, or materials outside the public input and your own work.
"""


def _safe_public_tree(source: Path) -> None:
    """Reject links which could copy anything outside the public input."""
    if not source.is_dir() or source.is_symlink():
        raise ValueError(f'missing public input directory: {source}')
    root = source.resolve()
    for path in source.rglob('*'):
        if path.is_symlink():
            if path.readlink().is_absolute():
                raise ValueError(f'unsafe absolute public-input symlink: {path}')
            if not path.resolve(strict=True).is_relative_to(root):
                raise ValueError(f'public-input symlink escapes input: {path}')


def make_workspace_mutable(workspace: Path) -> None:
    """Grant the sandbox UID ownership of this private public-input copy."""
    for path in (workspace, *workspace.rglob('*')):
        if path.is_symlink():
            continue
        if os.geteuid() == 0:
            os.chown(path, 1000, 1000, follow_symlinks=False)
        mode = path.stat().st_mode
        path.chmod(mode | (0o777 if path.is_dir() else 0o666))


def validate_public_task(task_path: Path | str) -> list[str]:
    """Return public-package errors without inspecting any private oracle."""
    task = Path(task_path)
    errors: list[str] = []
    try:
        _safe_public_tree(task / 'input')
    except (OSError, RuntimeError, ValueError) as exc:
        errors.append(str(exc))
    # ``TASK.md`` is the new public location. ``instruction.md`` is accepted only
    # as the human-authored task description, never as an oracle or test source.
    for name in ('TASK.md', 'instruction.md'):
        path = task / name
        if path.exists() and (not path.is_file() or path.is_symlink()):
            errors.append(f'{name} must be a regular, non-symlink file')
    if not (task / 'input' / 'TASK.md').is_file() and not any(
            (task / name).is_file() for name in ('TASK.md', 'instruction.md')):
        # The generic contract is sufficient on its own; missing task-specific
        # prose is not an infrastructure error.
        pass
    return errors


def prepare_workspace(task_path: Path | str, workspace: Path | str) -> None:
    """Copy only public input and instructions into a previously absent directory.

    The generic delivery contract is authoritative for old instructions that
    still mention patched rebuilds or fixed application paths. No source archive
    is verified or restored, and no private task path is searched.
    """
    task = Path(task_path)
    destination = Path(workspace)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f'refusing to replace existing workspace: {destination}')
    errors = validate_public_task(task)
    if errors:
        raise ValueError(f'{task.name}: invalid public task: {"; ".join(errors)}')

    source = task / 'input'
    shutil.copytree(
        source, destination, symlinks=True,
        ignore=shutil.ignore_patterns('BUILDING.md', 'build.md'),
    )
    public_task = task / 'TASK.md'
    legacy_instruction = task / 'instruction.md'
    input_task = destination / 'TASK.md'
    if public_task.is_file():
        description = public_task.read_text(encoding='utf-8')
    elif legacy_instruction.is_file():
        description = legacy_instruction.read_text(encoding='utf-8')
    elif input_task.is_file():
        description = input_task.read_text(encoding='utf-8')
    else:
        description = ''
    # Remove the legacy patched-rebuild instruction rather than contradicting
    # it in the appended contract. Vulnerability prose remains public input.
    description = description.split('\n## Verification', 1)[0]
    description = description.replace('input/src', 'src').replace(
        'input/CVE.md', 'CVE.md').replace(
        'input/VULNERABILITY.md', 'VULNERABILITY.md')
    input_task.write_text(
        description.rstrip() + '\n\n' + TASK_CONTRACT,
        encoding='utf-8',
    )
    make_workspace_mutable(destination)
