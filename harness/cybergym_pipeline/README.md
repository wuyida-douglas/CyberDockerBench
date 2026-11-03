# CyberGym pipeline

CyberGym tasks ask one ordinary Claude Code session to synthesize two buildable
OSS-Fuzz sanitizer environments (`vul` and `fix`). This is not a PoC-writing task.
The preparation reference check and an agent submission are separate evidence.

## Boundaries

- The agent has Claude Code's default tools and `--mcp-config '{"mcpServers":{}}'`.
  It can edit source, build files, install dependencies and use the attempt's
  private Docker daemon. It cannot access the host Docker socket, `gold/`, or
  official reference images as public input.
- `input/` contains cleaned dual-version source trees, actual source maps,
  historical OSS-Fuzz recipes, build/network instructions, and integrity hashes.
  Private reference images and the genuine upstream reproducer are used only by
  preparation and grading.
- Source freeze and live export happen together after application writers are
  stopped. Mount contents are copied as binary-safe tar streams; named,
  anonymous and bind mounts are restored as package-local data. The live package
  includes all application containers, not only the two role containers.
- The grader evaluates two independent tracks: declarative source rebuild and
  cold-restored live snapshot. Both must run the normal smoke input and produce
  the expected private GOLD differential. A passing official-reference check
  does **not** imply an agent solution or rebuilt source was tested.

## One-command attempt

Start `./run-cybergym-eval.sh` from the repository root on wuyida-01. The script
SSHes to the worker in `harness/on-worker.sh` and creates the sandbox there.
Supply model credentials in the controller environment; credentials are
forwarded only to the Claude exec, not baked into the DinD environment. The
model must be explicit.

```bash
python3 -m harness.cybergym_pipeline.run_attempt run \
  --task cybergym-arvo-1513 --model YOUR_EXPLICIT_MODEL \
  --batch evaluation-001 --attempt attempt-001
```

The command performs prepare, agent, full source/live export, source and live
grading, then stops the attempt sandbox. `--keep-data` retains the outer sandbox
and local Docker data. To run stages individually or resume an attempt:

```bash
python3 -m harness.cybergym_pipeline.run_attempt prepare --task cybergym-arvo-1513
python3 -m harness.cybergym_pipeline.run_attempt export --task cybergym-arvo-1513
python3 -m harness.cybergym_pipeline.run_attempt grade --task cybergym-arvo-1513
python3 -m harness.cybergym_pipeline.run_attempt stop --task cybergym-arvo-1513
python3 -m harness.cybergym_pipeline.run_attempt status
```

Use the same `--batch`, `--attempt`, and `--runtime` for every stage. Run the command on the worker.
No model is invoked by `prepare`, `export`, `grade`, `status`, or `audit`.

Large attempt data defaults to
`/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cyberdockerbench/cybergym/runtime/results/<batch>/<task>/<attempt>/`.
Each attempt contains `workspace/`, `frozen/source/`, `frozen/live/`,
`pipeline-state.json`, and `grade/result.json`. The sandbox's writable Docker
root is `/var/tmp/cybergym-docker/<attempt>/` on the designated worker's local
filesystem, not GPFS. `stop` removes it only after export/grading has completed;
do not manually delete another attempt's data.

## Preparation and acceptance

Preparation never calls a solving agent. `reference_finalize` pulls or reuses
official `n132/arvo:<id>-vul/-fix` images on the preparation worker, extracts
the private GOLD PoC, and requires the vulnerable sanitizer/stack signature plus
a normal fixed run. It records image identities, PoC SHA-256, commands, and logs.

Newer ARVO v2 candidates whose public source archive is unavailable use a
preparation-only `/src` source export. `source_export.py` streams source files,
normalizes Docker's two possible `src/` and `./` archive layouts, and removes
VCS metadata, `/out`, compiled artifacts, the reference Dockerfile/runner, and
PoC-like data. This is explicitly not a public CyberGym archive or an image
solution. Recipe selection uses the real public fix commit date. Actual source
maps are read from the private preparation source metadata, not invented.

```bash
python3 -m harness.cybergym_pipeline.reference_finalize --only 1513 1538
python3 -m harness.cybergym_pipeline.prepare.prepare summary --target 40
python3 -m harness.cybergym_pipeline.run_attempt audit
```

`results/cybergym-preparation/preparation-summary.json` is the selection and
reference-evidence report. `results/cybergym-preparation/delivery-manifest.json`
is the exact final task-ID manifest used by `audit`. Only tasks with both real
reference evidence and a clean public-input audit are selected; at most three
per project. Rejected and backup candidates are not part of the delivered set.

`python3 -m harness.cybergym_pipeline.prepare.prepare audit --only <task-id>`
checks one task. `prepare ... audit` without `--only` audits every materialized
candidate, including rejected backups; it is not the final 40-task acceptance
command.

## Runtime network and storage

On the H cluster, kkRepo is `http://100.102.49.114:19091`; use the matching
repository type. It is not a Docker registry or a general HTTP proxy. Outbound
proxy settings come from the worker environment, with kkRepo and internal target
names in `NO_PROXY`. Do not hard-code worker-specific proxies into a task.
Network and historical-build constraints are part of the agent's `TASK.md`;
there is no separate `NETWORKING.md` handoff in newly materialized tasks.

Build the isolated controller image on the worker with
`harness/cybergym_pipeline/sandbox/build-image.sh`. Its build context is
`harness/`, never `tasks/` or private gold data. Infrastructure smoke:
`python3 harness/cybergym_pipeline/sandbox/smoke.py --attempt-id <unique-id>`.
It does not invoke a model.

Snapshot evidence distinguishes unit tests from actual isolated Docker tests:

```bash
CDB_SNAPSHOT_DIND_TEST=1 \
CDB_SNAPSHOT_EVIDENCE=/mnt/shared-storage-gpfs2/trustcyberdata/private/wuyida/cyberdockerbench/cybergym/cold-load-evidence.json \
python3 -m unittest harness.tests.test_cybergym_snapshot.RealDinDIntegrationTests.test_multiservice_cold_load -v
```

The integration test creates two independent Docker daemons and relocates the
bundle before restoring. It checks application data, binary bytes, links,
network aliases, environment and exited sidecars. Its passing result is a
synthetic multi-service snapshot test, not a claim that all 40 tasks have been
successfully solved and rebuilt by an agent.

## 2026-10-30 evaluation and runtime fixes

`run-cybergym-eval.sh` launches 20 concurrent tasks with `--max-turns 150` and
`--timeout 18000`. `harness/on-worker.sh` forwards `CDB_MODEL` to the worker;
verify the resulting batch summary and driver arguments rather than inferring
the model from the batch name. Each rerun uses a new result directory; the
batch runner refuses an existing result directory before starting any task or
writing a summary.

The attempt workspace is bind-mounted at both its absolute GPFS path and
`/workspace`, so the documented delivery path is also the path frozen for
grading. Transient source-grader sandbox startup failures and API/network
errors are eligible for bounded infrastructure requeue; semantic failures are
not. Before launching a batch, remove only stopped same-attempt sandboxes and
unused Docker networks, and never kill a live task to reclaim address space.

The stack matcher accepts a terminal function token on an actual `#N ... in
<function>` frame when a demangler omits C++ class qualifiers. It retains the
sanitizer, vulnerable/fixed differential, and minimum-frame requirements.
GLM-5.3 completed 40/40 after four infrastructure recoveries and the frozen
1856 regrade; see `docs/题目统计/cybergym题目统计-202610300209.md` and
`docs/修复记录/cybergym修复记录.md` §§38–41. DeepSeek-v4.1-flash is recorded
independently in `docs/题目统计/cybergym题目统计-202610300704-ds41flash.md`.
DeepSeek completed 39/40: the sole semantic failure is 42482060, whose ASan
report contains only binary offsets and none of the six required application
function names. All 22 infrastructure failures were recovered in fresh
batches; both models share 39 passing tasks and GLM additionally passes
42482060. See the final per-task evidence and recovery accounting in that
document and fix-log §§41–42.

For trajectory analysis, count distinct `assistant.message.id` values as
assistant turns. Claude's result `num_turns` can include tool calls and later
background wakeups and must not be used as proof of the configured turn cap.
