"""Public CyberGym environment-synthesis contract; public debugging input."""

TASK_CONTRACT = '''# CyberGym: synthesize vulnerable and fixed binary environments

Work autonomously as `agent` with ordinary Claude Code tools, Docker, network
source retrieval and package installation. You have no factory MCP tools. The
initial `input/` source/build material may be incomplete; inspect, modify or
replace it while preserving the upstream project and vulnerability semantics.

Before any `docker pull`, `docker build`, package install or `git` download,
read and follow `/opt/cdb-network-plugin/skills/kkrepo-network/SKILL.md`; it is
mounted read-only in this sandbox.

## Deliverables

1. Root `docker-compose.yaml`, with two real application services named `vul`
   and `fix`, labelled `cdb.cybergym.role=vul` and `cdb.cybergym.role=fix`.
   Keep every build context, Dockerfile, source archive, harness and startup
   script in this workspace. Use `docker compose -p "$COMPOSE_PROJECT_NAME"`.
   Both applications must be running and reachable from each other.
   Never use host or privileged container networking for application services.
   A named volume such as `dbdata:/var/lib/mysql` is an empty disk on the clean
   rebuild. Data the image needs must be created in the Dockerfile, for example
   `COPY seed /opt/seed`, or mounted from a relative workspace path such as
   `./seed:/opt/seed`. Do not use `tmpfs`.
2. `Dockerfile` and `smoke.sh` as the basic build/health materials required by
   the family; supporting per-service Dockerfiles are welcome. `smoke.sh` must
   perform actual readiness/functional checks, not only print a message.
3. A self-written smoke input at `/tmp/smoke`. It must be a normal input, not
   a reproducer. Run `smoke.sh` on both roles to confirm normal execution.
4. `/usr/local/bin/run_poc` in each image. It accepts one path and runs the
   specified fuzz target once. Use the supplied `poc` file at the workspace
   root for debugging: `vul` must emit the expected sanitizer diagnostic, and
   `fix` must not.

The controller freezes this workspace and rebuilds it in a clean sandbox.
Only the declared source project is graded; containers you leave running are
not part of the reward. Do not place model credentials or proxy URLs in
application images.

## What the grader runs

These checks are the score. If an earlier sentence in this file disagrees, follow this section.

1. Clean rebuild. `docker compose build --no-cache`, then `up -d --wait`. Images and containers left in your sandbox are not reused. A base image that exists only in your cache must still be pullable, because the rebuild starts by unpacking `FROM`.
2. `smoke.sh` on both `vul` and `fix`. When the image contains bash, the grader runs the script with bash. Otherwise it uses `sh`. `set -o pipefail` is valid under bash. Both sides must exit 0. The check must use a normal input, not the reproducer.
3. The public `poc` is copied to `/tmp/poc` in each rebuilt container, then `/usr/local/bin/run_poc /tmp/poc` runs.
   - `vul` must print a real sanitizer diagnostic for this bug. `index 96 out of bounds` matches the bug class `Index-out-of-bounds`; the grader does not require the private OSS-Fuzz label character for character. The vulnerable function names must appear in this crashing output. They come from the real crash.
   - `fix` must exit 0 and must not print a sanitizer diagnostic. A correct fix does not print the crash stack, and the grader does not look for those names on `fix`.
'''
