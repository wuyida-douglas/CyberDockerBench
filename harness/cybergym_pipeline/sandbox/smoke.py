#!/usr/bin/env python3
"""Run a real small Docker smoke on a dedicated worker; never launch Claude.

Example:
  python3 harness/cybergym_pipeline/sandbox/smoke.py --attempt-id smoke-001

API checking is TCP/TLS connectivity only when ANTHROPIC_BASE_URL is present.
No /v1/messages request, paid model call, or run_claude invocation is made.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from harness.cybergym_pipeline.runtime import Sandbox, SandboxError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", default="cybergym-smoke")
    parser.add_argument("--attempt-id", default="smoke-" + time.strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--image", default=os.environ.get(
        "CYBERGYM_SANDBOX_IMAGE", "cdb-cybergym-sandbox:28.5.2-v2"))
    parser.add_argument("--keep-sandbox", action="store_true",
                        help="leave the live outer container/DinD for a parent snapshot")
    parser.add_argument("--keep-data", action="store_true",
                        help="when stopping, retain the local docker data-root and Claude home")
    parser.add_argument("--skip-api", action="store_true",
                        help="skip even the credential-free TCP/TLS endpoint check")
    args = parser.parse_args()
    runtime_root = (args.runtime_root or Path("/var/tmp/cybergym-controller") / args.attempt_id).resolve()
    workspace = (args.workspace or runtime_root / "workspace").resolve()
    docker_root = Path(os.environ.get("CYBERGYM_DOCKER_ROOT_BASE", "/var/tmp/cybergym-docker")) / args.attempt_id
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "PUBLIC.txt").write_text("public CyberGym smoke input\n")
    from harness.cybergym_pipeline.runtime.settings import load_runtime_settings
    env = load_runtime_settings()
    env["CYBERGYM_SANDBOX_IMAGE"] = args.image
    plugin = ROOT / "harness" / "agent_plugins" / "internal-network"
    if "CYBERGYM_NETWORK_PLUGIN" not in env and plugin.is_dir():
        env["CYBERGYM_NETWORK_PLUGIN"] = str(plugin)
    sandbox = Sandbox(args.task_id, args.attempt_id, workspace, runtime_root, docker_root, env=env)
    summary: dict[str, object] = {
        "task_id": args.task_id,
        "attempt_id": args.attempt_id,
        "image": args.image,
        "container": sandbox.container,
        "network": sandbox.network,
        "workspace": str(workspace),
        "docker_root": str(docker_root),
        "model_invoked": False,
    }
    started = False
    try:
        sandbox.start()
        started = True
        report = sandbox.preflight(check_api=not args.skip_api)
        summary["ok"] = True
        summary["checks"] = [entry["name"] for entry in report["checks"]]
        summary["api"] = report.get("api", {"status": "skipped"})
        summary["preflight_evidence"] = str(runtime_root / "preflight.json")
        summary["runtime_evidence"] = str(runtime_root / "runtime.json")
        summary["preserved_for_snapshot"] = args.keep_sandbox
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        summary["ok"] = False
        summary["error"] = str(exc)
        summary["preflight_evidence"] = str(runtime_root / "preflight.json")
        (runtime_root / "smoke-error.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(summary, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    finally:
        if not args.keep_sandbox and (started or sandbox.probe()["exists"]):
            try:
                sandbox.stop(remove_data=not args.keep_data)
            finally:
                cleanup = runtime_root / "cleanup.json"
                if cleanup.exists():
                    print(cleanup.read_text(), end="")


if __name__ == "__main__":
    raise SystemExit(main())
