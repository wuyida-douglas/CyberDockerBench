"""Run a real sandbox/network preflight without launching a model.

Run this on the worker, the same machine that runs the evaluation.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from harness.docker_sandbox import DockerSandbox  # noqa: E402
from harness.run_agent import (  # noqa: E402
    PLUGIN_SOURCE,
    PLUGIN_TARGET,
    run_preflight,
)


def _redact(value: str) -> str:
    from harness.docker_sandbox import redact_argument
    return redact_argument(value or '')


def local(args: argparse.Namespace) -> dict:
    from harness.docker_sandbox import SANDBOX_IMAGE
    from harness.storage import validate_storage_root
    report: dict = {'schema_version': 1, 'success': False,
                    'started_at': datetime.now(timezone.utc).isoformat(),
                    'results': str(args.results.resolve()), 'checks': [],
                    'model_smoke': {'status': 'skipped',
                                    'reason': 'explicit opt-in required; no model credentials loaded'},
                    'optional_ecosystems': {'status': 'not_run',
                                            'reason': 'probe only package managers used by the task Dockerfile'}}
    args.results.mkdir(parents=True, exist_ok=True)
    check_file = args.results / 'controller.json'

    def check(name: str, cp: subprocess.CompletedProcess, category: str) -> None:
        item = {'name': name, 'category': category, 'returncode': cp.returncode,
                'stdout_tail': _redact(cp.stdout)[-4000:],
                'stderr_tail': _redact(cp.stderr)[-4000:]}
        report['checks'].append(item)
        check_file.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        if cp.returncode:
            raise RuntimeError(f'{category} preflight failed: {name}: '
                               f'{item["stderr_tail"] or item["stdout_tail"]}')

    try:
        check('host-docker', subprocess.run(
            ['docker', 'version', '--format', '{{.Server.Version}}'],
            capture_output=True, text=True, timeout=45), 'pipeline')
        check('sandbox-image', subprocess.run(
            ['docker', 'image', 'inspect', '--format', '{{.Id}}',
             SANDBOX_IMAGE], capture_output=True, text=True, timeout=45), 'pipeline')
        check('agent-cli', subprocess.run(
            ['docker', 'run', '--rm', '--entrypoint', 'claude',
             SANDBOX_IMAGE, '--version'],
            capture_output=True, text=True, timeout=90), 'pipeline')
        if os.environ.get('CDB_LOCAL_DOCKER_DATA') == '1':
            data_root = Path(os.environ.get('CDB_DOCKER_DATA_ROOT', '/var/tmp'))
            storage = validate_storage_root(
                data_root, float(os.environ.get('CDB_MIN_FREE_GIB', '20')))
            report['storage'] = storage
        else:
            report['storage'] = {'skipped': True,
                                 'reason': 'CDB_LOCAL_DOCKER_DATA is not enabled'}
        sandbox = DockerSandbox('network-preflight', args.results,
                                name='cdb-preflight-' + uuid.uuid4().hex[:12])
        sandbox.agent_plugin(str(PLUGIN_SOURCE), PLUGIN_TARGET)
        try:
            sandbox.start()
            report['sandbox'] = {'image': sandbox.image_reference,
                                 'image_id': sandbox.image_id,
                                 'contract': sandbox.runtime_contract}
            report['network'] = run_preflight(sandbox, args.results, require_task=False)
            if not report['network']['success']:
                raise RuntimeError('network preflight failed')
        finally:
            sandbox.stop(remove_data=True)
            report['cleanup'] = {'status': 'passed', 'sandbox': sandbox.container}
        report['success'] = True
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as exc:
        report['error'] = _redact(f'{type(exc).__name__}: {exc}')
    finally:
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        check_file.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, required=True,
                        help='new directory for controller.json, preflight.json and sandbox logs')
    args = parser.parse_args(argv)
    if args.results.exists() and any(args.results.iterdir()):
        parser.error('--results must be a new or empty directory')
    report = local(args)
    print(json.dumps({'success': report['success'], 'results': str(args.results),
                      'error': report.get('error')}, ensure_ascii=False), flush=True)
    return 0 if report['success'] else 1


if __name__ == '__main__':
    sys.exit(main())
