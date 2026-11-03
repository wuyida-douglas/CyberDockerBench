"""One-attempt CyberGym state machine, without invoking a model implicitly.

States are atomically recorded so prepare -> agent -> freeze -> export -> grade
can resume without repeating paid model work or silently mixing source revisions.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import time
import uuid
from pathlib import Path

from harness.execution import write_json
from harness.families.cybergym.plugin import CyberGymFamily
from harness.task_api import GradeRequest, PrepareRequest, TaskSpec

ROOT = Path(__file__).resolve().parents[2]


class Pipeline:
    def __init__(self, task: TaskSpec, result: Path, runtime: Path):
        self.task, self.result, self.runtime = task, result, runtime
        self.workspace = result / 'workspace'
        self.source = result / 'frozen' / 'source'
        self.live = result / 'frozen' / 'live'
        self.state_path = result / 'pipeline-state.json'
        self.plugin = CyberGymFamily()
        from harness.cybergym_pipeline.runtime.settings import load_runtime_settings
        self.settings = load_runtime_settings()
        if not self.settings.get('CYBERGYM_NETWORK_PLUGIN'):
            plugin = ROOT / 'harness' / 'agent_plugins' / 'internal-network'
            if (plugin / '.claude-plugin' / 'plugin.json').is_file():
                self.settings['CYBERGYM_NETWORK_PLUGIN'] = str(plugin)

    def checkpoint(self, state: str, **details):
        self.result.mkdir(parents=True, exist_ok=True)
        write_json(self.state_path, {'task_id': self.task.task_id, 'state': state,
                                     'attempt_id': self.result.name, 'updated_at': time.time(), **details})

    def prepare(self, force=False):
        if self.workspace.exists():
            if not force:
                raise FileExistsError(f'use a fresh result directory or --force: {self.workspace}')
            shutil.rmtree(self.workspace)
        errors = self.plugin.validate_task(self.task)
        if errors:
            raise ValueError(f'task failed audit: {errors}')
        self.plugin.prepare_workspace(PrepareRequest(self.task, self.workspace))
        self.checkpoint('prepared', workspace=str(self.workspace))
        return self.workspace

    def open_sandbox(self):
        """The attempt sandbox on this machine. Run the pipeline on the worker."""
        from harness.cybergym_pipeline.runtime.sandbox import DOCKER_ROOT_BASE, Sandbox
        runtime = Path(self.runtime) / self.task.task_id / self.result.name
        docker_root = DOCKER_ROOT_BASE / f'{self.task.task_id}--{self.result.name}'
        return Sandbox(self.task.task_id, self.result.name, self.workspace, runtime,
                       docker_root, env=self.settings)

    def ready_sandbox(self):
        sandbox = self.open_sandbox()
        sandbox.ensure()
        return sandbox

    def run_agent(self, model: str, timeout: int, max_turns: int):
        if not self.workspace.is_dir():
            self.prepare()
        if not self.settings.get('ANTHROPIC_AUTH_TOKEN') and not self.settings.get('ANTHROPIC_API_KEY'):
            raise ValueError('ANTHROPIC_AUTH_TOKEN or ANTHROPIC_API_KEY is required for an explicit agent run')
        self.checkpoint('agent_running', model=model)
        sandbox = self.ready_sandbox()
        prompt = ('Read TASK.md in the current directory and complete it autonomously. '
                  'Before any docker pull, docker build, or package install, read '
                  'and follow /opt/cdb-network-plugin/skills/kkrepo-network/SKILL.md. '
                  'Do not ask for confirmation.')
        try:
            claude = sandbox.run_claude(prompt, model, timeout, max_turns,
                                        self.result / 'trajectory.jsonl',
                                        view_dir=self.result.parent)
            report = {'model': model, 'claude_result': claude.as_dict(),
                      'agent_success': claude.success,
                      'agent_status': ('max_turns' if claude.turn_limit_reached else
                                       'timeout' if claude.timed_out else
                                       'completed' if claude.success else 'agent_error')}
            self.checkpoint('agent_finished', **report)
            return report
        except Exception as exc:
            self.checkpoint('agent_error', error=f'{type(exc).__name__}: {exc}')
            raise

    def freeze(self):
        from harness.bundle import export_bundle
        sandbox = self.ready_sandbox()
        report = export_bundle(sandbox, self.result / 'frozen',
                               project=self.task.task_id)
        self.checkpoint('source_frozen', export=report)
        return {'valid': True, 'export': report}

    def export(self):
        """Freeze only the declarative source; running containers are not graded."""
        if not (self.workspace / 'docker-compose.yaml').is_file():
            report = self.plugin.grade(GradeRequest(
                self.task, self.result / 'grade', stage=self.workspace,
                options={'keep_data': False}))
            write_json(self.result / 'grade' / 'result.json', {
                'schema_version': 1, 'task_id': self.task.task_id,
                'family': 'cybergym', 'task_type': self.task.task_type,
                'stage': str(self.workspace), **report})
            self.checkpoint('grade_failed', reward=0, failure_stage='delivery')
            return report
        return self.freeze()

    def grade(self, timeout=60):
        stage = self.result / 'frozen' / 'delivery'
        if not (stage / 'source').is_dir():
            if not (self.workspace / 'docker-compose.yaml').is_file():
                # export() already grades a completed workspace without a
                # compose file; do not replace that verdict with a freeze error.
                return self.export()
            raise ValueError('frozen source is absent')
        self.checkpoint('grading')
        request = GradeRequest(self.task, self.result / 'grade', stage=stage,
                               options={'keep_data': False})
        record = self.plugin.grade(request)
        write_json(self.result / 'grade' / 'result.json', {
            'schema_version': 1, 'task_id': self.task.task_id, 'family': 'cybergym',
            'task_type': self.task.task_type,
            'stage': str(stage), **record})
        self.checkpoint('graded' if record['reward'] else 'grade_failed', reward=record['reward'],
                        failure_stage=record.get('failure_stage'))
        return record

    def stop(self, remove_data: bool = False):
        sandbox = self.open_sandbox()
        if sandbox.probe()['exists']:
            sandbox.attach()
            sandbox.stop(remove_data=remove_data)
        self.checkpoint('stopped')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'agent', 'freeze', 'export', 'grade', 'stop'))
    parser.add_argument('--task', required=True)
    parser.add_argument('--result', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, default=Path('/var/tmp/cybergym-runs'))
    parser.add_argument('--model', default='')
    parser.add_argument('--timeout', type=int, default=18000)
    parser.add_argument('--max-turns', type=int, default=150)
    parser.add_argument('--oracle-timeout', type=int, default=60)
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args(argv)
    task = TaskSpec.load(Path(args.task).resolve())
    pipeline = Pipeline(task, args.result.resolve(), args.runtime.resolve())
    if args.command == 'prepare':
        pipeline.prepare(force=args.force)
    elif args.command == 'agent':
        if not args.model:
            parser.error('--model is required for agent; this pipeline never chooses a paid model implicitly')
        pipeline.run_agent(args.model, args.timeout, args.max_turns)
    elif args.command == 'freeze':
        report = pipeline.freeze()
        if not report['valid']:
            return 1
    elif args.command == 'export':
        pipeline.export()
    elif args.command == 'grade':
        return 0 if pipeline.grade(args.oracle_timeout)['reward'] else 1
    else:
        pipeline.stop()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
