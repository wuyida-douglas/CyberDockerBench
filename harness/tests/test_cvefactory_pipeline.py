"""Offline contract tests for the agent-only CVE-Factory grading pipeline."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from harness.families.cvefactory import grader
from harness.families.cvefactory.workspace import prepare_workspace, validate_public_task


def cp(args, returncode=0, stdout='', stderr=''):
    return subprocess.CompletedProcess(args, returncode, stdout, stderr)


class FakeSandbox:
    """Strict command-level fake; no Docker daemon or real test files are used."""

    instances = []
    behaviors = {}

    def __init__(self, task_id, runtime_root):
        self.task_id = task_id
        self.runtime_root = Path(runtime_root)
        self.kind = self.runtime_root.name.split('-', 1)[0]
        self.workspace = self.runtime_root / 'workspace'
        self.calls = []
        self.started = False
        self.stopped = False
        self.phase = 'vulnerable'
        self.test_runs = 0
        self.behavior = dict(self.behaviors.get(self.kind, {}))
        self.__class__.instances.append(self)

    def start(self):
        self.calls.append(('sandbox', 'start'))
        self.started = True
        self.workspace.mkdir(parents=True, exist_ok=True)

    def stop(self, remove_data=True):
        self.calls.append(('sandbox', 'stop', remove_data))
        self.stopped = True

    def docker(self, args, timeout=120, **kwargs):
        args = list(args)
        if args[:2] == ['restart', 'client-source'] and not self.behavior.get('no_solution'):
            self.phase = 'fixed'
        self.calls.append(('docker', args, timeout))
        if args[0] == 'compose':
            operation = next((part for part in args[1:]
                              if part in ('config', 'build', 'up', 'ps')), '')
            if operation == 'config':
                config = {
                    'client': {'image': 'example/client'},
                    'db': {'image': 'example/db'},
                }
                if self.behavior.get('tester'):
                    config['tester'] = {
                        'image': 'example/tester',
                        'labels': {
                            'cdb.test_service': 'tester',
                            'cdb.test_command': self.behavior.get(
                                'custom_command', 'bash /opt/tester/bootstrap.sh --offline'),
                        },
                    }
                return cp(args, stdout=yaml.safe_dump({'services': config}, sort_keys=False))
            if operation == 'build':
                failure = self.behavior.get('build_failure')
                return cp(args, returncode=bool(failure), stderr=failure or '')
            if operation == 'up':
                return cp(args)
            if operation == 'ps':
                service = args[-1]
                if service == 'db':
                    return cp(args, returncode=1, stderr='unexpected direct db lookup')
                if service == 'tester' and not self.behavior.get('tester'):
                    return cp(args, returncode=1, stderr='no such service')
                return cp(args, stdout=f'{service}-{self.kind}\n')
        if args[0] == 'restart':
            if self.behavior.get('restart_failure'):
                return cp(args, returncode=1, stderr='unhealthy after restart')
            return cp(args, stdout=args[1] + '\n')
        if args[0] == 'inspect':
            if '{{.State.Running}}' in args:
                return cp(args, stdout=('true\n' if self.behavior.get('replaced_client')
                                        else 'false\n'))
            if self.behavior.get('restart_failure'):
                return cp(args, stdout='unhealthy\n')
            return cp(args, stdout='healthy\n')
        if args[0] == 'cp':
            source = Path(args[1].removesuffix('/.'))
            if not source.exists():
                return cp(args, returncode=1, stderr='frozen source is missing')
            return cp(args)
        if args[0] == 'exec':
            if any(str(part).endswith('/solution.sh') for part in args):
                if self.behavior.get('solution_failure'):
                    return cp(args, returncode=2, stderr='patch rejected')
                return cp(args)
            if any(str(part).endswith('run-tests.sh') for part in args) or (
                    len(args) >= 2 and args[-2] == '-c' and '-m pytest' not in str(args[-1])
                    and 'rm -rf' not in str(args[-1])):
                return cp(args, returncode=self.behavior.get('script_returncode', 0),
                          stdout='agent runner completed\n')
            if '-m pytest' in args[-1]:
                name = 'test_func.py' if 'test_func.py' in args[-1] else 'test_vuln.py'
                return cp(args, **self._pytest(name))
        return cp(args)

    def _pytest(self, name):
        override = self.behavior.get(f'{self.phase}_{name}')
        if override is not None:
            return override
        if self.phase == 'vulnerable' and name == 'test_vuln.py':
            return {
                'returncode': 1,
                'stdout': ('FAILED test_vuln.py::test_real_vulnerability - '
                           'AssertionError: exploit was blocked\n1 failed in 0.1s\n'),
            }
        return {'returncode': 0, 'stdout': (
            f'PASSED {name}::test_real_behavior\n'
            f'PASSED {name}::test_second_behavior\n'
            '2 passed in 0.1s\n')}


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cdb-new-pipeline-')
        self.root = Path(self.temp.name)
        self.task = self.root / 'tasks' / 'cvefactory-cve-2099-0001'
        self.task.mkdir(parents=True)
        (self.task / 'gold').mkdir()
        (self.task / 'gold' / 'test_vuln.py').write_text('raise AssertionError("private")\n')
        (self.task / 'gold' / 'official-tests').mkdir()
        self.delivery = self.root / 'results' / self.task.name / 'delivery'
        self.source = self.delivery / 'source'
        (self.source / 'tests').mkdir(parents=True)
        for name in ('test_func.py', 'test_vuln.py', 'run-tests.sh'):
            (self.source / 'tests' / name).write_text(f'# agent-owned {name}\n')
        (self.source / 'docker-compose.yaml').write_text(
            'services:\n  client:\n    image: example/client\n')
        (self.source / 'Dockerfile').write_text('FROM scratch\n')
        (self.source / 'solution.sh').write_text('# agent patch\n')
        for name in ('bundle.json', 'source-inventory.json'):
            (self.delivery / name).write_text(json.dumps({'agent_owned': True}))
        self.out = self.root / 'results' / self.task.name
        self.before = {
            path.relative_to(self.task): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.task.rglob('*') if path.is_file()
        }
        FakeSandbox.instances = []
        FakeSandbox.behaviors = {}
        self.sandbox_patch = mock.patch.object(grader, 'DockerSandbox', FakeSandbox)
        self.sandbox_patch.start()

    def tearDown(self):
        self.sandbox_patch.stop()
        self.temp.cleanup()

    def assert_task_untouched(self):
        after = {
            path.relative_to(self.task): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.task.rglob('*') if path.is_file()
        }
        self.assertEqual(after, self.before)

    def test_source_patch_restart_and_fixed_passes(self):
        result = grader.grade(self.task, self.out, self.delivery)
        self.assertEqual(result['reward'], 1, result)
        self.assertEqual(result['status'], 'passed')
        self.assertIsNone(result['failure_class'])
        self.assertTrue(result['checks']['differential']['f2p']['success'])
        self.assertTrue(result['checks']['differential']['p2p']['success'])
        self.assertNotIn('snapshot', result['checks'])
        self.assertEqual(len(FakeSandbox.instances), 1)
        source = FakeSandbox.instances[0]
        self.assertTrue(source.stopped)

        source_significant = [
            call[1] for call in source.calls if call[0] == 'docker' and (
                call[1][0] in ('cp', 'restart') or
                call[1][0] == 'compose' and any(
                    item in ('build', 'up') for item in call[1]) or
                call[1][0] == 'exec' and any(
                    str(part).endswith('/solution.sh') for part in call[1]))
        ]
        vulnerable = next(i for i, args in enumerate(source_significant)
                          if args[0] == 'cp' and '/tests' in args[1])
        solution = next(i for i, args in enumerate(source_significant)
                        if args[0] == 'exec' and args[-1].endswith('/solution.sh'))
        restart = next(i for i, args in enumerate(source_significant)
                       if args[0] == 'restart')
        fixed = next(i for i, args in enumerate(source_significant)
                     if args[0] == 'cp' and '/tests' in args[1] and i > solution)
        positions = {'vulnerable': vulnerable, 'solution': solution,
                     'restart': restart, 'fixed': fixed}
        self.assertLess(positions['vulnerable'], positions['solution'])
        self.assertLess(positions['solution'], positions['restart'])
        self.assertLess(positions['restart'], positions['fixed'])
        solution_call = next(args for args in source_significant
                             if args[0] == 'exec' and args[-1].endswith('/solution.sh'))
        self.assertEqual(solution_call[-2:], ['sh', '/tmp/cdb-solution/solution.sh'])
        self.assertIn('--user', solution_call)
        self.assertEqual(solution_call[solution_call.index('--user') + 1], 'root')
        runner_calls = [call[1] for call in source.calls if call[0] == 'docker'
                        and call[1][0] == 'exec'
                        and call[1][-3:-1] == ['sh', '/tmp/cdb-tests/run-tests.sh']]
        self.assertEqual([args[-1] for args in runner_calls], ['vulnerable', 'fixed'])
        for call in source.calls:
            if call[0] == 'docker' and call[1][0] == 'compose':
                args = call[1]
                directory = args[args.index('--project-directory') + 1]
                compose_file = args[args.index('-f') + 1]
                self.assertEqual(Path(compose_file).parent, Path(directory))
                self.assertTrue(args[args.index('-p') + 1].startswith('cdb-'))
        self.assertEqual(sum(args[0] == 'compose' and 'build' in args
                             for args in source_significant), 1)
        all_arguments = repr(source.calls)
        self.assertNotIn('/app', all_arguments)
        solution_copies = [args for args in source_significant
                           if args[0] == 'cp' and args[-1].endswith(':/tmp/cdb-solution')]
        self.assertEqual(len(solution_copies), 1)
        self.assertTrue(solution_copies[0][1].startswith(str(source.workspace) + '/'))
        self.assertNotEqual(Path(solution_copies[0][1].removesuffix('/.')),
                            source.workspace / 'source')
        self.assertNotIn('pip install', all_arguments)
        self.assertNotIn('-m pytest', all_arguments)
        self.assertNotIn('uv pip', all_arguments)
        self.assertNotIn('patched', all_arguments)
        self.assert_task_untouched()

    def test_solution_cannot_replace_client_to_fake_a_successful_restart(self):
        FakeSandbox.behaviors['source'] = {'restart_failure': True, 'replaced_client': True}
        result = grader.grade(self.task, self.out, self.delivery)
        self.assertEqual(result['reward'], 0)
        self.assertEqual(result['failure_class'], 'agent_semantic')
        self.assertEqual(result['failure_stage'], 'restart')
        self.assertNotIn('fixed', result['checks'])

    def test_runner_nonzero_fails_the_phase(self):
        FakeSandbox.behaviors['source'] = {'script_returncode': 1}
        result = grader.grade(self.task, self.out, self.delivery)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['failure_class'], 'agent_semantic')
        self.assertEqual(result['failure_stage'], 'vulnerable')
        self.assertFalse(result['checks']['vulnerable']['success'])
        self.assertIn('run-tests.sh vulnerable exited 1', result['error'])
        self.assertNotIn('solution', result['checks'])
        self.assertNotIn('-m pytest', repr(FakeSandbox.instances[0].calls))
        self.assertEqual(len(FakeSandbox.instances), 1)

    def test_solution_failure_skips_restart_and_fixed(self):
        FakeSandbox.behaviors['source'] = {'solution_failure': True}
        result = grader.grade(self.task, self.out, self.delivery)
        self.assertEqual(result['failure_class'], 'agent_semantic')
        self.assertEqual(result['failure_stage'], 'solution')
        self.assertNotIn('restart', result['checks'])
        self.assertNotIn('fixed', result['checks'])
        self.assertEqual(len(FakeSandbox.instances), 1)

    def test_network_build_failure_is_not_agent_semantic(self):
        FakeSandbox.behaviors['source'] = {
            'build_failure': 'failed to fetch registry: i/o timeout',
        }
        result = grader.grade(self.task, self.out, self.delivery)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['failure_class'], 'network')
        self.assertNotIn('vulnerable', result['checks'])

    def test_declarative_build_failure_is_agent_semantic(self):
        FakeSandbox.behaviors['source'] = {
            'build_failure': 'Dockerfile parse error: unknown instruction FROB',
        }
        result = grader.grade(self.task, self.out, self.delivery)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['failure_class'], 'agent_semantic')

    def test_private_task_stage_and_test_symlink_are_rejected(self):
        result = grader.grade(self.task, self.out, self.task)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['failure_class'], 'pipeline')
        self.assertEqual(FakeSandbox.instances, [])
        self.assert_task_untouched()

        (self.source / 'tests' / 'test_vuln.py').unlink()
        (self.source / 'tests' / 'test_vuln.py').symlink_to(
            self.task / 'gold' / 'test_vuln.py')
        result = grader.grade(self.task, self.out, self.delivery)
        self.assertEqual(result['failure_class'], 'pipeline')
        self.assertEqual(result['failure_stage'], 'delivery')
        self.assertEqual(FakeSandbox.instances, [])

    def test_custom_test_service_and_command_are_unchanged(self):
        command = "bash /opt/tester/bootstrap.sh --offline --flag 'two words'"
        FakeSandbox.behaviors['source'] = {'tester': True, 'custom_command': command}
        result = grader.grade(self.task, self.out, self.delivery)
        self.assertEqual(result['reward'], 1, result)
        source = FakeSandbox.instances[0]
        script_calls = [call[1] for call in source.calls if call[0] == 'docker'
                        and call[1][0] == 'exec' and call[1][-1] == command]
        self.assertEqual(len(script_calls), 2)
        for args in script_calls:
            self.assertEqual(args[-3:], ['sh', '-c', command])
            self.assertIn('tester-source', args)
        self.assertNotEqual(source.behavior['custom_command'] + ' altered', command)
        self.assert_task_untouched()

    def test_compose_escaped_test_command_matches_runtime_label(self):
        command = 'sh /tmp/cdb-tests/run-tests.sh $${CDB_TEST_PHASE:-vulnerable}'
        resolved = grader._validate_compose_contract(
            {'services': {
                'client': {},
                'tester': {'labels': {
                    'cdb.test_service': 'tester',
                    'cdb.test_command': command,
                }},
            }}, 'agent_semantic', 'source_contract')
        self.assertEqual(resolved, (
            'client', 'tester',
            'sh /tmp/cdb-tests/run-tests.sh ${CDB_TEST_PHASE:-vulnerable}',
        ))

    def test_failed_status_and_result_json_survive_exceptions(self):
        with mock.patch.object(FakeSandbox, 'start', side_effect=RuntimeError('dockerd died')):
            result = grader.grade(self.task, self.out, self.delivery)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['failure_class'], 'pipeline')
        saved = json.loads((self.out / 'result.json').read_text())
        self.assertEqual(saved['reward'], 0)
        self.assertEqual(saved['failure_class'], 'pipeline')


class PublicWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cdb-public-workspace-')
        self.root = Path(self.temp.name)
        self.task = self.root / 'task'
        (self.task / 'input' / 'src').mkdir(parents=True)
        (self.task / 'input' / 'src' / 'main.py').write_text('print("public")\n')
        (self.task / 'input' / 'CVE.md').write_text('public CVE\n')
        (self.task / 'input' / 'BUILDING.md').write_text('public build notes\n')
        (self.task / 'gold').mkdir()
        (self.task / 'gold' / 'solution.sh').write_text('private\n')
        (self.task / 'instruction.md').write_text('# Public task\n\nDo not use /app.')

    def tearDown(self):
        self.temp.cleanup()

    def test_prepare_copies_public_input_and_new_contract_only(self):
        workspace = self.root / 'workspace'
        self.assertEqual(validate_public_task(self.task), [])
        prepare_workspace(self.task, workspace)
        self.assertEqual((workspace / 'src' / 'main.py').read_text(), 'print("public")\n')
        self.assertFalse((workspace / 'BUILDING.md').exists())
        task_text = (workspace / 'TASK.md').read_text()
        self.assertIn('# Public task', task_text)
        self.assertIn('vulnerable', task_text)
        self.assertIn('cdb.test_service', task_text)
        self.assertIn('not required to live in `/app`', task_text)
        self.assertNotIn('SOURCES.md', task_text)
        self.assertNotIn('snapshot', task_text)
        self.assertFalse((workspace / 'gold').exists())
        with self.assertRaises(FileExistsError):
            prepare_workspace(self.task, workspace)

    def test_public_input_symlink_cannot_reach_private_files(self):
        (self.task / 'input' / 'answer').symlink_to(
            self.task / 'gold' / 'solution.sh')
        self.assertTrue(validate_public_task(self.task))
        with self.assertRaises(ValueError):
            prepare_workspace(self.task, self.root / 'workspace')


if __name__ == '__main__':
    unittest.main()
