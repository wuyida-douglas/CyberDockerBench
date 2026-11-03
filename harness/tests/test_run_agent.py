"""Mocked contract tests for the one-task Claude runner; never launches Claude."""
from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import harness.run_agent as runner
import harness.run_batch as batch
from harness.docker_sandbox import DockerSandbox
from harness.task_api import TaskSpec


class DeliveryContractTests(unittest.TestCase):
    def test_solution_execution_contract_uses_client_root(self):
        from harness.families.cvefactory import grader
        self.assertEqual(grader.SOLUTION_ROOT, '/tmp/cdb-solution')
        environment = grader._Environment.__new__(grader._Environment)
        with mock.patch.object(environment, 'container', return_value='cdb-client'), \
                mock.patch.object(environment, 'docker', side_effect=[
                    subprocess.CompletedProcess([], 0),
                    subprocess.CompletedProcess([], 0),
                    subprocess.CompletedProcess([], 0)]) as docker:
            environment.solution_source = Path('/frozen/source')
            result = environment.apply_solution()
        self.assertTrue(result['success'])
        command = docker.call_args_list[2].args[0]
        self.assertEqual(command[:4], ['exec', '--user', 'root', '--workdir'])
        self.assertEqual(command[-4:], ['/tmp/cdb-solution', 'cdb-client',
                                       'sh', '/tmp/cdb-solution/solution.sh'])

    def test_test_injection_refuses_a_bind_mount_before_deleting(self):
        from harness.families.cvefactory import grader
        environment = grader._Environment.__new__(grader._Environment)
        environment.kind = 'source'
        environment.test_source = Path('/frozen/tests')
        with mock.patch.object(environment, 'docker', return_value=subprocess.CompletedProcess([], 0)) as docker:
            environment.inject_tests('client')
        script = docker.call_args_list[0].args[0][-1]
        self.assertIn('/proc/mounts', script)
        self.assertIn('exit 42', script)
        self.assertIn('rm -rf /tmp/cdb-tests', script)
        environment.kind = 'source'
        with mock.patch.object(environment, 'docker', return_value=subprocess.CompletedProcess(
                [], 42, stderr='refusing to replace bind-mounted /tmp/cdb-tests\n')):
            with self.assertRaises(grader._Failure) as caught:
                environment.inject_tests('client')
        self.assertEqual(caught.exception.failure_class, 'agent_semantic')
        self.assertIn('bind mount', str(caught.exception))

    def test_debug_alias_does_not_fail_a_frozen_tree(self):
        from harness.families.cvefactory import grader
        from harness.staging import stage_delivery
        parent = Path(tempfile.mkdtemp(prefix='cdb-debug-link-'))
        root = parent / 'delivery'
        root.mkdir()
        try:
            (root / 'docker-compose.yaml').write_text('services: {}\n')
            (root / 'latest').symlink_to(root / 'cli-debug.log')
            grader._safe_tree(root, parent / 'private-task')
            staged = parent / 'staged'
            stage_delivery(root, staged)
            self.assertFalse((staged / 'latest').exists())
            self.assertTrue((root / 'latest').is_symlink())
        finally:
            import shutil
            shutil.rmtree(parent, ignore_errors=True)


class SandboxTransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cdb-sandbox-transfer-')
        self.root = Path(self.temp.name)
        self.sandbox = DockerSandbox('transfer-test', self.root / 'runtime')
        self.sandbox.container = 'cdb-transfer-test'

    def tearDown(self):
        self.temp.cleanup()

    def test_public_copy_in_is_writable_by_agent(self):
        with mock.patch.object(self.sandbox, 'exec',
                               return_value=subprocess.CompletedProcess([], 0)), \
                mock.patch('harness.docker_sandbox.run',
                           return_value=subprocess.CompletedProcess([], 0)) as command:
            self.sandbox.copy_in(self.root, str(self.sandbox.workspace / 'input'))
        self.assertEqual(command.call_count, 2)
        self.assertEqual(command.call_args.args[0][-2:],
                         ['1000:1000', str(self.sandbox.workspace / 'input')])

    def test_plain_file_copy_in_is_not_untarred(self):
        source = self.root / 'helper.sh'
        source.write_text('#!/bin/sh\n')
        with mock.patch('harness.docker_sandbox.run',
                        return_value=subprocess.CompletedProcess([], 0)) as command, \
                mock.patch.object(self.sandbox, 'exec',
                                  return_value=subprocess.CompletedProcess([], 0)) as execute:
            self.sandbox.copy_in(source, '/usr/local/bin/helper')
        self.assertEqual(command.call_args.args[0],
                         ['docker', 'cp', str(source), 'cdb-transfer-test:/usr/local/bin/helper'])
        self.assertEqual(execute.call_args.args[0],
                         ['mkdir', '-p', '--', '/usr/local/bin'])

    def test_explicit_sandbox_name_survives_path_specific_attempt(self):
        sandbox = DockerSandbox('snapshot-validation', self.root / 'second-attempt',
                                name='snapshot-restoration-unique')
        self.assertEqual(sandbox.container, 'snapshot-restoration-unique')
        self.assertEqual(sandbox.network, 'snapshot-restoration-unique-net')

    def test_absolute_copy_out_stays_in_outer_sandbox(self):
        with mock.patch('harness.docker_sandbox.run',
                        return_value=subprocess.CompletedProcess([], 0)) as command:
            self.sandbox.copy_out('/var/tmp/image.tar', self.root / 'image.tar')
        command.assert_called_once()
        self.assertIn('cdb-transfer-test:/var/tmp/image.tar', command.call_args.args[0])

    def test_inner_copy_out_extracts_only_outer_paths(self):
        calls = []

        def fake_exec(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0)

        with mock.patch.object(self.sandbox, 'exec', side_effect=fake_exec), \
                mock.patch('harness.docker_sandbox.run',
                           return_value=subprocess.CompletedProcess([], 0)) as command:
            self.sandbox.copy_out('a' * 64 + ':/var/lib/data/.',
                                  self.root / 'unmounted-delivery' / 'volume')
        self.assertEqual(calls[0][:4], [
            'sh', '-c', 'exec docker cp "$1" - > "$2"', 'cdb-copy',
        ])
        self.assertEqual(calls[0][4], 'a' * 64 + ':/var/lib/data/.')
        archive = calls[0][5]
        self.assertTrue(archive.startswith('/var/tmp/cdb-copy-'))
        extract = next(call for call in calls if call[:3] == ['python3', '-c', mock.ANY])
        self.assertEqual(extract[3], archive)
        self.assertTrue(extract[4].startswith('/var/tmp/cdb-copy-destination-'))
        self.assertEqual(extract[5], 'directory')
        command.assert_called_once()
        self.assertEqual(command.call_args.args[0], [
            'docker', 'cp', 'cdb-transfer-test:' + extract[4] + '/.',
            str(self.root / 'unmounted-delivery' / 'volume'),
        ])
        self.assertEqual(calls[-1], ['rm', '-rf', '--', archive, extract[4]])


class FakeSandbox:
    instances = []

    def __init__(self, task_id, runtime_root):
        self.task_id = task_id
        self.runtime_root = Path(runtime_root)
        self.workspace = self.runtime_root / 'workspace'
        self.container = 'cdb-fake-' + task_id
        self.image_reference = 'cdb-sandbox:unit-test'
        self.image_id = 'sha256:' + '0' * 64
        self.plugin_mounts = []
        self.started = False
        self.stopped = False
        self.stop_calls = []
        self.exec_calls = []
        self.docker_calls = []
        self.popen_calls = []
        FakeSandbox.instances.append(self)

    def agent_plugin(self, source, target):
        self.plugin_mounts.append((source, target))

    def start(self):
        self.started = True

    def stop(self, remove_data=False):
        self.stop_calls.append(remove_data)
        self.stopped = True

    def exec(self, args, timeout=120, **kwargs):
        self.exec_calls.append((args, timeout, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout='source ok', stderr='')

    def docker(self, args, timeout=120):
        self.docker_calls.append((args, timeout))
        return subprocess.CompletedProcess(args, 0, stdout='docker ok', stderr='')

    def popen(self, *args, **kwargs):
        self.popen_calls.append((args, kwargs))
        return FakeProcess()


class FakeProcess:
    def __init__(self, returncode=0):
        self.returncode = returncode

    def communicate(self, timeout=None):
        return 'preflight ok', ''


class RunnerContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cdb-run-agent-test-')
        self.root = Path(self.temp.name)
        FakeSandbox.instances = []
        runner._SECRET_VALUES.clear()
        self.task = self.root / 'tasks' / 'cvefactory-cve-2099-0001'
        (self.task / 'input' / 'src').mkdir(parents=True)
        (self.task / 'input' / 'CVE.md').write_text('public CVE\n')
        (self.task / 'input' / 'src' / 'app.py').write_text('print("vulnerable")\n')
        (self.task / 'metadata.yaml').write_text(json.dumps({
            'task_id': self.task.name, 'task_type': 'bugfix', 'family': 'cvefactory',
        }))
        (self.task / 'gold').mkdir()
        (self.task / 'gold' / 'answer.sh').write_text('private\n')
        self.results = self.root / 'result'

    def tearDown(self):
        runner._SECRET_VALUES.clear()
        self.temp.cleanup()

    def credentials(self):
        return {'ANTHROPIC_BASE_URL': 'https://model.invalid/v1',
                'ANTHROPIC_AUTH_TOKEN': 'unit-test-token'}

    def deliver(self, sandbox):
        for name in runner.REQUIRED_DELIVERABLES:
            path = sandbox.workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name + '\n')

    def test_native_cli_uses_default_tools_empty_settings_and_network_plugin(self):
        cmd = runner.build_agent_command('test-model', 180)
        self.assertIn('--output-format', cmd)
        self.assertEqual(cmd[cmd.index('--output-format') + 1], 'stream-json')
        self.assertIn('--verbose', cmd)
        self.assertNotIn('even if they do not build or pass yet', ' '.join(cmd))
        self.assertEqual(cmd[cmd.index('--setting-sources') + 1], '')
        self.assertEqual(cmd[cmd.index('--plugin-dir') + 1], '/opt/cdb-network-plugin')
        self.assertEqual(cmd[cmd.index('--permission-mode') + 1], 'bypassPermissions')
        self.assertEqual(cmd[cmd.index('--max-turns') + 1], '180')
        self.assertNotIn('--tools', cmd)
        self.assertIn('--strict-mcp-config', cmd)
        self.assertEqual(cmd[cmd.index('--mcp-config') + 1], '{"mcpServers":{}}')
        self.assertEqual(cmd[cmd.index('--permission-prompts') + 1], 'none')
        self.assertNotIn('gold', runner.TASK_PROMPT)
        self.assertNotIn('/app/solution.sh', runner.TASK_PROMPT)
        self.assertIn('/tmp/cdb-tests', runner.TASK_PROMPT)
        self.assertNotIn(':/cdb-tests', runner.TASK_PROMPT)
        self.assertNotIn('`/cdb-tests`', runner.TASK_PROMPT)
        self.assertIn('Do not bind-mount', runner.TASK_PROMPT)
        self.assertIn('vulnerable|fixed', runner.TASK_PROMPT)
        self.assertNotIn('SOURCES.md', runner.TASK_PROMPT)
        self.assertIn('sh /tmp/cdb-solution/solution.sh', runner.TASK_PROMPT)
        self.assertIn('not on the sandbox host', runner.TASK_PROMPT)
        self.assertIn('Do not use `docker`, `sudo`', runner.TASK_PROMPT)
        self.assertIn('pip install', runner.TASK_PROMPT)
        self.assertIn('COPY /tmp/app /opt/app', runner.TASK_PROMPT)
        self.assertIn('outside this workspace', runner.TASK_PROMPT)
        self.assertIn('dbdata:/var/lib/mysql', runner.TASK_PROMPT)
        self.assertIn('Do not use `tmpfs`', runner.TASK_PROMPT)
        # Both the task contract and the short -p prompt explicitly name the
        # same Skill; plugin metadata discovery alone does not prove it was read.
        self.assertIn('/opt/cdb-network-plugin/skills/kkrepo-network/SKILL.md', runner.TASK_PROMPT)
        self.assertIn('/opt/cdb-network-plugin/skills/kkrepo-network/SKILL.md', ' '.join(cmd))
        self.assertNotIn('optional guidance', runner.TASK_PROMPT)
        self.assertIn('run-tests.sh vulnerable', runner.TASK_PROMPT)
        self.assertIn('exits 0', runner.TASK_PROMPT)
        self.assertNotIn('python3 -m pytest', runner.TASK_PROMPT)
        self.assertNotIn('even if they do not build', runner.TASK_PROMPT)
        self.assertNotIn('disk, debug them.', runner.TASK_PROMPT)

    def test_staging_is_public_mutable_and_does_not_restore_source(self):
        workspace = self.root / 'workspace'
        runner.prepare_public_workspace(TaskSpec.load(self.task), workspace)
        self.assertEqual((workspace / 'CVE.md').read_text(), 'public CVE\n')
        self.assertEqual((workspace / 'src' / 'app.py').read_text(), 'print("vulnerable")\n')
        self.assertFalse((workspace / 'gold').exists())
        task_prompt = (workspace / 'TASK.md').read_text()
        self.assertIn('private task data', task_prompt.lower())
        self.assertIn('COMPOSE_PROJECT_NAME', task_prompt)
        (workspace / 'src' / 'app.py').write_text('replaced\n')
        self.assertEqual((workspace / 'src' / 'app.py').read_text(), 'replaced\n')
        self.assertEqual((self.task / 'input' / 'src' / 'app.py').read_text(),
                         'print("vulnerable")\n')
        with self.assertRaises(FileExistsError):
            runner.prepare_public_workspace(TaskSpec.load(self.task), workspace)

    def test_moving_the_debug_log_removes_its_alias(self):
        sandbox = FakeSandbox(self.task.name, self.results)
        sandbox.workspace.mkdir(parents=True)
        log = sandbox.workspace / 'cli-debug.log'
        log.write_text('debug\n')
        (sandbox.workspace / 'latest').symlink_to(log)
        runner._finalize_debug_log(sandbox, self.results)
        self.assertFalse((sandbox.workspace / 'latest').exists())
        self.assertFalse(log.exists())
        self.assertEqual((self.results / 'cli-debug.log').read_text(), 'debug\n')

    def test_model_credentials_come_from_the_launcher_environment(self):
        credentials, info = runner.load_model_environment({
            'ANTHROPIC_BASE_URL': 'https://gateway.invalid',
            'ANTHROPIC_AUTH_TOKEN': 'process-token',
            'ANTHROPIC_SMALL_FAST_MODEL': 'qwen36-baseline',
            'CLAUDE_CODE_STREAM_TIMEOUT': '7200000',
            'UNRELATED_SECRET': 'leave-behind',
            'CDB_MODEL_ENV_FILE': '/tmp/ignored.env',
        })
        self.assertEqual(credentials['ANTHROPIC_BASE_URL'], 'https://gateway.invalid')
        self.assertEqual(credentials['ANTHROPIC_AUTH_TOKEN'], 'process-token')
        self.assertEqual(credentials['ANTHROPIC_SMALL_FAST_MODEL'], 'qwen36-baseline')
        self.assertEqual(credentials['CLAUDE_CODE_STREAM_TIMEOUT'], '7200000')
        self.assertNotIn('UNRELATED_SECRET', credentials)
        self.assertEqual(info['source'], 'run-factory-eval.sh')
        self.assertEqual(info['values'], '<redacted>')
        with self.assertRaisesRegex(RuntimeError, 'requires ANTHROPIC_BASE_URL'):
            runner.load_model_environment({})

    def test_success_launches_agent_as_agent_then_exports_and_does_not_grade(self):
        seen = {}

        def fake_stream(sandbox, cmd, out_dir, timeout_sec, extra_env, console_path=None, max_turns=None):
            seen.update(sandbox=sandbox, cmd=cmd, timeout=timeout_sec, env=extra_env)
            self.deliver(sandbox)
            (sandbox.workspace / 'cli-debug.log').write_text('debug\n')
            (out_dir / 'trajectory.jsonl').write_text(json.dumps({
                'type': 'result', 'is_error': False, 'num_turns': 4, 'result': 'done',
            }) + '\n')
            return FakeProcess()

        def fake_export(sandbox, destination, project=None, **kwargs):
            seen['exported_before_stop'] = not sandbox.stopped
            seen['bundle'] = destination
            seen['export_kwargs'] = kwargs
            destination.mkdir(parents=True)
            (destination / 'manifest.json').write_text('{}\n')
            return {'manifest': str(destination / 'manifest.json')}

        with mock.patch.object(runner, 'DockerSandbox', FakeSandbox), \
                mock.patch.object(runner, 'stream_agent', fake_stream), \
                mock.patch('harness.bundle.export_bundle', fake_export), \
                mock.patch.dict(runner.os.environ, self.credentials(), clear=True):
            record = runner.run_one(self.task, self.results, model='glm-5.3',
                                    max_turns=180, timeout_sec=43200)
        self.assertEqual(record['pipeline']['status'], 'succeeded')
        self.assertEqual(record['agent']['status'], 'completed')
        self.assertEqual(record['export']['status'], 'completed')
        self.assertEqual(record['failure_category'], None)
        self.assertNotIn('reward', record)
        self.assertEqual(record['grading']['status'], 'not_run')
        self.assertTrue(seen['exported_before_stop'])
        self.assertNotIn('snapshot', seen['export_kwargs'])
        self.assertEqual(seen['bundle'], self.results / 'bundle')
        self.assertEqual(seen['timeout'], 43200)
        self.assertEqual(seen['env']['HOME'], '/home/agent')
        self.assertEqual(seen['env']['CLAUDE_CODE_MAX_RETRIES'], '15')
        self.assertEqual(seen['env']['CLAUDE_CODE_MAX_CONTEXT_TOKENS'], '131072')
        self.assertEqual(set(seen['env']), {
            'HOME', *self.credentials(), 'CLAUDE_CODE_MAX_RETRIES',
            'CLAUDE_CODE_MAX_CONTEXT_TOKENS',
        })
        sandbox = FakeSandbox.instances[0]
        self.assertEqual(sandbox.plugin_mounts, [
            (str(runner.PLUGIN_SOURCE), '/opt/cdb-network-plugin'),
        ])
        self.assertFalse((sandbox.workspace / 'gold').exists())
        self.assertEqual(json.loads((self.results / 'result.json').read_text()), record)
        self.assertEqual(record['missing_deliverables'], [])
        self.assertEqual(record['containers'][0]['labels']['cyberdockerbench.task'],
                         self.task.name)
        self.assertNotIn('unit-test-token', (self.results / 'result.json').read_text())

    def test_preflight_only_needs_no_credentials_and_never_launches_model(self):
        def no_model(*args, **kwargs):
            raise AssertionError('Claude must not launch in preflight-only mode')

        with mock.patch.object(runner, 'DockerSandbox', FakeSandbox), \
                mock.patch.object(runner, 'stream_agent', no_model), \
                mock.patch.object(runner, 'GENERIC_PREFLIGHT', True), \
                mock.patch.object(runner, 'load_model_environment') as load_env, \
                mock.patch('harness.bundle.export_bundle', return_value={}), \
                mock.patch.dict(runner.os.environ, {'HTTPS_PROXY': 'http://proxy.invalid'}, clear=True):
            record = runner.run_one(self.task, self.results, preflight_only=True)
        load_env.assert_not_called()
        self.assertEqual(record['agent']['status'], 'skipped')
        self.assertEqual(record['pipeline']['status'], 'succeeded')
        self.assertTrue(record['preflight']['success'])
        self.assertEqual(record['attempts']['agent'], 0)
        sandbox = FakeSandbox.instances[0]
        source_commands = [call[0] for call in sandbox.exec_calls]
        self.assertTrue(any('git clone' in part for command in source_commands
                            for part in command))
        self.assertTrue(any(call[0][0] == 'pull' for call in sandbox.docker_calls))
        all_commands = '\n'.join(part for command in source_commands for part in command)
        all_commands += '\n'.join(part for call in sandbox.popen_calls
                                 for part in call[0] for part in part)
        self.assertIn('raw.githubusercontent.com', all_commands)
        self.assertIn("curl --noproxy '*'", all_commands)
        self.assertIn('docker compose', all_commands)
        self.assertIn('--no-cache', all_commands)
        self.assertNotIn('pytest wheel', all_commands)
        self.assertNotIn('wheels/', all_commands)
        self.assertIn('six==1.17.0', all_commands)
        names = [step['name'] for step in record['preflight']['steps']]
        self.assertIn('container-network-direct-diagnostic', names)
        self.assertIn('container-network-explicit-deployment-config', names)

    def test_container_network_direct_failure_is_not_hidden_by_optional_diagnostic(self):
        sandbox = FakeSandbox(self.task.name, self.results)
        sandbox.workspace.mkdir(parents=True, exist_ok=True)
        original_docker = sandbox.docker

        def direct_fails(args, timeout=120):
            if args[:2] == ['run', '--rm'] and '-e' not in args:
                return subprocess.CompletedProcess(args, 1, '', 'direct timed out')
            return original_docker(args, timeout)

        sandbox.docker = direct_fails
        with mock.patch.dict(runner.os.environ, {'HTTPS_PROXY': 'http://proxy.invalid'}, clear=True):
            report = runner.run_preflight(sandbox, self.results, require_task=False)
        self.assertTrue(report['success'])
        direct = next(step for step in report['steps']
                      if step['name'] == 'container-network-direct-diagnostic')
        self.assertEqual(direct['returncode'], 1)
        self.assertIn('container-network-explicit-deployment-config',
                      [step['name'] for step in report['steps']])

    def test_agent_incomplete_is_semantic_but_bundle_is_still_exported(self):
        def fake_stream(sandbox, cmd, out_dir, timeout_sec, extra_env, console_path=None, max_turns=None):
            (out_dir / 'trajectory.jsonl').write_text(json.dumps({
                'type': 'result', 'is_error': False, 'num_turns': 3, 'result': 'built',
            }) + '\n')
            return FakeProcess()

        with mock.patch.object(runner, 'DockerSandbox', FakeSandbox), \
                mock.patch.object(runner, 'stream_agent', fake_stream), \
                mock.patch('harness.bundle.export_bundle', return_value={}) as exported, \
                mock.patch.dict(runner.os.environ, self.credentials(), clear=True):
            record = runner.run_one(self.task, self.results)
        self.assertEqual(record['agent']['status'], 'incomplete')
        self.assertEqual(record['pipeline']['status'], 'succeeded')
        self.assertEqual(record['failure_category'], 'agent_semantic')
        self.assertIsNone(record['pipeline']['exception'])
        exported.assert_called_once()

    def test_agent_deadline_is_semantic_and_frozen_delivery_is_still_exported(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired('claude', 5)

        with mock.patch.object(runner, 'DockerSandbox', FakeSandbox), \
                mock.patch.object(runner, 'stream_agent', timeout), \
                mock.patch('harness.bundle.export_bundle', return_value={}) as exported, \
                mock.patch.dict(runner.os.environ, self.credentials(), clear=True):
            record = runner.run_one(self.task, self.results, timeout_sec=5)
        self.assertEqual(record['agent']['status'], 'timeout')
        self.assertEqual(record['pipeline']['status'], 'succeeded')
        self.assertEqual(record['pipeline']['phase'], 'complete')
        self.assertEqual(record['failure_category'], 'agent_semantic')
        self.assertIn('exceeded 5s', record['agent']['error'])
        exported.assert_called_once()
        self.assertTrue(FakeSandbox.instances[0].stopped)

    def test_missing_credentials_is_pipeline_error_not_agent_semantic(self):
        with mock.patch.object(runner, 'DockerSandbox', FakeSandbox), \
                mock.patch.object(runner, 'ROOT', self.root / 'no-default-credentials'), \
                mock.patch.object(runner, 'stream_agent') as streamed, \
                mock.patch('harness.bundle.export_bundle') as exported, \
                mock.patch.dict(runner.os.environ, {}, clear=True):
            record = runner.run_one(self.task, self.results)
        self.assertEqual(record['pipeline']['status'], 'failed')
        self.assertEqual(record['failure_category'], 'pipeline')
        self.assertEqual(record['pipeline']['failed_phase'], 'prepare')
        self.assertNotEqual(record['failure_category'], 'agent_semantic')
        streamed.assert_not_called()
        exported.assert_not_called()
        self.assertEqual(record['export']['status'], 'not_started_no_application')
        self.assertIn('requires ANTHROPIC_BASE_URL', record['error'])

    def test_export_exception_keeps_traceback_and_does_not_grade(self):
        def fake_stream(sandbox, cmd, out_dir, timeout_sec, extra_env, console_path=None, max_turns=None):
            self.deliver(sandbox)
            (out_dir / 'trajectory.jsonl').write_text(json.dumps({
                'type': 'result', 'is_error': False, 'num_turns': 1, 'result': 'done',
            }) + '\n')
            return FakeProcess()

        with mock.patch.object(runner, 'DockerSandbox', FakeSandbox), \
                mock.patch.object(runner, 'stream_agent', fake_stream), \
                mock.patch('harness.bundle.export_bundle', side_effect=RuntimeError('snapshot failed')), \
                mock.patch.dict(runner.os.environ, self.credentials(), clear=True):
            record = runner.run_one(self.task, self.results)
        self.assertEqual(record['agent']['status'], 'completed')
        self.assertEqual(record['pipeline']['failed_phase'], 'export')
        self.assertEqual(record['failure_category'], 'export')
        self.assertIn('snapshot failed', record['export']['traceback'])
        self.assertEqual(record['grading']['status'], 'not_run')

    def test_streaming_persists_jsonl_and_redacts_secrets_without_claude(self):
        class StreamProcess:
            def __init__(self):
                self.stdout = io.StringIO(
                    json.dumps({'type': 'result', 'is_error': False, 'num_turns': 1,
                                'result': 'token=unit-test-token'}) + '\n')
                self.stderr = io.StringIO('ANTHROPIC_AUTH_TOKEN=unit-test-token\n')
                self.returncode = 0

            def wait(self, timeout=None):
                return self.returncode

        def fake_popen(cmd, **kwargs):
            self.assertEqual(kwargs['user'], 'agent')
            self.assertEqual(kwargs['workdir'], str(sandbox.workspace))
            self.assertEqual(kwargs['extra_env']['HOME'], '/home/agent')
            return StreamProcess()

        sandbox = FakeSandbox(self.task.name, self.results)
        sandbox.workspace.mkdir(parents=True)
        sandbox.popen = fake_popen
        runner._SECRET_VALUES.add('unit-test-token')
        process = runner.stream_agent(
            sandbox, ['claude', '-p', 'test'], self.results, 10,
            {'HOME': '/home/agent', 'ANTHROPIC_AUTH_TOKEN': 'unit-test-token'})
        self.assertEqual(process.returncode, 0)
        trajectory = (self.results / 'trajectory.jsonl').read_text()
        self.assertIn('observed_at', trajectory)
        self.assertNotIn('unit-test-token', trajectory)
        self.assertNotIn('unit-test-token', (self.results / 'agent_stderr.log').read_text())
        self.assertNotIn('unit-test-token', (self.results / 'agent_stdout.jsonl').read_text())

    def test_compact_trajectory_is_live_complete_and_filters_heartbeats(self):
        class StreamProcess:
            def __init__(self):
                events = [
                    {'type': 'system', 'subtype': 'init', 'model': 'test-model'},
                    {'type': 'system', 'subtype': 'thinking_tokens',
                     'estimated_tokens': 4, 'estimated_tokens_delta': 2},
                    {'type': 'assistant', 'timestamp': '2026-10-27T18:07:30Z',
                     'message': {'content': [
                        {'type': 'thinking', 'thinking': 'Check the build context.',
                         'signature': 'transport-signature'},
                        {'type': 'text', 'text': 'I will build it.'},
                        {'type': 'tool_use', 'id': 'call-1', 'name': 'Bash',
                         'input': {'command': 'docker compose build --no-cache'}},
                    ]}},
                    {'type': 'user', 'message': {'content': [
                        {'type': 'tool_result', 'tool_use_id': 'call-1',
                         'content': 'Build completed successfully.\n'},
                    ]}},
                    {'type': 'result', 'is_error': False, 'num_turns': 1,
                     'result': 'Delivery ready.'},
                ]
                self.stdout = io.StringIO(''.join(json.dumps(event) + '\n'
                                                  for event in events))
                self.stderr = io.StringIO('')
                self.returncode = 0

            def wait(self, timeout=None):
                return self.returncode

        sandbox = FakeSandbox(self.task.name, self.results)
        sandbox.workspace.mkdir(parents=True)
        sandbox.popen = lambda *args, **kwargs: StreamProcess()
        runner.stream_agent(sandbox, ['claude'], self.results, 10, {})
        raw = (self.results / 'agent_stdout.jsonl').read_text()
        compact = (self.results / 'trajectory.jsonl').read_text()
        readable = (self.results / 'trajectory.md').read_text()
        self.assertIn('thinking_tokens', raw)
        self.assertNotIn('thinking_tokens', compact)
        self.assertNotIn('thinking_tokens', readable)
        # Thinking blocks are rendered in full in the human view.
        self.assertIn('Check the build context.', readable)
        self.assertIn('thinking 块 1 个', readable)
        # Heartbeats are aggregated into one counted line (2 tokens here).
        self.assertIn('心跳 ×1 条，约 2 tokens', readable)
        self.assertIn('心跳 1 条', readable)
        # Headings use Beijing time: 18:07:30Z -> next-day 02:07:30+08:00.
        self.assertIn('2026-10-28 02:07:30+08:00', readable)
        self.assertIn('Check the build context.', compact)
        self.assertIn('I will build it.', readable)
        self.assertIn('docker compose build --no-cache', readable)
        self.assertIn('Build completed successfully.', readable)
        self.assertIn('Delivery ready.', readable)
        events = [json.loads(line) for line in compact.splitlines()]
        self.assertEqual([event['type'] for event in events],
                         ['system', 'assistant', 'user', 'result'])
        self.assertTrue(all('observed_at' in event for event in events))
        self.assertEqual(events[1]['message']['content'][0]['signature'],
                         'transport-signature')
        # Tools-only trail in the live.trail.jsonl shape.
        trail = [json.loads(line) for line in
                 (self.results / 'trail.jsonl').read_text().splitlines()]
        self.assertEqual(len(trail), 1)
        self.assertEqual(trail[0]['tool'], 'Bash')
        self.assertEqual(trail[0]['summary'], 'docker compose build --no-cache')
        self.assertEqual(trail[0]['turn'], 1)
        self.assertIn('\n## 轮次 1 · 2026-10-28 02:07:30+08:00\n', readable)
        self.assertNotIn('\n## 1.', readable)
        self.assertIn('\n### 工具调用 · Bash\n', readable)
        self.assertLess(readable.index('I will build it.'),
                        readable.index('Build completed successfully.'))

    def test_streaming_stops_at_global_turn_budget_before_wakeup(self):
        class StreamProcess:
            def __init__(self):
                events = [
                    {'type': 'assistant', 'message': {'id': 'm1', 'content': []}},
                    {'type': 'result', 'subtype': 'error_max_turns', 'num_turns': 1},
                    {'type': 'system', 'subtype': 'task_notification'},
                    {'type': 'assistant', 'message': {'id': 'm2', 'content': []}},
                    {'type': 'assistant', 'message': {'id': 'm3', 'content': []}},
                ]
                self.stdout = io.StringIO(''.join(json.dumps(event) + '\n' for event in events))
                self.stderr = io.StringIO('')
                self.returncode = 0

            def wait(self, timeout=None):
                return self.returncode

        process = StreamProcess()
        sandbox = FakeSandbox(self.task.name, self.results)
        sandbox.workspace.mkdir(parents=True)
        sandbox.popen = lambda *args, **kwargs: process
        with mock.patch.object(runner, '_terminate_agent') as terminate:
            runner.stream_agent(sandbox, ['claude'], self.results, 10, {}, max_turns=2)
        terminate.assert_called_once_with(sandbox, process)
        self.assertEqual(process.cdb_turn_limit, 2)
        record = {'agent': {}}
        runner._record_agent_result(record, self.results, process)
        self.assertEqual(record['agent']['status'], 'max_turns')
        self.assertEqual(record['agent']['num_turns'], 2)

    def test_one_assistant_message_is_one_turn(self):
        from harness.compact_trace import convert
        source = self.results / 'raw-turns.jsonl'
        source.parent.mkdir(parents=True, exist_ok=True)
        events = [
            {'type': 'system', 'subtype': 'init', 'model': 'm'},
            {'type': 'assistant', 'timestamp': '2026-10-27T14:25:42Z',
             'message': {'id': 'm1', 'content': [
                 {'type': 'thinking', 'thinking': 'Read the task.'},
             ]}},
            {'type': 'assistant', 'timestamp': '2026-10-27T14:25:42Z',
             'message': {'id': 'm1', 'content': [
                 {'type': 'tool_use', 'id': 'c1', 'name': 'Read',
                  'input': {'file_path': 'TASK.md'}},
             ]}},
            {'type': 'assistant', 'timestamp': '2026-10-27T14:25:42Z',
             'message': {'id': 'm1', 'content': [
                 {'type': 'tool_use', 'id': 'c2', 'name': 'Read',
                  'input': {'file_path': 'CVE.md'}},
             ]}},
            {'type': 'user', 'timestamp': '2026-10-27T14:25:43Z',
             'message': {'content': [
                 {'type': 'tool_result', 'tool_use_id': 'c1', 'content': 'task body'},
             ]}},
            {'type': 'user', 'timestamp': '2026-10-27T14:25:43Z',
             'message': {'content': [
                 {'type': 'tool_result', 'tool_use_id': 'c2', 'content': 'cve body'},
             ]}},
            {'type': 'assistant', 'timestamp': '2026-10-27T14:27:30Z',
             'message': {'id': 'm2', 'content': [
                 {'type': 'thinking', 'thinking': 'Now the source.'},
                 {'type': 'text', 'text': 'Looking at src.'},
             ]}},
            {'type': 'result', 'is_error': False, 'num_turns': 2, 'result': 'done'},
        ]
        source.write_text(''.join(json.dumps(event) + '\n' for event in events))
        report = convert(source, None, self.results / 'turns.md', self.results / 'turns.trail')
        text = (self.results / 'turns.md').read_text()
        self.assertEqual(report['turns'], 2)
        self.assertEqual(text.count('\n## 轮次 '), 2)
        self.assertNotIn('\n## 1.', text)
        turn1, turn2 = text.split('\n## 轮次 2', 1)
        self.assertIn('Read the task.', turn1)
        self.assertIn('TASK.md', turn1)
        self.assertIn('CVE.md', turn1)
        self.assertNotIn('task body', turn1)
        self.assertIn('task body', turn2)
        self.assertIn('cve body', turn2)
        self.assertLess(turn2.index('task body'), turn2.index('Now the source.'))
        self.assertLess(turn2.index('cve body'), turn2.index('Looking at src.'))
        trail = [json.loads(line) for line in
                 (self.results / 'turns.trail').read_text().splitlines()]
        self.assertEqual([row['turn'] for row in trail], [1, 1])

    def test_batch_defaults_are_code_constants(self):
        with mock.patch.dict(batch.os.environ, {
                'CDB_MODEL': 'ignored-model', 'CDB_MAX_TURNS': '1',
                'CDB_TIMEOUT': '1', 'CDB_CONCURRENCY': '1'}):
            args = batch.build_parser().parse_args([
                '--tasks', str(self.task), '--results', str(self.results)])
        self.assertEqual(args.model, 'glm-5.3')
        self.assertEqual(args.max_turns, 50)
        self.assertEqual(args.timeout, 18000)
        self.assertEqual(args.grade_timeout, 10800)
        self.assertEqual(args.concurrency, 20)
        self.assertEqual(batch.RUNNER_GRACE_SECONDS, 3600)

    def test_run_eval_uses_code_defaults_and_explicit_model_override(self):
        text = (ROOT / 'run-factory-eval.sh').read_text()
        for setting in ('CONCURRENCY=20', 'MODEL="${CDB_MODEL:-glm-5.3}"', 'MAX_TURNS=50',
                        'TIMEOUT=18000', 'GRADE_TIMEOUT=1800',
                        'TASKS="$ROOT/delivery/cvefactory-verified-40-20261026/tasks"',
                        ': "${ANTHROPIC_BASE_URL:?set ANTHROPIC_BASE_URL in CDB_MODEL_ENV_FILE}"',
                        'RESULTS="${1:-$ROOT/runtime/cvefactory-$(date +%Y%m%d%H%M)}"'):
            self.assertIn('\n' + setting + '\n', text)
        for override in ('${CDB_CONCURRENCY', '${CDB_MAX_TURNS', '${CDB_TIMEOUT',
                         '${CDB_TASKS:-', 'exploit-from-git/.env'):
            self.assertNotIn(override, text)
        self.assertNotRegex(text, r'ANTHROPIC_AUTH_TOKEN=[\'\"]sk-')
        self.assertNotRegex(text, r'ANTHROPIC_BASE_URL=[\'\"]http://')
        self.assertIn('--concurrency "$CONCURRENCY" --model "$MODEL"', text)
        self.assertIn('--max-turns "$MAX_TURNS" --timeout "$TIMEOUT" '
                      '--grade-timeout "$GRADE_TIMEOUT"', text)

    def test_offline_converter_never_overwrites_raw_source(self):
        from harness.compact_trace import convert
        source = self.results / 'raw.jsonl'
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(json.dumps({'type': 'system', 'subtype': 'init'}) + '\n')
        report = convert(source, self.results / 'clean.jsonl', self.results / 'clean.md')
        self.assertEqual(report['events'], 1)
        self.assertIn('"subtype": "init"', source.read_text())
        with self.assertRaises(ValueError):
            convert(source, source, self.results / 'other.md')

    def test_probe_timeout_is_a_structured_failed_step(self):
        sandbox = FakeSandbox(self.task.name, self.results)
        sandbox.workspace.mkdir(parents=True, exist_ok=True)
        error = subprocess.TimeoutExpired(['docker', 'info'], 45, output='partial',
                                         stderr='deadline exceeded')
        with mock.patch.object(sandbox, 'docker', side_effect=error):
            with self.assertRaisesRegex(runner.PipelineFailure, 'probe-timeout.*124'):
                runner.run_preflight(sandbox, self.results, require_task=False)
        persisted = json.loads((self.results / 'preflight.json').read_text())
        step = persisted['steps'][-1]
        self.assertFalse(persisted['success'])
        self.assertEqual(step['name'], 'probe-timeout')
        self.assertEqual(step['error_type'], 'TimeoutExpired')
        self.assertEqual(step['returncode'], 124)
        self.assertEqual(step['timeout_sec'], 45)
        self.assertEqual(step['stdout_tail'], 'partial')

    def test_registry_pull_slots_are_exclusive(self):
        import threading
        import time
        order = []
        lock = threading.Lock()
        with mock.patch.object(runner, 'REGISTRY_PULL_SLOTS', 1), \
                mock.patch.dict(runner.os.environ, {'CDB_DOCKER_DATA_ROOT': str(self.results)}):
            def hold() -> None:
                with runner._RegistryPullSlot():
                    with lock:
                        order.append('enter')
                    time.sleep(0.2)
                    with lock:
                        order.append('exit')
            threads = [threading.Thread(target=hold) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(3)
                self.assertFalse(thread.is_alive())
        self.assertEqual(order, ['enter', 'exit', 'enter', 'exit'])

    def test_main_is_single_task_cli(self):
        parser = runner.build_parser()
        with mock.patch.dict(runner.os.environ, {'CDB_MODEL': 'ignored-model',
                                                 'CDB_MAX_TURNS': '1', 'CDB_TIMEOUT': '1'}):
            args = parser.parse_args(['--task', str(self.task), '--results', str(self.results)])
        self.assertEqual(args.model, 'glm-5.3')
        self.assertEqual(args.max_turns, 50)
        self.assertEqual(args.timeout, 18000)
        self.assertFalse(args.preflight_only)
        with mock.patch.object(runner, 'run_one', return_value={
                'pipeline': {'status': 'succeeded'}}) as run:
            rc = runner.main(['--task', str(self.task), '--results', str(self.results),
                              '--preflight-only'])
        self.assertEqual(rc, 0)
        run.assert_called_once()
        self.assertTrue(run.call_args.kwargs['preflight_only'])


class BatchContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cdb-batch-contract-')
        self.root = Path(self.temp.name)
        self.task = self.root / 'tasks' / 'cvefactory-cve-2099-0001'
        (self.task / 'input').mkdir(parents=True)
        self.output = self.root / 'results' / self.task.name
        self.delivery = self.output / 'bundle' / 'delivery'
        self.delivery.mkdir(parents=True)
        (self.delivery / 'bundle.json').write_text('{}\n')
        self.agent = {'status': 'completed'}
        self.export = {'status': 'completed'}
        (self.output / 'agent-result.json').write_text(json.dumps({
            'agent': self.agent, 'export': self.export,
            'pipeline': {'status': 'succeeded'},
        }))

    def tearDown(self):
        self.temp.cleanup()

    def test_reuses_agent_and_grades_export_delivery_root(self):
        def fake_run(command, **kwargs):
            if command[1:2] == ['-c']:
                self.assertEqual(Path(command[-1]), self.delivery)
                self.assertEqual(Path(command[-2]), self.output)
                self.assertEqual(Path(command[-3]), self.task)
                (self.output / 'result.json').write_text(json.dumps({
                    'reward': 1, 'status': 'passed', 'failure_class': None,
                }))
                return subprocess.CompletedProcess(command, 0)
            raise AssertionError(f'unexpected agent rerun: {command}')

        args = type('Args', (), {
            'force_agent': False, 'force_grade': False, 'skip_grade': False,
            'grade_timeout': 60, 'model': 'test-model', 'max_turns': 10, 'timeout': 60,
        })()
        with mock.patch.object(batch.subprocess, 'run', side_effect=fake_run):
            result = batch.run_one(self.task, self.root / 'results', args)
        self.assertEqual(result['reward'], 1, result)
        self.assertEqual(result['status'], 'passed')

    def args(self, **overrides):
        values = {'force_agent': True, 'force_grade': False, 'skip_grade': False,
                  'grade_timeout': 60, 'model': 'test-model', 'max_turns': 10,
                  'timeout': 60}
        values.update(overrides)
        return type('Args', (), values)()

    def test_valid_turn_limit_can_still_grade_the_frozen_delivery(self):
        (self.output / 'agent-result.json').write_text(json.dumps({
            'agent': {'status': 'incomplete', 'error': 'maximum turns reached'},
            'export': {'status': 'completed'}, 'pipeline': {'status': 'succeeded'},
        }))

        def grade(command, **kwargs):
            (self.output / 'result.json').write_text(json.dumps({
                'reward': 0, 'status': 'failed', 'failure_class': 'agent_semantic',
            }))
            return subprocess.CompletedProcess(command, 0)

        with mock.patch.object(batch.subprocess, 'run', side_effect=grade):
            result = batch.run_one(self.task, self.root / 'results', self.args(force_agent=False))
        self.assertEqual(result['failure_class'], 'agent_semantic')
        self.assertNotEqual(result['status'], 'error')

    def test_missing_delivery_is_pipeline_error_not_agent_failure(self):
        (self.output / 'result.json').write_text('{"reward": 1, "status": "passed"}\n')
        def failed_rerun(command, **kwargs):
            (self.output / 'agent-result.json').write_text(json.dumps({
                'agent': {'status': 'incomplete'},
                'export': {'status': 'error', 'error': 'missing frozen delivery'},
                'pipeline': {'status': 'failed'}, 'failure_category': 'pipeline',
            }))
            return subprocess.CompletedProcess(command, 1)
        with mock.patch.object(batch.subprocess, 'run', side_effect=failed_rerun):
            result = batch.run_one(self.task, self.root / 'results', self.args())
        self.assertEqual(result['failure_class'], 'pipeline')
        self.assertEqual(result['status'], 'error')
        self.assertIn('missing frozen delivery', result['error'])
        self.assertEqual(json.loads((self.output / 'previous-result.json').read_text())['reward'], 1)

    def test_preflight_and_api_stops_go_back_on_the_queue(self):
        self.assertEqual(batch.infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'network', 'agent_status': 'not_started',
            'error': 'NetworkFailure: preflight probe-timeout failed with exit 124',
        }), 'preflight')
        self.assertEqual(batch.infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'pipeline',
            'error': 'API Error: 400 {"error":"invalid or oversized HTTP request"}',
        }), 'api')
        self.assertEqual(batch.infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'pipeline',
            'error': 'API Error: 504 {"error":"upstream connection failed"}',
        }), 'api')
        self.assertIsNone(batch.infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'agent_semantic',
            'error': 'sh /tmp/cdb-tests/run-tests.sh vulnerable exited 1',
        }))
        self.assertIsNone(batch.infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'pipeline',
            'error': "TimeoutExpired: docker compose up timed out after 300 seconds",
        }))
        self.assertIsNone(batch.infrastructure_requeue_reason({
            'reward': 1, 'status': 'passed', 'failure_class': None,
        }))
        self.assertEqual(batch.INFRASTRUCTURE_ATTEMPTS, 3)

    def test_only_keeps_named_tasks(self):
        args = batch.build_parser().parse_args([
            '--tasks', str(self.task.parent), '--results', str(self.root / 'out'),
            '--only', self.task.name])
        selected = [task for task in batch.tasks_from(args.tasks) if task.name in set(args.only)]
        self.assertEqual([task.name for task in selected], [self.task.name])

    def test_incomplete_api_response_is_not_an_agent_semantic_failure(self):
        def failed_rerun(command, **kwargs):
            (self.output / 'agent-result.json').write_text(json.dumps({
                'agent': {'status': 'incomplete', 'error': 'API Error: status 401 Unauthorized'},
                'export': {'status': 'completed'},
                'pipeline': {'status': 'succeeded'}, 'failure_category': 'agent_semantic',
            }))
            return subprocess.CompletedProcess(command, 0)
        with mock.patch.object(batch.subprocess, 'run', side_effect=failed_rerun):
            result = batch.run_one(self.task, self.root / 'results', self.args())
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['failure_class'], 'pipeline')
        self.assertIn('Claude/API execution failed', result['error'])

    def test_agent_timeout_does_not_reuse_previous_reward(self):
        (self.output / 'result.json').write_text('{"reward": 1, "status": "passed"}\n')
        def timeout(command, **kwargs):
            (self.output / 'agent-result.json').write_text(json.dumps({
                'agent': {'status': 'timeout'}, 'export': {'status': 'completed'},
                'pipeline': {'status': 'failed'}, 'failure_category': 'pipeline',
            }))
            return subprocess.CompletedProcess(command, 124)
        with mock.patch.object(batch.subprocess, 'run', side_effect=timeout):
            result = batch.run_one(self.task, self.root / 'results', self.args())
        self.assertEqual(result['reward'], 0)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['failure_class'], 'pipeline')

    def test_finished_task_view_keeps_only_the_readable_files(self):
        (self.output / 'trajectory.md').write_text('view\n')
        (self.output / 'trail.jsonl').write_text('{}\n')
        (self.output / 'console.log').write_text('log\n')
        batch.file_task_view(self.output)
        self.assertEqual(sorted(path.name for path in self.output.iterdir()),
                         ['detail', 'trail.jsonl', 'trajectory.md'])
        self.assertTrue((self.output / 'detail' / 'console.log').is_file())
        self.assertTrue((self.output / 'detail' / 'bundle' / 'delivery' / 'bundle.json').is_file())


if __name__ == '__main__':
    unittest.main()
