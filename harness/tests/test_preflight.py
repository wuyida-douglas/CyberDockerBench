"""Offline tests for worker routing and the real-preflight controller."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from harness import preflight
from harness.docker_sandbox import DockerSandbox, SandboxError


class Sandbox:
    instances = []

    def __init__(self, *args, **kwargs):
        self.image_reference = 'cdb-sandbox:test'
        self.image_id = 'sha256:test'
        self.container = 'cdb-preflight-unit-test'
        self.runtime_contract = {'storage_driver': 'overlay2', 'agent_uid': 1000}
        self.plugin_mounts = []
        self.stopped = False
        self.__class__.instances.append(self)

    def agent_plugin(self, source, target):
        self.plugin_mounts.append((source, target))

    def start(self):
        pass

    def stop(self, remove_data=False):
        self.stopped = True


class PreflightControllerTests(unittest.TestCase):
    def test_infrastructure_imports_do_not_require_pyyaml(self):
        code = '''
import sys

class RejectYaml:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "yaml" or fullname.startswith("yaml."):
            raise ModuleNotFoundError("PyYAML blocked by preflight import test")

sys.meta_path.insert(0, RejectYaml())
from harness import preflight, run_agent
assert "yaml" not in sys.modules
assert preflight.run_preflight is run_agent.run_preflight
'''
        cp = subprocess.run([sys.executable, '-c', code], cwd=ROOT,
                            capture_output=True, text=True, timeout=30)
        self.assertEqual(cp.returncode, 0, cp.stderr)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cdb-preflight-test-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_preflight_runs_here_and_does_not_accept_a_worker_hop(self):
        with self.assertRaises(SystemExit):
            preflight.main(['--worker', 'worker.invalid',
                            '--results', str(self.root / 'new-results')])

    def test_local_checks_sandbox_without_model_or_task_input(self):
        args = argparse.Namespace(results=self.root / 'report')
        with mock.patch.object(preflight, 'DockerSandbox', Sandbox), \
                mock.patch('harness.docker_sandbox.SANDBOX_IMAGE', 'cdb-sandbox:test'), \
                mock.patch('harness.storage.validate_storage_root', return_value={'root': '/nvme'}), \
                mock.patch.object(preflight, 'run_preflight', return_value={'success': True}) as network, \
                mock.patch.object(preflight.subprocess, 'run',
                                  return_value=subprocess.CompletedProcess([], 0, 'ok', '')) as commands, \
                mock.patch.dict(preflight.os.environ, {'CDB_LOCAL_DOCKER_DATA': '1'}, clear=True):
            report = preflight.local(args)
        self.assertTrue(report['success'])
        self.assertFalse(network.call_args.kwargs['require_task'])
        self.assertEqual(report['model_smoke']['status'], 'skipped')
        self.assertEqual(report['cleanup']['status'], 'passed')
        self.assertTrue(Sandbox.instances[-1].stopped)
        self.assertEqual(Sandbox.instances[-1].plugin_mounts, [
            (str(preflight.PLUGIN_SOURCE), preflight.PLUGIN_TARGET)])
        self.assertEqual(report['sandbox']['contract']['agent_uid'], 1000)
        image_check = next(call for call in commands.call_args_list
                           if call.args[0][1:2] == ['image'])
        self.assertIn('cdb-sandbox:test', image_check.args[0])
        self.assertEqual(report['storage'], {'root': '/nvme'})

    def test_cleanup_failure_is_not_a_success(self):
        class CleanupFailure(Sandbox):
            def stop(self, remove_data=False):
                raise RuntimeError('temporary volume remains')

        args = argparse.Namespace(results=self.root / 'report')
        with mock.patch.object(preflight, 'DockerSandbox', CleanupFailure), \
                mock.patch('harness.docker_sandbox.SANDBOX_IMAGE', 'cdb-sandbox:test'), \
                mock.patch.object(preflight, 'run_preflight', return_value={'success': True}), \
                mock.patch.object(preflight.subprocess, 'run',
                                  return_value=subprocess.CompletedProcess([], 0, 'ok', '')), \
                mock.patch.dict(preflight.os.environ, {}, clear=True):
            report = preflight.local(args)
        self.assertFalse(report['success'])
        self.assertIn('temporary volume remains', report['error'])
        self.assertNotIn('cleanup', report)

    def test_disk_headroom_raises_pipeline_error_when_starved(self):
        from harness.docker_sandbox import SandboxError
        sandbox = DockerSandbox('disk-test', self.root / 'runtime', name='cdb-disk-starved')
        info = subprocess.CompletedProcess([], 0, '/data/docker\n', '')
        usage = mock.Mock(free=10 * 1024 ** 3)  # below the 60G floor
        with mock.patch('harness.docker_sandbox.subprocess.run', return_value=info), \
                mock.patch('harness.docker_sandbox.shutil.disk_usage', return_value=usage), \
                mock.patch.dict('harness.docker_sandbox.os.environ',
                                {'CDB_GRADE_DISK_WAIT_S': '0'}), \
                mock.patch('harness.docker_sandbox.time.sleep', return_value=None):
            with self.assertRaises(SandboxError) as ctx:
                sandbox._await_docker_disk_headroom()
        self.assertIn('headroom', str(ctx.exception))

    def test_disk_headroom_passes_with_space(self):
        sandbox = DockerSandbox('disk-test', self.root / 'runtime', name='cdb-disk-roomy')
        info = subprocess.CompletedProcess([], 0, '/data/docker\n', '')
        usage = mock.Mock(free=200 * 1024 ** 3)
        with mock.patch('harness.docker_sandbox.subprocess.run', return_value=info), \
                mock.patch('harness.docker_sandbox.shutil.disk_usage', return_value=usage):
            sandbox._await_docker_disk_headroom()

    def test_local_entrypoint_returns_nonzero_on_controller_failure(self):
        with mock.patch.object(preflight, 'local', return_value={
                'success': False, 'error': 'pipeline preflight failed'}):
            result = preflight.main(['--results', str(self.root / 'new-results')])
        self.assertEqual(result, 1)

    def isolation_sandbox(self):
        sandbox = DockerSandbox('isolation-test', self.root / 'runtime',
                                name='cdb-isolation-test')
        outer = {
            'Id': 'outer-id', 'Config': {'Hostname': 'sandbox-hostname'},
            'Path': 'dockerd', 'Args': ['--storage-driver=vfs', '--dns=169.254.20.10'],
            'Image': 'sha256:test',
            'HostConfig': {'Privileged': True, 'NetworkMode': sandbox.network},
            'Mounts': [
                {'Type': 'bind', 'Source': str(sandbox.workspace),
                 'Destination': str(sandbox.workspace), 'RW': True},
                {'Type': 'volume', 'Name': sandbox.name + '-docker',
                 'Destination': '/var/lib/docker', 'RW': True},
                {'Type': 'volume', 'Name': sandbox.name + '-home',
                 'Destination': '/home/agent', 'RW': True},
                {'Type': 'bind', 'Source': str(sandbox.runtime_root / 'docker-daemon.json'),
                 'Destination': '/etc/docker/daemon.json', 'RW': False},
                {'Type': 'bind', 'Source': str(sandbox.runtime_root / 'docker-proxy.conf'),
                 'Destination': '/etc/docker/daemon-proxy.conf', 'RW': False},
                {'Type': 'bind', 'Source': str(preflight.PLUGIN_SOURCE),
                 'Destination': preflight.PLUGIN_TARGET, 'RW': False},
            ],
        }
        inner = {'DockerRootDir': '/var/lib/docker', 'Driver': 'vfs',
                 'Name': 'sandbox-hostname', 'DNS': ['169.254.20.10']}
        sandbox.agent_plugin(str(preflight.PLUGIN_SOURCE), preflight.PLUGIN_TARGET)
        return sandbox, outer, inner

    def test_real_mount_and_inner_daemon_contract(self):
        sandbox, outer, inner = self.isolation_sandbox()
        with mock.patch.object(sandbox, '_host', return_value=subprocess.CompletedProcess(
                [], 0, json.dumps([outer]), '')), \
                mock.patch.object(sandbox, 'docker', side_effect=[
                    subprocess.CompletedProcess([], 0, json.dumps(inner), '')]), \
                mock.patch.object(sandbox, 'exec',
                                  return_value=subprocess.CompletedProcess([], 0, '', '')) as execute:
            report = sandbox.inspect_contract()
        self.assertFalse(report['host_docker_socket_mounted'])
        self.assertEqual(report['read_only_plugins'], [preflight.PLUGIN_TARGET])
        self.assertEqual(report['dns'], '169.254.20.10')
        self.assertTrue(all(call.kwargs.get('user') == 'agent'
                            for call in execute.call_args_list))

    def test_unexpected_or_host_socket_mount_is_rejected(self):
        sandbox, outer, inner = self.isolation_sandbox()
        outer['Mounts'].append({'Type': 'bind', 'Source': '/var/run/docker.sock',
                                'Destination': '/var/run/docker.sock', 'RW': True})
        with mock.patch.object(sandbox, '_host', return_value=subprocess.CompletedProcess(
                [], 0, json.dumps([outer]), '')):
            with self.assertRaisesRegex(SandboxError, 'unexpected or missing'):
                sandbox.inspect_contract()

    def test_private_driver_mismatch_is_rejected(self):
        sandbox, outer, inner = self.isolation_sandbox()
        inner['Driver'] = 'overlay2'
        with mock.patch.object(sandbox, '_host', return_value=subprocess.CompletedProcess(
                [], 0, json.dumps([outer]), '')), \
                mock.patch.object(sandbox, 'docker', return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(inner), '')):
            with self.assertRaisesRegex(SandboxError, 'root/driver/name/DNS'):
                sandbox.inspect_contract()


class DaemonChurnRetryTest(unittest.TestCase):
    """dockerd stalls name lookups while reclaiming a giant vfs/overlay tree;
    probe commands must ride it out instead of killing the next grade (59072 r6)."""

    def test_timeouts_are_retried_until_success(self):
        from harness import docker_sandbox as ds
        calls = []

        def flaky(cmd, timeout=30, **kwargs):
            calls.append(cmd)
            if len(calls) < 3:
                raise subprocess.TimeoutExpired(cmd, timeout)
            return subprocess.CompletedProcess(cmd, 1, '', 'No such object')

        with mock.patch.object(ds, 'run', side_effect=flaky), \
                mock.patch.object(ds.time, 'sleep') as sleep:
            cp = ds.run_riding_out_daemon_churn(['docker', 'inspect', 'x'], timeout=30)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(cp.returncode, 1)

    def test_definitive_answer_returns_immediately(self):
        from harness import docker_sandbox as ds
        with mock.patch.object(ds, 'run', return_value=subprocess.CompletedProcess([], 0, 'id\n', '')) as runner, \
                mock.patch.object(ds.time, 'sleep') as sleep:
            cp = ds.run_riding_out_daemon_churn(['docker', 'inspect', 'x'])
        self.assertEqual(runner.call_count, 1)
        sleep.assert_not_called()
        self.assertEqual(cp.returncode, 0)

    def test_persistent_stall_raises_after_attempts(self):
        from harness import docker_sandbox as ds
        with mock.patch.object(ds, 'run', side_effect=subprocess.TimeoutExpired(['docker'], 30)), \
                mock.patch.object(ds.time, 'sleep'):
            with self.assertRaises(subprocess.TimeoutExpired):
                ds.run_riding_out_daemon_churn(['docker', 'inspect', 'x'], attempts=4)


class DirectHostsTest(unittest.TestCase):
    """kkRepo mirror hosts must bypass the egress proxy even when the
    caller's NO_PROXY omits them (regression: clean-room builds died with
    squid 502 when a regrade shell lacked the batch's NO_PROXY extras)."""

    def test_mirror_hosts_appended(self):
        from harness.docker_sandbox import _with_direct_hosts
        merged = _with_direct_hosts('localhost,127.0.0.1,10.0.0.0/8')
        parts = merged.split(',')
        self.assertIn('100.102.49.113', parts)
        self.assertIn('100.102.49.114', parts)
        self.assertEqual(parts[:3], ['localhost', '127.0.0.1', '10.0.0.0/8'])

    def test_mirror_hosts_not_duplicated(self):
        from harness.docker_sandbox import _with_direct_hosts
        merged = _with_direct_hosts('localhost,100.102.49.114,100.102.49.113')
        self.assertEqual(merged.split(',').count('100.102.49.114'), 1)
        self.assertEqual(merged.split(',').count('100.102.49.113'), 1)

    def test_empty_no_proxy(self):
        from harness.docker_sandbox import _with_direct_hosts
        self.assertEqual(
            _with_direct_hosts(''),
            '100.102.49.113,100.102.49.114')


if __name__ == '__main__':
    unittest.main()
