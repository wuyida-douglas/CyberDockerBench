from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from harness.cybergym_pipeline.runtime import (  # noqa: E402
    Sandbox,
    SandboxError,
    SandboxTimeout,
    merge_no_proxy,
)


def cp(args=None, code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args or [], code, stdout, stderr)


class FakeProcess:
    def __init__(self, stdout='{"type":"result"}\n', stderr=""):
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO(stderr)
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


class SandboxTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cybergym-runtime-test-")
        self.root = Path(self.temporary.name)
        self.environment = mock.patch.dict(os.environ, {}, clear=True)
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def make(self, **kwargs):
        values = dict(
            task_id="cybergym-task",
            attempt_id="attempt-001",
            workspace=self.root / "workspace",
            runtime_root=self.root / "runtime",
            docker_root=Path("/var/tmp/cybergym-docker/attempt-001"),
            env={},
        )
        values.update(kwargs)
        return Sandbox(**values)

    def test_reclaim_stale_removes_orphaned_network(self):
        import json as _json
        from harness.cybergym_pipeline.runtime.sandbox import SandboxError
        sandbox = self.make()
        orphan = _json.dumps([{"Labels": sandbox._labels, "Containers": {}}])
        with mock.patch.object(sandbox, '_host', return_value=cp()) as host:
            sandbox._reclaim_stale('network', sandbox.network, orphan)
        self.assertEqual(host.call_args.args[0], ['docker', 'network', 'rm', sandbox.network])

    def test_reclaim_stale_refuses_live_or_foreign_resources(self):
        import json as _json
        from harness.cybergym_pipeline.runtime.sandbox import SandboxError
        sandbox = self.make()
        busy = _json.dumps([{"Labels": sandbox._labels, "Containers": {"abc": {}}}])
        foreign = _json.dumps([{"Labels": {}, "Containers": {}}])
        running = _json.dumps([{"Config": {"Labels": sandbox._labels}, "State": {"Running": True}}])
        stopped = _json.dumps([{"Config": {"Labels": sandbox._labels}, "State": {"Running": False}}])
        with mock.patch.object(sandbox, '_host', return_value=cp()) as host:
            with self.assertRaises(SandboxError):
                sandbox._reclaim_stale('network', sandbox.network, busy)
            with self.assertRaises(SandboxError):
                sandbox._reclaim_stale('network', sandbox.network, foreign)
            with self.assertRaises(SandboxError):
                sandbox._reclaim_stale('container', sandbox.container, running)
            sandbox._reclaim_stale('container', sandbox.container, stopped)
        self.assertEqual(host.call_args.args[0], ['docker', 'rm', '-f', sandbox.container])

    def test_no_proxy_preserves_both_cases_and_appends_direct_hosts(self):
        merged = merge_no_proxy({"NO_PROXY": "internal.example,127.0.0.1", "no_proxy": "other.example"})
        self.assertEqual(
            merged.split(",")[:3], ["internal.example", "127.0.0.1", "other.example"])
        self.assertIn("100.102.49.113", merged.split(","))
        self.assertIn("client", merged.split(","))
        self.assertEqual(merged.count("127.0.0.1"), 1)

    def test_docker_root_is_fixed_to_worker_local_attempt_directory(self):
        with self.assertRaisesRegex(ValueError, "docker_root must be"):
            self.make(docker_root=self.root / "shared-overlay")
        with self.assertRaisesRegex(ValueError, "task_id"):
            self.make(task_id="../private")
        with self.assertRaisesRegex(ValueError, "workspace must be absolute"):
            self.make(workspace=Path("relative"))

    def test_sensitive_config_is_not_outer_environment(self):
        sandbox = self.make(env={
            "HTTP_PROXY": "http://proxy.invalid:8080",
            "ANTHROPIC_BASE_URL": "https://model.invalid",
            "ANTHROPIC_AUTH_TOKEN": "never-in-dind",
            "CUSTOM_TOKEN": "also-secret",
            "PUBLIC_SETTING": "yes",
            "HOME": "/root",
            "PATH": "/host/path",
            "DOCKER_CONFIG": "/root/.docker",
        })
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", sandbox._outer_env)
        self.assertNotIn("ANTHROPIC_BASE_URL", sandbox._outer_env)
        self.assertNotIn("CUSTOM_TOKEN", sandbox._outer_env)
        self.assertEqual(sandbox._outer_env["PUBLIC_SETTING"], "yes")
        self.assertNotIn("HOME", sandbox._outer_env)
        self.assertNotIn("PATH", sandbox._outer_env)
        self.assertEqual(sandbox._outer_env["DOCKER_CONFIG"], "/home/agent/.docker")
        self.assertEqual(sandbox._claude_env["ANTHROPIC_AUTH_TOKEN"], "never-in-dind")
        self.assertIn("100.102.49.113", sandbox._outer_env["NO_PROXY"])

    def test_start_creates_one_privileged_bridge_without_host_or_secret_mounts(self):
        sandbox = self.make(env={
            "ANTHROPIC_AUTH_TOKEN": "do-not-serialize",
            "ANTHROPIC_BASE_URL": "https://model.invalid",
            "HTTP_PROXY": "http://proxy.invalid:8080",
        })
        calls = []

        def host(args, timeout=120):
            calls.append(args)
            if args[:3] == ["docker", "container", "inspect"]:
                return cp(args, 1)
            if args[:3] == ["docker", "network", "inspect"]:
                return cp(args, 1)
            if args[:3] == ["docker", "network", "create"]:
                return cp(args)
            if args[:2] == ["docker", "run"]:
                return cp(args, stdout="container-id\n")
            if args[:2] == ["docker", "exec"]:
                return cp(args, stdout="28.5.2\n")
            if args[:2] == ["docker", "cp"]:
                return cp(args)
            raise AssertionError(args)

        with mock.patch.object(sandbox, "_validate_local_root"), \
                mock.patch.object(sandbox, "_prepare_workspace"), \
                mock.patch.object(sandbox, "_assert_isolation"), \
                mock.patch.object(sandbox, "_host", side_effect=host):
            sandbox.start()
        daemon = json.loads(sandbox.daemon_config.read_text())
        self.assertEqual(daemon['proxies']['http-proxy'], 'http://proxy.invalid:8080')
        self.assertIn('100.102.49.113', daemon['proxies']['no-proxy'])
        self.assertNotIn('registry-mirrors', daemon)
        self.assertIn('100.102.49.114:19091', daemon['insecure-registries'])
        self.assertIn('100.102.49.114', daemon['proxies']['no-proxy'])
        self.assertNotIn('do-not-serialize', sandbox.daemon_config.read_text())
        run = next(args for args in calls if args[:2] == ["docker", "run"])
        joined = " ".join(run)
        self.assertIn("--privileged", run)
        self.assertIn("--cgroupns=private", run)
        self.assertIn(sandbox.network, run)
        self.assertNotIn("host", run[run.index("--network") + 1])
        self.assertIn(f"{sandbox.workspace}:{sandbox.workspace}:rw", run)
        self.assertIn(f"{sandbox.workspace}:/workspace:rw", run)
        self.assertIn(f"{sandbox.docker_root}:{sandbox.docker_root}:rw", run)
        self.assertNotIn("/var/run/docker.sock:/var/run/docker.sock", joined)
        self.assertNotIn("do-not-serialize", joined)
        self.assertNotIn("model.invalid", joined)
        self.assertIn("HTTP_PROXY=http://proxy.invalid:8080", run)
        self.assertTrue(sandbox._created_container)
        self.assertTrue(sandbox._created_network)

    def test_isolation_rejects_host_socket(self):
        sandbox = self.make()
        info = [{
            "HostConfig": {
                "Privileged": True,
                "NetworkMode": "bridge",
                "Binds": ["/var/run/docker.sock:/var/run/docker.sock"],
            },
            "Mounts": [{"Source": "/var/run/docker.sock"}],
        }]
        with mock.patch.object(sandbox, "_host", return_value=cp(stdout=json.dumps(info))):
            with self.assertRaisesRegex(SandboxError, "forbidden host mount"):
                sandbox._assert_isolation()

    def test_isolation_allows_only_explicit_readonly_shared_plugin(self):
        sandbox = self.make(env={"CYBERGYM_NETWORK_PLUGIN": "/mnt/shared-storage-user/public-plugin"})
        info = [{
            "Image": "sha256:image",
            "HostConfig": {"Privileged": True, "NetworkMode": "bridge", "Binds": []},
            "Mounts": [{"Source": "/mnt/shared-storage-user/public-plugin",
                        "Destination": "/opt/cdb-network-plugin", "RW": False}] + [
                {"Source": str(path), "Destination": destination, "RW": True}
                for path, destination in (
                    (sandbox.workspace, str(sandbox.workspace)),
                    (sandbox.workspace, "/workspace"),
                    (sandbox.docker_root, str(sandbox.docker_root)),
                    (sandbox.home, str(sandbox.home)),
                )
            ],
        }]
        outer = cp(stdout=sandbox.container + "\n")
        with mock.patch.object(sandbox, "_host", side_effect=[cp(stdout=json.dumps(info)), outer]), \
                mock.patch.object(sandbox, "docker", return_value=cp(stdout=json.dumps({
                    "DockerRootDir": str(sandbox.docker_root), "ServerVersion": "28.5.2"}))), \
                mock.patch("harness.cybergym_pipeline.runtime.sandbox.Path.write_text"):
            sandbox._assert_isolation()
        info[0]["Mounts"][0]["RW"] = True
        with mock.patch.object(sandbox, "_host", return_value=cp(stdout=json.dumps(info))):
            with self.assertRaisesRegex(SandboxError, "read-only"):
                sandbox._assert_isolation()

    def test_network_skill_is_mounted_at_the_shared_path_and_the_old_path(self):
        plugin = ROOT / "harness/agent_plugins/internal-network"
        sandbox = self.make(env={"CYBERGYM_NETWORK_PLUGIN": str(plugin)})
        calls = []

        def host(args, timeout=120):
            calls.append(args)
            if args[:2] == ["docker", "exec"]:
                return cp(args, stdout="28.5.2\n")
            if args[:3] in (["docker", "container", "inspect"], ["docker", "network", "inspect"]):
                return cp(args, 1)
            return cp(args, stdout="container-id\n")

        with mock.patch.object(sandbox, "_validate_local_root"), \
                mock.patch.object(sandbox, "_prepare_workspace"), \
                mock.patch.object(sandbox, "_assert_isolation"), \
                mock.patch.object(sandbox, "_host", side_effect=host):
            sandbox.start()
        run = next(args for args in calls if args[:2] == ["docker", "run"])
        source = str(plugin.resolve())
        self.assertIn(f"{source}:/opt/cdb-network-plugin:ro", run)
        self.assertIn(f"{source}:/opt/cybergym-network:ro", run)

    def test_exec_defaults_to_agent_and_forwards_env_by_name(self):
        sandbox = self.make()
        sandbox._started = True
        process = mock.Mock()
        process.communicate.return_value = ("ok\n", "")
        process.returncode = 0
        with mock.patch("harness.cybergym_pipeline.runtime.sandbox.subprocess.Popen", return_value=process) as popen:
            result = sandbox.exec(["printf", "ok"], timeout=5, extra_env={"VISIBLE": "not-in-argv"})
        command = popen.call_args.args[0]
        self.assertEqual(command[command.index("--user") + 1], "agent")
        self.assertEqual(command[command.index("--workdir") + 1], str(sandbox.workspace))
        self.assertIn("VISIBLE", command)
        self.assertNotIn("VISIBLE=not-in-argv", command)
        self.assertEqual(popen.call_args.kwargs["env"]["VISIBLE"], "not-in-argv")
        self.assertEqual(result.stdout, "ok\n")

    def test_exec_timeout_kills_only_recorded_exec(self):
        sandbox = self.make()
        sandbox._started = True
        process = mock.Mock()
        process.communicate.side_effect = [subprocess.TimeoutExpired("docker", 1), ("", "killed")]
        process.returncode = 137
        with mock.patch("harness.cybergym_pipeline.runtime.sandbox.subprocess.Popen", return_value=process), \
                mock.patch.object(sandbox, "_kill_exec") as kill:
            with self.assertRaises(SandboxTimeout):
                sandbox.exec(["sleep", "100"], timeout=1)
        token = kill.call_args.args[0]
        self.assertRegex(token, r"^[0-9a-f]{32}$")
        self.assertTrue(sandbox._started)

    def test_docker_targets_inner_cli(self):
        sandbox = self.make()
        sandbox._started = True
        with mock.patch.object(sandbox, "exec", return_value=cp()) as execute:
            sandbox.docker(["info"], timeout=9)
        self.assertEqual(execute.call_args.args[0], ["docker", "info"])
        self.assertEqual(execute.call_args.kwargs["user"], "agent")

    def test_claude_uses_default_tools_empty_mcp_and_process_only_credentials(self):
        sandbox = self.make(env={
            "CYBERGYM_NETWORK_PLUGIN": "/plugin",
            "ANTHROPIC_BASE_URL": "https://model.invalid",
            "ANTHROPIC_AUTH_TOKEN": "claude-only",
            "CLAUDE_CODE_MAX_RETRIES": "3",
            "CLAUDE_CODE_STREAM_TIMEOUT": "7200000",
            "PUBLIC_SETTING": "not-needed-in-claude",
        })
        sandbox._started = True
        process = FakeProcess()
        with mock.patch.object(sandbox, "_start_exec", return_value=(process, "a" * 32, [])) as start, \
                mock.patch.object(sandbox, "stop") as stop:
            result = sandbox.run_claude("solve normally", "self-hosted-model", 30, 7, self.root / "events.jsonl")
        args, user, extra_env = start.call_args.args[:3]
        self.assertEqual(user, "agent")
        self.assertNotIn("--tools", args)
        self.assertNotIn("--allowedTools", args)
        self.assertIn("--strict-mcp-config", args)
        self.assertEqual(args[args.index("--mcp-config") + 1], '{"mcpServers":{}}')
        self.assertEqual(args[args.index("--setting-sources") + 1], "")
        self.assertEqual(args[args.index("--permission-mode") + 1], "bypassPermissions")
        self.assertEqual(args[args.index("--permission-prompts") + 1], "none")
        self.assertEqual(args[args.index("--model") + 1], "self-hosted-model")
        self.assertEqual(args[args.index("--max-turns") + 1], "7")
        self.assertEqual(args[args.index("--plugin-dir") + 1], "/opt/cdb-network-plugin")
        self.assertEqual(extra_env["ANTHROPIC_AUTH_TOKEN"], "claude-only")
        self.assertEqual(extra_env["CLAUDE_CODE_MAX_RETRIES"], "15")
        self.assertEqual(extra_env["CLAUDE_CODE_MAX_CONTEXT_TOKENS"], "131072")
        self.assertEqual(extra_env["CLAUDE_CODE_STREAM_TIMEOUT"], "7200000")
        self.assertNotIn("PUBLIC_SETTING", extra_env)
        self.assertTrue(result.success)
        self.assertEqual(result.log_path.read_text(), '{"type":"result"}\n')
        stop.assert_not_called()

    def test_claude_global_turn_limit_kills_wakeup_and_keeps_exportable_sandbox(self):
        sandbox = self.make()
        events = ''.join(json.dumps(event) + '\n' for event in [
            {'type': 'assistant', 'message': {'id': 'm1', 'content': []}},
            {'type': 'result', 'subtype': 'error_max_turns', 'num_turns': 1},
            {'type': 'system', 'subtype': 'task_notification'},
            {'type': 'assistant', 'message': {'id': 'm2', 'content': []}},
            {'type': 'assistant', 'message': {'id': 'm3', 'content': []}},
        ])
        process = FakeProcess(events)
        with mock.patch.object(sandbox, '_start_exec', return_value=(process, 'c' * 32, [])), \
                mock.patch.object(sandbox, '_kill_exec') as kill, \
                mock.patch.object(sandbox, 'stop') as stop:
            result = sandbox.run_claude('test', 'model', 30, 2, self.root / 'turns.jsonl')
        self.assertTrue(result.turn_limit_reached)
        self.assertEqual(result.num_turns, 2)
        self.assertFalse(result.success)
        kill.assert_called_once_with('c' * 32)
        stop.assert_not_called()

    def test_claude_timeout_kills_process_and_retains_sandbox(self):
        sandbox = self.make()
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(30)"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            with mock.patch.object(sandbox, "_start_exec", return_value=(process, "b" * 32, [])), \
                    mock.patch.object(sandbox, "_kill_exec", side_effect=lambda _: process.kill()) as kill, \
                    mock.patch.object(sandbox, "stop") as stop:
                result = sandbox.run_claude("test", "any-model", 0.1, 1, self.root / "timeout.jsonl")
            self.assertTrue(result.timed_out)
            self.assertFalse(result.success)
            self.assertEqual(result.log_path.read_text(), "started\n")
            kill.assert_called_once_with("b" * 32)
            stop.assert_not_called()
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()

    def test_api_probe_is_tcp_only_without_credentials_or_model_request(self):
        sandbox = self.make(env={"ANTHROPIC_BASE_URL": "http://model.invalid:18080/v1"})
        with mock.patch.object(sandbox, "exec", return_value=cp(stdout="")) as execute:
            result = sandbox._api_probe()
        command = execute.call_args.args[0]
        self.assertEqual(command[-3:], ["model.invalid", "18080", "0"])
        self.assertEqual(execute.call_args.kwargs["extra_env"] if "extra_env" in execute.call_args.kwargs else None, None)
        self.assertEqual(result["status"], "passed")
        self.assertNotIn("request", result)

    def test_claude_builder_does_not_start_a_session(self):
        sandbox = self.make(env={"CYBERGYM_NETWORK_PLUGIN": "/plugin"})
        with mock.patch.object(sandbox, "_start_exec") as start:
            args = sandbox.claude_args("public task", "generic-model", 3)
        self.assertEqual(args[0], "claude")
        self.assertNotIn("--tools", args)
        self.assertEqual(json.loads(args[args.index("--mcp-config") + 1]), {"mcpServers": {}})
        start.assert_not_called()

    def test_stop_preserves_workspace_and_optionally_removes_data(self):
        sandbox = self.make()
        sandbox.workspace.mkdir(parents=True)
        sandbox.docker_root.mkdir(parents=True)
        sandbox.home.mkdir(parents=True)
        (sandbox.workspace / "answer.txt").write_text("keep")
        sandbox._created_container = sandbox._created_network = True
        with mock.patch.object(sandbox, "_host", return_value=cp()):
            sandbox.stop(remove_data=False)
        self.assertTrue(sandbox.workspace.joinpath("answer.txt").exists())
        self.assertTrue(sandbox.docker_root.exists())
        sandbox._created_container = sandbox._created_network = True
        with mock.patch.object(sandbox, "_host", return_value=cp()):
            sandbox.stop(remove_data=True)
        self.assertFalse(sandbox.docker_root.exists())
        self.assertFalse(sandbox.home.exists())
        self.assertTrue(sandbox.workspace.exists())

    def test_ensure_attaches_once_and_rolls_back_partial_attachment(self):
        sandbox = self.make()
        with mock.patch.object(sandbox, 'probe', return_value={'exists': True}), \
                mock.patch.object(sandbox, 'attach', side_effect=lambda: setattr(sandbox, '_started', True)), \
                mock.patch.object(sandbox, 'start') as start:
            sandbox.ensure()
        self.assertTrue(sandbox._started)
        start.assert_not_called()
        sandbox._started = False

        def failed_attach():
            sandbox._started = True
            sandbox._created_container = True
            sandbox._created_network = True
            raise SandboxError('incomplete isolation check')

        with mock.patch.object(sandbox, 'probe', return_value={'exists': True}), \
                mock.patch.object(sandbox, 'attach', side_effect=failed_attach), \
                mock.patch.object(sandbox, 'start', side_effect=AssertionError(
                    'test stops before a real Docker start')) as start:
            with self.assertRaisesRegex(AssertionError, 'test stops'):
                sandbox.ensure()
        self.assertFalse(sandbox._started)
        self.assertFalse(sandbox._created_container)
        self.assertFalse(sandbox._created_network)
        start.assert_called_once_with()

    def test_pipeline_uses_the_local_sandbox_and_reattaches_before_stop(self):
        from types import SimpleNamespace
        from harness.cybergym_pipeline.pipeline import Pipeline
        pipeline = Pipeline(SimpleNamespace(task_id='cybergym-task'),
                            self.root / 'result' / 'attempt-001',
                            Path('/var/tmp/cybergym-runs'))
        sandbox = pipeline.open_sandbox()
        self.assertIsInstance(sandbox, Sandbox)
        self.assertEqual(sandbox.docker_root,
                         Path('/var/tmp/cybergym-docker/cybergym-task--attempt-001'))
        self.assertIn('internal-network', pipeline.settings['CYBERGYM_NETWORK_PLUGIN'])
        with mock.patch.object(Sandbox, 'probe', return_value={'exists': True}), \
                mock.patch.object(Sandbox, 'attach') as attach, \
                mock.patch.object(Sandbox, 'stop') as stop:
            pipeline.stop()
        attach.assert_called_once_with()
        stop.assert_called_once_with(remove_data=False)

    def test_runtime_settings_refresh_outer_and_claude_environments(self):
        sandbox = self.make()
        sandbox._apply_runtime_settings({
            "ANTHROPIC_AUTH_TOKEN": "claude-only",
            "HTTP_PROXY": "http://proxy.invalid:8080",
        })
        self.assertEqual(sandbox._claude_env['ANTHROPIC_AUTH_TOKEN'], 'claude-only')
        self.assertEqual(sandbox._outer_env['HTTP_PROXY'], 'http://proxy.invalid:8080')
        self.assertNotIn('ANTHROPIC_AUTH_TOKEN', sandbox._outer_env)
        with self.assertRaisesRegex(ValueError, 'string mapping'):
            sandbox._apply_runtime_settings({'INVALID': None})

    def test_image_does_not_modify_legacy_or_use_task_build_context(self):
        dockerfile = (ROOT / "harness/cybergym_pipeline/sandbox/Dockerfile").read_text()
        builder = (ROOT / "harness/cybergym_pipeline/sandbox/build-image.sh").read_text()
        self.assertIn("cdb-cybergym-sandbox:28.5.2-v2", dockerfile)
        self.assertIn("COPY agent_image/node/ /opt/node/", dockerfile)
        self.assertIn("docker compose version", dockerfile)
        self.assertIn("docker buildx version", dockerfile)
        self.assertIn("fuse-overlayfs", dockerfile)
        init = (ROOT / "harness/cybergym_pipeline/sandbox/sandbox-init").read_text()
        self.assertIn("chmod 0666 /dev/null", init)
        self.assertIn("driver=fuse-overlayfs", init)
        self.assertNotIn("tasks/", builder)
        self.assertNotIn("cvefactory", builder)


if __name__ == "__main__":
    unittest.main()
