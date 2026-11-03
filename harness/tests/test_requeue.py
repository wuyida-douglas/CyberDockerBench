"""Infrastructure requeue is the same rule for every family."""
import json
import tempfile
import unittest
from pathlib import Path

from harness.families.cybergym.contract import TASK_CONTRACT
from harness.families.webexploit.run import source_build_failure_is_semantic
from harness.requeue import (
    INFRASTRUCTURE_ATTEMPTS, api_error_from_text, api_error_from_transcript,
    archive_attempt_dir, infrastructure_requeue_reason)


class RequeueReasonTests(unittest.TestCase):
    def test_api_and_preflight_go_back_semantic_and_timeout_stay(self):
        self.assertEqual(INFRASTRUCTURE_ATTEMPTS, 3)
        self.assertEqual(infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'pipeline',
            'error': 'API Error: 400 {"error":"invalid or oversized HTTP request"}',
        }), 'api')
        self.assertEqual(infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'pipeline',
            'error': 'PipelineError: runtime preflight failed: probe-timeout',
        }), 'preflight')
        self.assertEqual(infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'pipeline',
            'error': "cannot start/stage source sandbox: Command '['docker', 'info']' timed out after 15 seconds",
        }), 'source_sandbox')
        self.assertEqual(infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'pipeline',
            'error': 'SandboxError: sandbox already started',
        }), 'sandbox')
        self.assertIsNone(infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'pipeline',
            'error': 'PipelineError: outbound plant has no declared doorbell port',
        }))
        self.assertIsNone(infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'agent_semantic',
            'error': 'GOLD PoC differential failed',
        }))
        self.assertIsNone(infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'pipeline',
            'error': 'ExportError: docker-compose.yaml: no such file or directory',
        }))
        self.assertIsNone(infrastructure_requeue_reason({
            'reward': 0, 'failure_class': 'pipeline',
            'error': 'TimeoutExpired: docker compose build timed out after 3600 seconds',
        }))
        self.assertIsNone(infrastructure_requeue_reason({
            'reward': 1, 'status': 'passed', 'error': 'API Error: ignored once passed',
        }))

    def test_structured_transcript_stop_is_an_api_error(self):
        events = '\n'.join([
            json.dumps({'type': 'assistant', 'message': {
                'content': [{'type': 'text', 'text': 'API Error: 400 {"error":"invalid or oversized HTTP request"}'}],
            }, 'is_api_error_message': True, 'api_error_status': 400}),
            json.dumps({'type': 'result', 'terminal_reason': 'api_error', 'is_error': True}),
        ])
        self.assertIn('invalid or oversized', api_error_from_text(events))
        self.assertIsNone(api_error_from_text(json.dumps({
            'type': 'assistant',
            'message': {'content': [{'type': 'text', 'text': 'The docs mention an API Error: 400'}]},
        })))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'trajectory.jsonl'
            path.write_text(events + '\n')
            self.assertIn('API Error', api_error_from_transcript(path))

    def test_archive_clears_the_task_directory_and_keeps_the_lock_name(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory) / 'task'
            (task / 'detail').mkdir(parents=True)
            (task / 'detail' / 'batch-record.json').write_text('{}\n')
            (task / 'trajectory.md').write_text('view\n')
            (task / '.batch.lock').write_text('pid\n')
            archive_attempt_dir(task, 1, keep=frozenset({'.batch.lock'}))
            self.assertTrue((task / 'failed-attempt-01' / 'detail' / 'batch-record.json').is_file())
            self.assertTrue((task / 'failed-attempt-01' / 'trajectory.md').is_file())
            self.assertFalse((task / 'detail').exists())
            self.assertTrue((task / '.batch.lock').is_file())


class WebExploitBuildAttributionTests(unittest.TestCase):
    def test_model_delivery_build_errors_do_not_requeue(self):
        for detail in ('"/config/monitorix.conf": not found',
                       'gcc: error: missing implementation'):
            record = {'failure_class': 'pipeline',
                      'error': 'PipelineError: docker compose build failed (exit 1): ' + detail}
            self.assertTrue(source_build_failure_is_semantic(record))
            record['failure_class'] = 'agent_semantic'
            self.assertIsNone(infrastructure_requeue_reason(record))

    def test_registry_gateway_build_error_retries_without_relabeling(self):
        record = {'failure_class': 'pipeline',
                  'error': 'PipelineError: docker compose build failed (exit 1): '
                           'Error response from daemon: received unexpected HTTP status: 502'}
        self.assertFalse(source_build_failure_is_semantic(record))
        self.assertIsNone(infrastructure_requeue_reason(record))
        record['failure_class'] = 'network'
        self.assertEqual(infrastructure_requeue_reason(record), 'preflight')

    def test_other_pipeline_errors_are_unchanged(self):
        self.assertFalse(source_build_failure_is_semantic({
            'failure_class': 'pipeline', 'error': 'PipelineError: docker compose up failed'}))


class GraderContractTests(unittest.TestCase):
    def test_task_text_matches_the_grader(self):
        self.assertIn('with bash', TASK_CONTRACT)
        self.assertIn('set -o pipefail', TASK_CONTRACT)
        self.assertIn('does not look for those names on `fix`', TASK_CONTRACT)
        self.assertIn('index 96 out of bounds', TASK_CONTRACT)
        self.assertIn('build --no-cache', TASK_CONTRACT)


if __name__ == '__main__':
    unittest.main()
