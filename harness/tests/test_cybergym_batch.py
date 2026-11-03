"""Batch-level result-directory ownership regression tests."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from harness.cybergym_pipeline import run_batch


class BatchDirectoryTest(unittest.TestCase):
    @mock.patch("harness.cybergym_pipeline.pipeline.Pipeline")
    @mock.patch("harness.task_api.TaskSpec.load")
    def test_aborted_agent_is_not_exported_or_graded(self, load, pipeline_type) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pipeline = pipeline_type.return_value
            pipeline.result = Path(tmp) / "result"
            pipeline.run_agent.return_value = {
                "agent_status": "agent_error",
                "claude_result": {"returncode": 0, "duration_sec": 12},
            }
            args = mock.Mock(runtime=tmp, batch="batch", attempt="detail", model="model",
                             timeout=100, max_turns=10, keep_data=True)
            record = run_batch.run_one("cybergym-test", args)
            self.assertEqual(record["failure_class"], "pipeline")
            self.assertIn("agent_error", record["error"])
            self.assertNotIn("docker-compose", record["error"])
            pipeline.export.assert_not_called()
            pipeline.grade.assert_not_called()

    def test_missing_delivery_grade_is_not_overwritten(self) -> None:
        """A completed no-compose submission is graded exactly once per phase."""
        from types import SimpleNamespace
        from harness.cybergym_pipeline.pipeline import Pipeline
        from harness.task_api import TaskSpec
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(TaskSpec, 'load', return_value=SimpleNamespace(
                    task_id='cybergym-test', path=Path(tmp), task_type='binary-env-synthesis')), \
                mock.patch.object(Pipeline, 'prepare'), \
                mock.patch.object(Pipeline, 'run_agent', return_value={
                    'agent_status': 'completed', 'claude_result': {'is_error': False}}), \
                mock.patch.object(Pipeline, 'stop'):
            args = mock.Mock(runtime=tmp, batch='batch', attempt='detail', model='model',
                             timeout=100, max_turns=10, oracle_timeout=60, keep_data=True)
            record = run_batch.run_one('cybergym-test', args)
            self.assertEqual(record['state'], 'graded')
            self.assertEqual(record['failure_class'], 'agent_semantic')
            self.assertEqual(record['failure_stage'], 'delivery')
            grade_path = Path(tmp) / 'results' / 'batch' / 'cybergym-test' / 'detail' / 'grade' / 'result.json'
            grade_record = json.loads(grade_path.read_text())
            self.assertEqual(grade_record["status"], "failed")
            self.assertEqual(grade_record["failure_class"], "agent_semantic")

    def test_completed_agent_without_delivery_is_semantic_failure(self) -> None:
        from harness.families.cybergym.grader import grade
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            workspace.mkdir()
            (workspace / "TASK.md").write_text("public task")
            result = grade(Path(tmp), Path(tmp) / "grade", workspace)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure_class"], "agent_semantic")
            self.assertEqual(result["failure_stage"], "delivery")
            self.assertIn("docker-compose.yaml", result["error"])

    def test_existing_result_directory_is_rejected_before_any_task(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            batch = Path(tmp) / "results" / "completed-batch"
            batch.mkdir(parents=True)
            (batch / "batch-summary.json").write_text('{"finished": 40, "total": 40}\n')
            with mock.patch.dict(os.environ, {"ANTHROPIC_AUTH_TOKEN": "test"}, clear=False), \
                    mock.patch.object(run_batch.cf, "ThreadPoolExecutor") as pool:
                rc = run_batch.main([
                    "--tasks", "cybergym-arvo-1513", "--batch", "completed-batch",
                    "--model", "deepseek-v4.1-flash", "--runtime", tmp,
                ])
            self.assertEqual(rc, 2)
            pool.assert_not_called()
            self.assertEqual(
                (batch / "batch-summary.json").read_text(),
                '{"finished": 40, "total": 40}\n',
            )


if __name__ == "__main__":
    unittest.main()
