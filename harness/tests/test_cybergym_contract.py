from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from harness.cybergym_pipeline.oracle import crash_type_matches
from harness.cybergym_pipeline.submission import validate_source
from harness.families.cybergym.plugin import CyberGymFamily
from harness.task_api import PrepareRequest, TaskSpec


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def task(self):
        task_dir = self.root / 'tasks' / 'cybergym-test'
        (task_dir / 'input').mkdir(parents=True)
        metadata = {'task_id': 'cybergym-test', 'task_type': 'binary-env-synthesis',
                    'family': 'cybergym', 'sanitizer': 'address'}
        (task_dir / 'metadata.yaml').write_text(json.dumps(metadata))
        (task_dir / 'input' / 'TASK.md').write_text('environment synthesis')
        (task_dir / 'input' / 'manifest.json').write_text('{}')
        (task_dir / 'input' / 'src.txt').write_text('source')
        (task_dir / 'gold').mkdir()
        (task_dir / 'gold' / 'poc').write_bytes(b'secret')
        return TaskSpec.load(task_dir)

    def test_prepare_never_stages_private_poc(self):
        task = self.task()
        workspace = self.root / 'workspace'
        CyberGymFamily().prepare_workspace(PrepareRequest(task, workspace))
        self.assertFalse((workspace / 'gold').exists())
        self.assertFalse((workspace / 'poc').exists())
        task_text = (workspace / 'TASK.md').read_text()
        self.assertTrue(task_text.startswith('environment synthesis'))
        self.assertNotIn('even if they do not build', task_text)
        self.assertNotIn('disk, debug them.', task_text)
        self.assertEqual((workspace / 'src.txt').read_text(), 'source')

    def test_missing_fixed_service_and_role_fails(self):
        (self.root / 'Dockerfile').write_text('FROM scratch\n')
        (self.root / 'smoke.sh').write_text('#!/bin/sh\n')
        (self.root / 'docker-compose.yaml').write_text('services:\n  vul:\n    build: .\n')
        report = validate_source(self.root)
        self.assertFalse(report['valid'])
        self.assertTrue(any('fix' in error for error in report['errors']))

    def test_source_symlink_escape_fails(self):
        (self.root / 'Dockerfile').write_text('FROM scratch\n')
        (self.root / 'smoke.sh').write_text('#!/bin/sh\n')
        (self.root / 'docker-compose.yaml').write_text(
            'services:\n  vul:\n    build: .\n    labels: [cdb.cybergym.role=vul]\n'
            '  fix:\n    build: .\n    labels: [cdb.cybergym.role=fix]\n')
        (self.root / 'leak').symlink_to('/etc/passwd')
        self.assertFalse(validate_source(self.root)['valid'])

    def test_crash_category_spelling_is_normalized(self):
        self.assertTrue(crash_type_matches('heap-buffer-overflow', 'Heap-buffer-overflow'))
        self.assertTrue(crash_type_matches('index 4 out of bounds for type', 'index-out-of-bounds'))
        self.assertFalse(crash_type_matches('heap-use-after-free', 'heap-buffer-overflow'))

    def test_cleanroom_preserves_absolute_runtime_and_uses_frozen_source(self):
        from types import SimpleNamespace
        from harness.cybergym_pipeline.cleanroom import CleanRoom
        host = mock.Mock()
        host.success.return_value = SimpleNamespace(returncode=0, stdout='28.0\n', stderr='')
        host.run.return_value = SimpleNamespace(returncode=0, stdout='28.0\n', stderr='')
        source = self.root / 'frozen' / 'source'
        source.mkdir(parents=True)
        room = CleanRoom('test', self.root / 'evidence', source, self.root / 'gold',
                         host=host)
        room.start()
        argv = host.success.call_args_list[0].args[0]
        self.assertIn(f'{source.resolve()}:/submission:ro', argv)
        self.assertNotIn('/live:ro', ' '.join(argv))
        self.assertIn(f'{self.root / "evidence"}:/evidence', argv)
        self.assertIn(f'{self.root / "evidence"}:{self.root / "evidence"}', argv)
        room.stop()


if __name__ == '__main__':
    unittest.main()
