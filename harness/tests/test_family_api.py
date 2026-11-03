"""API tests use synthetic packages only; no Docker or real task is mutated."""
from __future__ import annotations

import concurrent.futures
import json
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from harness.execution import TaskBusy, execute_grade, grade_lock
from harness.registry import FamilyRegistry
from harness.task_api import GradeRequest, PrepareRequest, TaskFamily, TaskSpec


class StubFamily(TaskFamily):
    def __init__(self, family='stub', reward=1, barrier=None):
        self.family = family
        self.reward = reward
        self.barrier = barrier

    def grade(self, request):
        if self.barrier:
            self.barrier.wait(timeout=5)
        return {'reward': self.reward, 'family': 'must-not-override-request',
                'checks': {'output': request.results.name}}


class FamilyContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cdb-family-test-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def task(self, name='sample-bugfix', family=None):
        path = self.root / 'tasks' / name
        path.mkdir(parents=True)
        metadata = {'task_id': name, 'task_type': 'bugfix'}
        if family:
            metadata['family'] = family
        (path / 'metadata.yaml').write_text(json.dumps(metadata))
        return TaskSpec.load(path)

    def request(self, task=None, name='attempt'):
        task = task or self.task()
        stage = self.root / name / 'bundle' / 'delivery'
        stage.mkdir(parents=True, exist_ok=True)
        return GradeRequest(task, self.root / name, stage=stage)

    def test_builtin_adapter_and_legacy_alias(self):
        registry = FamilyRegistry()
        self.assertEqual(registry.resolve('bugfix').family, 'cvefactory')
        self.assertEqual(registry.resolve('cvefactory').family, 'cvefactory')
        self.assertEqual(registry.create('bugfix').family, 'cvefactory')

    def test_legacy_cvefactory_import_suffix_uses_canonical_directory_id(self):
        path = self.root / 'tasks' / 'cvefactory-cve-2099-0099'
        path.mkdir(parents=True)
        original = {'task_id': path.name + '.importing', 'task_type': 'bugfix'}
        (path / 'metadata.yaml').write_text(json.dumps(original))
        task = TaskSpec.load(path)
        self.assertEqual(task.task_id, path.name)
        self.assertEqual(task.family, 'cvefactory')
        self.assertEqual(task.metadata['task_id'], path.name + '.importing')
        self.assertEqual(json.loads((path / 'metadata.yaml').read_text()), original)

    def test_unrelated_metadata_id_is_still_rejected(self):
        path = self.root / 'tasks' / 'other-task'
        path.mkdir(parents=True)
        (path / 'metadata.yaml').write_text(json.dumps({
            'task_id': 'not-the-directory', 'task_type': 'bugfix'}))
        with self.assertRaisesRegex(ValueError, 'must equal directory name'):
            TaskSpec.load(path)

    def test_family_is_distinct_from_task_type(self):
        spec = self.task(family='new_family')
        self.assertEqual(spec.task_type, 'bugfix')
        self.assertEqual(spec.family, 'new_family')

    def test_default_prepare_copies_only_public_input(self):
        task = self.task()
        source = task.path / 'input' / 'src'
        source.mkdir(parents=True)
        (source / 'app.py').write_text('print(1)\n')
        (source / 'alias.py').symlink_to('app.py')
        (task.path / 'gold').mkdir()
        (task.path / 'gold' / 'solution.sh').write_text('secret\n')
        (task.path / 'instruction.md').write_text('public instruction\n')
        workspace = self.root / 'results' / task.task_id / 'workspace'
        StubFamily().prepare_workspace(PrepareRequest(task, workspace))
        self.assertEqual((workspace / 'src' / 'app.py').read_text(), 'print(1)\n')
        self.assertTrue((workspace / 'src' / 'alias.py').is_symlink())
        self.assertEqual((workspace / 'TASK.md').read_text(), 'public instruction\n')
        self.assertFalse((workspace / 'gold').exists())
        with self.assertRaises(FileExistsError):
            StubFamily().prepare_workspace(PrepareRequest(task, workspace))

    def test_cvefactory_prepare_keeps_its_contract(self):
        task = self.task('cvefactory-cve-2099-0001')
        (task.path / 'input' / 'src').mkdir(parents=True)
        (task.path / 'input' / 'CVE.md').write_text('CVE.md')
        workspace = self.root / 'results' / task.task_id / 'workspace'
        plugin = FamilyRegistry().create('cvefactory')
        plugin.prepare_workspace(PrepareRequest(task, workspace))
        self.assertIn('reproduce and fix', (workspace / 'TASK.md').read_text())
        with self.assertRaises(FileExistsError):
            plugin.prepare_workspace(PrepareRequest(task, workspace))

    def test_adapter_errors_are_normalized_without_calling_docker(self):
        request = self.request(self.task('cvefactory-cve-2099-0002'))
        request = GradeRequest(request.task, request.results, stage=request.stage,
                               options={'unknown': True})
        record = execute_grade(FamilyRegistry().create('cvefactory'), request)
        self.assertEqual(record['reward'], 0)
        self.assertEqual(record['status'], 'error')
        self.assertEqual(record['family'], 'cvefactory')
        self.assertIn('unsupported cvefactory options', record['error'])

    def test_common_result_fields_cannot_be_spoofed_by_plugin(self):
        request = self.request()
        record = execute_grade(StubFamily(family=request.task.family, reward=1), request)
        self.assertEqual(record['reward'], 1)
        self.assertEqual(record['family'], request.task.family)
        self.assertEqual(record['checks']['output'], request.results.name)
        self.assertEqual(json.loads((request.out_dir / 'result.json').read_text()), record)
        self.assertFalse((request.out_dir / 'running.json').exists())

    def test_existing_result_is_not_overwritten_without_force(self):
        request = self.request()
        first = execute_grade(StubFamily(reward=1), request)
        second = execute_grade(StubFamily(reward=0), request)
        self.assertEqual(second['status'], 'skipped_existing')
        self.assertEqual(second['reward'], 1)
        self.assertEqual(second['previous_status'], first['status'])
        forced = execute_grade(StubFamily(reward=0), request, force=True)
        self.assertEqual(forced['reward'], 0)

    def test_same_attempt_is_locked_across_processes(self):
        request = self.request()
        with grade_lock(request.out_dir):
            with self.assertRaises(TaskBusy):
                execute_grade(StubFamily(), request)
        record = execute_grade(StubFamily(), request)
        self.assertEqual(record['reward'], 1)

    def test_different_attempts_can_grade_same_task_in_parallel(self):
        task = self.task()
        barrier = threading.Barrier(2)
        requests = [self.request(task, 'attempt-a'), self.request(task, 'attempt-b')]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            records = list(pool.map(
                lambda request: execute_grade(StubFamily(barrier=barrier), request), requests))
        self.assertEqual([record['reward'] for record in records], [1, 1])
        self.assertNotEqual(records[0]['checks'], records[1]['checks'])

    def test_new_external_family_needs_no_core_registry_edit(self):
        directory = self.root / 'plugins' / 'new_family'
        directory.mkdir(parents=True)
        (directory / 'plugin.json').write_text(json.dumps({
            'api_version': 1, 'family': 'new_family', 'aliases': ['new-type'],
        }))
        (directory / 'helpers.py').write_text('REWARD = 1\n')
        (directory / 'plugin.py').write_text(
            'from harness.task_api import TaskFamily\n'
            'from .helpers import REWARD\n'
            'class Plugin(TaskFamily):\n'
            '    family = "new_family"\n'
            '    def grade(self, request):\n'
            '        return {"reward": REWARD}\n'
            'def create_plugin():\n'
            '    return Plugin()\n')
        registry = FamilyRegistry([self.root / 'plugins'])
        self.assertEqual(registry.create('new-type').family, 'new_family')
        self.assertEqual(registry.issues, [])

    def test_broken_unselected_family_does_not_break_builtin(self):
        directory = self.root / 'plugins' / 'broken_family'
        directory.mkdir(parents=True)
        (directory / 'plugin.json').write_text(json.dumps({
            'api_version': 99, 'family': 'broken_family'}))
        registry = FamilyRegistry([ROOT / 'harness' / 'families', self.root / 'plugins'])
        self.assertEqual(registry.create('cvefactory').family, 'cvefactory')
        self.assertEqual(len(registry.issues), 1)
        with self.assertRaises(Exception):
            registry.create('broken_family')

    def test_grading_must_name_a_frozen_agent_stage(self):
        task = self.task()
        with self.assertRaises(TypeError):
            GradeRequest(task, self.root / 'results')
        # The retired `source` knob must stay gone: only an explicit frozen
        # stage is gradable, and there is no mode parameter to confuse again.
        with self.assertRaises(TypeError):
            GradeRequest(task, self.root / 'results', stage=self.root / 's',
                         source='submission')


if __name__ == '__main__':
    unittest.main()
