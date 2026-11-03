"""Storage validation and conservative stale-attempt cleanup tests."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from harness.docker_sandbox import DockerSandbox
from harness.storage import (
    OWNER_SCHEMA,
    StorageError,
    cleanup_stale_docker_data,
    owner_marker,
    storage_report,
    validate_storage_root,
    write_owner_marker,
)


class ContainerExistsTests(unittest.TestCase):
    """Regression: a hung daemon must make _container_exists return None,
    not raise and abort an unrelated grade's address-lease scan (59072 r4)."""

    def test_inspect_timeout_returns_none(self):
        from harness.storage import _container_exists
        with mock.patch('harness.storage.subprocess.run',
                        side_effect=subprocess.TimeoutExpired(['docker'], 30)):
            self.assertIsNone(_container_exists('cdb-stalled'))

    def test_inspect_oserror_returns_none(self):
        from harness.storage import _container_exists
        with mock.patch('harness.storage.subprocess.run',
                        side_effect=OSError('docker binary missing')):
            self.assertIsNone(_container_exists('cdb-whatever'))

    def test_definitive_answers_unchanged(self):
        from harness.storage import _container_exists
        running = subprocess.CompletedProcess([], 0, 'true\n', '')
        missing = subprocess.CompletedProcess([], 1, '', 'Error: No such object: cdb-x')
        with mock.patch('harness.storage.subprocess.run', return_value=running):
            self.assertTrue(_container_exists('cdb-live'))
        with mock.patch('harness.storage.subprocess.run', return_value=missing):
            self.assertFalse(_container_exists('cdb-gone'))


class StorageValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cdb-storage-validation-')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_virtiofs_is_rejected_before_dockerd_starts(self):
        with mock.patch('harness.storage.filesystem_type', return_value='virtiofs'):
            with self.assertRaisesRegex(StorageError, 'mmap-compatible'):
                validate_storage_root(self.root / 'shared')

    def test_xfs_with_sufficient_capacity_is_accepted(self):
        usage = SimpleNamespace(free=30 * 1024 ** 3, total=100 * 1024 ** 3)
        with mock.patch('harness.storage.filesystem_type', return_value='xfs'), \
                mock.patch('harness.storage.shutil.disk_usage', return_value=usage):
            result = validate_storage_root(self.root / 'nvme', 20)
        self.assertEqual(result['filesystem'], 'xfs')
        self.assertEqual(result['free_gib'], 30)

    def test_capacity_threshold_fails_closed(self):
        usage = SimpleNamespace(free=2 * 1024 ** 3, total=100 * 1024 ** 3)
        with mock.patch('harness.storage.filesystem_type', return_value='xfs'), \
                mock.patch('harness.storage.shutil.disk_usage', return_value=usage):
            with self.assertRaisesRegex(StorageError, 'insufficient Docker storage'):
                validate_storage_root(self.root / 'small', 20)


class StaleCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cdb-storage-cleanup-')
        self.root = Path(self.temp.name)
        self.now = 2_000_000_000.0

    def tearDown(self):
        self.temp.cleanup()

    def marked(self, name: str, age_hours: float):
        data = self.root / f'cdb-{name}-docker-data'
        data.mkdir()
        (data / 'payload').write_text(name)
        marker = owner_marker(data)
        marker.write_text(json.dumps({
            'schema_version': OWNER_SCHEMA,
            'sandbox_name': f'cdb-{name}',
            'container': f'cdb-{name}',
            'task_id': name,
            'runtime_root': str(self.root / 'runtime' / name),
            'created_at': self.now - age_hours * 3600,
        }))
        return data, marker

    def test_dry_run_preserves_data_and_apply_removes_only_stale_marked_attempt(self):
        data, marker = self.marked('stale', 48)
        dry = cleanup_stale_docker_data(
            self.root, 24, now=self.now, container_exists=lambda _: False)
        self.assertEqual(dry['actions'][0]['action'], 'would_remove')
        self.assertTrue(data.exists())
        self.assertTrue(marker.exists())
        applied = cleanup_stale_docker_data(
            self.root, 24, apply=True, now=self.now,
            container_exists=lambda _: False)
        self.assertEqual(applied['actions'][0]['action'], 'removed')
        self.assertFalse(data.exists())
        self.assertFalse(marker.exists())

    def test_young_and_live_attempts_are_preserved(self):
        young, _ = self.marked('young', 1)
        live, _ = self.marked('live', 72)
        cleanup_stale_docker_data(
            self.root, 24, apply=True, now=self.now,
            container_exists=lambda name: name == 'cdb-live')
        self.assertTrue(young.exists())
        self.assertTrue(live.exists())

    def test_unknown_container_state_and_unmarked_data_are_preserved(self):
        marked, _ = self.marked('unknown', 72)
        unmarked = self.root / 'cdb-legacy-docker-data'
        unmarked.mkdir()
        report = cleanup_stale_docker_data(
            self.root, 24, apply=True, now=self.now,
            container_exists=lambda _: None)
        self.assertTrue(marked.exists())
        self.assertTrue(unmarked.exists())
        self.assertEqual(report['actions'][0]['reason'],
                         'container inspection unavailable')

    def test_invalid_marker_is_reported_not_deleted(self):
        data, marker = self.marked('invalid', 72)
        marker.write_text('{not-json')
        report = cleanup_stale_docker_data(
            self.root, 24, apply=True, now=self.now,
            container_exists=lambda _: False)
        self.assertTrue(data.exists())
        self.assertTrue(marker.exists())
        self.assertEqual(len(report['errors']), 1)

    def test_normal_sandbox_stop_removes_data_and_owner_marker(self):
        with mock.patch.dict('os.environ', {
                'CDB_LOCAL_DOCKER_DATA': '1',
                'CDB_DOCKER_DATA_ROOT': str(self.root)}):
            sandbox = DockerSandbox('cleanup-test', self.root / 'runtime',
                                    name='cdb-cleanup-test')
            sandbox.docker_data.mkdir(parents=True)
            marker = write_owner_marker(
                sandbox.docker_data,
                task_id=sandbox.task_id,
                sandbox_name=sandbox.name,
                container=sandbox.container,
                runtime_root=sandbox.runtime_root,
            )
            with mock.patch.object(sandbox, '_host',
                                   return_value=subprocess.CompletedProcess([], 0)):
                sandbox.stop(remove_data=True)
            self.assertFalse(sandbox.docker_data.exists())
            self.assertFalse(marker.exists())

    def test_owner_marker_removal_failure_is_not_silent(self):
        with mock.patch.dict('os.environ', {
                'CDB_LOCAL_DOCKER_DATA': '1',
                'CDB_DOCKER_DATA_ROOT': str(self.root)}):
            sandbox = DockerSandbox('cleanup-test', self.root / 'runtime',
                                    name='cdb-cleanup-test')
            with mock.patch.object(sandbox, '_host',
                                   return_value=subprocess.CompletedProcess([], 0)), \
                    mock.patch('harness.docker_sandbox.remove_owner_marker',
                               side_effect=OSError('marker is read-only')):
                with self.assertRaisesRegex(Exception, 'owner marker'):
                    sandbox.stop(remove_data=True)

    def test_address_leases_do_not_overlap_and_reuse_a_finished_sandbox(self):
        from harness.docker_sandbox import (
            acquire_address_lease, address_ranges, release_address_lease)
        outers = set()
        inners = set()
        for index in range(256):
            outer, _gateway, inner = address_ranges(index)
            outers.add(outer)
            inners.add(inner)
        self.assertEqual(len(outers), 256)
        self.assertEqual(len(inners), 256)
        self.assertEqual(address_ranges(0), ('10.200.0.0/24', '10.200.0.1', '10.160.0.0/20'))
        alive = {'sandbox-a'}
        free = dict(container_exists=lambda name: name in alive, occupied_subnets=[])
        first = acquire_address_lease(self.root, 'sandbox-a', **free)
        second = acquire_address_lease(self.root, 'sandbox-b', **free)
        self.assertNotEqual(first, second)
        alive.discard('sandbox-a')
        release_address_lease(self.root, 'sandbox-a')
        reused = acquire_address_lease(
            self.root, 'sandbox-c', container_exists=lambda name: name in alive,
            occupied_subnets=[])
        self.assertEqual(reused, first)
        # A reservation whose container is not up yet still owns its subnet.
        held = acquire_address_lease(
            self.root, 'sandbox-starting', container_exists=lambda name: False,
            occupied_subnets=[])
        stolen = acquire_address_lease(
            self.root, 'sandbox-other', container_exists=lambda name: False,
            occupied_subnets=[])
        self.assertNotEqual(stolen, held)

    def test_docker_occupied_subnet_is_not_handed_out(self):
        from harness.docker_sandbox import acquire_address_lease, address_ranges
        taken = acquire_address_lease(
            self.root, 'sandbox-new', container_exists=lambda name: False,
            occupied_subnets=['10.200.0.0/24'])
        self.assertNotEqual(address_ranges(taken)[0], '10.200.0.0/24')
        # An old lease whose bridge is still on the daemon stays taken too.
        lease = self.root / 'address-leases' / '1.lease'
        lease.write_text(json.dumps({
            'index': 1, 'container': 'gone-sandbox',
            'created_at': time.time() - 10_000,
        }))
        again = acquire_address_lease(
            self.root, 'sandbox-next', container_exists=lambda name: False,
            occupied_subnets=['10.200.1.0/24'])
        self.assertNotEqual(address_ranges(again)[0], '10.200.1.0/24')
        self.assertTrue(lease.is_file())

    def test_old_lease_is_reused_after_docker_drops_the_subnet(self):
        from harness.docker_sandbox import acquire_address_lease
        directory = self.root / 'address-leases'
        directory.mkdir()
        (directory / '0.lease').write_text(json.dumps({
            'index': 0, 'container': 'finished',
            'created_at': time.time() - 10_000,
        }))
        reused = acquire_address_lease(
            self.root, 'sandbox-new', container_exists=lambda name: False,
            occupied_subnets=[])
        self.assertEqual(reused, 0)

    def test_project_runtime_directory_stays_in_the_delivery(self):
        from harness.bundle import _scan_source
        workspace = self.root / 'workspace'
        script = workspace / 'runtime' / 'profile.d' / 'autojump.sh'
        script.parent.mkdir(parents=True)
        script.write_text('j()\n')
        rows, excluded = _scan_source(workspace, self.root / 'delivery-out')
        self.assertIn('runtime/profile.d/autojump.sh', {row['path'] for row in rows})
        self.assertNotIn('runtime', excluded)

    def test_report_distinguishes_unmarked_legacy_directories(self):
        legacy = self.root / 'cdb-legacy-docker-data'
        legacy.mkdir()
        report = storage_report(self.root)
        self.assertEqual(report['unmarked_directories'], [legacy.name])


if __name__ == '__main__':
    unittest.main()
