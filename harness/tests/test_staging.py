"""Pin the shared staging helpers: symlink-safe copies and debug-alias drops."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness.staging import (drop_controller_debug_symlinks, stage_delivery,
                             stage_tree)


class StageTreeTest(unittest.TestCase):
    def test_dangling_symlink_is_copied_as_symlink(self):
        # nDPI-style delivery: ndpi/lib -> src/lib/.libs dangles until build
        # time; staging must never follow it (webexploit fix #22).
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'delivery'
            (source / 'ndpi').mkdir(parents=True)
            (source / 'ndpi' / 'Makefile.am').write_text('x\n')
            (source / 'ndpi' / 'lib').symlink_to('src/lib/.libs')
            stage_tree(source, root / 'workspace')
            staged = root / 'workspace' / 'ndpi' / 'lib'
            self.assertTrue(staged.is_symlink())
            self.assertEqual(staged.readlink().as_posix(), 'src/lib/.libs')
            self.assertEqual((root / 'workspace' / 'ndpi' / 'Makefile.am').read_text(), 'x\n')


class DropControllerDebugSymlinksTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / 'cli-debug.log').write_text('debug\n')
        (self.root / 'latest').symlink_to('cli-debug.log')
        vendor = self.root / 'vendor' / 'lib'
        vendor.mkdir(parents=True)
        (vendor / 'libfoo.so.1').write_text('bin\n')
        (vendor / 'libfoo.so').symlink_to('libfoo.so.1')
        (vendor / 'latest').symlink_to('../../cli-debug.log')
        (self.root / 'plain').write_text('keep me\n')

    def tearDown(self):
        self._tmp.cleanup()

    def test_only_debug_aliases_are_removed(self):
        drop_controller_debug_symlinks(self.root)
        self.assertFalse((self.root / 'latest').exists())
        self.assertFalse((self.root / 'vendor' / 'lib' / 'latest').exists())
        self.assertTrue((self.root / 'vendor' / 'lib' / 'libfoo.so').is_symlink())
        self.assertEqual((self.root / 'plain').read_text(), 'keep me\n')
        self.assertTrue((self.root / 'cli-debug.log').exists())

    def test_regular_file_named_latest_survives(self):
        (self.root / 'latest').unlink()
        (self.root / 'latest').write_text('not a symlink')
        drop_controller_debug_symlinks(self.root)
        self.assertEqual((self.root / 'latest').read_text(), 'not a symlink')

    def test_missing_root_is_a_no_op(self):
        drop_controller_debug_symlinks(self.root / 'does-not-exist')

    def test_stage_delivery_combines_copy_and_drop(self):
        destination = self.root / 'staged-out'
        stage_delivery(self.root / 'vendor', destination)
        self.assertFalse((destination / 'lib' / 'latest').exists())
        self.assertTrue((destination / 'lib' / 'libfoo.so').is_symlink())
        # The source tree keeps its alias: only the staged copy is cleaned.
        self.assertTrue((self.root / 'vendor' / 'lib' / 'latest').is_symlink())


if __name__ == '__main__':
    unittest.main()
