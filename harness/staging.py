"""Shared staging helpers for grading pipelines.

Every bench family stages a frozen delivery into the grader sandbox before
building; the delivery itself stays untouched so revalidation can re-run
from the same bits. Staging must copy symlinks as symlinks: deliveries can
contain dangling links into build-time artifacts (e.g. ndpi/lib ->
src/lib/.libs in nDPI) and copytree's default follows links, crashing on
them with a misleading Errno 2 that names the link, not the missing target
(webexploit fix #22). All families must use these helpers instead of
calling shutil.copytree directly.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

__all__ = ['stage_tree', 'stage_delivery', 'drop_controller_debug_symlinks']


def stage_tree(source: Path, destination: Path) -> None:
    """Copy a tree preserving symlinks exactly, never following them."""
    shutil.copytree(source, destination, symlinks=True)


def drop_controller_debug_symlinks(root: Path) -> None:
    """Remove staged copies of the controller's debug alias (* -> cli-debug.log).

    Only symlinks pointing at cli-debug.log are removed. Every other symlink
    in the frozen tree is part of the delivery contract (vendored sources
    carry ``libfoo.so -> libfoo.so.1`` chains); deleting those would make the
    clean-room build diverge from what the agent built and misjudge the task
    as agent_semantic.
    """
    if not root.is_dir():
        return
    links = []
    for path in root.rglob('*'):
        if not path.is_symlink():
            continue
        try:
            if Path(os.readlink(path)).name == 'cli-debug.log':
                links.append(path)
        except OSError:
            continue
    for path in links:
        path.unlink(missing_ok=True)


def stage_delivery(source: Path, destination: Path) -> None:
    """Stage a frozen delivery for grading: symlink-safe copy, then drop
    the controller's debug aliases from the staged copy (never the delivery).
    """
    stage_tree(source, destination)
    drop_controller_debug_symlinks(destination)
