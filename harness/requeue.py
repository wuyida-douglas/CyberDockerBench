"""Put a task back on the batch queue when the stop was infrastructure.

A passed task, a semantic grade failure, and a grader or build timeout stay
finished. A dead gateway, a preflight network failure, and a session ended by
an API error are not a verdict on the model. Each task gets
``INFRASTRUCTURE_ATTEMPTS`` tries. The in-session Claude retry cap is separate
and already set on all three families.
"""
from __future__ import annotations

import json
from pathlib import Path

INFRASTRUCTURE_ATTEMPTS = 3

_API_MARKERS = (
    'api error', 'upstream connection failed',
    'invalid or oversized http request', 'rate limit', 'overloaded',
    'connection error', 'status 401', 'status 403', 'status 429',
    'status 500', 'status 502', 'status 503', 'status 504',
)
_API_NEEDLES = (
    b'is_api_error_message":true',
    b'is_api_error_message": true',
    b'terminal_reason":"api_error"',
    b'terminal_reason": "api_error"',
)


def infrastructure_requeue_reason(record: dict) -> str | None:
    """Return why a finished attempt should go back on the queue."""
    if record.get('reward') == 1 or record.get('status') == 'locked':
        return None
    failure = str(record.get('failure_class') or '')
    error = str(record.get('error') or '')
    lowered = error.lower()
    if failure == 'network' or 'preflight' in lowered or 'networkfailure' in lowered:
        return 'preflight'
    if any(marker in lowered for marker in _API_MARKERS):
        return 'api'
    # A healthy frozen delivery can still lose its clean-room grade to a
    # transient inner daemon. Retry only this precise pre-build probe, not
    # missing deliverables, build timeouts, or semantic differentials.
    if failure == 'pipeline' and 'cannot start/stage source sandbox' in lowered:
        return 'source_sandbox'
    if failure == 'pipeline' and 'sandboxerror:' in lowered:
        return 'sandbox'
    return None


def api_error_from_text(text: str) -> str | None:
    """Pull the structured API-stop line out of a Claude JSONL transcript.

    A model message that merely discusses an API error is ignored. Only the
    synthetic ``is_api_error_message`` event or a result whose
    ``terminal_reason`` is ``api_error`` counts.
    """
    found = None
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        if not (event.get('is_api_error_message') or event.get('terminal_reason') == 'api_error'):
            continue
        piece = ''
        message = event.get('message')
        content = message.get('content') if isinstance(message, dict) else None
        if isinstance(content, list):
            piece = ' '.join(str(item.get('text', '')) for item in content if isinstance(item, dict))
        elif isinstance(content, str):
            piece = content
        piece = piece or str(event.get('result') or '')
        useful = 'api error' in piece.lower() or 'invalid or oversized' in piece.lower()
        if useful:
            found = piece[:500]
        elif found is None:
            found = 'API Error: ' + (piece or 'terminal_reason api_error')[:400]
    return found


def api_error_from_transcript(path: Path) -> str | None:
    """Scan a transcript for a structured API stop without loading it twice on a miss."""
    try:
        handle = path.open('rb')
    except OSError:
        return None
    overlap = b''
    hit = b''
    with handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            blob = overlap + chunk
            if any(needle in blob for needle in _API_NEEDLES):
                hit = blob
                break
            overlap = blob[-240:]
    if not hit:
        return None
    return api_error_from_text(hit.decode('utf-8', 'replace'))


VIEW_NAMES = frozenset({'trajectory.md', 'trail.jsonl'})


def file_task_view(output: Path) -> None:
    """Leave trail.jsonl and trajectory.md at the task root; file the rest."""
    if not output.is_dir():
        return
    detail = output / 'detail'
    movable = [child for child in output.iterdir()
               if child.name not in VIEW_NAMES and child.name not in {'detail', '.batch.lock'}]
    if not movable:
        return
    detail.mkdir(exist_ok=True)
    for child in movable:
        destination = detail / child.name
        if destination.exists():
            raise FileExistsError(f'refusing to hide an existing file: {destination}')
        child.rename(destination)


def filed_path(output: Path, name: str) -> Path:
    """Prefer a live task-root file, then the copy already moved into detail/."""
    root = output / name
    nested = output / 'detail' / name
    if root.exists() or not nested.exists():
        return root
    return nested


def archive_attempt_dir(task_dir: Path, attempt: int,
                        keep: frozenset[str] = frozenset()) -> Path:
    """Move one failed attempt aside so the next try gets an empty task directory."""
    task_dir.mkdir(parents=True, exist_ok=True)
    destination = task_dir / f'failed-attempt-{attempt:02d}'
    # An interrupted driver may retry the same attempt after a resume. Keep
    # every earlier failure instead of aborting the whole batch on collision.
    suffix = 1
    while destination.exists():
        destination = task_dir / f'failed-attempt-{attempt:02d}-resume-{suffix:02d}'
        suffix += 1
    destination.mkdir()
    for child in list(task_dir.iterdir()):
        if child.name == destination.name or child.name in keep:
            continue
        child.rename(destination / child.name)
    return destination
