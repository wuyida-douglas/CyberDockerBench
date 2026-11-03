"""Convert Claude stream-json events to human-readable trajectory views.

Three views, all written in real time as events arrive:

- ``trajectory.jsonl``: full-fidelity machine audit, one event per line.
- ``trajectory.md``: the human view. One ``## 轮次 N`` per assistant turn
  (one model reply, the same unit as Claude ``--max-turns`` / ``num_turns``).
  A turn opens with the previous reply's tool results, then this reply's
  thinking, text, and tool calls. Blocks inside a turn are ``###`` headings,
  not a second global counter. Nothing is omitted or truncated.
  thinking_tokens heartbeats carry no timestamps, so consecutive ones are
  aggregated into a single counted line at their stream position.
- ``trail.jsonl``: one line per tool call, ``{ts, role, tool, summary}``,
  the same shape as exploit-from-git's ``live.trail.jsonl``.

``convert()`` rebuilds the views from a retained raw stream after the fact.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TextIO

REDUNDANT_EVENTS = frozenset({('system', 'thinking_tokens')})

# All human-facing timestamps are fixed to Beijing time (UTC+8), matching
# trail.jsonl's +08:00 offsets and the project convention.
BEIJING = timezone(timedelta(hours=8))


def _fence(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(
        value, ensure_ascii=False, indent=2, default=str)
    longest = max((len(line) - len(line.lstrip('`'))
                   for line in text.splitlines()), default=0)
    fence = '`' * max(3, longest + 1)
    return f'{fence}text\n{text}\n{fence}\n'


def _event_dt(event: dict) -> datetime | None:
    raw = str(event.get('timestamp') or event.get('observed_at') or '')
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except ValueError:
        return None
    return dt.astimezone(BEIJING)


def _event_ts(event: dict) -> str:
    dt = _event_dt(event)
    return dt.strftime('%Y-%m-%d %H:%M:%S+08:00') if dt else ''


def _tool_summary(name: str, inp: dict, one_line: bool = False) -> str:
    if name == 'Bash':
        cmd = str(inp.get('command', ''))
        if one_line:
            return cmd.splitlines()[0][:160] if cmd else ''
        return '```bash\n' + cmd + '\n```'
    if name in ('Read', 'NotebookEdit'):
        return str(inp.get('file_path') or inp.get('notebook_path', ''))
    if name in ('Edit', 'Write', 'MultiEdit'):
        path = str(inp.get('file_path', ''))
        if one_line:
            return path
        if name == 'Write':
            return f"`{path}`\n```\n{inp.get('content', '')}\n```"
        body = str(inp.get('old_string', '')) + '\n  →\n' + str(inp.get('new_string', ''))
        return f"`{path}`\n```diff\n{body}\n```"
    if name == 'Task':
        if one_line:
            return str(inp.get('description', ''))[:160]
        return (f"**{inp.get('description', '')}**\n```\n"
                + str(inp.get('prompt', '')) + '\n```')
    if name in ('Glob', 'Grep'):
        return f"{inp.get('pattern', '')} {inp.get('path', '')}".strip()
    brief = json.dumps(inp, ensure_ascii=False)
    return brief[:160] if one_line else ('```\n' + brief + '\n```')


class TrajectoryWriter:
    """Flush all views after each event, without rewriting prior content."""

    def __init__(self, jsonl_path: Path | None, markdown_path: Path,
                 trail_path: Path | None = None):
        self.jsonl_path = jsonl_path
        self.markdown_path = markdown_path
        self.trail_path = trail_path
        self.jsonl: TextIO | None = None
        self.markdown: TextIO | None = None
        self.trail: TextIO | None = None
        self.sequence = 0
        self.turn = 0
        self.omitted_heartbeats = 0
        self.heartbeat_tokens = 0
        self.thinking_blocks = 0
        self._pending_heartbeats = 0
        self._pending_heartbeat_tokens = 0
        self._message_id: str | None = None
        self._pending_results: list[str] = []

    def __enter__(self) -> 'TrajectoryWriter':
        if self.jsonl_path is not None:
            self.jsonl = self.jsonl_path.open('w', encoding='utf-8')
        self.markdown = self.markdown_path.open('w', encoding='utf-8')
        self.markdown.write('# Agent trajectory\n\n'
                            '时间戳均为北京时间（UTC+8）。一轮是一次 assistant 回复'
                            '（与 Claude `--max-turns` / `num_turns` 相同）：上一轮的'
                            '工具返回，加上这一轮的思考、正文和工具调用。标题只写轮次，'
                            '不给每个片段另编号。thinking、正文、工具调用与工具返回均不'
                            '省略、不截断；thinking 心跳事件（无时间戳）按相邻位置聚合为'
                            '单行。机器审计原件见同目录 trajectory.jsonl，工具流水见 '
                            'trail.jsonl。\n')
        self.markdown.flush()
        if self.trail_path is not None:
            self.trail = self.trail_path.open('w', encoding='utf-8')
        return self

    def __exit__(self, *args: Any) -> None:
        if self.markdown is not None:
            self._flush_heartbeats()
            self._flush_pending_results()
            self.markdown.write(
                f'\n---\n_事件 {self.sequence} 条；thinking 块 '
                f'{self.thinking_blocks} 个；心跳 {self.omitted_heartbeats} 条'
                f'（约 {self.heartbeat_tokens} tokens，已按位置聚合为单行）。_\n')
        for stream in (self.jsonl, self.markdown, self.trail):
            if stream is not None:
                stream.close()

    def _flush_heartbeats(self) -> None:
        if self.markdown is None or not self._pending_heartbeats:
            return
        self.markdown.write(
            f'\n_thinking 心跳 ×{self._pending_heartbeats} 条，'
            f'约 {self._pending_heartbeat_tokens} tokens；'
            f'逐条见原始事件流。_\n')
        self._pending_heartbeats = 0
        self._pending_heartbeat_tokens = 0

    def write(self, event: Any) -> bool:
        if not isinstance(event, dict):
            return False
        key = (event.get('type'), event.get('subtype'))
        if key in REDUNDANT_EVENTS:
            self.omitted_heartbeats += 1
            self.heartbeat_tokens += event.get('estimated_tokens_delta') or 0
            self._pending_heartbeats += 1
            self._pending_heartbeat_tokens += event.get('estimated_tokens_delta') or 0
            return False
        self.sequence += 1
        if self.jsonl is not None:
            self.jsonl.write(json.dumps(event, ensure_ascii=False, default=str) + '\n')
            self.jsonl.flush()
        self._render(event)
        self.markdown.flush()
        if self.trail is not None:
            self.trail.flush()
        return True

    def _stamp(self, event: dict) -> str:
        ts = _event_ts(event)
        return f' · {ts}' if ts else ''

    def _plain(self, title: str, event: dict) -> None:
        assert self.markdown is not None
        self.markdown.write(f'\n## {title}{self._stamp(event)}\n\n')

    def _subsection(self, title: str, event: dict | None = None) -> None:
        assert self.markdown is not None
        stamp = self._stamp(event) if event is not None else ''
        self.markdown.write(f'\n### {title}{stamp}\n\n')

    def _flush_pending_results(self) -> None:
        if self.markdown is None or not self._pending_results:
            return
        self.markdown.write(''.join(self._pending_results))
        self._pending_results.clear()

    def _open_turn(self, event: dict, message_id: str) -> None:
        assert self.markdown is not None
        self.turn += 1
        self._message_id = message_id or None
        self.markdown.write(f'\n## 轮次 {self.turn}{self._stamp(event)}\n')
        self._flush_pending_results()

    def _begin_assistant_turn(self, event: dict, message: dict) -> None:
        message_id = str(message.get('id') or '') if isinstance(message, dict) else ''
        if message_id and message_id == self._message_id:
            return
        self._open_turn(event, message_id)

    def _format_tool_result(self, event: dict, item: dict) -> str:
        parts = [f'\n### 工具返回{self._stamp(event)}\n\n']
        result = item.get('content', '')
        if isinstance(result, list):
            for part in result:
                if isinstance(part, dict) and part.get('type') == 'text':
                    parts.append(_fence(str(part.get('text', ''))))
                elif isinstance(part, dict) and part.get('type') != 'tool_reference':
                    parts.append(_fence(str(part)))
        else:
            parts.append(_fence(str(result)))
        if item.get('is_error'):
            parts.append('\n**Tool returned an error.**\n')
        return ''.join(parts)

    def _trail(self, event: dict, tool: str, summary: str) -> None:
        if self.trail is None:
            return
        # Same shape as exploit-from-git's live.trail.jsonl. The sandbox runs
        # with permissions bypassed, so every call is effectively allowed.
        dt = _event_dt(event)
        ts = (dt.isoformat(timespec='seconds') if dt
              else str(event.get('timestamp') or event.get('observed_at') or ''))
        self.trail.write(json.dumps({
            'ts': ts,
            'role': 'agent', 'tool': tool, 'decision': 'allow',
            'reason': '', 'turn': self.turn, 'summary': summary,
        }, ensure_ascii=False) + '\n')

    def _render_assistant_block(self, event: dict, item: Any) -> None:
        assert self.markdown is not None
        if not isinstance(item, dict):
            self._subsection('assistant')
            self.markdown.write(_fence(item))
            return
        block = item.get('type')
        if block == 'thinking':
            self.thinking_blocks += 1
            self._subsection('思考')
            self.markdown.write(item.get('thinking', '').strip() + '\n')
            return
        if block == 'text':
            self._subsection('正文')
            self.markdown.write(item.get('text', '').strip() + '\n')
            return
        if block == 'tool_use':
            name = item.get('name', '?')
            inp = item.get('input', {}) or {}
            self._subsection(f'工具调用 · {name}')
            self.markdown.write(_tool_summary(name, inp) + '\n')
            self._trail(event, name, _tool_summary(name, inp, one_line=True))
            return
        self._subsection(f'assistant · {block or "event"}')
        self.markdown.write(_fence(item))

    def _render_user_block(self, event: dict, item: Any) -> None:
        assert self.markdown is not None
        if not isinstance(item, dict):
            self._subsection('用户正文')
            self.markdown.write(_fence(item))
            return
        block = item.get('type')
        if block == 'tool_result':
            self._pending_results.append(self._format_tool_result(event, item))
            return
        if block == 'text':
            self._subsection('用户正文')
            self.markdown.write(item.get('text', '').strip() + '\n')
            return
        self._subsection(f'user · {block or "event"}')
        self.markdown.write(_fence(item))

    def _render(self, event: dict) -> None:
        assert self.markdown is not None
        self._flush_heartbeats()
        kind = event.get('type')
        message = event.get('message', {})
        content = message.get('content', []) if isinstance(message, dict) else []
        if kind == 'assistant' and isinstance(content, list):
            self._begin_assistant_turn(event, message if isinstance(message, dict) else {})
            for item in content:
                self._render_assistant_block(event, item)
            return
        if kind == 'user' and isinstance(content, list):
            for item in content:
                self._render_user_block(event, item)
            return
        if kind == 'result':
            self._flush_pending_results()
            status = 'error' if event.get('is_error') else 'success'
            self._plain(f'会话结果 · {status}', event)
            summary = {key: event.get(key) for key in (
                'subtype', 'num_turns', 'duration_ms', 'total_cost_usd', 'result',
                'is_error') if key in event}
            self.markdown.write(_fence(summary))
            return
        if kind == 'tool_progress':
            name = event.get('tool_name') or 'tool'
            elapsed = event.get('elapsed_time_seconds')
            self.markdown.write(f'\n_工具进度 · {name} · {elapsed}s_\n')
            return
        if kind == 'system' and event.get('subtype') == 'init':
            self._plain('会话初始化', event)
            self.markdown.write(_fence({key: event.get(key) for key in (
                'model', 'permissionMode', 'cwd') if key in event}))
            return
        if kind == 'system' and event.get('subtype') == 'api_retry':
            self._plain('API 重试', event)
            self.markdown.write(_fence(str(event.get('error', ''))))
            return
        if kind == 'system' and event.get('subtype') in ('task_started', 'task_notification'):
            title = '子代理' + ('启动' if event.get('subtype') == 'task_started' else '回报')
            self._subsection(title) if self.turn else self._plain(title, event)
            self.markdown.write(_fence(str(event.get('description') or
                                           event.get('summary') or '')))
            return
        title = f'{kind} · {event.get("subtype", "event")}'
        if self.turn:
            self._subsection(title)
        else:
            self._plain(title, event)
        self.markdown.write(_fence(event))


def convert(source: Path, jsonl_path: Path | None, markdown_path: Path,
            trail_path: Path | None = None) -> dict[str, int]:
    """Rebuild views from a retained raw stream; never modify the source.

    ``jsonl_path`` may be None to regenerate only the human views.
    """
    source = source.resolve()
    if jsonl_path is not None and source == jsonl_path.resolve():
        raise ValueError('source must differ from output paths')
    invalid = 0
    with source.open(encoding='utf-8', errors='replace') as lines, \
            TrajectoryWriter(jsonl_path, markdown_path, trail_path) as writer:
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                invalid += 1
                continue
            writer.write(event)
    return {'events': writer.sequence, 'turns': writer.turn,
            'heartbeats': writer.omitted_heartbeats,
            'heartbeat_tokens': writer.heartbeat_tokens,
            'thinking_blocks': writer.thinking_blocks,
            'invalid_json_lines': invalid}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='retained raw stream-json JSONL')
    parser.add_argument('--jsonl', type=Path, default=None)
    parser.add_argument('--markdown', type=Path, required=True)
    parser.add_argument('--trail', type=Path, default=None)
    args = parser.parse_args(argv)
    if args.jsonl and args.source.resolve() == args.jsonl.resolve():
        parser.error('refusing to overwrite the raw source; choose another JSONL path')
    try:
        report = convert(args.source, args.jsonl, args.markdown, args.trail)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
