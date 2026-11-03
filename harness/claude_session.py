"""One Claude Code command for CVE-Factory, WebExploit and CyberGym.

The three families keep their own prompt and debug file. MCP is empty.
The network skill is the same directory, mounted at PLUGIN_DIR.
"""
from __future__ import annotations

PLUGIN_DIR = '/opt/cdb-network-plugin'
EMPTY_MCP = '{"mcpServers":{}}'
# Claude Code 2.1.311 reads CLAUDE_CODE_MAX_RETRIES and clamps anything above
# 15 is the highest value that is actually used.
API_MAX_RETRIES = 15
# Match the serving window. An unknown custom model otherwise defaults to
# 200k, delaying compaction until a 131072-token server rejects the request.
MODEL_CONTEXT_TOKENS = 131072


class TurnBudget:
    """Count complete-session assistant replies, including background wake-ups."""

    def __init__(self, max_turns: int):
        if max_turns <= 0:
            raise ValueError('max_turns must be positive')
        self.max_turns = max_turns
        self.turns = 0
        self._message_ids: set[str] = set()

    def observe(self, event: object) -> bool:
        """Return true only on the reply that first reaches the hard budget."""
        if not isinstance(event, dict) or event.get('type') != 'assistant':
            return False
        message = event.get('message')
        if not isinstance(message, dict) or not isinstance(message.get('content'), list):
            return False
        message_id = str(message.get('id') or '')
        if message_id:
            if message_id in self._message_ids:
                return False
            self._message_ids.add(message_id)
        self.turns += 1
        return self.turns == self.max_turns


def with_claude_retries(env: dict[str, str]) -> dict[str, str]:
    """Apply deployment limits to a Claude process without exposing credentials."""
    merged = dict(env)
    merged['CLAUDE_CODE_MAX_RETRIES'] = str(API_MAX_RETRIES)
    merged['CLAUDE_CODE_MAX_CONTEXT_TOKENS'] = str(MODEL_CONTEXT_TOKENS)
    return merged


def claude_command(prompt: str, model: str, max_turns: int, *, debug_file: str) -> list[str]:
    return [
        'claude', '-p', prompt,
        '--output-format', 'stream-json', '--verbose',
        '--permission-mode', 'bypassPermissions',
        '--setting-sources', '',
        '--strict-mcp-config',
        '--mcp-config', EMPTY_MCP,
        '--permission-prompts', 'none',
        '--max-turns', str(max_turns),
        '--model', model,
        '--debug-file', debug_file,
        '--plugin-dir', PLUGIN_DIR,
    ]
