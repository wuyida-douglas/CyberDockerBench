from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from harness.claude_session import TurnBudget, with_claude_retries  # noqa: E402


class ClaudeEnvironmentTests(unittest.TestCase):
    def test_matches_declared_serving_context_window(self):
        env = with_claude_retries({'ANTHROPIC_AUTH_TOKEN': 'secret'})
        self.assertEqual(env['CLAUDE_CODE_MAX_CONTEXT_TOKENS'], '131072')
        self.assertEqual(env['CLAUDE_CODE_MAX_RETRIES'], '15')
        self.assertEqual(env['ANTHROPIC_AUTH_TOKEN'], 'secret')


class TurnBudgetTests(unittest.TestCase):
    def test_counts_wakeups_not_segments_and_deduplicates_message_chunks(self):
        budget = TurnBudget(3)
        self.assertFalse(budget.observe({'type': 'result', 'num_turns': 2,
                                         'subtype': 'error_max_turns'}))
        self.assertFalse(budget.observe({'type': 'assistant', 'message': {
            'id': 'message-1', 'content': [{'type': 'thinking', 'thinking': 'build'}]}}))
        self.assertFalse(budget.observe({'type': 'assistant', 'message': {
            'id': 'message-1', 'content': [{'type': 'tool_use', 'name': 'Bash'}]}}))
        self.assertFalse(budget.observe({'type': 'system', 'subtype': 'task_notification'}))
        self.assertFalse(budget.observe({'type': 'assistant', 'message': {
            'id': 'message-2', 'content': [{'type': 'text', 'text': 'resume'}]}}))
        self.assertFalse(budget.observe({'type': 'result', 'num_turns': 1}))
        self.assertTrue(budget.observe({'type': 'assistant', 'message': {
            'id': 'message-3', 'content': [{'type': 'text', 'text': 'last'}]}}))
        self.assertFalse(budget.observe({'type': 'assistant', 'message': {
            'id': 'message-4', 'content': []}}))
        self.assertEqual(budget.turns, 4)


if __name__ == '__main__':
    unittest.main()
