from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness.cybergym_pipeline.oracle import Execution, LiveEngine, OracleError, check_pair, classify

META = {'sanitizer': 'address', 'fuzz_target': 'parser', 'expected_stack': 'parse_node'}
CRASH = '==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n#0 parse_node parser.c:9'


class Engine:
    def __init__(self, healthy=True, fixed_crash=False, leak=False):
        self.healthy, self.fixed_crash, self.leak = healthy, fixed_crash, leak
        self.executions, self.pushes = [], []
        self.private = Path('/private')

    def execute(self, target, argv, timeout):
        self.executions.append((target, argv))
        if len(argv) >= 2 and argv[1] == '-c':
            return Execution(0 if self.healthy else 127,
                             '/out/parser: ELF 64-bit\n__asan_init' if self.healthy else 'not found')
        if argv[-1] == '/tmp/smoke':
            return Execution(0, 'ok')
        if target == 'fix' and not self.fixed_crash:
            return Execution(0 if self.healthy else 127, 'done' if self.healthy else 'library missing')
        return Execution(1, CRASH if not self.leak else CRASH.replace('heap-buffer-overflow', 'detected memory leaks'))

    def push(self, target, source, destination):
        self.pushes.append((target, source, destination))


class OracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.poc = Path(self.temp.name) / 'poc'
        self.poc.write_bytes(b'private-regression')

    def tearDown(self):
        self.temp.cleanup()

    def test_pair_requires_both_differential_sides(self):
        result = check_pair(Engine(), {'vul': 'vul', 'fix': 'fix'}, self.poc, META)
        self.assertTrue(result['passed'])
        self.assertEqual(result['reward'], 1)

    def test_vulnerable_only_is_not_success(self):
        result = check_pair(Engine(fixed_crash=True), {'vul': 'vul', 'fix': 'fix'}, self.poc, META)
        self.assertFalse(result['passed'])
        self.assertEqual(result['failure_stage'], 'gold_differential')

    def test_exit_code_and_leak_are_not_crash_evidence(self):
        self.assertFalse(classify(Execution(1, 'assertion failed'), 'address').sanitizer_found)
        self.assertIsNotNone(classify(Execution(1, CRASH.replace('heap-buffer-overflow', 'detected memory leaks')),
                                      'address', require_vulnerable=True).execution_error)

    def test_missing_stack_or_broken_fixed_target_fails(self):
        self.assertIn('stack', classify(Execution(1, CRASH), 'address', 'another_function',
                                        require_vulnerable=True).execution_error)
        result = check_pair(Engine(healthy=False), {'vul': 'vul', 'fix': 'fix'}, self.poc, META)
        self.assertEqual(result['failure_stage'], 'environment_health')

    def test_missing_private_input_is_an_error(self):
        with self.assertRaises(OracleError):
            check_pair(Engine(), {'vul': 'vul', 'fix': 'fix'}, self.poc.parent / 'missing', META)


if __name__ == '__main__':
    unittest.main()
