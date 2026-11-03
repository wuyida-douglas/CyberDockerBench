from __future__ import annotations

import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.cybergym_pipeline.prepare.audit import audit_reference, audit_task, audit_tree
from harness.cybergym_pipeline.prepare.materialize import (
    INSTRUCTION, discover_timestamps, parse_sanitizer, sanitize_cleaning_report,
    sanitize_public_provenance,
)
from harness.cybergym_pipeline.prepare.reference_materialize import ANSI
from harness.cybergym_pipeline.prepare.source_export import stream_source
from harness.cybergym_pipeline.prepare.verify import (
    crash_type_observed,
    pull_reference,
    sanitizer_observed,
    stack_observed,
    verify_task,
)


class PrepareAuditTest(unittest.TestCase):
    def test_networking_is_part_of_task_contract(self):
        self.assertIn('/opt/cdb-network-plugin/skills/kkrepo-network/SKILL.md', INSTRUCTION)
        self.assertIn('## Network scope and historical-build constraints', INSTRUCTION)
        self.assertNotIn('NETWORKING.md', INSTRUCTION)
        self.assertNotIn('100.102.49.114:19091', INSTRUCTION)

    def test_sanitizer_aliases(self):
        self.assertEqual(parse_sanitizer("ubsan"), ("UBSan", "undefined"))
        self.assertEqual(parse_sanitizer("msan"), ("MSan", "memory"))

    def test_srcmap_revisions_are_not_placeholder(self):
        upstream = {"report": {"comments": [{"content": (
            "Regressed: https://oss-fuzz.com/revisions?job=x&range=201701020304:201701020305\\n"
            "Fixed: https://oss-fuzz.com/revisions?job=x&range=201701030405:201701030406\\n"
        )}]}}
        self.assertEqual(discover_timestamps(upstream), ("201701020305", "201701030406"))

    def test_archive_leaks_and_nested_gold_poc_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "main.c").write_text("int main(void) { return 0; }\n")
            with tarfile.open(root / "sources-vul.tar.gz", "w:gz") as archive:
                def add(name, data):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
                add("src-vul/main.c", b"int main(void) { return 0; }\n")
                add("src-vul/.git/config", b"[core]\n")
                add("src-vul/out/fuzzer", b"\x7fELF\0\0\0")
                add("src-vul/poc", b"private marker")
            (root / "normal.txt").write_text("n132/arvo:123-vul\n")
            issues = audit_tree(root)["issues"]
            self.assertTrue(any(".git" in issue for issue in issues))
            self.assertTrue(any("executable content" in issue for issue in issues))
            self.assertTrue(any("PoC-like" in issue for issue in issues))
            self.assertTrue(any("official_reference_image" in issue for issue in issues))

    def test_public_root_poc_is_a_deliberate_task_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "poc").write_bytes(b"genuine public reproducer")
            (root / "nested").mkdir()
            (root / "nested" / "poc").write_bytes(b"unexpected extra reproducer")
            issues = audit_tree(root)["issues"]
            self.assertNotIn("public input PoC-like name: poc", issues)
            self.assertIn("public input PoC-like name: nested/poc", issues)

    def test_unverified_task_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            task = Path(temporary) / "cybergym-arvo-1"
            (task / "input").mkdir(parents=True)
            (task / "metadata.yaml").write_text(
                "family: cybergym\ntask_type: binary-env-synthesis\n"
                "project: x\nupstream_task_id: arvo:1\nsanitizer: ASan\n"
                "fuzz_target: fuzz\ncrash_type: Heap-buffer-overflow\n"
                "expected_stack: [frame]\nreference_verified: true\n"
                "private: {gold_poc: gold/poc, reference_manifest: gold/reference-manifest.json}\n"
            )
            report = audit_task(task)
            self.assertFalse(report["passed"])
            self.assertTrue(any("missing public input" in item for item in report["issues"]))
            self.assertTrue(any("evidence missing" in item for item in report["issues"]))


class SourceExportTest(unittest.TestCase):
    def test_cached_cleaning_evidence_removes_private_provenance(self):
        report = {"kept_files": 12, "source_export_evidence": {
            "reference": "n132/arvo:123-vul",
            "private_extraction_log_directory": "/mnt/shared-storage-gpfs2/private/cyberdockerbench",
            "transport": {"kept_files": 12, "log": "/private/copy.log"},
        }}
        sanitized = sanitize_cleaning_report(report)
        self.assertEqual(sanitized, {"kept_files": 12})

    def test_public_sanitizer_refreshes_manifest_not_gold(self):
        with tempfile.TemporaryDirectory() as temporary:
            task = Path(temporary)
            public = task / "input"
            public.mkdir()
            report = {"kept_files": 1, "source_export_evidence": {
                "reference": "n132/arvo:123-fix",
                "transport": {"log": "/mnt/shared-storage-gpfs2/private/cyberdockerbench/log"},
            }}
            path = public / "cleaning-fix.json"
            path.write_text(json.dumps(report))
            manifest = public / "manifest.json"
            manifest.write_text(json.dumps({"files": {
                "cleaning-fix.json": {"sha256": "stale", "bytes": 0}}}))
            (task / "gold").mkdir()
            (task / "gold" / "verify_reference.json").write_text('{"passed": true}\n')
            self.assertEqual(sanitize_public_provenance(task), ["cleaning-fix.json"])
            self.assertNotIn(b"n132/arvo", path.read_bytes())
            entry = json.loads(manifest.read_text())["files"]["cleaning-fix.json"]
            import hashlib
            self.assertEqual(entry["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(entry["bytes"], path.stat().st_size)
            self.assertEqual(json.loads((task / "gold" / "verify_reference.json").read_text()), {"passed": True})

    def test_both_docker_cp_root_layouts_are_cleaned(self):
        import re
        for prefix in ("./", "src/"):
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                transport = root / "transport.tar"
                with tarfile.open(transport, "w") as archive:
                    for name, data in ((".git/config", b"[core]\n"),
                                       ("Dockerfile", b"FROM n132/arvo:1-vul\n"),
                                       ("project/main.c", b"int main(void) { return 0; }\n"),
                                       ("project/link", b"target"),
                                       ("out/fuzzer", b"\x7fELF\0\0")):
                        member = tarfile.TarInfo(prefix + name)
                        member.size = len(data)
                        if name.endswith("/link"):
                            member.type = tarfile.SYMTYPE
                            member.linkname = "main.c"
                            archive.addfile(member)
                        else:
                            archive.addfile(member, io.BytesIO(data))
                def fake_popen(command, stdout=None, stderr=None):
                    del command, stdout, stderr
                    class Process:
                        def __init__(self):
                            self.stdout = transport.open("rb")
                        def __del__(self):
                            self.stdout.close()
                        stderr = io.BytesIO(b"")
                        def wait(self, timeout=None): return 0
                        def poll(self): return 0
                        def kill(self): pass
                    return Process()
                with patch("harness.cybergym_pipeline.prepare.source_export.subprocess.Popen", fake_popen):
                    stream_source(["docker"], "unused", root / "sources.tar.gz", root / "copy.log")
                with tarfile.open(root / "sources.tar.gz") as archive:
                    self.assertEqual([member.name for member in archive.getmembers()],
                                     ["src/project/main.c"])
                self.assertTrue(ANSI.sub("", "pcre2_fuzzer"))
                self.assertEqual(ANSI.sub("", "^[[A^[[Bpcre2_fuzzer"), "pcre2_fuzzer")


class ReferenceVerificationTest(unittest.TestCase):
    def test_diagnostic_matching(self):
        output = "SUMMARY: AddressSanitizer: heap-buffer-overflow READ 1\n #0 in parse_header /src/x.c:2\n"
        self.assertTrue(sanitizer_observed(output, "ASan"))
        self.assertTrue(crash_type_observed(output, "Heap-buffer-overflow READ 1"))
        self.assertEqual(stack_observed(output, ["parse_header", "not_here"]), {"parse_header": True, "not_here": False})
        self.assertFalse(sanitizer_observed(output, "MSan"))
        self.assertTrue(crash_type_observed("index -1 out of bounds for type 'VLC [15]'", "Index-out-of-bounds"))
        self.assertFalse(crash_type_observed("out of memory", "Index-out-of-bounds"))

    def test_reference_audit_rechecks_logs_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            task = Path(temporary).resolve() / 'cybergym-arvo-1'
            logs = task / 'gold' / 'reference-logs'
            logs.mkdir(parents=True)
            poc = task / 'gold' / 'poc'
            poc.write_bytes(b'private gold')
            (logs / 'vul.log').write_text(
                'SUMMARY: AddressSanitizer: heap-buffer-overflow READ 1\n #0 in parse_header /src/x.c:2\n')
            (logs / 'fix.log').write_text('normal execution\n')
            metadata = {'upstream_task_id': 'arvo:1', 'sanitizer': 'ASan',
                        'crash_type': 'heap-buffer-overflow', 'expected_stack': ['parse_header']}
            import hashlib
            import shlex
            digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            evidence = {'passed': True, 'reference_verified': True,
                        'upstream_task_id': 'arvo:1', 'gold_poc_sha256': digest(poc), 'images': {}, 'runs': {}}
            for role in ('vul', 'fix'):
                image = f'n132/arvo:1-{role}'
                evidence['images'][role] = {'image': image, 'rootfs_layers': ['sha256:' + 'a' * 64]}
                command = ['ssh', '-o', 'BatchMode=yes', 'root@worker',
                           f'docker run --rm --network none -v {poc}:/tmp/poc:ro {image} arvo']
                evidence['runs'][role] = {
                    'passed': True, 'command': command, 'command_text': shlex.join(command),
                    'digest': 'sha256:' + 'a' * 64, 'log': f'{role}.log',
                    'log_sha256': digest(logs / f'{role}.log'), 'timed_out': False,
                    'return_code': 1 if role == 'vul' else 0,
                }
            legacy = command[:-1] + shlex.split(command[-1])
            evidence['runs']['fix']['command'] = legacy
            evidence['runs']['fix']['command_text'] = shlex.join(legacy)
            self.assertEqual(audit_reference(task, metadata, evidence), [])
            (logs / 'fix.log').write_text('fixed crash\nSUMMARY: AddressSanitizer: heap-buffer-overflow\n')
            evidence['runs']['fix']['log_sha256'] = digest(logs / 'fix.log')
            errors = audit_reference(task, metadata, evidence)
            self.assertIn('fixed reference log contains an unexpected sanitizer report', errors)
            evidence['runs']['fix']['return_code'] = 2
            self.assertIn('fixed reference did not exit normally with code 0',
                          audit_reference(task, metadata, evidence))

    def test_reference_command_records_exact_worker_docker_invocation(self):
        from types import SimpleNamespace
        from harness.cybergym_pipeline.prepare.verify import run_reference
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            poc = root / 'poc'
            poc.write_bytes(b'gold')
            def execute(command, log, timeout=1800, extra_env=None):
                Path(log).write_text('SUMMARY: AddressSanitizer: heap-buffer-overflow\n#0 in parse_header\n')
                import shlex
                return {'command': command, 'command_text': shlex.join(command),
                        'return_code': 1, 'timed_out': False}
            with patch('harness.cybergym_pipeline.prepare.verify.command_result', side_effect=execute) as run:
                result = run_reference('n132/arvo:1-vul', 'vul', poc, 'root@worker', root,
                                       {'sanitizer': 'ASan', 'crash_type': 'heap-buffer-overflow',
                                        'expected_stack': ['parse_header']}, 60)
            remote = run.call_args.args[0]
            self.assertEqual(remote[0], 'ssh')
            self.assertIn('docker run --rm --network none', remote[-1])
            self.assertIn(':/tmp/poc:ro', remote[-1])
            self.assertEqual(result['command'], remote)
            self.assertEqual(run.call_count, 1)
            self.assertTrue(result['passed'])

    def test_worker_transport_uses_save_load_and_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = "n132/arvo:1513-vul"
            inspect_value = json.dumps(["n132/arvo@sha256:" + "a" * 64]) + " sha256:" + "b" * 64 + "\n"
            local = subprocess.CompletedProcess([], 0, stdout=inspect_value, stderr="")
            remote = subprocess.CompletedProcess([], 1, stdout="", stderr="")

            inspections = []

            def fake_inspect(ref, worker):
                inspections.append(worker)
                if worker and inspections.count(worker) <= 1 + 4:
                    raise subprocess.CalledProcessError(1, "inspect")
                return {"image": ref, "config_id": "sha256:" + "b" * 64,
                        "repo_digests": ["n132/arvo@sha256:" + "a" * 64], "digest": "sha256:" + "a" * 64,
                        "rootfs_layers": ["sha256:" + "c" * 64],
                        "runtime_identity_sha256": "d" * 64}

            def fake_command(command, log, timeout=1800, extra_env=None):
                Path(log).write_text("ok\n")
                if command[:2] == ["docker", "save"]:
                    Path(command[3]).write_bytes(b"private image archive")
                if command[:1] == ["ssh"] and "load" in command:
                    archive = command[command.index("load") + 2]
                    Path(archive).write_bytes(b"private image archive")
                return {"command": command, "return_code": 0, "log": Path(log).name}

            with patch("harness.cybergym_pipeline.prepare.verify.reference_digest", side_effect=fake_inspect), \
                 patch("harness.cybergym_pipeline.prepare.verify.command_result", side_effect=fake_command), \
                 patch("harness.cybergym_pipeline.prepare.verify.subprocess.run", side_effect=[local, remote]):
                result = pull_reference(image, "root@worker", root, root)
            self.assertEqual(result["transport"], "docker_save_docker_load_gpfs2")
            self.assertEqual(result["expected_repo_digest"], "sha256:" + "a" * 64)
            self.assertTrue((root / "1513-vul.tar.sha256").is_file())


if __name__ == "__main__":
    unittest.main()
