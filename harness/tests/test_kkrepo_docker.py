import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

MODULE = Path(__file__).parents[1] / 'agent_image' / 'docker-kkrepo'
SPEC = importlib.util.spec_from_loader('docker_kkrepo', importlib.machinery.SourceFileLoader('docker_kkrepo', str(MODULE)))
docker_kkrepo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(docker_kkrepo)


class KkRepoDockerTests(unittest.TestCase):
    def test_official_short_image_gets_library_namespace(self):
        self.assertEqual(docker_kkrepo.mapped_name('python:3.11-slim'),
                         '100.102.49.114:19091/docker-hub/library/python:3.11-slim')

    def test_named_user_repository_is_preserved(self):
        self.assertEqual(docker_kkrepo.mapped_name('library/python:3.11'),
                         '100.102.49.114:19091/docker-hub/library/python:3.11')

    def test_build_digest_tags_verified_local_name_without_digest(self):
        calls = []
        pinned = 'docker:28.5.2-dind@sha256:' + 'a' * 64
        mirrored = '100.102.49.114:19091/docker-hub/library/' + pinned
        original_prepare = docker_kkrepo.prepare_dockerfile
        original_exec = docker_kkrepo.os.execv
        try:
            docker_kkrepo.prepare_dockerfile = lambda path: calls.append(['prepare', str(path)])
            def record(args, **kwargs):
                calls.append(args)
                return mock.Mock(returncode=0 if args[0] == 'pull' else 1, stdout='[]')
            docker_kkrepo.run = record
            docker_kkrepo.os.execv = lambda path, args: None
            with tempfile.TemporaryDirectory() as directory:
                dockerfile = Path(directory) / 'Dockerfile'
                dockerfile.write_text('FROM ' + pinned + '\n')
                docker_kkrepo.build(['build', '--pull=false', '--file', str(dockerfile), '.'])
                self.assertEqual(calls, [['prepare', str(dockerfile)]])
                original_prepare(dockerfile)
                self.assertEqual(calls[1], ['image', 'inspect', pinned])
                self.assertEqual(calls[2], ['info', '--format', '{{json .RegistryConfig.Mirrors}}'])
                self.assertEqual(calls[3], ['image', 'inspect', mirrored])
                self.assertEqual(calls[4], ['pull', mirrored])
                self.assertEqual(calls[5], ['tag', mirrored, pinned.split('@')[0]])
        finally:
            docker_kkrepo.prepare_dockerfile = original_prepare
            docker_kkrepo.os.execv = original_exec

    def test_compose_build_without_dockerfile_uses_context_default(self):
        with tempfile.TemporaryDirectory() as directory:
            context = Path(directory) / 'mysql'
            context.mkdir()
            dockerfile = context / 'Dockerfile'
            dockerfile.write_text('FROM mysql:5.7\n')
            original = dockerfile.read_bytes()
            config = {'services': {'db': {'build': {'context': str(context)}}}}
            response = mock.Mock(returncode=0, stdout=__import__('json').dumps(config), stderr='')
            with (mock.patch.object(docker_kkrepo.subprocess, 'run', return_value=response),
                  mock.patch.object(docker_kkrepo, 'prepare_dockerfile') as prepare,
                  mock.patch.object(docker_kkrepo.os, 'execv')):
                docker_kkrepo.compose(['compose', '-f', str(Path(directory) / 'docker-compose.yaml'),
                                       'build', '--no-cache'])
            prepare.assert_called_once_with(dockerfile)
            self.assertEqual(dockerfile.read_bytes(), original)

    def test_third_party_registry_is_never_rewritten(self):
        for image in ('ghcr.io/org/image:v1', 'localhost:5000/app:v1'):
            self.assertFalse(docker_kkrepo.original_name(image))
            self.assertEqual(docker_kkrepo.mapped_name(image), image)


if __name__ == '__main__':
    unittest.main()
