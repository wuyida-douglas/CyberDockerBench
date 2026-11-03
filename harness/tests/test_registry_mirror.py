"""The three benches use kkRepo; the legacy Hub cache is opt-in."""
import unittest

from harness.registry_mirror import apply_mirror, mirror_url


class RegistryMirrorTests(unittest.TestCase):
    def test_default_has_no_legacy_cache(self):
        self.assertEqual(mirror_url({}), "")
        config = {}
        self.assertEqual(apply_mirror(config, {}), "")
        self.assertNotIn("registry-mirrors", config)
        self.assertEqual(config["insecure-registries"], ["100.102.49.114:19091"])

    def test_explicit_mirror_wins_over_the_public_list(self):
        env = {
            "CDB_REGISTRY_MIRROR": "http://10.1.2.3:5000",
            "CDB_REGISTRY_MIRRORS": "https://docker.1ms.run,https://docker.m.daocloud.io",
        }
        config = {}
        self.assertEqual(apply_mirror(config, env), "http://10.1.2.3:5000")
        self.assertEqual(config["registry-mirrors"], ["http://10.1.2.3:5000"])
        self.assertEqual(config["insecure-registries"], ["10.1.2.3:5000", "100.102.49.114:19091"])

    def test_worker_address_change_follows_cdb_worker(self):
        self.assertEqual(
            mirror_url({"CDB_ENABLE_HUB_CACHE": "1", "CDB_WORKER": "root@10.9.9.9"}),
            "http://10.9.9.9:5000")


if __name__ == "__main__":
    unittest.main()
