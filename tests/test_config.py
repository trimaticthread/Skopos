"""config.py: yükleme, profil çözümleme, deep-merge karakterizasyon testleri."""

import unittest

from skopos import config


class DeepMergeTest(unittest.TestCase):
    def test_nested_override_merges(self):
        base = {"a": {"x": 1, "y": 2}, "b": 3}
        over = {"a": {"y": 20, "z": 30}}
        res = config._deep_merge(base, over)
        self.assertEqual(res, {"a": {"x": 1, "y": 20, "z": 30}, "b": 3})

    def test_base_not_mutated(self):
        base = {"a": {"x": 1}}
        config._deep_merge(base, {"a": {"x": 99}})
        self.assertEqual(base["a"]["x"], 1)


class LoadConfigTest(unittest.TestCase):
    def test_default_profiles_present(self):
        cfg = config.load_config()
        self.assertIn("profiles", cfg)
        for name in ("stealth", "normal", "aggressive"):
            self.assertIn(name, cfg["profiles"])

    def test_resolve_profile_normal(self):
        cfg = config.load_config()
        prof = config.resolve_profile(cfg, "normal")
        self.assertIn("nmap", prof)
        self.assertEqual(prof["nmap"]["timing"], 4)

    def test_resolve_unknown_profile_raises(self):
        cfg = config.load_config()
        with self.assertRaises(ValueError):
            config.resolve_profile(cfg, "does-not-exist")

    def test_general_defaults(self):
        cfg = config.load_config()
        self.assertEqual(cfg["general"]["default_profile"], "normal")


if __name__ == "__main__":
    unittest.main()
