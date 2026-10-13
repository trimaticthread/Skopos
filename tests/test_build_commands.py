"""Modül build_commands() golden testleri: üretilen argv'yi kilitler."""

import unittest

from skopos import config
from skopos.modules.nmap import NmapModule
from skopos.modules.subdomain import SubdomainModule
from skopos.modules.fuzzing import FuzzingModule


def _profile(name):
    return config.resolve_profile(config.load_config(), name)


class NmapBuildTest(unittest.TestCase):
    def test_normal_profile_argv(self):
        cfg = config.load_config()
        pcfg = _profile("normal")["nmap"]
        ctx = {"run_dir": "/tmp/run", "target": "10.10.10.5"}
        mod = NmapModule("10.10.10.5", pcfg, cfg, ctx)
        argv = mod.build_commands()[0].argv
        # temel iskelet
        self.assertEqual(argv[0], "nmap")
        self.assertIn("-sV", argv)
        self.assertIn("-Pn", argv)
        self.assertIn("-T4", argv)
        self.assertIn("--top-ports", argv)
        self.assertIn("1000", argv)
        self.assertIn("--script=default", argv)
        self.assertEqual(argv[-1], "10.10.10.5")
        self.assertIn("-oX", argv)

    def test_aggressive_full_scan_uses_dash_p(self):
        cfg = config.load_config()
        pcfg = _profile("aggressive")["nmap"]
        ctx = {"run_dir": "/tmp/run", "target": "t"}
        argv = NmapModule("t", pcfg, cfg, ctx).build_commands()[0].argv
        self.assertIn("-p-", argv)
        self.assertIn("-A", argv)

    def test_extra_args_escape_hatch_appended(self):
        cfg = config.load_config()
        pcfg = dict(_profile("normal")["nmap"])
        pcfg["extra_args"] = ["--min-rate", "5000"]
        ctx = {"run_dir": "/tmp/run", "target": "t"}
        argv = NmapModule("t", pcfg, cfg, ctx).build_commands()[0].argv
        self.assertIn("--min-rate", argv)
        self.assertIn("5000", argv)


class SubdomainBuildTest(unittest.TestCase):
    def test_ip_target_skipped(self):
        cfg = config.load_config()
        pcfg = _profile("normal")["subdomain"]
        mod = SubdomainModule("10.10.10.5", pcfg, cfg, {"target": "10.10.10.5"})
        self.assertEqual(mod.build_commands(), [])

    def test_domain_target_builds(self):
        cfg = config.load_config()
        pcfg = _profile("normal")["subdomain"]
        mod = SubdomainModule("example.com", pcfg, cfg, {"target": "example.com"})
        argv = mod.build_commands()[0].argv
        self.assertEqual(argv[0], "subfinder")
        self.assertIn("-d", argv)
        self.assertIn("example.com", argv)


class FuzzingBuildTest(unittest.TestCase):
    def test_derives_http_target_when_no_ctx(self):
        cfg = config.load_config()
        pcfg = _profile("normal")["fuzzing"]
        ctx = {"run_dir": "/tmp/run", "target": "site.com"}
        cmds = FuzzingModule("site.com", pcfg, cfg, ctx).build_commands()
        self.assertTrue(cmds)
        argv = cmds[0].argv
        self.assertIn("-u", argv)
        joined = " ".join(argv)
        self.assertIn("FUZZ", joined)


if __name__ == "__main__":
    unittest.main()
