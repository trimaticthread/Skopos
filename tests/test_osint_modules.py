"""OSINT/native modüller (probe, crtsh) ve native modül altyapısı testleri.

Ağ gerektiren yollar test edilmez; yalnızca aday toplama / atlama / kayıt
mantığı doğrulanır."""

import unittest

from skopos.module_base import BaseModule
from skopos.modules.probe import ProbeModule
from skopos.modules.crtsh import CrtShModule, _domain_of
from skopos.runner import discover_modules


class BaseNativeExtTest(unittest.TestCase):
    def test_build_commands_defaults_empty_and_native_hooks(self):
        class M(BaseModule):
            name = "m"
        m = M("t", {}, {}, {})
        self.assertEqual(m.build_commands(), [])
        self.assertIsNone(m.native_run())
        self.assertFalse(m.native)


class ProbeCandidatesTest(unittest.TestCase):
    def _mod(self, target, ctx, pcfg=None):
        return ProbeModule(target, pcfg or {}, {}, ctx)

    def test_dedup_and_trailing_slash(self):
        ctx = {"web_targets": ["http://a/", "http://a", "http://b"], "target": "a"}
        self.assertEqual(self._mod("a", ctx)._candidates(), ["http://a", "http://b"])

    def test_subdomains_expanded_http_and_https(self):
        ctx = {"subdomains": ["dev.x.com"], "target": "x.com"}
        c = self._mod("x.com", ctx)._candidates()
        self.assertIn("http://dev.x.com", c)
        self.assertIn("https://dev.x.com", c)

    def test_raw_ip_target_used_when_no_web_targets(self):
        ctx = {"target": "10.0.0.1"}
        self.assertEqual(self._mod("10.0.0.1", ctx)._candidates(), ["http://10.0.0.1"])

    def test_max_hosts_cap(self):
        ctx = {"web_targets": [f"http://h{i}" for i in range(100)]}
        c = self._mod("t", ctx, {"max_hosts": 5})._candidates()
        self.assertEqual(len(c), 5)

    def test_is_native(self):
        self.assertTrue(ProbeModule.native)


class CrtShTest(unittest.TestCase):
    def test_domain_of(self):
        self.assertEqual(_domain_of("http://a.com:80/x"), "a.com")
        self.assertIsNone(_domain_of("10.0.0.1"))

    def test_ip_target_skips_without_network(self):
        m = CrtShModule("10.0.0.1", {}, {}, {"target": "10.0.0.1", "run_dir": "."})
        self.assertIsNone(m.native_run())  # ağ çağrısı yapmadan döner

    def test_is_native(self):
        self.assertTrue(CrtShModule.native)


class DnsTest(unittest.TestCase):
    def _mod(self, target):
        from skopos.modules.dns import DnsModule
        return DnsModule(target, {}, {}, {"target": target, "run_dir": "."})

    def test_ip_target_builds_no_commands(self):
        self.assertEqual(self._mod("10.0.0.1").build_commands(), [])

    def test_domain_builds_one_cmd_per_record_type(self):
        from skopos.modules.dns import _TYPES
        cmds = self._mod("example.com").build_commands()
        self.assertEqual(len(cmds), len(_TYPES))
        self.assertEqual(cmds[0].argv[0], "dig")
        self.assertIn("example.com", cmds[0].argv)

    def test_post_process_parses_records(self):
        from skopos.module_base import Command
        mod = self._mod("example.com")
        results = [
            (Command(label="a", argv=[]), 0, "93.184.216.34\n"),
            (Command(label="mx", argv=[]), 0, "0 .\n"),
            (Command(label="ns", argv=[]), 0, ";; comment\na.iana-servers.net.\n"),
        ]
        mod.post_process(results)
        dns = mod.ctx["dns"]
        self.assertEqual(dns["A"], ["93.184.216.34"])
        self.assertIn("a.iana-servers.net.", dns["NS"])


class RegistryTest(unittest.TestCase):
    def test_all_modules_registered(self):
        reg = discover_modules()
        for n in ("nmap", "subdomain", "fuzzing", "web", "bloodhound",
                  "probe", "crtsh", "dns"):
            self.assertIn(n, reg)


if __name__ == "__main__":
    unittest.main()
