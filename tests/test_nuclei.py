"""nuclei modülü: komut üretimi, JSONL parse ve Finding entegrasyonu."""

import json
import os
import tempfile
import unittest

from skopos import config
from skopos.core import finding
from skopos.modules.nuclei import NucleiModule


class NucleiBuildTest(unittest.TestCase):
    def setUp(self):
        self.run_dir = tempfile.mkdtemp(prefix="skopos_nuclei_")
        self.cfg = config.load_config()
        self.pcfg = self.cfg["profiles"]["normal"]["nuclei"]

    def _mod(self, ctx):
        return NucleiModule(ctx.get("target", "t"), self.pcfg, self.cfg, ctx)

    def test_build_uses_web_targets_and_writes_file(self):
        ctx = {"run_dir": self.run_dir, "target": "t",
               "web_targets": ["http://a", "http://b", "http://a"]}
        cmd = self._mod(ctx).build_commands()[0]
        self.assertEqual(cmd.argv[0], "nuclei")
        self.assertIn("-l", cmd.argv)
        self.assertIn("-jsonl", cmd.argv)
        self.assertIn("-severity", cmd.argv)
        tf = os.path.join(self.run_dir, "nuclei_targets.txt")
        self.assertTrue(os.path.exists(tf))
        with open(tf, encoding="utf-8") as fh:
            lines = fh.read().split()
        self.assertEqual(lines, ["http://a", "http://b"])  # tekilleştirilmiş

    def test_build_falls_back_to_raw_target(self):
        ctx = {"run_dir": self.run_dir, "target": "10.0.0.1"}
        cmd = self._mod(ctx).build_commands()[0]
        tf = os.path.join(self.run_dir, "nuclei_targets.txt")
        with open(tf, encoding="utf-8") as fh:
            self.assertIn("http://10.0.0.1", fh.read())
        self.assertIn("-l", cmd.argv)

    def test_post_process_parses_jsonl(self):
        ctx = {"run_dir": self.run_dir, "target": "t"}
        with open(os.path.join(self.run_dir, "nuclei.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"template-id": "tls-version",
                                 "info": {"name": "TLS 1.0", "severity": "low",
                                          "tags": ["tls"], "reference": ["https://x"]},
                                 "matched-at": "https://a:443"}) + "\n")
            fh.write(json.dumps({"template-id": "cve-2021-1",
                                 "info": {"name": "RCE", "severity": "critical"},
                                 "host": "http://a"}) + "\n")
            fh.write("\n")  # boş satır tolere edilmeli
        mod = self._mod(ctx)
        mod.post_process([])
        items = mod.ctx["nuclei"]
        self.assertEqual(len(items), 2)
        self.assertIn("critical", {it["severity"] for it in items})


class NucleiFindingTest(unittest.TestCase):
    def test_nuclei_findings_carry_real_severity(self):
        summary = {"target": "t", "nuclei": [
            {"name": "RCE", "severity": "critical", "matched": "http://a",
             "template": "cve", "tags": ["rce"], "refs": ["https://x"]},
            {"name": "Info leak", "severity": "info", "matched": "http://a"},
        ]}
        fs = finding.build_findings(summary)
        vulns = [f for f in fs if f["source"] == "nuclei"]
        self.assertEqual(len(vulns), 2)
        crit = next(f for f in vulns if f["title"] == "RCE")
        self.assertEqual(crit["severity"], "critical")
        self.assertEqual(crit["category"], "vuln")
        self.assertIn("https://x", crit["refs"])
        # kritik bulgu severity sıralamasında en üstte olmalı
        self.assertEqual(fs[0]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
