"""core.finding: birleşik bulgu modeli testleri."""

import unittest

from skopos.core import finding
from skopos.core.finding import Finding, Severity, severity_rank


class FindingTest(unittest.TestCase):
    def test_auto_id_is_stable_and_dedupes(self):
        a = Finding(title="x", category="port", source="nmap", target="t",
                    data={"port": 80})
        b = Finding(title="x", category="port", source="nmap", target="t",
                    data={"port": 80})
        c = Finding(title="x", category="port", source="nmap", target="t",
                    data={"port": 81})
        self.assertEqual(a.id, b.id)
        self.assertNotEqual(a.id, c.id)

    def test_enum_severity_coerced_to_str(self):
        f = Finding(title="x", severity=Severity.HIGH)
        self.assertEqual(f.severity, "high")
        self.assertIsInstance(f.to_dict()["severity"], str)

    def test_severity_rank_ordering(self):
        self.assertLess(severity_rank("info"), severity_rank("medium"))
        self.assertLess(severity_rank("medium"), severity_rank("critical"))
        self.assertEqual(severity_rank("bogus"), 0)


class BuildFindingsTest(unittest.TestCase):
    def setUp(self):
        self.summary = {
            "target": "10.10.10.5",
            "open_ports": [
                {"port": 22, "proto": "tcp", "service": "ssh",
                 "product": "OpenSSH", "version": "8.2"},
                {"port": 445, "proto": "tcp", "service": "microsoft-ds"},
            ],
            "web_assets": [
                {"url": "http://10.10.10.5", "tech": ["nginx"], "server": "nginx",
                 "title": "Home", "host": "10.10.10.5", "port": 80},
            ],
            "subdomains": ["dev.site.com"],
            "os": ["Ubuntu"],
            "scripts": [{"port": 80, "id": "http-title", "output": "Home"}],
            "key_findings": {
                "ffuf_dirs": [{"url": "http://t/admin", "status": 200, "length": 10,
                               "input": "admin"}],
                "ffuf_apis": [{"url": "http://t/api", "status": 200, "length": 5,
                               "input": "api"}],
                "nikto": ["/admin/ login page"],
                "nikto_caveat": False,
            },
        }

    def test_findings_built_for_each_category(self):
        fs = finding.build_findings(self.summary)
        cats = {f["category"] for f in fs}
        self.assertTrue({"port", "web", "content", "vuln", "subdomain", "host",
                         "script"}.issubset(cats))

    def test_smb_port_is_low_ssh_is_info(self):
        fs = finding.build_findings(self.summary)
        smb = next(f for f in fs if f["data"].get("port") == 445)
        ssh = next(f for f in fs if f["data"].get("port") == 22)
        self.assertEqual(smb["severity"], "low")
        self.assertEqual(ssh["severity"], "info")

    def test_api_finding_is_medium(self):
        fs = finding.build_findings(self.summary)
        api = next(f for f in fs if "API" in f["title"])
        self.assertEqual(api["severity"], "medium")

    def test_nikto_caveat_downgrades_to_low(self):
        self.summary["key_findings"]["nikto_caveat"] = True
        fs = finding.build_findings(self.summary)
        nk = next(f for f in fs if f["source"] == "web/nikto")
        self.assertEqual(nk["severity"], "low")
        self.assertIn("spa-caveat", nk["tags"])

    def test_sorted_by_severity_desc(self):
        fs = finding.build_findings(self.summary)
        ranks = [severity_rank(f["severity"]) for f in fs]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_severity_counts(self):
        fs = finding.build_findings(self.summary)
        counts = finding.severity_counts(fs)
        self.assertEqual(sum(counts.values()), len(fs))
        self.assertIn("medium", counts)


if __name__ == "__main__":
    unittest.main()
