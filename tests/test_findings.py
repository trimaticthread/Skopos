"""findings.build_suggestions karakterizasyon testleri."""

import unittest

from skopos import findings


def _texts(sugg):
    return " || ".join(s["text"] for s in sugg)


class SuggestionsTest(unittest.TestCase):
    def test_wordpress_web_asset_suggests_wpscan(self):
        summary = {
            "target": "10.0.0.1",
            "open_ports": [{"port": 80, "proto": "tcp", "service": "http"}],
            "web_assets": [{"host": "10.0.0.1", "url": "http://10.0.0.1",
                            "tech": ["WordPress"], "server": "Apache"}],
        }
        sugg = findings.build_suggestions(summary)
        blob = _texts(sugg)
        self.assertIn("WordPress", blob)
        self.assertTrue(any("wpscan" in (s.get("cmd") or "") for s in sugg))

    def test_ssh_port_suggests_version_check(self):
        summary = {
            "target": "10.0.0.1",
            "open_ports": [{"port": 22, "proto": "tcp", "service": "ssh",
                            "product": "OpenSSH", "version": "8.2"}],
        }
        blob = _texts(findings.build_suggestions(summary))
        self.assertIn("SSH", blob)

    def test_smb_ports_suggest_enum4linux(self):
        summary = {
            "target": "10.0.0.1",
            "open_ports": [{"port": 445, "proto": "tcp", "service": "microsoft-ds"}],
        }
        sugg = findings.build_suggestions(summary)
        self.assertTrue(any("enum4linux" in (s.get("cmd") or "") for s in sugg))

    def test_ad_ports_suggest_bloodhound(self):
        summary = {
            "target": "dc.corp.local",
            "open_ports": [{"port": 88, "proto": "tcp", "service": "kerberos"},
                           {"port": 389, "proto": "tcp", "service": "ldap"}],
        }
        self.assertIn("bloodhound", _texts(findings.build_suggestions(summary)).lower())

    def test_empty_summary_has_fallback(self):
        sugg = findings.build_suggestions({"target": "10.0.0.1", "open_ports": []})
        self.assertEqual(len(sugg), 1)

    def test_url_target_without_ports_still_suggests_web(self):
        summary = {"target": "http://site.com", "open_ports": [], "web_assets": []}
        self.assertTrue(len(findings.build_suggestions(summary)) >= 1)


if __name__ == "__main__":
    unittest.main()
