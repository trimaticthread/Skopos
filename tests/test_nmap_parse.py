"""nmap modülü XML parse (post_process) karakterizasyon testi."""

import os
import tempfile
import unittest

from skopos.modules.nmap import NmapModule

_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host>
  <address addr="10.10.10.5" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu Linux"/>
      <script id="ssh-hostkey" output="2048 aa:bb:cc:dd ssh-rsa"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="nginx" version="1.18.0"/>
      <script id="http-title" output="Welcome to Example"/>
    </port>
    <port protocol="tcp" portid="3306">
      <state state="closed"/>
      <service name="mysql"/>
    </port>
  </ports>
  <os><osmatch name="Linux 5.4" accuracy="95"/></os>
</host>
</nmaprun>
"""


class NmapParseTest(unittest.TestCase):
    def setUp(self):
        self.run_dir = tempfile.mkdtemp(prefix="skopos_nmap_")
        with open(os.path.join(self.run_dir, "nmap.xml"), "w", encoding="utf-8") as fh:
            fh.write(_SAMPLE_XML)
        self.ctx = {"run_dir": self.run_dir, "target": "10.10.10.5"}
        self.mod = NmapModule("10.10.10.5", {}, {}, self.ctx)

    def test_open_ports_extracted_closed_skipped(self):
        self.mod.post_process([])
        ports = {p["port"] for p in self.ctx["open_ports"]}
        self.assertEqual(ports, {22, 80})
        self.assertNotIn(3306, ports)

    def test_web_asset_detected_on_port_80(self):
        self.mod.post_process([])
        urls = {wa["url"] for wa in self.ctx["web_assets"]}
        self.assertIn("http://10.10.10.5:80", urls)

    def test_os_hints_from_osmatch_and_extrainfo(self):
        self.mod.post_process([])
        os_hints = set(self.ctx.get("os", []))
        self.assertIn("Linux 5.4", os_hints)
        self.assertIn("Ubuntu", os_hints)

    def test_ssh_hostkey_captured(self):
        self.mod.post_process([])
        keys = self.ctx.get("host_info", {}).get("ssh_hostkeys", [])
        self.assertTrue(any("ssh-rsa" in k for k in keys))

    def test_service_product_version_on_ssh(self):
        self.mod.post_process([])
        ssh = next(p for p in self.ctx["open_ports"] if p["port"] == 22)
        self.assertEqual(ssh["service"], "ssh")
        self.assertEqual(ssh["product"], "OpenSSH")


if __name__ == "__main__":
    unittest.main()
