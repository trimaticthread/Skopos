"""Nmap modülü: port/servis taraması + açık portların çözümlenmesi."""

import os
import xml.etree.ElementTree as ET

from ..module_base import BaseModule, Command, register
from .. import utils

# Web servisi kabul edilecek servis adları / portlar (web modülüne aktarılır)
_WEB_SERVICES = {"http", "https", "http-proxy", "https-alt", "http-alt"}
_WEB_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888}


@register
class NmapModule(BaseModule):
    name = "nmap"
    description = "Port ve servis/versiyon taraması (nmap)"
    requires = ["nmap"]

    def _xml_path(self):
        return os.path.join(self.ctx["run_dir"], "nmap.xml")

    def build_commands(self):
        binary = self.module_settings().get("binary", "nmap")
        p = self.pcfg

        argv = [binary, "-sV", "-Pn"]                      # servis tespiti, ping atlama
        argv += [f"-T{p.get('timing', 3)}"]
        argv += ["--version-intensity", str(p.get("version_intensity", 5))]

        # Port aralığı: full_scan > top_ports
        if p.get("full_scan"):
            argv.append("-p-")
        elif p.get("top_ports"):
            argv += ["--top-ports", str(p["top_ports"])]

        # NSE script kategorileri
        scripts = p.get("scripts") or []
        if scripts:
            argv += ["--script=" + ",".join(scripts)]

        # Profil'e özel ekstra flag'ler (ör. aggressive -> -A)
        argv += p.get("extra_flags") or []

        # Kullanıcının ham ekstra parametreleri (kaçış kapısı)
        argv += self.extra_args()

        # XML çıktısı (parse için) + normal çıktı ekrana akar
        argv += ["-oX", self._xml_path()]
        argv.append(self.target)

        return [Command(label="portscan", argv=argv)]

    def post_process(self, results):
        """XML'i parse edip açık portları ctx'e yazar; web hedeflerini türetir."""
        xml_path = self._xml_path()
        if not os.path.exists(xml_path):
            return

        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError:
            utils.warn("nmap XML çıktısı parse edilemedi.")
            return

        open_ports = []
        web_targets = []
        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else self.target
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = int(port.get("portid"))
                proto = port.get("protocol")
                svc_el = port.find("service")
                svc = svc_el.get("name", "") if svc_el is not None else ""
                product = svc_el.get("product", "") if svc_el is not None else ""

                open_ports.append(
                    {"host": addr, "port": portid, "proto": proto,
                     "service": svc, "product": product}
                )

                # Web servisi mi? -> web modülü için hedef üret
                if svc in _WEB_SERVICES or portid in _WEB_PORTS:
                    scheme = "https" if ("https" in svc or portid in (443, 8443)) else "http"
                    web_targets.append(f"{scheme}://{addr}:{portid}")

        self.ctx.setdefault("open_ports", []).extend(open_ports)
        self.ctx.setdefault("web_targets", []).extend(web_targets)

        if open_ports:
            utils.good(f"{len(open_ports)} açık port bulundu.")
            for op in open_ports:
                extra = f" ({op['product']})" if op["product"] else ""
                utils.info(f"  {op['port']}/{op['proto']}  {op['service']}{extra}")
        if web_targets:
            utils.good(f"Web hedefleri türetildi: {', '.join(web_targets)}")
