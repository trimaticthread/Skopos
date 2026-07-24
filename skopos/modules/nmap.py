"""Nmap modülü: port/servis taraması + açık portların çözümlenmesi."""

import os
import xml.etree.ElementTree as ET

from ..module_base import BaseModule, Command, param, register
from .. import utils

# Web servisi kabul edilecek servis adları / portlar (web modülüne aktarılır)
_WEB_SERVICES = {"http", "https", "http-proxy", "https-alt", "http-alt"}
_WEB_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888}


@register
class NmapModule(BaseModule):
    name = "nmap"
    description = "Port ve servis/versiyon taraması (nmap)"
    requires = ["nmap"]

    PARAMETERS = [
        # --- Tarama Tipi ---
        param("-sS", "SYN taraması", "Yarı-açık, hızlı, görece sessiz. En yaygın seçim.",
              "Tarama Tipi", ["root", "sessiz"]),
        param("-sT", "TCP connect", "Bağlantıyı tamamlar; root gerektirmez ama gürültülü.",
              "Tarama Tipi", ["root yoksa", "gürültülü"]),
        param("-sU", "UDP taraması", "DNS/SNMP/SIP gibi UDP servisleri için. Çok yavaştır.",
              "Tarama Tipi", ["yavaş"]),
        param("-sA", "ACK taraması", "Portu değil firewall kurallarını haritalar.",
              "Tarama Tipi", ["kırmızı takım"]),
        # --- Port Kapsamı ---
        param("-p-", "Tüm portlar", "65535 portun hepsini tara. HTB'de standart.",
              "Port Kapsamı", ["CTF", "yavaş"]),
        param("--top-ports", "En yaygın N port", "Sadece en sık kullanılan N portu tara.",
              "Port Kapsamı", ["hızlı"],
              value={"prompt": "Kaç port? (ör. 100)", "required": True}),
        param("-p", "Belirli portlar", "Sadece verdiğin portları tara.",
              "Port Kapsamı", [],
              value={"prompt": "Portlar (ör. 22,80,443 ya da 1-1000):", "required": True}),
        param("-F", "Hızlı mod", "Varsayılandan az port (top-100). Hızlı ön keşif.",
              "Port Kapsamı", ["hızlı"]),
        # --- Tespit ---
        param("-sV", "Versiyon tespiti", "Açık portlarda hangi servis/sürüm çalışıyor?",
              "Tespit", []),
        param("-sC", "Varsayılan scriptler", "Güvenli NSE scriptleri. HTB'de neredeyse şart.",
              "Tespit", ["CTF"]),
        param("-O", "İşletim sistemi tespiti", "Hedefin OS'unu tahmin eder.",
              "Tespit", ["root"]),
        param("-A", "Agresif (hepsi)", "OS + versiyon + script + traceroute, bir arada.",
              "Tespit", ["CTF", "gürültülü", "root"]),
        param("--script=vuln", "Zafiyet scriptleri", "Bilinen zafiyetleri arar. Değerli ama gürültülü.",
              "Tespit", ["gürültülü"]),
        param("--script", "Özel NSE script", "Belirli script ya da kategori çalıştır.",
              "Tespit", [],
              value={"prompt": "script/kategori (ör. http-enum,smb-os-discovery):", "required": True}),
        # --- Zamanlama ---
        param("-T4", "Hızlı zamanlama", "Lab/HTB için ideal. Filtreli portlarda hızlı geçer.",
              "Zamanlama", ["CTF", "hızlı", "gürültülü"]),
        param("-T2", "Yavaş/kibar", "IDS eşiğinin altında kalmak için yavaş tarar.",
              "Zamanlama", ["kırmızı takım", "sessiz", "yavaş"]),
        param("--min-rate", "Min paket hızı", "Saniyede en az N paket gönder (hızlandırır).",
              "Zamanlama", ["hızlı"],
              value={"prompt": "min-rate (ör. 1000):", "required": True}),
        param("--max-rate", "Max paket hızı", "Saniyede en fazla N paket (hız limiti, sessizlik).",
              "Zamanlama", ["kırmızı takım", "sessiz"],
              value={"prompt": "max-rate (ör. 100):", "required": True}),
        # --- Firewall/IDS Atlatma ---
        param("-Pn", "Ping atla", "Host'u online say, keşif atla. ICMP kesikse şart.",
              "Firewall/IDS Atlatma", ["kırmızı takım"]),
        param("-f", "Paket parçalama", "Paketleri böler, basit IDS'leri şaşırtır.",
              "Firewall/IDS Atlatma", ["kırmızı takım"]),
        param("-D", "Decoy (sahte kaynak)", "Taramayı sahte IP'lerle gizler.",
              "Firewall/IDS Atlatma", ["kırmızı takım"],
              value={"prompt": "decoy'lar (ör. 10.0.0.1,ME,10.0.0.2):", "required": True}),
        param("--source-port", "Kaynak port", "53/88 gibi güvenilen porttan tara; bazı firewall'lar geçirir.",
              "Firewall/IDS Atlatma", ["kırmızı takım"],
              value={"prompt": "kaynak port (ör. 53):", "required": True}),
        param("--scan-delay", "Prob gecikmesi", "Problar arası bekleme; hız-tabanlı tespiti atlatır.",
              "Firewall/IDS Atlatma", ["kırmızı takım", "yavaş"],
              value={"prompt": "gecikme (ör. 500ms, 1s):", "required": True}),
        # --- Çıktı / Diğer ---
        param("--open", "Sadece açık portlar", "Çıktıyı sadece açık portlarla sınırla.",
              "Çıktı / Diğer", []),
        param("--reason", "Durum sebebi", "Portun neden o durumda olduğunu gösterir.",
              "Çıktı / Diğer", []),
        param("-v", "Ayrıntılı çıktı", "Daha fazla ayrıntı bas.",
              "Çıktı / Diğer", []),
        param("-6", "IPv6", "IPv6 taraması yap.",
              "Çıktı / Diğer", []),
    ]

    def interactive_command(self, selected_args):
        binary = self.module_settings().get("binary", "nmap")
        # Seçilen bayraklar + XML çıktısı (parse için) + hedef
        argv = [binary] + list(selected_args) + ["-oX", self._xml_path(), self.target]
        return [Command(label="portscan", argv=argv)]

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
