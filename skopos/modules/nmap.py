"""Nmap modülü: port/servis taraması + istihbarat çıkarımı (deep parse)."""

import os
import re
import xml.etree.ElementTree as ET

from ..module_base import BaseModule, Command, param, register
from .. import utils

# Web servisi kabul edilecek servis adları
_WEB_SERVICES = {"http", "https", "http-proxy", "https-alt", "http-alt",
                 "ssl/http", "http-alt", "ws", "wss"}
# Yaygın web portları (nmap servisi tanıyamasa bile web say)
_WEB_PORTS = {80, 81, 443, 591, 832, 981, 1010, 1311, 2082, 2087, 2095, 2096,
              3000, 3128, 3333, 4000, 4243, 4443, 4567, 4711, 4712, 4993, 5000,
              5104, 5108, 5601, 5800, 6543, 7000, 7001, 7396, 7474, 8000, 8001,
              8008, 8009, 8014, 8042, 8060, 8069, 8080, 8081, 8083, 8085, 8088,
              8089, 8090, 8091, 8118, 8123, 8172, 8181, 8222, 8243, 8280, 8281,
              8333, 8443, 8500, 8834, 8880, 8888, 8983, 9000, 9001, 9043, 9060,
              9080, 9090, 9091, 9200, 9443, 9800, 9981, 10000, 12443, 16080,
              18091, 18092, 20720, 28017}
# Servis çıktısında HTTP'yi ele veren izler
_HTTP_MARKERS = ("HTTP/1.", "HTTP/2", "Server:", "X-Powered-By:", "Set-Cookie:",
                 "<!DOCTYPE html", "<html")
# Bilinen teknoloji/uygulama anahtar kelimeleri (blob içinde aranır)
_TECH_KEYWORDS = ("Next.js", "Nuxt", "React", "Angular", "Vue", "WordPress",
                  "Drupal", "Joomla", "Django", "Flask", "Express", "Laravel",
                  "Spring", "Tomcat", "Jetty", "nginx", "Apache", "IIS",
                  "Jenkins", "Grafana", "Kibana", "phpMyAdmin", "GitLab",
                  "Gitea", "Werkzeug", "PHP", "ASP.NET", "Node.js")
# Servis sürüm/çıktısında OS ipuçları
_OS_KEYWORDS = ("Ubuntu", "Debian", "CentOS", "Red Hat", "Fedora", "FreeBSD",
                "Windows", "Alpine", "Gentoo", "Arch")


def _unescape_fp(s):
    """nmap servicefp kaçışlarını okunur hale getirir; satır yapısını korur."""
    if not s:
        return ""
    s = s.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    s = s.replace("\\t", " ").replace("\\x20", " ")
    s = re.sub(r"\\x[0-9a-fA-F]{2}", " ", s)  # kalan hex kaçışları
    return re.sub(r"\\(.)", r"\1", s)         # \. \" \( gibi kaçışları sadeleştir


def _clean_header_val(v):
    """Bir HTTP header değerini temizler (sonraki header/tag'de keser, kısaltır)."""
    v = v.strip()
    v = re.split(r"\s+[A-Z][A-Za-z-]*:\s", v)[0]  # sonraki "Header:" değerinde kes
    v = re.split(r'["\'<>]', v)[0]                # tırnak / HTML tag'de kes
    return v.strip()[:60]


def _extract_web_meta(blob):
    """Web cevabından Server, teknoloji listesi ve başlık çıkarır."""
    server = ""
    m = re.search(r"Server:\s*([^\r\n]+)", blob)
    if m:
        server = _clean_header_val(m.group(1))
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", blob, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]

    tech = []
    m = re.search(r"X-Powered-By:\s*([^\r\n]+)", blob)
    if m:
        val = _clean_header_val(m.group(1))
        if val:
            tech.append(val)
    # bilinen teknolojiler — kelime sınırıyla (substring false-positive'i önler)
    for kw in _TECH_KEYWORDS:
        if re.search(r"\b" + re.escape(kw) + r"\b", blob, re.I):
            tech.append(kw)
    # tekrarları at, sırayı koru
    seen, uniq = set(), []
    for t in tech:
        if t.lower() not in seen:
            seen.add(t.lower())
            uniq.append(t)
    return server, uniq, title


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
        """XML'i derin parse eder: portlar, web varlıkları, OS, script bulguları."""
        xml_path = self._xml_path()
        if not os.path.exists(xml_path):
            return
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError:
            utils.warn("nmap XML çıktısı parse edilemedi.")
            return

        open_ports, web_targets, web_assets, scripts_found = [], [], [], []
        host_info, os_hints = {}, set()

        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else self.target

            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                portid = int(port.get("portid"))
                proto = port.get("protocol")
                svc = port.find("service")
                name = svc.get("name", "") if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                extrainfo = svc.get("extrainfo", "") if svc is not None else ""
                ostype = svc.get("ostype", "") if svc is not None else ""
                servicefp = svc.get("servicefp", "") if svc is not None else ""

                script_texts = []
                for scr in port.findall("script"):
                    sid = scr.get("id", "")
                    out = scr.get("output", "") or ""
                    script_texts.append(out)
                    if sid == "ssh-hostkey":
                        host_info.setdefault("ssh_hostkeys", []).extend(
                            ln.strip() for ln in out.splitlines() if ln.strip())
                    elif sid in ("http-title", "http-server-header", "http-generator",
                                 "ssl-cert", "ftp-anon", "http-robots.txt",
                                 "smb-os-discovery", "http-methods"):
                        scripts_found.append(
                            {"port": portid, "id": sid,
                             "output": re.sub(r"\s+", " ", out).strip()[:300]})

                blob = " ".join([product, version, extrainfo,
                                 _unescape_fp(servicefp)] + script_texts)

                open_ports.append(
                    {"host": addr, "port": portid, "proto": proto, "service": name,
                     "product": product, "version": version, "extrainfo": extrainfo})

                if ostype:
                    os_hints.add(ostype)
                for kw in _OS_KEYWORDS:
                    if re.search(r"\b" + re.escape(kw) + r"\b", blob):
                        os_hints.add(kw)

                # --- Web tespiti (nmap "ppp" dese bile HTTP izlerinden yakala) ---
                is_web = (name in _WEB_SERVICES or "http" in name
                          or portid in _WEB_PORTS
                          or any(mk in blob for mk in _HTTP_MARKERS))
                if is_web:
                    secure = ("https" in name or "ssl" in name
                              or portid in (443, 8443, 4443, 9443, 8834))
                    url = f"{'https' if secure else 'http'}://{addr}:{portid}"
                    web_targets.append(url)
                    server, tech, title = _extract_web_meta(blob)
                    if product and product not in tech:
                        tech.append(product)
                    web_assets.append(
                        {"host": addr, "port": portid, "url": url,
                         "server": server, "tech": tech[:8], "title": title})

            for osm in host.findall("./os/osmatch"):
                if osm.get("name"):
                    os_hints.add(osm.get("name"))

        # --- ctx'e yaz (rapor + öneriler bunları kullanır) ---
        self.ctx.setdefault("open_ports", []).extend(open_ports)
        self.ctx.setdefault("web_targets", []).extend(web_targets)
        if web_assets:
            self.ctx.setdefault("web_assets", []).extend(web_assets)
        if scripts_found:
            self.ctx.setdefault("scripts", []).extend(scripts_found)
        if host_info.get("ssh_hostkeys"):
            self.ctx.setdefault("host_info", {}).setdefault(
                "ssh_hostkeys", []).extend(host_info["ssh_hostkeys"])
        if os_hints:
            merged = set(self.ctx.get("os", [])) | {x for x in os_hints if x}
            self.ctx["os"] = sorted(merged)

        # --- terminal çıktısı ---
        if open_ports:
            utils.good(f"{len(open_ports)} açık port bulundu.")
            for op in open_ports:
                ver = f" {op['product']} {op['version']}".rstrip()
                utils.info(f"  {op['port']}/{op['proto']}  {op['service']}{ver}")
        for wa in web_assets:
            tech = f"  [{', '.join(wa['tech'])}]" if wa["tech"] else ""
            utils.good(f"Web: {wa['url']}{tech}")
        if self.ctx.get("os"):
            utils.info("OS ipucu: " + ", ".join(self.ctx["os"]))
