"""
BloodHound modülü: Active Directory veri toplama (bloodhound-python ingestor).

DİKKAT — diğer modüllerden farkı:
  * Bu modül YETKİLİ (authenticated) bir AD kullanıcısının kimlik bilgilerini
    gerektirir (domain + kullanıcı + parola/hash + DC IP).
  * bloodhound-python sadece VERİYİ toplar (.json/.zip). Grafiği görmek için
    ayrıca Neo4j + BloodHound GUI'ye bu zip'i import etmen gerekir.
  * Parolayı config'e YAZMA. BH_PASSWORD ortam değişkenini kullan; parola
    komut satırında görünse bile log/ekranda '***' olarak maskelenir.
    (Not: parola yine de sistemin process listesinde -ps- görünebilir; bu
    bloodhound-python'un bilinen bir sınırıdır. İzole ortamda çalıştır.)

Yalnızca yetkin olduğun AD ortamlarında (kendi lab, izinli pentest, CTF) kullan.
"""

import os
import re

from ..module_base import BaseModule, Command, register
from .. import utils

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Geçerli toplama yöntemleri (bloodhound-python -c)
_VALID_COLLECTION = {
    "Default", "All", "DCOnly", "Group", "LocalAdmin", "RDP", "DCOM",
    "PSRemote", "Session", "LoggedOn", "Trusts", "ACL", "Container",
    "ObjectProps",
}


def _domain_of(target):
    """URL/port temizleyip domain döndürür; IP ise None."""
    t = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    return None if _IP_RE.match(t) else t


@register
class BloodHoundModule(BaseModule):
    name = "bloodhound"
    description = "Active Directory veri toplama (bloodhound-python) — AD kimlik bilgisi gerekir"
    requires = ["bloodhound-python"]

    def build_commands(self):
        s = self.module_settings()
        p = self.pcfg

        domain = s.get("domain") or _domain_of(self.target)
        username = s.get("username") or os.environ.get("BH_USER")
        password = os.environ.get("BH_PASSWORD") or s.get("password")
        dc_ip = s.get("dc_ip") or s.get("nameserver")
        collection = p.get("collection", "Default")
        use_hashes = any(a in ("-hashes", "--hashes") for a in self.extra_args())

        # Zorunlu alan kontrolü — eksikse modülü atla (taramayı düşürme)
        missing = []
        if not domain:
            missing.append("domain (hedef IP ise config: modules.bloodhound.domain)")
        if not username:
            missing.append("username (config: modules.bloodhound.username veya BH_USER env)")
        if not password and not use_hashes:
            missing.append("password (BH_PASSWORD env; ya da -x 'bloodhound=-hashes LM:NT')")
        if not dc_ip:
            missing.append("dc_ip (config: modules.bloodhound.dc_ip)")
        if missing:
            utils.warn("BloodHound eksik bilgi nedeniyle atlanıyor:")
            for m in missing:
                utils.warn(f"    - {m}")
            return []

        if collection not in _VALID_COLLECTION:
            utils.warn(f"Bilinmeyen collection '{collection}', 'Default' kullanılıyor.")
            collection = "Default"

        binary = s.get("binary", "bloodhound-python")
        out_prefix = os.path.join(self.ctx["run_dir"], "bloodhound")

        argv = [binary, "-d", domain, "-u", username,
                "-ns", dc_ip, "-c", collection, "--zip", "-op", out_prefix]
        # Parola sadece hash kullanılmıyorsa eklenir (hash ise -x ile geçilir)
        redact = None
        if password and not use_hashes:
            argv += ["-p", password]
            redact = [password]

        argv += self.extra_args()  # -hashes, -k (kerberos), -dc-ip vb. kaçış kapısı
        return [Command(label="collect", argv=argv, redact=redact)]

    def post_process(self, results):
        run_dir = self.ctx["run_dir"]
        zips = [f for f in os.listdir(run_dir) if f.endswith(".zip")]
        if zips:
            utils.good(f"BloodHound verisi toplandı: {', '.join(zips)}")
            utils.info("  Görüntülemek için: Neo4j'yi başlat, BloodHound GUI'de bu "
                       ".zip'i 'Upload Data' ile içeri aktar.")
