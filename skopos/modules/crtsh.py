"""
crt.sh pasif subdomain modülü (OSINT, pür-Python, API anahtarı gerekmez).

Sertifika şeffaflık loglarını (crt.sh) sorgulayıp hedef domainin geçmişte
sertifika almış alt-alan adlarını çıkarır. Tamamen pasif: hedefe tek bir
paket bile gitmez, yalnızca crt.sh'e sorulur. Bulunan subdomainler ctx'e
eklenir; probe modülü bunları canlı mı diye dener, canlı olanlar taranır.

Yalnızca stdlib (urllib). Sadece https. IP hedeflerde atlanır.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from ..module_base import BaseModule, register
from .. import utils

# crt.sh sık sık 429/502/503 döner (aşırı yüklü servis); kısa retry ile aşarız.
_RETRYABLE = {429, 502, 503, 504}


def _fetch_crtsh(url, timeout, attempts=3):
    """crt.sh'i retry ile sorgular; (data | None, hata_mesajı | None) döner."""
    last = "bilinmeyen hata"
    for i in range(attempts):
        req = urllib.request.Request(url, headers={"User-Agent": "skopos-crtsh/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace")), None
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            if exc.code not in _RETRYABLE:
                return None, last
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            last = str(exc)
        if i < attempts - 1:
            time.sleep(2 * (i + 1))  # artan bekleme
    return None, last

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _domain_of(target):
    t = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    return None if _IP_RE.match(t) else t


def _extract_subdomains(data, domain):
    """
    crt.sh JSON'undan hedef domainin GERÇEK alt-alan adlarını çıkarır.

    Etiket sınırı şarttır: sertifikalar (CT logları) çok-SAN olabilir ve aynı
    sorguya takılan alakasız domainleri de taşıyabilir. Sadece son-ek eşleşmesi
    (endswith(domain)) 'evilexample.com'u da 'example.com' alt-alanı sanardı —
    bu bir kapsam ihlali. Bu yüzden '.' + domain ile tam etiket sınırı aranır
    (apex domainin kendisi de alt-alan sayılmaz).
    """
    suffix = "." + domain
    found = set()
    for entry in data:
        names = (entry.get("name_value") or "").splitlines()
        names.append(entry.get("common_name") or "")
        for n in names:
            n = n.strip().lower().lstrip("*.")
            if n and n.endswith(suffix) and "@" not in n:
                found.add(n)
    return sorted(found)


@register
class CrtShModule(BaseModule):
    name = "crtsh"
    description = "Pasif subdomain keşfi (crt.sh, OSINT) — araç/anahtar gerekmez"
    requires = []
    native = True

    def native_run(self):
        domain = _domain_of(self.target)
        if not domain:
            utils.info("crtsh: hedef IP — pasif subdomain keşfi atlanıyor.")
            return

        url = "https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + domain,
                                                           "output": "json"})
        timeout = float(self.pcfg.get("timeout", 25) or 25)
        utils.info(f"crtsh: {domain} için sertifika logları sorgulanıyor...")
        data, error = _fetch_crtsh(url, timeout)
        if data is None:
            utils.warn(f"crtsh: sorgu başarısız ({error}). crt.sh aşırı yüklü "
                       f"olabilir — sonra tekrar dene.")
            return

        subs = _extract_subdomains(data, domain)
        if not subs:
            utils.info("crtsh: yeni subdomain bulunamadı.")
            self.write_log("crtsh", f"# crt.sh — {domain}\n(sonuç yok)\n")
            return

        existing = set(self.ctx.get("subdomains", []) or [])
        new = [s for s in subs if s not in existing]
        self.ctx.setdefault("subdomains", []).extend(new)

        self.write_log("crtsh", f"# crt.sh pasif subdomainler — {domain} "
                       f"({len(subs)} benzersiz)\n\n" + "\n".join(subs) + "\n")
        utils.good(f"crtsh: {len(subs)} subdomain ({len(new)} yeni).")
        for s in subs[:15]:
            utils.info(f"  {s}")
        if len(subs) > 15:
            utils.info(f"  ... (+{len(subs) - 15} daha, loglarda)")
