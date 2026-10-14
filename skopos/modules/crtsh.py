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
import urllib.parse
import urllib.request

from ..module_base import BaseModule, register
from .. import utils

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _domain_of(target):
    t = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    return None if _IP_RE.match(t) else t


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
        req = urllib.request.Request(url, headers={"User-Agent": "skopos-crtsh/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
            data = json.loads(raw)
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            utils.warn(f"crtsh: sorgu başarısız ({exc}).")
            return

        found = set()
        for entry in data:
            names = (entry.get("name_value") or "").splitlines()
            common = entry.get("common_name") or ""
            for n in names + [common]:
                n = n.strip().lower().lstrip("*.")
                if n and n.endswith(domain) and n != domain and "@" not in n:
                    found.add(n)

        subs = sorted(found)
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
