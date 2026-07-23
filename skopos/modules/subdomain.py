"""Subdomain keşif modülü (subfinder)."""

import re

from ..module_base import BaseModule, Command, register
from .. import utils

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _domain_of(target):
    """URL/şema ve port varsa temizleyip saf domain döndürür; IP ise None."""
    t = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    if _IP_RE.match(t):
        return None
    return t


@register
class SubdomainModule(BaseModule):
    name = "subdomain"
    description = "Subdomain enumeration (subfinder)"
    requires = ["subfinder"]

    def build_commands(self):
        domain = _domain_of(self.target)
        if not domain:
            utils.warn("Hedef bir IP; subdomain taraması atlanıyor.")
            return []

        binary = self.module_settings().get("binary", "subfinder")
        p = self.pcfg
        argv = [binary, "-d", domain, "-t", str(p.get("threads", 30)), "-silent"]
        if not p.get("passive_only", True):
            argv.append("-all")  # tüm kaynaklar (daha agresif)

        argv += self.extra_args()  # ham ekstra parametreler (kaçış kapısı)
        return [Command(label="subdomains", argv=argv)]

    def post_process(self, results):
        """Bulunan subdomain'leri ctx'e yaz (ilerideki modüller kullanabilir)."""
        for _cmd, _rc, out in results:
            subs = [ln.strip() for ln in out.splitlines() if ln.strip() and "." in ln]
            if subs:
                self.ctx.setdefault("subdomains", []).extend(subs)
                utils.good(f"{len(subs)} subdomain bulundu.")
