"""Subdomain keşif modülü (subfinder)."""

import re

from ..module_base import BaseModule, Command, param, register
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

    PARAMETERS = [
        param("-all", "Tüm kaynaklar", "Bütün OSINT kaynaklarını kullan. Kapsamlı ama yavaş, false-positive artar.",
              "Kaynaklar", ["yavaş", "kapsamlı"]),
        param("-recursive", "Özyinelemeli", "Alt-alan adlarını da özyinelemeli çözen kaynakları kullan.",
              "Kaynaklar", []),
        param("-s", "Belirli kaynak", "Sadece verdiğin kaynakları kullan (ör. crtsh,github).",
              "Kaynaklar", [],
              value={"prompt": "kaynaklar (ör. crtsh,github):", "required": True}),
        param("-active", "Aktif doğrulama", "Sadece IP'ye çözülen/doğrulanan alt-alanları göster.",
              "Doğrulama", ["aktif"]),
        param("-t", "Eşzamanlılık", "Çözümleme thread sayısı.",
              "Performans", [],
              value={"prompt": "thread (ör. 30):", "required": True}),
        param("-rl", "Hız limiti", "Saniyede en fazla istek (kaynaklarca bloklanmamak için).",
              "Performans", ["sessiz"],
              value={"prompt": "istek/sn (ör. 10):", "required": True}),
    ]

    def interactive_command(self, selected_args):
        domain = _domain_of(self.target)
        if not domain:
            utils.warn("Hedef bir IP; subdomain taraması atlanıyor.")
            return []
        binary = self.module_settings().get("binary", "subfinder")
        argv = [binary, "-d", domain] + list(selected_args) + ["-silent"]
        return [Command(label="subdomains", argv=argv)]

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
