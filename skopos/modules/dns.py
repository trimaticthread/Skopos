"""
DNS kayıt keşfi (dig) — pasif OSINT.

Hedef domainin A/AAAA/MX/NS/TXT/CNAME/SOA kayıtlarını toplar. MX ve TXT
kayıtları (SPF/DMARC, posta sağlayıcı) ve NS kayıtları sıkça saldırı
yüzeyine dair ipucu verir. IP hedeflerde atlanır.
"""

import re

from ..module_base import BaseModule, Command, register
from .. import utils

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _domain_of(target):
    t = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    return None if _IP_RE.match(t) else t


@register
class DnsModule(BaseModule):
    name = "dns"
    description = "DNS kayıt keşfi (dig): A/MX/NS/TXT…"
    requires = ["dig"]

    def build_commands(self):
        domain = _domain_of(self.target)
        if not domain:
            utils.info("dns: hedef IP — DNS keşfi atlanıyor.")
            return []
        binary = self.module_settings().get("binary", "dig")
        cmds = []
        for t in _TYPES:
            cmds.append(Command(label=t.lower(),
                                argv=[binary, "+short", domain, t]))
        # Kullanıcının ham ekstra parametreleri (son komuta eklenir yeterli)
        return cmds

    def post_process(self, results):
        records = {}
        for cmd, _rc, out in results:
            rtype = cmd.label.upper()
            vals = [ln.strip() for ln in (out or "").splitlines() if ln.strip()
                    and not ln.startswith(";")]
            if vals:
                records[rtype] = vals
        if records:
            self.ctx.setdefault("dns", {}).update(records)
            total = sum(len(v) for v in records.values())
            utils.good(f"dns: {total} kayıt ({', '.join(records.keys())}).")
            for rtype in ("A", "MX", "NS"):
                for v in records.get(rtype, [])[:5]:
                    utils.info(f"  {rtype:<5} {v}")
