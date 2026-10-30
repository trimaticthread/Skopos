"""
nuclei modülü: şablon bazlı zafiyet taraması.

Keşfedilen tüm web hedeflerine (nmap web portları + probe'un doğruladığı
canlı adresler) nuclei'nin topluluk şablonlarını uygular. nuclei'nin kendi
severity'si (info/low/medium/high/critical) doğrudan Skopos Finding
severity'sine eşlenir — yani arayüzdeki renk/filtre gerçek risk seviyesini
yansıtır. Çıktı JSONL olarak alınır ve parse edilir.

Zincirdeki yeri: en sonda çalışır ki probe/fuzzing'in çıkardığı tüm canlı
web adreslerini hedef alsın.
"""

import json
import os

from ..module_base import BaseModule, Command, register
from .. import utils


@register
class NucleiModule(BaseModule):
    name = "nuclei"
    description = "Şablon bazlı zafiyet taraması (nuclei)"
    requires = ["nuclei"]

    def _web_targets(self):
        targets = self.ctx.get("web_targets") or []
        if targets:
            # sırayı koruyarak tekilleştir
            return list(dict.fromkeys(targets))
        t = self.target
        if t.startswith(("http://", "https://")):
            return [t]
        return ["http://" + t]

    def build_commands(self):
        targets = self._web_targets()
        if not targets:
            utils.info("nuclei: taranacak web hedefi yok.")
            return []

        run_dir = self.ctx["run_dir"]
        targets_file = os.path.join(run_dir, "nuclei_targets.txt")
        with open(targets_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(targets) + "\n")
        json_out = os.path.join(run_dir, "nuclei.jsonl")

        binary = self.module_settings().get("binary", "nuclei")
        p = self.pcfg
        argv = [binary, "-l", targets_file, "-jsonl", "-o", json_out,
                "-silent", "-no-color", "-disable-update-check"]

        sev = p.get("severity")
        if sev:
            argv += ["-severity", ",".join(sev) if isinstance(sev, list) else str(sev)]
        tags = p.get("tags")
        if tags:
            argv += ["-tags", ",".join(tags) if isinstance(tags, list) else str(tags)]
        if p.get("rate_limit"):
            argv += ["-rate-limit", str(p["rate_limit"])]
        if p.get("concurrency"):
            argv += ["-c", str(p["concurrency"])]
        if p.get("timeout"):
            argv += ["-timeout", str(p["timeout"])]

        argv += self.extra_args()  # ham ekstra parametreler (kaçış kapısı)
        return [Command(label="scan", argv=argv)]

    def post_process(self, results):
        json_out = os.path.join(self.ctx["run_dir"], "nuclei.jsonl")
        if not os.path.exists(json_out):
            return
        items = []
        with open(json_out, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                info = d.get("info", {}) or {}
                items.append({
                    "name": info.get("name") or d.get("template-id", "nuclei"),
                    "severity": (info.get("severity") or "info").lower(),
                    "matched": d.get("matched-at") or d.get("host", ""),
                    "template": d.get("template-id", ""),
                    "tags": info.get("tags", []) or [],
                    "refs": info.get("reference") or [],
                })
        if items:
            self.ctx.setdefault("nuclei", []).extend(items)
            # severity'ye göre öne çıkar (önce kritikler)
            rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            items.sort(key=lambda it: rank.get(it["severity"], 0), reverse=True)
            utils.good(f"nuclei: {len(items)} bulgu.")
            for it in items[:12]:
                utils.info(f"  [{it['severity']}] {it['name']} — {it['matched']}")
