"""Dizin/dosya fuzzing modülü (ffuf veya gobuster)."""

from ..module_base import BaseModule, Command, register
from .. import utils, resources


def _web_targets(target, ctx):
    """nmap web hedefleri varsa onları, yoksa ham target'ı kullan."""
    targets = ctx.get("web_targets")
    if targets:
        return targets
    if target.startswith(("http://", "https://")):
        return [target]
    return [f"http://{target}"]


@register
class FuzzingModule(BaseModule):
    name = "fuzzing"
    description = "Web dizin/dosya keşfi (ffuf/gobuster)"
    requires = []  # tool seçime bağlı; run sırasında kontrol edilir

    def runtime_requires(self):
        s = self.module_settings()
        tool = s.get("tool", "ffuf")
        if tool == "gobuster":
            return [s.get("gobuster_binary", "gobuster")]
        return [s.get("ffuf_binary", "ffuf")]

    def _wordlist(self):
        size = self.pcfg.get("wordlist", "medium")
        # Sistem yolu yoksa yerel önbelleğe bakar, gerekirse indirir (--auto-fetch)
        path = resources.resolve_wordlist(
            self.cfg, "dir", size,
            auto_fetch=self.ctx.get("auto_fetch", False),
            confirm=self.ctx.get("fetch_confirm", True),
        )
        # Rapor için kullanılan wordlist'i kaydet
        if path:
            self.ctx.setdefault("wordlists", []).append(
                {"module": self.name, "size": size, "path": path})
        return path

    def build_commands(self):
        settings = self.module_settings()
        tool = settings.get("tool", "ffuf")
        p = self.pcfg
        wordlist = self._wordlist()
        threads = str(p.get("threads", 40))
        exts = p.get("extensions") or []
        rate = p.get("rate", 0)

        commands = []
        for i, url in enumerate(_web_targets(self.target, self.ctx)):
            if tool == "gobuster":
                binary = settings.get("gobuster_binary", "gobuster")
                argv = [binary, "dir", "-u", url, "-w", wordlist, "-t", threads, "-q"]
                if exts:
                    argv += ["-x", ",".join(exts)]
            else:  # ffuf (varsayılan)
                binary = settings.get("ffuf_binary", "ffuf")
                argv = [binary, "-u", f"{url.rstrip('/')}/FUZZ", "-w", wordlist,
                        "-t", threads, "-c"]
                if exts:
                    argv += ["-e", ",".join("." + e.lstrip(".") for e in exts)]
                if rate and rate > 0:
                    argv += ["-rate", str(rate)]

            argv += self.extra_args()  # ham ekstra parametreler (kaçış kapısı)
            commands.append(Command(label=f"dirscan{i}", argv=argv))
        return commands
