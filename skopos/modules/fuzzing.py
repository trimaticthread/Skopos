"""Dizin/dosya fuzzing modülü (ffuf veya gobuster)."""

from ..module_base import BaseModule, Command, param, register
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

    # İnteraktif katalog ffuf odaklı (varsayılan tool). Temel komut (-u/-w)
    # otomatik kurulur; buradakiler filtre/ayar seçenekleridir.
    PARAMETERS = [
        # --- Filtreler (en kritik: çöp sonucu ele) ---
        param("-fc", "Kod ile filtrele", "Bu HTTP kodlarını gizle (ör. 404 çöpünü at).",
              "Filtreler", ["kritik"],
              value={"prompt": "kodlar (ör. 404,403):", "required": True}),
        param("-fs", "Boyut ile filtrele", "Bu byte boyutundaki cevapları gizle (varsayılan sayfayı at).",
              "Filtreler", ["kritik"],
              value={"prompt": "boyut(lar) (ör. 4242):", "required": True}),
        param("-fw", "Kelime ile filtrele", "Bu kelime sayısındaki cevapları gizle.",
              "Filtreler", [],
              value={"prompt": "kelime sayısı (ör. 12):", "required": True}),
        param("-mc", "Kod ile eşleştir", "Sadece bu HTTP kodlarını göster.",
              "Filtreler", [],
              value={"prompt": "kodlar (ör. 200,301,302):", "required": True}),
        param("-ac", "Otomatik kalibrasyon", "Varsayılan/çöp cevabı otomatik öğrenip filtreler.",
              "Filtreler", ["kolay"]),
        # --- Kapsam ---
        param("-recursion", "Özyineleme", "Bulunan dizinlerin içine de girip tarar.",
              "Kapsam", []),
        param("-recursion-depth", "Özyineleme derinliği", "Kaç seviye derine insin.",
              "Kapsam", [],
              value={"prompt": "derinlik (ör. 2):", "required": True}),
        param("-e", "Uzantılar", "Her kelimeyi bu uzantılarla dene.",
              "Kapsam", [],
              value={"prompt": "uzantılar (ör. .php,.html,.bak):", "required": True}),
        # --- İstek ---
        param("-X", "HTTP metodu", "GET yerine POST/PUT vb. kullan.",
              "İstek", [],
              value={"prompt": "metod (ör. POST):", "required": True}),
        param("-H", "Header ekle", "Özel HTTP header (auth/cookie testi).",
              "İstek", [],
              value={"prompt": "header (ör. 'Authorization: Bearer xxx'):", "required": True}),
        param("-t", "Thread sayısı", "Eşzamanlı istek sayısı (hız).",
              "İstek", [],
              value={"prompt": "thread (ör. 40):", "required": True}),
        param("-rate", "Hız limiti", "Saniyede en fazla N istek (sessizlik/rate-limit).",
              "İstek", ["sessiz"],
              value={"prompt": "istek/sn (ör. 50):", "required": True}),
    ]

    def interactive_command(self, selected_args):
        s = self.module_settings()
        binary = s.get("ffuf_binary", "ffuf")
        wordlist = self._wordlist()
        commands = []
        for i, url in enumerate(_web_targets(self.target, self.ctx)):
            argv = [binary, "-u", f"{url.rstrip('/')}/FUZZ", "-w", wordlist, "-c"]
            argv += list(selected_args)
            commands.append(Command(label=f"dirscan{i}", argv=argv))
        return commands

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
