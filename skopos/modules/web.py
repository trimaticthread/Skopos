"""Web teknoloji tespiti (whatweb) + zafiyet taraması (nikto)."""

from ..module_base import BaseModule, Command, param, register
from .. import utils


def _web_targets(target, ctx):
    targets = ctx.get("web_targets")
    if targets:
        return targets
    if target.startswith(("http://", "https://")):
        return [target]
    return [f"http://{target}"]


@register
class WebModule(BaseModule):
    name = "web"
    description = "Web teknoloji tespiti (whatweb) + zafiyet taraması (nikto)"
    requires = []  # profile bağlı; whatweb/nikto ayrı ayrı kontrol edilir

    # İnteraktif katalog nikto odaklı. whatweb her zaman (hızlı tespit) çalışır;
    # buradaki seçenekler nikto'ya uygulanır.
    PARAMETERS = [
        param("-Tuning", "Test grupları", "Sadece belirli testleri çalıştır. "
              "1=dosya 2=yanlış yapılandırma 3=bilgi sızıntısı 4=XSS 9=SQLi b=yazılım tespiti.",
              "Test Kapsamı", ["odaklı"],
              value={"prompt": "tuning (ör. 349b; sadece SQLi+XSS+bilgi+yazılım):", "required": True}),
        param("-Plugins", "Belirli pluginler", "Sadece verdiğin pluginleri çalıştır.",
              "Test Kapsamı", [],
              value={"prompt": "pluginler (ör. apache_expect_xss,cookies):", "required": True}),
        param("-maxtime", "Süre sınırı", "Taramayı belirli süre sonra durdur.",
              "Test Kapsamı", [],
              value={"prompt": "süre (ör. 300s):", "required": True}),
        param("-evasion", "IDS atlatma", "LibWhisker atlatma tekniği. "
              "1=URI encode 2=/./ 3=erken URL sonu 6=TAB 7=harf büyüklüğü.",
              "IDS Atlatma", ["kırmızı takım"],
              value={"prompt": "teknik (ör. 1 ya da 17):", "required": True}),
        param("-useragent", "User-Agent", "İsteklerde özel User-Agent kullan.",
              "IDS Atlatma", [],
              value={"prompt": "UA (ör. Mozilla/5.0):", "required": True}),
        param("-ssl", "SSL zorla", "Bağlantıyı HTTPS/SSL üzerinden yap.",
              "Bağlantı", []),
        param("-timeout", "Zaman aşımı", "Her istek için saniye cinsinden zaman aşımı.",
              "Bağlantı", [],
              value={"prompt": "saniye (ör. 5):", "required": True}),
    ]

    def interactive_command(self, selected_args):
        s = self.module_settings()
        whatweb = s.get("whatweb_binary", "whatweb")
        nikto = s.get("nikto_binary", "nikto")
        commands = []
        for i, url in enumerate(_web_targets(self.target, self.ctx)):
            commands.append(Command(label=f"whatweb{i}", argv=[whatweb, "-a", "3", url]))
            commands.append(
                Command(label=f"nikto{i}", argv=[nikto, "-h", url] + list(selected_args)))
        return commands

    def runtime_requires(self):
        s = self.module_settings()
        needed = []
        if self.pcfg.get("run_whatweb", True):
            needed.append(s.get("whatweb_binary", "whatweb"))
        if self.pcfg.get("run_nikto", False):
            needed.append(s.get("nikto_binary", "nikto"))
        return needed

    def build_commands(self):
        settings = self.module_settings()
        p = self.pcfg
        whatweb = settings.get("whatweb_binary", "whatweb")
        nikto = settings.get("nikto_binary", "nikto")

        commands = []
        for i, url in enumerate(_web_targets(self.target, self.ctx)):
            if p.get("run_whatweb", True):
                commands.append(
                    Command(label=f"whatweb{i}", argv=[whatweb, "-a", "3", url])
                )
            if p.get("run_nikto", False):
                # ham ekstra parametreler nikto'ya bağlanır (ör. -Tuning, -evasion)
                commands.append(
                    Command(label=f"nikto{i}", argv=[nikto, "-h", url] + self.extra_args())
                )

        if not commands:
            utils.warn("Web modülünde çalıştırılacak bir şey yok (profile bak).")
        return commands
