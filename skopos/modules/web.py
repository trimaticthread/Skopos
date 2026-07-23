"""Web teknoloji tespiti (whatweb) + zafiyet taraması (nikto)."""

from ..module_base import BaseModule, Command, register
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
