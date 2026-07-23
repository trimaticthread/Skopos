"""
'doctor' / '--setup': ortam kontrolü.
  * Modüllerin ihtiyaç duyduğu harici araçları tespit eder, eksikler için
    tam kurulum komutunu gösterir (sistem paketlerini SESSIZCE kurmaz).
  * Kaynak URL'si tanımlı ama sistemde bulunmayan wordlist'leri indirir.
"""

from . import utils, resources
from .module_base import REGISTRY

# Bilinen araçlar için kurulum ipuçları (Kali/Debian tabanlı)
_INSTALL_HINTS = {
    "nmap": "sudo apt install -y nmap",
    "ffuf": "sudo apt install -y ffuf   # ya da: go install github.com/ffuf/ffuf/v2@latest",
    "gobuster": "sudo apt install -y gobuster",
    "nikto": "sudo apt install -y nikto",
    "whatweb": "sudo apt install -y whatweb",
    "subfinder": "sudo apt install -y subfinder   # ya da: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "bloodhound-python": "pipx install bloodhound   # ya da: pip install bloodhound",
}


def check_tools(cfg):
    """Tüm kayıtlı modüllerin gerçekten ihtiyaç duyduğu araçları kontrol eder."""
    utils.banner("Araç kontrolü")

    # Modülleri varsayılan profille örnekleyip runtime_requires()'ı sor.
    # (fuzzing/web gibi modüller gerçek ihtiyacını burada bildirir; statik
    #  'requires' onlarda boş olduğundan tek başına yanıltıcı olurdu.)
    from .config import resolve_profile
    profile_name = cfg.get("general", {}).get("default_profile", "normal")
    try:
        pcfg = resolve_profile(cfg, profile_name)
    except ValueError:
        pcfg = {}

    needed = {}
    for name, cls in REGISTRY.items():
        try:
            module = cls("setup-check", pcfg.get(name, {}), cfg, {})
            binaries = module.runtime_requires()
        except Exception:
            binaries = list(cls.requires)
        for binary in binaries:
            needed.setdefault(binary, []).append(name)

    missing = []
    for binary in sorted(needed):
        path = utils.which(binary)
        users = ", ".join(needed[binary])
        if path:
            utils.good(f"{binary:<20} bulundu  ({users})")
        else:
            utils.err(f"{binary:<20} EKSİK    ({users})")
            missing.append(binary)

    if missing:
        print()
        utils.warn("Eksik araçları kurmak için:")
        for binary in missing:
            hint = _INSTALL_HINTS.get(binary, f"# {binary} için kurulum bilgisini araştır")
            print(f"    {utils.C.CYAN}{binary}{utils.C.RESET}: {hint}")
    return missing


def fetch_wordlists(cfg, confirm=True):
    """Sistemde bulunmayan, kaynağı tanımlı tüm wordlist'leri indirir."""
    utils.banner("Wordlist kontrolü / indirme")
    sources = cfg.get("wordlist_sources", {})
    if not sources:
        utils.info("Tanımlı wordlist kaynağı yok.")
        return

    for category, sizes in sources.items():
        for size in sizes:
            path = resources.resolve_wordlist(
                cfg, category, size, auto_fetch=True, confirm=confirm)
            if path:
                utils.good(f"{category}/{size}: hazır -> {path}")
            else:
                utils.warn(f"{category}/{size}: sağlanamadı.")


def run(cfg, fetch=True, confirm=True):
    """--setup akışı: araç kontrolü + wordlist indirme."""
    missing = check_tools(cfg)
    if fetch:
        fetch_wordlists(cfg, confirm=confirm)
    utils.banner("Kurulum kontrolü tamamlandı")
    if missing:
        utils.warn(f"{len(missing)} araç eksik — yukarıdaki komutlarla kur.")
    else:
        utils.good("Tüm araçlar hazır.")
    return 0
