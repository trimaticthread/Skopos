"""
Kaynak (resource) yöneticisi: eksik wordlist/şablon gibi dosyaları
bilinen URL'lerden indirir. Sadece stdlib (urllib) kullanır — ek bağımlılık yok.

Tasarım:
  * Öncelik sistemdeki hazır dosya (ör. /usr/share/seclists/...).
  * Yoksa proje içi yerel önbellek (wordlists/ altı).
  * O da yoksa ve indirme izni verilmişse, kaynağın URL'sinden indir.
Sadece https URL'lere izin verilir.
"""

import os
import ssl
import sys
import urllib.request

from . import utils

# Proje kökü (bu dosyanın iki üstü) ve yerel önbellek klasörü
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CACHE_DIR = os.path.join(_ROOT, "wordlists")


def _human(nbytes):
    for unit in ("B", "KB", "MB", "GB"):
        if nbytes < 1024 or unit == "GB":
            return f"{nbytes:.1f}{unit}"
        nbytes /= 1024


def download(url, dest, confirm=True):
    """
    url -> dest indirir. confirm True ise kullanıcıdan onay ister (TTY'de).
    Dönüş: başarı (bool).
    """
    if not url.lower().startswith("https://"):
        utils.err(f"Güvensiz kaynak reddedildi (https değil): {url}")
        return False

    os.makedirs(os.path.dirname(dest), exist_ok=True)

    if confirm and sys.stdin.isatty():
        utils.warn(f"İndirilecek: {url}")
        utils.warn(f"        -> {dest}")
        try:
            ans = input("    Onaylıyor musun? [e/H] ").strip().lower()
        except EOFError:
            ans = ""
        if ans not in ("e", "evet", "y", "yes"):
            utils.info("İndirme atlandı.")
            return False

    utils.info(f"İndiriliyor: {url}")
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "recon-tool"})
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            done = 0
            tmp = dest + ".part"
            with open(tmp, "wb") as fh:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    fh.write(chunk)
                    done += len(chunk)
                    if total:
                        pct = done * 100 // total
                        sys.stdout.write(
                            f"\r    {_human(done)}/{_human(total)} ({pct}%)")
                        sys.stdout.flush()
            os.replace(tmp, dest)
        if total:
            sys.stdout.write("\n")
        utils.good(f"İndirildi: {dest}")
        return True
    except Exception as exc:
        utils.err(f"İndirme başarısız: {exc}")
        if os.path.exists(dest + ".part"):
            os.remove(dest + ".part")
        return False


def resolve_wordlist(cfg, category, size, auto_fetch=False, confirm=True):
    """
    Bir wordlist yolunu çözümler; gerekiyorsa indirir.
    category: 'dir' | 'subdomain' ...
    size    : 'small' | 'medium' | 'large'
    Dönüş: kullanılabilir dosya yolu ya da None.
    """
    # 1) Config'te tanımlı sistem yolu (varsa ve mevcutsa) tercih edilir
    sys_path = cfg.get("wordlists", {}).get(category, {}).get(size)
    if sys_path and os.path.exists(sys_path):
        return sys_path

    # 2) Yerel önbellekte var mı?
    cache_path = os.path.join(CACHE_DIR, f"{category}_{size}.txt")
    if os.path.exists(cache_path):
        return cache_path

    # 3) Kaynak URL tanımlıysa ve izin varsa indir
    url = cfg.get("wordlist_sources", {}).get(category, {}).get(size)
    if url and auto_fetch:
        if download(url, cache_path, confirm=confirm):
            return cache_path

    # Bulunamadı — kullanıcıya ipucu ver
    if url:
        utils.warn(f"Wordlist yok: {category}/{size}. "
                   f"İndirmek için: python recon.py --setup "
                   f"(veya çalışırken --auto-fetch)")
    else:
        utils.warn(f"Wordlist yok ve kaynak URL tanımsız: {category}/{size}. "
                   f"config'te wordlists.{category}.{size} yolunu düzelt.")
    return sys_path  # yine de config yolunu döndür (araç kendi hatasını versin)
