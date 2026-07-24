"""
İnteraktif parametre sihirbazı.

Akış:
  1. Her modül için kataloğu (PARAMETERS) kategorilere ayrılmış, kategoriler
     arası KESİNTİSİZ numaralandırılmış olarak gösterir.
  2. Kullanıcı numaraları seçer (virgül, boşluk ve aralık '1-3' desteklenir).
  3. Değer isteyen parametreler için tek tek sorar.
  4. Seçilen ham bayrakları modül başına döndürür (overrides).
  5. İsteğe bağlı: seçimi isimli bir profil olarak config/saved.yaml'e kaydeder.
"""

import os
import re

import yaml

from . import utils
from .module_base import REGISTRY

_SAVED_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "saved.yaml")


def _parse_selection(raw, maxn):
    """'1,4 7-9' -> [1,4,7,8,9]. Aralık, virgül, boşluk destekler; doğrular."""
    chosen = []
    for tok in re.split(r"[,\s]+", raw.strip()):
        if not tok:
            continue
        rng = re.match(r"^(\d+)-(\d+)$", tok)
        if rng:
            a, b = int(rng.group(1)), int(rng.group(2))
            chosen.extend(range(min(a, b), max(a, b) + 1))
        elif tok.isdigit():
            chosen.append(int(tok))
        else:
            utils.warn(f"Geçersiz giriş yok sayıldı: '{tok}'")
    # tekrar edenleri at, sırayı koru, aralık dışını ele
    seen, out = set(), []
    for n in chosen:
        if not (1 <= n <= maxn):
            utils.warn(f"Aralık dışı (1-{maxn}) yok sayıldı: {n}")
        elif n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _render_catalog(parameters):
    """Kataloğu kategori kategori, kesintisiz numarayla basar; sıralı liste döndürür."""
    order, groups = [], {}
    for p in parameters:
        if p["category"] not in groups:
            groups[p["category"]] = []
            order.append(p["category"])
        groups[p["category"]].append(p)

    numbered, n = [], 1
    for cat in order:
        print(f"\n  {utils.C.BOLD}▸ {cat}{utils.C.RESET}")
        for p in groups[cat]:
            tags = " ".join(f"{utils.C.DIM}[{t}]{utils.C.RESET}" for t in p["tags"])
            needs = f" {utils.C.YELLOW}(değer sorulacak){utils.C.RESET}" if p["value"] else ""
            print(f"   {utils.C.CYAN}{n:>2}{utils.C.RESET}) "
                  f"{utils.C.BOLD}{p['flag']:<16}{utils.C.RESET} {p['desc']}{needs}  {tags}")
            numbered.append(p)
            n += 1
    return numbered


def _collect_module(name, cls):
    """Tek bir modül için menüyü göster, seçimleri ve değerleri topla -> args listesi."""
    utils.banner(f"{name} — ne yapmak istiyorsun?")
    numbered = _render_catalog(cls.PARAMETERS)

    try:
        raw = input(f"\n  Seç (ör. 1,4,7-9)  [boş = bu modülü varsayılanla geç]: ")
    except EOFError:
        raw = ""
    picks = _parse_selection(raw, len(numbered))

    args = []
    for idx in picks:
        p = numbered[idx - 1]
        if p["value"]:
            prompt = p["value"].get("prompt", "Değer:")
            try:
                val = input(f"    → {utils.C.BOLD}{p['flag']}{utils.C.RESET} "
                            f"için {prompt} ").strip()
            except EOFError:
                val = ""
            if not val:
                if p["value"].get("required"):
                    utils.warn(f"{p['flag']} değeri boş bırakıldı, atlanıyor.")
                    continue
            args += [p["flag"], val]
        else:
            args.append(p["flag"])

    shown = " ".join(args) if args else "(varsayılan)"
    utils.good(f"{name} → {shown}")
    return args


def run_interactive(module_names):
    """
    Seçili modüller için interaktif seçim yürütür.
    Dönüş: {modül_adı: [seçilen bayraklar]} (sadece kataloğu olan modüller).
    """
    utils.banner("İnteraktif tarama sihirbazı")
    utils.info("Her kategoriden istediğin kadar seçebilirsin. Numaraları virgülle "
               "ya da aralıkla gir (ör. 1,4,7-9).")

    overrides = {}
    for name in module_names:
        cls = REGISTRY.get(name)
        if cls is None:
            continue
        if not cls.PARAMETERS:
            utils.warn(f"'{name}' için interaktif katalog yok — bu modülü atlıyorum. "
                       f"(profil moduyla çalıştır: -m {name} -p normal)")
            continue
        overrides[name] = _collect_module(name, cls)
    return overrides


def ask_name():
    """Taramaya isim sorar (çıktı klasörü + olası kayıt için)."""
    try:
        name = input("\n  Bu taramaya bir isim ver (çıktı bu isimle klasörlenir) "
                     "[interactive]: ").strip()
    except EOFError:
        name = ""
    return _sanitize_name(name) or "interactive"


def ask_save():
    try:
        ans = input("  Bu seçimi ileride '-p <isim>' ile tekrar kullanmak için "
                    "kaydedeyim mi? [e/H]: ").strip().lower()
    except EOFError:
        ans = ""
    return ans in ("e", "evet", "y", "yes")


def _sanitize_name(name):
    return re.sub(r"[^A-Za-z0-9._-]", "-", name).strip("-")


def save_profile(name, overrides):
    """Seçimi config/saved.yaml içine '_mode: raw' profili olarak yazar."""
    data = {}
    if os.path.exists(_SAVED_PATH):
        with open(_SAVED_PATH, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    data.setdefault("profiles", {})

    profile = {"_mode": "raw"}
    for mod, args in overrides.items():
        profile[mod] = {"args": args}
    data["profiles"][name] = profile

    os.makedirs(os.path.dirname(_SAVED_PATH), exist_ok=True)
    with open(_SAVED_PATH, "w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh, allow_unicode=True, sort_keys=False)
    utils.good(f"'{name}' profili kaydedildi. Tekrar çalıştır: "
               f"python -m skopos -t <hedef> -p {name}")
