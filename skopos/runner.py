"""Orkestratör: modülleri keşfeder, sırayla çalıştırır, çıktıları toplar."""

import datetime
import importlib
import json
import os
import pkgutil
import re

from . import utils
from .module_base import REGISTRY

# Modüllerin çalıştırılacağı kanonik sıra (bağımlılık zinciri).
# nmap önce çalışır ki web hedeflerini (ctx) sonraki modüllere aktarabilsin.
DEFAULT_ORDER = ["nmap", "subdomain", "fuzzing", "web"]


def discover_modules():
    """skopos/modules altındaki tüm modülleri import eder -> REGISTRY dolar."""
    from . import modules as modules_pkg

    for _finder, mod_name, _ispkg in pkgutil.iter_modules(modules_pkg.__path__):
        importlib.import_module(f"{modules_pkg.__name__}.{mod_name}")
    return REGISTRY


def _sanitize(target):
    """Hedefi klasör adı olarak güvenli hale getir."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", target)


def _ordered(selected):
    """Seçili modülleri kanonik sıraya diz; sırada olmayanları sona ekle."""
    in_order = [m for m in DEFAULT_ORDER if m in selected]
    extras = [m for m in selected if m not in DEFAULT_ORDER]
    return in_order + extras


def run_scan(target, module_names, profile_cfg, cfg, output_root,
             auto_fetch=False, fetch_confirm=True):
    """Tek bir hedef için seçili modülleri çalıştırır."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(output_root, _sanitize(target), ts)
    os.makedirs(run_dir, exist_ok=True)

    ctx = {"run_dir": run_dir, "target": target,
           "auto_fetch": auto_fetch, "fetch_confirm": fetch_confirm}
    summary = {"target": target, "profile_settings": profile_cfg,
               "started": ts, "modules": {}}

    utils.banner(f"HEDEF: {target}   (çıktı: {run_dir})")

    for mod_name in _ordered(module_names):
        cls = REGISTRY.get(mod_name)
        if cls is None:
            utils.err(f"Bilinmeyen modül: {mod_name}")
            continue

        utils.banner(f"Modül: {cls.name} — {cls.description}")
        module = cls(target, profile_cfg.get(mod_name, {}), cfg, ctx)

        # Bağımlılık kontrolü
        missing = [b for b in module.runtime_requires() if not utils.which(b)]
        if missing:
            utils.err(f"Eksik araç(lar): {', '.join(missing)} — modül atlanıyor.")
            summary["modules"][mod_name] = {"status": "skipped_missing_tool",
                                            "missing": missing}
            continue

        try:
            commands = module.build_commands()
        except Exception as exc:  # modül kaynaklı hata tüm taramayı düşürmesin
            utils.err(f"{mod_name} komut üretiminde hata: {exc}")
            summary["modules"][mod_name] = {"status": "error", "error": str(exc)}
            continue

        if not commands:
            summary["modules"][mod_name] = {"status": "no_commands"}
            continue

        results = []
        for cmd in commands:
            logfile = os.path.join(run_dir, f"{mod_name}_{cmd.label}.log")
            rc, out = utils.stream_command(cmd.argv, logfile=logfile,
                                           redact=cmd.redact)
            results.append((cmd, rc, out))

        try:
            module.post_process(results)
        except Exception as exc:
            utils.warn(f"{mod_name} post_process hatası: {exc}")

        summary["modules"][mod_name] = {
            "status": "done",
            "commands": [" ".join(c.argv) for c, _, _ in results],
        }

    # ctx'te biriken keşif verilerini özete ekle
    for key in ("open_ports", "web_targets", "subdomains"):
        if ctx.get(key):
            summary[key] = ctx[key]

    summary_path = os.path.join(run_dir, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    utils.good(f"Özet yazıldı: {summary_path}")
    return summary
