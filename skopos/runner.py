"""Orkestratör: modülleri keşfeder, sırayla çalıştırır, çıktıları toplar."""

import datetime
import importlib
import json
import os
import pkgutil
import re

from . import utils, report, findings, curate
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
             auto_fetch=False, fetch_confirm=True, profile_name=None,
             overrides=None):
    """
    Tek bir hedef için seçili modülleri çalıştırır.
    overrides : {modül: [ham bayraklar]} verilirse o modül için build_commands
                yerine interactive_command(seçilenler) kullanılır (interaktif mod).
    profile_name : verilirse çıktı output/<isim>/<hedef>/<zaman>/ altına yazılır.
    """
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if profile_name:
        run_dir = os.path.join(output_root, _sanitize(profile_name),
                               _sanitize(target), ts)
    else:
        run_dir = os.path.join(output_root, _sanitize(target), ts)
    os.makedirs(run_dir, exist_ok=True)

    ctx = {"run_dir": run_dir, "target": target,
           "auto_fetch": auto_fetch, "fetch_confirm": fetch_confirm}
    summary = {"target": target, "profile": profile_name,
               "profile_settings": profile_cfg, "started": ts, "modules": {}}

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
            if overrides is not None and mod_name in overrides:
                commands = module.interactive_command(overrides[mod_name] or [])
            else:
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
    for key in ("open_ports", "web_targets", "subdomains", "wordlists",
                "web_assets", "scripts", "host_info", "os"):
        if ctx.get(key):
            summary[key] = ctx[key]

    # Bulgulardan önerilen sonraki adımları üret
    summary["suggestions"] = findings.build_suggestions(summary)

    # Kürasyon: ham çıktılardan sadece önemli bulguları seç + ozet.txt yaz
    txt_path = os.path.join(run_dir, "ozet.txt")
    try:
        summary["key_findings"] = curate.curate(summary, run_dir)
    except Exception as exc:
        utils.warn(f"Kürasyon başarısız: {exc}")
        txt_path = None

    summary_path = os.path.join(run_dir, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    # HTML rapor üret
    report_path = None
    try:
        report_path = report.write_html(summary, run_dir)
    except Exception as exc:
        utils.warn(f"HTML rapor üretilemedi: {exc}")

    _print_summary(summary, summary_path, report_path, txt_path)
    return summary


def _print_summary(summary, summary_path, report_path, txt_path=None):
    """Tarama sonunda terminale okunur bir özet basar."""
    utils.banner("Tarama özeti")

    ops = summary.get("open_ports", [])
    if ops:
        utils.good(f"Açık portlar ({len(ops)}):")
        for op in ops:
            ver = f" — {op['product']} {op.get('version','')}".rstrip()
            print(f"      {op['port']}/{op['proto']}  {op['service']}{ver if op.get('product') else ''}")
    else:
        utils.info("Açık port bulunamadı.")

    for wa in summary.get("web_assets", []):
        tech = f"  [{', '.join(wa['tech'])}]" if wa.get("tech") else ""
        utils.good(f"Web varlığı: {wa['url']}{tech}")
    if summary.get("os"):
        utils.info("OS ipucu: " + ", ".join(summary["os"]))
    if summary.get("subdomains"):
        utils.good(f"Subdomain: {len(summary['subdomains'])} adet")

    # Modül durumları tek satırda
    parts = []
    for name, info in summary.get("modules", {}).items():
        st = info.get("status", "?")
        mark = {"done": "✓", "error": "✗"}.get(st, "•" if st.startswith("skipped") else "·")
        parts.append(f"{mark} {name}")
    if parts:
        utils.info("Modüller: " + "   ".join(parts))

    # Kürasyon: öne çıkan bulgular
    kf = summary.get("key_findings", {})
    if kf.get("ffuf_note"):
        utils.warn("ffuf: " + kf["ffuf_note"])
    if kf.get("ffuf_hits"):
        utils.good(f"Bulunan dizinler ({len(kf['ffuf_hits'])}):")
        for h in kf["ffuf_hits"][:12]:
            print(f"      [{h['status']}] {h['url']}")
    if kf.get("nikto"):
        utils.good("Nikto (önemli):")
        for n in kf["nikto"][:8]:
            print(f"      - {n}")

    # Önerilen sonraki adımlar
    sugg = summary.get("suggestions", [])
    if sugg:
        print()
        utils.good("Önerilen sonraki adımlar:")
        for s in sugg:
            print(f"      • {s['text']}")
            if s.get("cmd"):
                print(f"        {utils.C.DIM}$ {s['cmd']}{utils.C.RESET}")

    print()
    if txt_path:
        utils.good(f"TXT özet  : {txt_path}")
    utils.good(f"JSON özet : {summary_path}")
    if report_path:
        utils.good(f"HTML rapor: {report_path}")
        utils.info(f"Tarayıcıda aç: xdg-open {report_path}")
