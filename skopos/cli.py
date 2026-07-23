"""Komut satırı arayüzü (argparse)."""

import argparse
import os
import shlex
import sys

from . import utils
from .config import load_config, resolve_profile
from .module_base import REGISTRY
from .runner import discover_modules, run_scan, _ordered


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="skopos",
        description="Skopos — modüler, profil bazlı pentest/recon orkestratörü.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Örnekler:\n"
            "  python -m skopos -t 10.10.10.5 --profile aggressive\n"
            "  python -m skopos -t example.com -m nmap,subdomain,web\n"
            "  python -m skopos -t site.com -p stealth -m fuzzing\n"
            "  python -m skopos --setup\n"
            "  python -m skopos --list-modules\n"
        ),
    )
    parser.add_argument("-t", "--target",
                        help="Hedef: IP, domain veya URL")
    parser.add_argument("-tL", "--target-list",
                        help="Hedef listesi dosyası (her satır bir hedef)")
    parser.add_argument("-p", "--profile", default=None,
                        help="Agresiflik profili (stealth|normal|aggressive). "
                             "Varsayılan: config'teki default_profile")
    parser.add_argument("-m", "--modules", default="all",
                        help="Virgülle ayrılmış modül listesi ya da 'all' "
                             "(varsayılan: all)")
    parser.add_argument("-c", "--config", default=None,
                        help="Ek YAML config dosyası (default üstüne birleşir)")
    parser.add_argument("-o", "--output", default=None,
                        help="Çıktı klasörü (config'teki output_dir'i override eder)")
    parser.add_argument("-x", "--extra", action="append", default=[],
                        metavar="MOD=ARGS",
                        help="Bir modüle ham ekstra parametre geçir (kaçış kapısı). "
                             "Tekrarlanabilir. Ör: -x 'nmap=-sU --top-ports 50' "
                             "-x 'fuzzing=-recursion -mc 200,301'")
    parser.add_argument("--setup", action="store_true",
                        help="Ortam kontrolü: eksik araçları raporla + wordlist indir")
    parser.add_argument("--auto-fetch", action="store_true",
                        help="Tarama sırasında eksik wordlist'leri otomatik indir")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="İndirme onaylarını atla (otomatik evet)")
    parser.add_argument("--list-modules", action="store_true",
                        help="Mevcut modülleri listele ve çık")
    parser.add_argument("--list-profiles", action="store_true",
                        help="Mevcut profilleri listele ve çık")
    parser.add_argument("--dry-run", action="store_true",
                        help="Komutları üret ama çalıştırma (ne yapacağını göster)")
    return parser.parse_args(argv)


def _resolve_targets(args):
    targets = []
    if args.target:
        targets.append(args.target.strip())
    if args.target_list:
        with open(args.target_list, encoding="utf-8") as fh:
            targets += [ln.strip() for ln in fh if ln.strip()
                        and not ln.startswith("#")]
    return targets


def _resolve_modules(names_arg, registry):
    if names_arg.strip().lower() == "all":
        return list(registry.keys())
    requested = [m.strip() for m in names_arg.split(",") if m.strip()]
    unknown = [m for m in requested if m not in registry]
    if unknown:
        utils.err(f"Bilinmeyen modül(ler): {', '.join(unknown)}")
        utils.info(f"Mevcut: {', '.join(registry.keys())}")
        sys.exit(2)
    return requested


def main(argv=None):
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    try:
        cfg = load_config(args.config)
    except Exception as exc:
        utils.err(f"Config yüklenemedi: {exc}")
        return 1

    registry = discover_modules()

    if args.setup:
        from . import doctor
        return doctor.run(cfg, fetch=True, confirm=not args.yes)

    if args.list_modules:
        utils.banner("Mevcut modüller")
        for name, cls in registry.items():
            reqs = ", ".join(cls.requires) or "-"
            print(f"  {utils.C.BOLD}{name}{utils.C.RESET}: {cls.description} "
                  f"{utils.C.DIM}(gerekli: {reqs}){utils.C.RESET}")
        return 0

    if args.list_profiles:
        utils.banner("Mevcut profiller")
        for name in cfg.get("profiles", {}):
            print(f"  {name}")
        return 0

    targets = _resolve_targets(args)
    if not targets:
        utils.err("Hedef belirtilmedi. -t ya da -tL kullan. (yardım: -h)")
        return 2

    profile_name = args.profile or cfg["general"].get("default_profile", "normal")
    try:
        profile_cfg = resolve_profile(cfg, profile_name)
    except ValueError as exc:
        utils.err(str(exc))
        return 2

    module_names = _resolve_modules(args.modules, registry)

    # CLI'dan gelen ham ekstra parametreleri ilgili modülün profiline enjekte et
    for item in args.extra:
        if "=" not in item:
            utils.err(f"--extra formatı 'MOD=ARGS' olmalı: {item}")
            return 2
        mod, raw = item.split("=", 1)
        mod = mod.strip()
        if mod not in registry:
            utils.err(f"--extra bilinmeyen modül: {mod}")
            return 2
        block = profile_cfg.setdefault(mod, {})
        existing = block.get("extra_args", [])
        if isinstance(existing, str):
            existing = shlex.split(existing)
        block["extra_args"] = list(existing) + shlex.split(raw)

    output_root = args.output or cfg["general"].get("output_dir", "output")
    os.makedirs(output_root, exist_ok=True)

    utils.banner("recon-tool başlıyor")
    utils.info(f"Profil    : {profile_name}")
    utils.info(f"Modüller  : {', '.join(module_names)}")
    utils.info(f"Hedefler  : {', '.join(targets)}")

    if args.dry_run:
        _dry_run(targets, module_names, profile_cfg, cfg)
        return 0

    for target in targets:
        try:
            run_scan(target, module_names, profile_cfg, cfg, output_root,
                     auto_fetch=args.auto_fetch, fetch_confirm=not args.yes,
                     profile_name=profile_name)
        except KeyboardInterrupt:
            utils.warn("Tarama kullanıcı tarafından durduruldu.")
            return 130

    utils.good("Tüm hedefler tamamlandı.")
    return 0


def _dry_run(targets, module_names, profile_cfg, cfg):
    """Gerçekten çalıştırmadan üretilecek komutları göster."""
    for target in targets:
        utils.banner(f"[DRY-RUN] {target}")
        ctx = {"run_dir": "<run_dir>", "target": target}
        for mod_name in _ordered(module_names):
            cls = REGISTRY.get(mod_name)
            if cls is None:
                continue
            module = cls(target, profile_cfg.get(mod_name, {}), cfg, ctx)
            try:
                commands = module.build_commands()
            except Exception as exc:
                utils.warn(f"{mod_name}: komut üretilemedi ({exc})")
                continue
            for cmd in commands:
                shown = list(cmd.argv)
                for secret in (cmd.redact or []):
                    if secret:
                        shown = ["***" if a == secret else a for a in shown]
                print(f"  {utils.C.CYAN}{mod_name}{utils.C.RESET}: "
                      f"{' '.join(shown)}")
