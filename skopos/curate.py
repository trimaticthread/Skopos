"""
Kürasyon katmanı: ham modül çıktılarından SADECE önemli bulguları seçer.
- ffuf: baskın (tekrar eden) cevap grubunu gürültü sayıp eler, farklıları tutar.
- nikto: 'header missing' türü gürültüyü atar, önemli bulguları öne alır.
Hem ozet.txt hem raporun 'Öne Çıkan Bulgular' bölümü bunu kullanır.
"""

import glob
import json
import os
import re
from collections import Counter

# nikto'da gürültü sayılan (elenecek) satırlar
_NIKTO_NOISE = re.compile(
    r"(Suggested security header missing|X-Frame-Options header is deprecated|"
    r"X-Content-Type-Options header is not set|No CGI Directories|"
    r"Failed to check for updates|Start Time|End Time|Target IP|Target Hostname|"
    r"Target Port|Nikto v|requests:.*items reported)", re.I)
# nikto'da önemli sayılan (öne alınacak) izler
_NIKTO_IMPORTANT = re.compile(
    r"(/admin|/backup|/\.git|/config|/login|osvdb|CVE-|phpmyadmin|"
    r"indexing|default (file|account|credential)|outdated|/robots\.txt|"
    r"allowed http methods|PUT |DELETE |TRACE|shell|upload|/\.env|/\.htaccess)",
    re.I)


def _curate_ffuf(run_dir):
    """ffuf JSON'larından baskın grubu eleyip anlamlı hitleri döndürür."""
    hits = []
    for jf in sorted(glob.glob(os.path.join(run_dir, "ffuf*.json"))):
        try:
            with open(jf, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        for r in data.get("results", []):
            hits.append({"url": r.get("url", ""),
                         "input": (r.get("input") or {}).get("FUZZ", ""),
                         "status": r.get("status"), "length": r.get("length")})
    if not hits:
        return [], None

    combo = Counter((h["status"], h["length"]) for h in hits)
    (dom_status, dom_len), dom_count = combo.most_common(1)[0]
    interesting = hits
    note = None
    # Baskın grup toplamın yarısından fazlaysa ve çoksa -> gürültü kabul et
    if dom_count > 10 and dom_count / len(hits) > 0.5:
        interesting = [h for h in hits
                       if (h["status"], h["length"]) != (dom_status, dom_len)]
        if not interesting:
            if dom_status in (301, 302):
                note = (f"Tüm {len(hits)} cevap aynı ({dom_status}, size {dom_len}) "
                        f"— sunucu her şeyi yönlendiriyor. Muhtemelen sanal host "
                        f"(vhost): hedef domaini /etc/hosts'a ekleyip tekrar dene.")
            else:
                note = (f"Tüm cevaplar aynı ({dom_status}, size {dom_len}); "
                        f"anlamlı bir fark yok (wildcard yanıt).")
    return interesting[:40], note


def _curate_nikto(run_dir):
    """nikto log'larından gürültüyü eleyip önemli bulguları döndürür."""
    lines = []
    for lf in sorted(glob.glob(os.path.join(run_dir, "*nikto*.log"))):
        try:
            with open(lf, encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        for ln in content.splitlines():
            ln = ln.strip()
            if not ln.startswith("+") or _NIKTO_NOISE.search(ln):
                continue
            lines.append(ln.lstrip("+ ").strip())
    important = [l for l in lines if _NIKTO_IMPORTANT.search(l)]
    other = [l for l in lines if l not in important]
    return (important + other)[:20]


def curate(summary, run_dir):
    """key_findings üretir ve ozet.txt yazar; key_findings döndürür."""
    ffuf_hits, ffuf_note = _curate_ffuf(run_dir)
    key = {"ffuf_hits": ffuf_hits, "ffuf_note": ffuf_note,
           "nikto": _curate_nikto(run_dir)}
    _write_txt(summary, key, run_dir)
    return key


def _write_txt(summary, key, run_dir):
    """İnsan-okur temiz özet: ozet.txt"""
    out = []
    add = out.append
    add("=" * 62)
    add(f"  SKOPOS ÖZET  —  {summary.get('target', '')}")
    add("=" * 62)
    add(f"Profil : {summary.get('profile', '-')}")
    add(f"Zaman  : {summary.get('started', '-')}")
    if summary.get("os"):
        add(f"OS     : {', '.join(summary['os'])}")

    add("\n── AÇIK PORTLAR ──")
    for op in summary.get("open_ports", []):
        pv = " ".join(x for x in (op.get("product"), op.get("version")) if x)
        add(f"  {op['port']}/{op['proto']:<4} {op['service']:<10} {pv}")

    if summary.get("web_assets"):
        add("\n── WEB VARLIKLARI ──")
        for wa in summary["web_assets"]:
            tech = ", ".join(wa.get("tech") or []) or "-"
            title = f'  "{wa["title"]}"' if wa.get("title") else ""
            add(f"  {wa['url']}   [{tech}]{title}")

    add("\n── DİZİN KEŞFİ (ffuf) ──")
    if key["ffuf_note"]:
        add(f"  ! {key['ffuf_note']}")
    if key["ffuf_hits"]:
        for h in key["ffuf_hits"]:
            add(f"  [{h['status']}] {h['url']}  (size {h['length']})")
    elif not key["ffuf_note"]:
        add("  (anlamlı sonuç yok)")

    if key["nikto"]:
        add("\n── NIKTO (önemli) ──")
        for n in key["nikto"]:
            add(f"  - {n}")

    if summary.get("suggestions"):
        add("\n── ÖNERİLEN SONRAKİ ADIMLAR ──")
        for s in summary["suggestions"]:
            add(f"  → {s['text']}")
            if s.get("cmd"):
                add(f"      $ {s['cmd']}")

    path = os.path.join(run_dir, "ozet.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    return path
