"""
Tek dosyalık HTML rapor üretimi.
summary.json + modül log'larından, tarayıcıda açılabilen kendi kendine yeten
(inline CSS, harici bağımlılık yok) bir rapor oluşturur.
"""

import html
import os

_CSS = """
* { box-sizing: border-box; }
body { margin:0; font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
       background:#0d1117; color:#c9d1d9; }
.wrap { max-width:960px; margin:0 auto; padding:32px 20px 64px; }
header { border-bottom:1px solid #21262d; padding-bottom:16px; margin-bottom:24px; }
h1 { margin:0 0 4px; font-size:26px; }
h1 .logo { color:#58a6ff; }
.sub { color:#8b949e; font-size:14px; }
.meta { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
.pill { background:#161b22; border:1px solid #30363d; border-radius:999px;
        padding:3px 12px; font-size:13px; color:#8b949e; }
.pill b { color:#c9d1d9; }
h2 { font-size:16px; margin:32px 0 12px; color:#e6edf3; }
h3 { font-size:13px; margin:16px 0 8px; color:#8b949e; text-transform:uppercase; letter-spacing:.4px; }
.note { background:#3a2e15; border:1px solid #9e7b1f; border-radius:8px; padding:12px 14px;
        color:#e3b341; font-size:14px; }
.card { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:2px 16px; }
table { width:100%; border-collapse:collapse; }
th,td { text-align:left; padding:10px 8px; border-bottom:1px solid #21262d; font-size:14px; }
th { color:#8b949e; font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.4px; }
tr:last-child td { border-bottom:none; }
td.port { font-family:ui-monospace,Menlo,Consolas,monospace; color:#58a6ff; }
code { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12.5px;
       color:#79c0ff; word-break:break-all; }
.muted { color:#6e7681; }
ul.links { list-style:none; padding:0; margin:0; }
ul.links li { padding:8px 0; border-bottom:1px solid #21262d; }
ul.links li:last-child { border-bottom:none; }
a { color:#58a6ff; text-decoration:none; }
a:hover { text-decoration:underline; }
.badge { display:inline-block; padding:2px 10px; border-radius:999px; font-size:12px; font-weight:600; }
.badge.done { background:#1a3a24; color:#3fb950; }
.badge.skip { background:#3a2e15; color:#d29922; }
.badge.err  { background:#3a1d1d; color:#f85149; }
ul.steps { list-style:none; padding:0; margin:0; }
ul.steps > li { padding:12px 0; border-bottom:1px solid #21262d; }
ul.steps > li:last-child { border-bottom:none; }
ul.steps > li::before { content:"→ "; color:#3fb950; font-weight:700; }
.cmd { margin-top:8px; }
.cmd code { display:block; background:#0d1117; border:1px solid #30363d; border-radius:6px;
            padding:8px 12px; color:#7ee787; }
details { background:#161b22; border:1px solid #30363d; border-radius:8px; margin:8px 0; }
summary { cursor:pointer; padding:12px 16px; font-family:ui-monospace,Menlo,Consolas,monospace;
          font-size:13px; color:#8b949e; }
summary:hover { color:#c9d1d9; }
pre { margin:0; padding:16px; overflow-x:auto; background:#0d1117; border-top:1px solid #30363d;
      font:12px/1.5 ui-monospace,Menlo,Consolas,monospace; color:#c9d1d9; }
footer { margin-top:40px; color:#6e7681; font-size:12px; text-align:center; }
"""


def _esc(s):
    return html.escape(str(s if s is not None else ""))


def _status_badge(status):
    if status == "done":
        return '<span class="badge done">done</span>'
    if status and status.startswith("skipped"):
        return '<span class="badge skip">skipped</span>'
    if status == "error":
        return '<span class="badge err">error</span>'
    return f'<span class="badge">{_esc(status)}</span>'


def write_html(summary, run_dir):
    """summary sözlüğü + run_dir'deki .log dosyalarından report.html üretir."""
    target = summary.get("target", "")
    started = summary.get("started", "")
    profile = summary.get("profile") or "—"
    open_ports = summary.get("open_ports", [])
    web_targets = summary.get("web_targets", [])
    web_assets = summary.get("web_assets", [])
    subdomains = summary.get("subdomains", [])
    wordlists = summary.get("wordlists", [])
    scripts = summary.get("scripts", [])
    host_info = summary.get("host_info", {})
    os_hints = summary.get("os", [])
    suggestions = summary.get("suggestions", [])
    key = summary.get("key_findings", {})
    modules = summary.get("modules", {})

    # ⭐ Öne Çıkan Bulgular (kürasyon)
    highlight = ""
    if key.get("ffuf_note"):
        highlight += f"<div class='note'>⚠️ {_esc(key['ffuf_note'])}</div>"
    if key.get("ffuf_hits"):
        hit_rows = "".join(
            f"<tr><td class='port'>{_esc(h.get('status'))}</td>"
            f"<td><a href='{_esc(h.get('url'))}' target='_blank' rel='noopener'>{_esc(h.get('url'))}</a></td>"
            f"<td class='muted'>{_esc(h.get('length'))}</td></tr>" for h in key["ffuf_hits"])
        highlight += ("<h3>Bulunan dizinler/dosyalar</h3><table>"
                      "<thead><tr><th>Kod</th><th>URL</th><th>Boyut</th></tr></thead>"
                      f"<tbody>{hit_rows}</tbody></table>")
    if key.get("nikto"):
        nk = "".join(f"<li>{_esc(n)}</li>" for n in key["nikto"])
        highlight += f"<h3>Nikto (önemli)</h3><ul class='steps'>{nk}</ul>"
    highlight_section = (f"<h2>⭐ Öne Çıkan Bulgular</h2><div class='card'>{highlight}</div>"
                         if highlight else "")

    # Servisler & Sürümler tablosu
    if open_ports:
        rows = ""
        for op in open_ports:
            prodver = " ".join(x for x in (op.get("product"), op.get("version"),
                                           op.get("extrainfo")) if x)
            rows += (
                f"<tr><td class='port'>{_esc(op.get('port'))}/{_esc(op.get('proto'))}</td>"
                f"<td>{_esc(op.get('service')) or '<span class=muted>—</span>'}</td>"
                f"<td>{_esc(prodver) or '<span class=muted>—</span>'}</td>"
                f"<td class='muted'>{_esc(op.get('host'))}</td></tr>")
    else:
        rows = "<tr><td colspan='4' class='muted'>Açık port bulunamadı.</td></tr>"
    ports_html = (
        "<table><thead><tr><th>Port</th><th>Servis</th><th>Ürün / Sürüm</th>"
        f"<th>Host</th></tr></thead><tbody>{rows}</tbody></table>"
    )

    # 🌐 Web Varlıkları
    if web_assets:
        wa_rows = "".join(
            f"<tr><td><a href='{_esc(wa['url'])}' target='_blank' rel='noopener'>{_esc(wa['url'])}</a></td>"
            f"<td>{_esc(', '.join(wa.get('tech') or [])) or '<span class=muted>—</span>'}</td>"
            f"<td class='muted'>{_esc(wa.get('server')) or '—'}</td>"
            f"<td class='muted'>{_esc(wa.get('title')) or '—'}</td></tr>"
            for wa in web_assets)
        web_assets_html = (
            "<table><thead><tr><th>URL</th><th>Teknoloji</th><th>Server</th>"
            f"<th>Başlık</th></tr></thead><tbody>{wa_rows}</tbody></table>")
    else:
        web_assets_html = "<p class='muted'>Web varlığı tespit edilmedi.</p>"

    # 🖥️ Host / Sistem
    host_rows = ""
    if os_hints:
        host_rows += (f"<tr><td>İşletim sistemi</td>"
                      f"<td>{_esc(', '.join(os_hints))}</td></tr>")
    for hk in host_info.get("ssh_hostkeys", []):
        host_rows += f"<tr><td>SSH host key</td><td><code>{_esc(hk)}</code></td></tr>"
    host_html = (f"<table><tbody>{host_rows}</tbody></table>"
                 if host_rows else "<p class='muted'>Host bilgisi çıkarılmadı.</p>")

    # 📜 Script Bulguları
    if scripts:
        sc_rows = "".join(
            f"<tr><td class='port'>{_esc(s.get('port'))}</td>"
            f"<td class='muted'>{_esc(s.get('id'))}</td>"
            f"<td>{_esc(s.get('output'))}</td></tr>" for s in scripts)
        scripts_html = ("<table><thead><tr><th>Port</th><th>Script</th>"
                        f"<th>Çıktı</th></tr></thead><tbody>{sc_rows}</tbody></table>")
    else:
        scripts_html = "<p class='muted'>Script bulgusu yok (-sC / --script ekleyerek artar).</p>"

    # ✅ Önerilen Sonraki Adımlar
    if suggestions:
        sug_items = ""
        for s in suggestions:
            cmd = (f"<div class='cmd'><code>{_esc(s['cmd'])}</code></div>"
                   if s.get("cmd") else "")
            sug_items += f"<li>{_esc(s['text'])}{cmd}</li>"
        suggestions_html = f"<ul class='steps'>{sug_items}</ul>"
    else:
        suggestions_html = "<p class='muted'>—</p>"

    # Web hedefleri
    if web_targets:
        web_html = "<ul class='links'>" + "".join(
            f"<li><a href='{_esc(u)}' target='_blank' rel='noopener'>{_esc(u)}</a></li>"
            for u in web_targets
        ) + "</ul>"
    else:
        web_html = "<div class='card'><p class='muted'>Web hedefi türetilmedi.</p></div>"

    # Modül durumları
    mod_rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{_status_badge(info.get('status'))}</td>"
        f"<td class='muted'>{_esc((info.get('missing') and ', '.join(info['missing'])) or '')}</td></tr>"
        for name, info in modules.items()
    ) or "<tr><td colspan='3' class='muted'>—</td></tr>"
    modules_html = (
        "<table><thead><tr><th>Modül</th><th>Durum</th><th>Not</th></tr></thead>"
        f"<tbody>{mod_rows}</tbody></table>"
    )

    # Çalıştırılan komutlar (hangi araç, hangi flag'ler, hangi wordlist)
    cmd_rows = ""
    for name, info in modules.items():
        for cmd in info.get("commands", []):
            cmd_rows += (f"<tr><td class='muted'>{_esc(name)}</td>"
                         f"<td><code>{_esc(cmd)}</code></td></tr>")
    if cmd_rows:
        commands_section = (
            "<h2>⌨️ Çalıştırılan Komutlar</h2><div class='card'><table>"
            "<thead><tr><th>Modül</th><th>Komut</th></tr></thead>"
            f"<tbody>{cmd_rows}</tbody></table></div>"
        )
    else:
        commands_section = ""

    # Kullanılan wordlist'ler
    wl_section = ""
    if wordlists:
        wl_rows = "".join(
            f"<tr><td class='muted'>{_esc(w.get('module'))}</td>"
            f"<td>{_esc(w.get('size'))}</td>"
            f"<td><code>{_esc(w.get('path'))}</code></td></tr>"
            for w in wordlists
        )
        wl_section = (
            "<h2>📖 Kullanılan Wordlist'ler</h2><div class='card'><table>"
            "<thead><tr><th>Modül</th><th>Boyut</th><th>Yol</th></tr></thead>"
            f"<tbody>{wl_rows}</tbody></table></div>"
        )

    # Subdomain (varsa)
    subs_section = ""
    if subdomains:
        items = "".join(f"<li>{_esc(s)}</li>" for s in subdomains)
        subs_section = (
            f"<h2>🌐 Subdomainler ({len(subdomains)})</h2>"
            f"<div class='card'><ul class='links'>{items}</ul></div>"
        )

    # Ham log'lar (katlanabilir)
    logs_html = ""
    for fn in sorted(os.listdir(run_dir)):
        if not fn.endswith(".log"):
            continue
        try:
            with open(os.path.join(run_dir, fn), encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        logs_html += f"<details><summary>{_esc(fn)}</summary><pre>{_esc(content)}</pre></details>"
    if not logs_html:
        logs_html = "<p class='muted'>Log dosyası yok.</p>"

    doc = f"""<!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Skopos — {_esc(target)}</title><style>{_CSS}</style></head>
<body><div class="wrap">
<header>
  <h1><span class="logo">🛰️ Skopos</span> keşif raporu</h1>
  <div class="sub">Hedef: <b>{_esc(target)}</b></div>
  <div class="meta">
    <span class="pill">hedef <b>{_esc(target)}</b></span>
    <span class="pill">profil <b>{_esc(profile)}</b></span>
    <span class="pill">açık port <b>{len(open_ports)}</b></span>
    <span class="pill">web varlığı <b>{len(web_assets)}</b></span>
    <span class="pill">OS <b>{_esc(', '.join(os_hints)) or '—'}</b></span>
  </div>
</header>

{highlight_section}

<h2>🔓 Servisler &amp; Sürümler</h2>
<div class="card">{ports_html}</div>

<h2>🌐 Web Varlıkları</h2>
<div class="card">{web_assets_html}</div>

<h2>🖥️ Host / Sistem</h2>
<div class="card">{host_html}</div>

<h2>📜 Script Bulguları</h2>
<div class="card">{scripts_html}</div>

<h2>✅ Önerilen Sonraki Adımlar</h2>
<div class="card">{suggestions_html}</div>

{subs_section}

<h2>🧩 Modüller</h2>
<div class="card">{modules_html}</div>

{commands_section}

{wl_section}

<h2>📄 Ham Çıktı</h2>
{logs_html}

<footer>Skopos tarafından üretildi — yalnızca yetkili güvenlik testleri içindir.</footer>
</div></body></html>"""

    path = os.path.join(run_dir, "report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path
