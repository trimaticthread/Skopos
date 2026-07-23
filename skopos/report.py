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
.card { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:2px 16px; }
table { width:100%; border-collapse:collapse; }
th,td { text-align:left; padding:10px 8px; border-bottom:1px solid #21262d; font-size:14px; }
th { color:#8b949e; font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.4px; }
tr:last-child td { border-bottom:none; }
td.port { font-family:ui-monospace,Menlo,Consolas,monospace; color:#58a6ff; }
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
    open_ports = summary.get("open_ports", [])
    web_targets = summary.get("web_targets", [])
    subdomains = summary.get("subdomains", [])
    modules = summary.get("modules", {})

    # Açık portlar tablosu
    if open_ports:
        rows = "".join(
            f"<tr><td class='port'>{_esc(op.get('port'))}/{_esc(op.get('proto'))}</td>"
            f"<td>{_esc(op.get('service'))}</td>"
            f"<td>{_esc(op.get('product')) or '<span class=muted>—</span>'}</td>"
            f"<td class='muted'>{_esc(op.get('host'))}</td></tr>"
            for op in open_ports
        )
    else:
        rows = "<tr><td colspan='4' class='muted'>Açık port bulunamadı.</td></tr>"
    ports_html = (
        "<table><thead><tr><th>Port</th><th>Service</th><th>Product</th>"
        f"<th>Host</th></tr></thead><tbody>{rows}</tbody></table>"
    )

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
        "<table><thead><tr><th>Module</th><th>Status</th><th>Note</th></tr></thead>"
        f"<tbody>{mod_rows}</tbody></table>"
    )

    # Subdomain (varsa)
    subs_section = ""
    if subdomains:
        items = "".join(f"<li>{_esc(s)}</li>" for s in subdomains)
        subs_section = (
            f"<h2>Subdomains ({len(subdomains)})</h2>"
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
  <h1><span class="logo">🛰️ Skopos</span> report</h1>
  <div class="sub">Reconnaissance results for <b>{_esc(target)}</b></div>
  <div class="meta">
    <span class="pill">target <b>{_esc(target)}</b></span>
    <span class="pill">started <b>{_esc(started)}</b></span>
    <span class="pill">open ports <b>{len(open_ports)}</b></span>
    <span class="pill">modules <b>{len(modules)}</b></span>
  </div>
</header>

<h2>Open ports</h2>
<div class="card">{ports_html}</div>

<h2>Web targets</h2>
{web_html}

{subs_section}

<h2>Modules</h2>
<div class="card">{modules_html}</div>

<h2>Raw output</h2>
{logs_html}

<footer>Generated by Skopos — for authorized security testing only.</footer>
</div></body></html>"""

    path = os.path.join(run_dir, "report.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path
