"""
Canlı sonuç sunucusu.

`skopos serve` ile başlar; output/ altındaki tüm taramaları (summary.json)
okuyup tek bir web arayüzünde sunar. Kullanıcı tarama başına sonuçları
filtreleyebilir, arayabilir, kategori/severity'ye göre süzebilir ya da
hepsini birden görebilir. Yalnızca stdlib (http.server) kullanır — ek
bağımlılık yoktur.

Güvenlik:
  * Varsayılan olarak 127.0.0.1'e bağlanır (yalnızca yerel). Uzaktan erişim
    için --host ile açıkça bir adres verilmelidir (ör. Tailscale IP'si);
    0.0.0.0 vermedikçe VPN/HTB arayüzüne açılmaz.
  * Log/okuma uçlarında path-traversal'a karşı run dizini doğrulanır.
  * Sunucu sadece okur; hiçbir taramayı tetiklemez, hiçbir şey silmez.
"""

from __future__ import annotations

import glob
import json
import os
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import utils

ASSETS = os.path.join(os.path.dirname(__file__), "assets")


def _runs_index(output_root):
    """output/**/summary.json dosyalarından hafif bir tarama listesi üretir."""
    runs = []
    pattern = os.path.join(output_root, "**", "summary.json")
    for f in glob.glob(pattern, recursive=True):
        try:
            with open(f, encoding="utf-8") as fh:
                s = json.load(fh)
        except (OSError, ValueError):
            continue
        rel = os.path.relpath(os.path.dirname(f), output_root).replace(os.sep, "/")
        try:
            mtime = os.path.getmtime(f)
        except OSError:
            mtime = 0
        runs.append({
            "id": rel,
            "target": s.get("target", ""),
            "profile": s.get("profile"),
            "started": s.get("started", ""),
            "open_ports": len(s.get("open_ports", [])),
            "web_assets": len(s.get("web_assets", [])),
            "findings": len(s.get("findings", [])),
            "severity_counts": s.get("severity_counts", {}),
            "mtime": mtime,
        })
    runs.sort(key=lambda r: (r["started"], r["mtime"]), reverse=True)
    return runs


def _safe_run_dir(output_root, run_id):
    """run_id'yi output_root altında güvenli bir dizine çözer (path-traversal yok)."""
    if not run_id:
        return None
    candidate = os.path.normpath(os.path.join(output_root, run_id.replace("/", os.sep)))
    root = os.path.normpath(output_root)
    if candidate != root and not candidate.startswith(root + os.sep):
        return None
    if not os.path.isfile(os.path.join(candidate, "summary.json")):
        return None
    return candidate


class _Handler(BaseHTTPRequestHandler):
    output_root = "output"

    def log_message(self, *args):  # sunucu loglarını sustur
        pass

    # --- yardımcılar ---
    def _send_bytes(self, code, data, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code, obj):
        self._send_bytes(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                         "application/json; charset=utf-8")

    def _text(self, code, text):
        self._send_bytes(code, text.encode("utf-8"),
                         "text/plain; charset=utf-8")

    def _asset(self, name, ctype):
        fp = os.path.join(ASSETS, os.path.basename(name))
        if not os.path.isfile(fp):
            return self._json(404, {"error": "asset yok"})
        with open(fp, "rb") as fh:
            self._send_bytes(200, fh.read(), ctype)

    # --- yönlendirme ---
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        q = urllib.parse.parse_qs(parsed.query)
        rid = (q.get("id") or [""])[0]

        if path in ("/", "/index.html"):
            return self._asset("index.html", "text/html; charset=utf-8")
        if path == "/static/app.js":
            return self._asset("app.js", "application/javascript; charset=utf-8")
        if path == "/static/style.css":
            return self._asset("style.css", "text/css; charset=utf-8")

        if path == "/api/runs":
            return self._json(200, _runs_index(self.output_root))

        if path == "/api/run":
            d = _safe_run_dir(self.output_root, rid)
            if not d:
                return self._json(404, {"error": "tarama bulunamadı"})
            with open(os.path.join(d, "summary.json"), encoding="utf-8") as fh:
                return self._json(200, json.load(fh))

        if path == "/api/logfiles":
            d = _safe_run_dir(self.output_root, rid)
            if not d:
                return self._json(404, {"error": "tarama bulunamadı"})
            logs = sorted(x for x in os.listdir(d) if x.endswith(".log"))
            return self._json(200, logs)

        if path == "/api/log":
            d = _safe_run_dir(self.output_root, rid)
            fn = os.path.basename((q.get("file") or [""])[0])
            if not d or not fn:
                return self._json(404, {"error": "tarama/dosya yok"})
            fp = os.path.join(d, fn)
            if not os.path.isfile(fp):
                return self._json(404, {"error": "log yok"})
            with open(fp, encoding="utf-8", errors="replace") as fh:
                return self._text(200, fh.read())

        return self._json(404, {"error": "bulunamadı"})


def serve(output_root="output", host="127.0.0.1", port=8777, open_browser=False):
    """Arayüz sunucusunu başlatır (Ctrl+C ile durur)."""
    abs_root = os.path.abspath(output_root)
    os.makedirs(abs_root, exist_ok=True)
    _Handler.output_root = abs_root

    try:
        httpd = ThreadingHTTPServer((host, port), _Handler)
    except OSError as exc:
        utils.err(f"Sunucu başlatılamadı ({host}:{port}): {exc}")
        utils.info("Başka bir port dene: --serve-port <port>")
        return 1

    shown_host = host if host not in ("0.0.0.0", "::") else "<bu-makinenin-ip'si>"
    url = f"http://{shown_host}:{port}/"
    utils.banner("Skopos canlı arayüz")
    utils.good(f"Adres     : {url}")
    utils.info(f"Çıktı     : {abs_root}")
    if host == "127.0.0.1":
        utils.info("Sadece bu makineden erişilir. Uzaktan için: --serve-host <ip>")
    utils.info("Durdurmak için Ctrl+C.")

    if open_browser and host in ("127.0.0.1", "localhost"):
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        utils.warn("Arayüz kapatılıyor.")
    finally:
        httpd.server_close()
    return 0
