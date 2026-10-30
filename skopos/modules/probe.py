"""
Canlı HTTP probe modülü (pür-Python, harici araç gerektirmez).

Amaç: nmap'in bulduğu web portları + keşfedilen subdomainler + ham hedef
için gerçek bir HTTP isteği atıp hangilerinin CANLI olduğunu, durum kodunu,
başlığını, Server header'ını ve teknolojisini çıkarmak. Böylece:
  * Subdomain/web keşfi "ölü uç" olmaktan çıkar — canlı olanlar doğrulanır.
  * Bulunan canlı web adresleri zincire (web_targets) eklenir; fuzzing/web
    modülleri bunları da tarar.
Yalnızca stdlib (urllib) kullanır. Kendinden-imzalı sertifikaları (HTB/lab)
probe edebilmek için TLS doğrulaması kapatılır — bu bilinçli bir recon tercihidir.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from ..module_base import BaseModule, register
from .. import utils

# Gövde/Server içinde aranan teknoloji imzaları (kelime sınırıyla eşleşir)
_TECH = ("WordPress", "Drupal", "Joomla", "Django", "Flask", "Express",
         "Laravel", "Spring", "Tomcat", "Jetty", "nginx", "Apache", "IIS",
         "Jenkins", "Grafana", "Kibana", "phpMyAdmin", "GitLab", "Gitea",
         "Werkzeug", "Next.js", "Nuxt", "React", "Angular", "Vue", "Node.js")


def _unverified_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


@register
class ProbeModule(BaseModule):
    name = "probe"
    description = "Canlı HTTP probe (durum/başlık/teknoloji) — araç gerekmez"
    requires = []
    native = True

    def _candidates(self):
        """Probe edilecek benzersiz URL listesini toplar (nmap + subdomain + hedef)."""
        urls, seen = [], set()

        def add(u):
            if not u:
                return
            u = u.rstrip("/")
            if u not in seen:
                seen.add(u)
                urls.append(u)

        for u in self.ctx.get("web_targets", []) or []:
            add(u)
        for sub in self.ctx.get("subdomains", []) or []:
            add("http://" + sub)
            add("https://" + sub)

        t = self.target
        if t.startswith(("http://", "https://")):
            add(t)
        elif not self.ctx.get("web_targets"):
            # nmap web hedefi yoksa ham hedefi en azından http olarak dene
            add("http://" + t)

        max_hosts = int(self.pcfg.get("max_hosts", 60) or 60)
        return urls[:max_hosts]

    def _probe_one(self, url, timeout):
        req = urllib.request.Request(url, headers={"User-Agent": "skopos-probe/1.0"})
        status, server, xpb, body, final = None, "", "", "", url
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=_unverified_ctx()) as resp:
                status = getattr(resp, "status", resp.getcode())
                final = resp.geturl()
                server = resp.headers.get("Server", "") or ""
                xpb = resp.headers.get("X-Powered-By", "") or ""
                raw = resp.read(24576)
                body = raw.decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                server = exc.headers.get("Server", "") or ""
            except Exception:
                server = ""
        except (urllib.error.URLError, ssl.SSLError, OSError, ValueError):
            return None  # canlı değil / erişilemedi

        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]

        tech, seen = [], set()
        if xpb:
            v = xpb.split(",")[0].strip()[:40]
            if v:
                tech.append(v); seen.add(v.lower())
        blob = server + " " + body
        for kw in _TECH:
            if kw.lower() not in seen and re.search(r"\b" + re.escape(kw) + r"\b", blob, re.I):
                tech.append(kw); seen.add(kw.lower())

        return {"url": url, "final_url": final, "status": status,
                "server": server.strip()[:60], "title": title, "tech": tech[:8]}

    def native_run(self):
        candidates = self._candidates()
        if not candidates:
            utils.info("probe: denenecek web adresi yok.")
            return

        timeout = float(self.pcfg.get("timeout", 6) or 6)
        threads = int(self.pcfg.get("threads", 20) or 20)
        utils.info(f"probe: {len(candidates)} adres deneniyor "
                   f"(timeout {timeout:g}s, {threads} thread)...")

        results = []
        with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
            for res in pool.map(lambda u: self._probe_one(u, timeout), candidates):
                if res:
                    results.append(res)

        # Mevcut web_assets'te olmayan canlı adresleri ekle + zincire besle
        existing = {wa.get("url") for wa in self.ctx.get("web_assets", []) or []}
        web_targets = self.ctx.setdefault("web_targets", [])
        live = []
        log_lines = []
        for r in results:
            live.append(r)
            log_lines.append(f"[{r['status']}] {r['url']}  "
                             f"{('-> ' + r['final_url']) if r['final_url'] != r['url'] else ''}  "
                             f"{r['server']}  {('[' + ', '.join(r['tech']) + ']') if r['tech'] else ''}  "
                             f"{r['title']}".rstrip())
            if r["url"] not in existing:
                self.ctx.setdefault("web_assets", []).append({
                    "host": re.sub(r"^https?://", "", r["url"]).split(":")[0],
                    "port": "", "url": r["url"], "server": r["server"],
                    "tech": r["tech"], "title": r["title"],
                })
                existing.add(r["url"])
            if r["url"] not in web_targets:
                web_targets.append(r["url"])

        self.ctx["probe"] = live
        self.write_log("probe", "# skopos probe — canlı HTTP adresleri\n\n"
                       + ("\n".join(log_lines) if log_lines else "(canlı adres yok)") + "\n")

        if live:
            utils.good(f"probe: {len(live)} canlı web adresi.")
            for r in live[:12]:
                tech = f"  [{', '.join(r['tech'])}]" if r["tech"] else ""
                utils.info(f"  [{r['status']}] {r['url']}{tech}")
        else:
            utils.info("probe: canlı web adresi bulunamadı.")
