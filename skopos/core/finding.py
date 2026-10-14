"""
Birleşik bulgu (Finding) modeli.

Her modülün ham çıktısı er ya da geç tek bir ortak yapıya indirgenir:
severity'si olan, kategorilere ayrılmış, tekilleştirilebilir (dedup) bir bulgu.
Hem canlı web arayüzü hem rapor bu modeli tüketir; böylece filtreleme,
sıralama ve "hepsini göster" tek bir veri şeması üzerinden çalışır.

Tasarım notu: modüller bugün hâlâ summary'ye ham anahtarlar (open_ports,
web_assets, key_findings...) yazıyor. `build_findings(summary)` bunları
Finding'lere çevirir — yani modülleri değiştirmeden arayüze tek tip veri
sağlarız. İleride modüller doğrudan Finding üretebilir; şema aynı kalır.
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import asdict, dataclass, field


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Sıralama/filtre için önem derecesi. Büyük = daha kritik.
_ORDER = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


def severity_rank(sev: str) -> int:
    """Bilinmeyen severity'yi INFO sayar."""
    return _ORDER.get(sev, 0)


@dataclass
class Finding:
    """Tek bir keşif bulgusu. `id` verilmezse içerikten otomatik türetilir."""

    title: str
    severity: str = Severity.INFO.value
    category: str = "info"       # port | web | content | subdomain | host | script | vuln | osint
    source: str = ""             # üreten modül adı
    target: str = ""             # ilgili hedef
    evidence: str = ""           # kısa, insan-okur kanıt
    tags: list = field(default_factory=list)
    refs: list = field(default_factory=list)   # CVE / URL referansları
    data: dict = field(default_factory=dict)   # yapısal alanlar (port, url, status...)
    id: str = ""

    def __post_init__(self):
        if isinstance(self.severity, Severity):
            self.severity = self.severity.value
        if not self.id:
            payload = json.dumps(
                [self.category, self.source, self.target, self.title, self.data],
                sort_keys=True, default=str, ensure_ascii=False,
            )
            self.id = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict:
        return asdict(self)


# --- Port severity sınıflandırması -------------------------------------------
# Çoğu açık port bilgi amaçlıdır; aşağıdakiler görünürlük için 'low' işaretlenir
# (gerçek zafiyet severity'si nuclei gibi modüllerden gelir, buradan değil).
_NOTABLE_PORTS = {
    21: "ftp", 23: "telnet", 139: "smb", 445: "smb", 1433: "mssql",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    6379: "redis", 9200: "elasticsearch", 11211: "memcached",
    27017: "mongodb", 1521: "oracle", 2049: "nfs", 5984: "couchdb",
}
_NOTABLE_SERVICES = {
    "ftp", "telnet", "microsoft-ds", "netbios-ssn", "ms-wbt-server",
    "mysql", "ms-sql-s", "postgresql", "vnc", "redis", "mongodb",
}


def _port_severity(port, service) -> str:
    if port in _NOTABLE_PORTS or (service or "").lower() in _NOTABLE_SERVICES:
        return Severity.LOW.value
    return Severity.INFO.value


def build_findings(summary: dict) -> list:
    """
    summary sözlüğündeki ham keşif verisini Finding dict listesine çevirir.
    Severity'ye göre azalan, sonra kategoriye göre sıralı döner.
    """
    target = summary.get("target", "")
    out: list = []

    def add(f: Finding):
        out.append(f)

    # --- Açık portlar / servisler ---
    for op in summary.get("open_ports", []):
        port = op.get("port")
        proto = op.get("proto", "tcp")
        service = op.get("service") or "?"
        prodver = " ".join(x for x in (op.get("product"), op.get("version"),
                                       op.get("extrainfo")) if x)
        title = f"{port}/{proto} {service}".strip()
        add(Finding(
            title=title,
            severity=_port_severity(port, service),
            category="port",
            source="nmap",
            target=target,
            evidence=prodver,
            tags=[service] if service and service != "?" else [],
            data={"port": port, "proto": proto, "service": service,
                  "product": op.get("product", ""), "version": op.get("version", ""),
                  "host": op.get("host", "")},
        ))

    # --- Web varlıkları ---
    for wa in summary.get("web_assets", []):
        tech = wa.get("tech") or []
        add(Finding(
            title=f"Web varlığı: {wa.get('url', '')}",
            severity=Severity.INFO.value,
            category="web",
            source="nmap/web",
            target=target,
            evidence=(wa.get("title") or wa.get("server") or ""),
            tags=list(tech),
            data={"url": wa.get("url", ""), "server": wa.get("server", ""),
                  "tech": tech, "page_title": wa.get("title", ""),
                  "host": wa.get("host", ""), "port": wa.get("port", "")},
        ))

    # --- İçerik keşfi (ffuf): dizin / dosya / API ---
    key = summary.get("key_findings", {}) or {}
    _CONTENT = [("ffuf_dirs", "Dizin", Severity.LOW.value, "content"),
                ("ffuf_files", "Dosya", Severity.LOW.value, "content"),
                ("ffuf_apis", "API ucu", Severity.MEDIUM.value, "content")]
    for field_name, label, sev, cat in _CONTENT:
        for h in key.get(field_name, []) or []:
            add(Finding(
                title=f"{label}: [{h.get('status')}] {h.get('url', '')}",
                severity=sev,
                category=cat,
                source="fuzzing",
                target=target,
                evidence=f"size {h.get('length')}",
                tags=[label.lower()],
                data={"url": h.get("url", ""), "status": h.get("status"),
                      "length": h.get("length"), "input": h.get("input", "")},
            ))

    # ffuf gürültü notu (ör. vhost/wildcard) — bilgilendirici bulgu
    if key.get("ffuf_note"):
        add(Finding(title="Fuzzing notu", severity=Severity.INFO.value,
                    category="content", source="fuzzing", target=target,
                    evidence=key["ffuf_note"], tags=["note"]))

    # --- Nikto bulguları ---
    nikto_caveat = key.get("nikto_caveat")
    for n in key.get("nikto", []) or []:
        add(Finding(
            title=n if len(n) <= 120 else n[:117] + "...",
            # SPA yanlış-pozitif uyarısı varsa medium yerine low'a çek
            severity=Severity.LOW.value if nikto_caveat else Severity.MEDIUM.value,
            category="vuln",
            source="web/nikto",
            target=target,
            evidence=("SPA — yanlış pozitif olabilir, doğrula" if nikto_caveat else ""),
            tags=["nikto"] + (["spa-caveat"] if nikto_caveat else []),
            data={"raw": n},
        ))

    # --- NSE script bulguları ---
    for s in summary.get("scripts", []) or []:
        add(Finding(
            title=f"NSE {s.get('id')} (port {s.get('port')})",
            severity=Severity.INFO.value,
            category="script",
            source="nmap",
            target=target,
            evidence=s.get("output", ""),
            tags=["nse", str(s.get("id", ""))],
            data={"port": s.get("port"), "id": s.get("id")},
        ))

    # --- Subdomainler ---
    for sub in summary.get("subdomains", []) or []:
        add(Finding(title=f"Subdomain: {sub}", severity=Severity.INFO.value,
                    category="subdomain", source="subdomain", target=target,
                    evidence="", tags=["subdomain"], data={"host": sub}))

    # --- DNS kayıtları ---
    for rtype, values in (summary.get("dns") or {}).items():
        for val in values:
            add(Finding(title=f"{rtype}: {val}", severity=Severity.INFO.value,
                        category="dns", source="dns", target=target,
                        tags=["dns", rtype.lower()], data={"type": rtype, "value": val}))

    # --- OS ipuçları ---
    for os_hint in summary.get("os", []) or []:
        add(Finding(title=f"OS ipucu: {os_hint}", severity=Severity.INFO.value,
                    category="host", source="nmap", target=target,
                    tags=["os"], data={"os": os_hint}))

    # Severity (azalan) sonra kategoriye göre sırala
    out.sort(key=lambda f: (-severity_rank(f.severity), f.category, f.title))
    return [f.to_dict() for f in out]


def severity_counts(findings: list) -> dict:
    """Finding listesinden {severity: adet} sözlüğü üretir (UI rozetleri için)."""
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        sev = f.get("severity", Severity.INFO.value)
        counts[sev] = counts.get(sev, 0) + 1
    return counts
