"""
Bulgulardan "önerilen sonraki adımlar" üretir.
Açık portlar + web varlıkları + tespit edilen teknolojilere bakıp
kullanıcının taramadan sonra atacağı mantıklı adımları önerir.
"""


def build_suggestions(summary):
    """summary'den [{text, cmd?}] listesi üretir."""
    target = summary.get("target", "")
    ports = summary.get("open_ports", [])
    web = summary.get("web_assets", [])
    # URL hedefte (nmap çalışmadıysa) hedefi web varlığı say ki öneri boş kalmasın
    if not web and target.startswith("http"):
        web = [{"host": target, "url": target, "tech": [], "server": ""}]
    services = {op.get("service", "") for op in ports}
    portnums = {op.get("port") for op in ports}
    sugg = []

    # --- Web varlıkları ---
    for wa in web:
        techs = ", ".join(wa.get("tech") or []) or "web"
        sugg.append({
            "text": f"Web uygulaması ({techs}) — tarayıcıda aç: {wa['url']}",
            "cmd": f"python3 -m skopos -t {wa['host']} -m fuzzing,web -p normal",
        })
        low = (techs + " " + (wa.get("server") or "")).lower()
        if "wordpress" in low:
            sugg.append({"text": "WordPress → eklenti/kullanıcı taraması",
                         "cmd": f"wpscan --url {wa['url']} --enumerate u,vp"})
        if "jenkins" in low:
            sugg.append({"text": "Jenkins → /script konsolu ve bilinen RCE'leri dene"})
        if "grafana" in low:
            sugg.append({"text": "Grafana → CVE-2021-43798 path traversal dene"})
        if "gitlab" in low or "gitea" in low:
            sugg.append({"text": "Git servisi → açık repolar / kayıt açık mı kontrol et"})
        if "tomcat" in low:
            sugg.append({"text": "Tomcat → /manager (default creds) ve WAR upload dene"})
        if "phpmyadmin" in low:
            sugg.append({"text": "phpMyAdmin → varsayılan/zayıf DB kimlik bilgisi dene"})

    # --- Diğer servisler ---
    if "ssh" in services or 22 in portnums:
        sshv = next((f"{op.get('product','')} {op.get('version','')}".strip()
                     for op in ports if op.get("service") == "ssh"), "")
        sugg.append({"text": f"SSH açık ({sshv}) — sürüm zafiyeti ara / zayıf kimlik dene",
                     "cmd": "searchsploit openssh"})
    if "ftp" in services or 21 in portnums:
        sugg.append({"text": "FTP açık — anonim giriş dene",
                     "cmd": f"ftp {target}"})
    if portnums & {139, 445} or {"microsoft-ds", "netbios-ssn"} & services:
        sugg.append({"text": "SMB açık — paylaşım ve kullanıcıları listele",
                     "cmd": f"enum4linux -a {target}"})
    if 3306 in portnums or "mysql" in services:
        sugg.append({"text": "MySQL açık — varsayılan/zayıf kimlik bilgisi dene"})
    if 3389 in portnums or "ms-wbt-server" in services:
        sugg.append({"text": "RDP açık — kimlik bilgisi / BlueKeep (CVE-2019-0708) kontrol et"})
    if {389, 636, 88} & portnums:
        sugg.append({"text": "LDAP/Kerberos açık — Active Directory ortamı olabilir, "
                             "bloodhound modülünü düşün"})

    if not sugg:
        sugg.append({"text": "Belirgin bir sonraki adım çıkmadı — "
                             "-p- ile tüm portları tara ya da -sC/-sV ekleyerek derinleş."})
    return sugg
