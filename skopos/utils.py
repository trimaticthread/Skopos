"""Yardımcı fonksiyonlar: renkli log, binary tespiti, komut çalıştırma."""

import os
import shutil
import subprocess
import sys
import time

# --- Basit ANSI renkler (Windows 10+ ve Linux terminallerinde çalışır) ---
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class C:
    RESET = "\033[0m" if _USE_COLOR else ""
    BOLD = "\033[1m" if _USE_COLOR else ""
    DIM = "\033[2m" if _USE_COLOR else ""
    RED = "\033[31m" if _USE_COLOR else ""
    GREEN = "\033[32m" if _USE_COLOR else ""
    YELLOW = "\033[33m" if _USE_COLOR else ""
    BLUE = "\033[34m" if _USE_COLOR else ""
    CYAN = "\033[36m" if _USE_COLOR else ""


def info(msg):
    print(f"{C.CYAN}[*]{C.RESET} {msg}")


def good(msg):
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def warn(msg):
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def err(msg):
    print(f"{C.RED}[-]{C.RESET} {msg}")


def banner(msg):
    line = "=" * (len(msg) + 4)
    print(f"\n{C.BOLD}{C.BLUE}{line}\n  {msg}\n{line}{C.RESET}")


def which(binary):
    """Harici aracın PATH'te olup olmadığını döndürür (yol ya da None)."""
    return shutil.which(binary)


def stream_command(argv, logfile=None, timeout=None, redact=None):
    """
    Komutu çalıştırır; çıktıyı hem ekrana hem (verilmişse) dosyaya yazar.
    argv   : liste halinde komut (shell=False, injection'a karşı güvenli).
    redact : ekran/log gösteriminde '***' ile maskelenecek değerler (ör. parola).
             Sadece gösterimi etkiler; komut gerçek değerle çalışır.
    Dönüş: (return_code, birleşik_çıktı)
    """
    display = list(argv)
    for secret in (redact or []):
        if secret:
            display = ["***" if a == secret else a for a in display]
    printable = " ".join(display)
    info(f"Çalıştırılıyor: {C.DIM}{printable}{C.RESET}")

    collected = []
    start = time.time()
    fh = open(logfile, "w", encoding="utf-8", errors="replace") if logfile else None
    if fh:
        fh.write(f"# komut: {printable}\n\n")

    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        err(f"Komut bulunamadı: {argv[0]}")
        if fh:
            fh.close()
        return 127, ""

    try:
        for line in proc.stdout:
            sys.stdout.write(line)
            collected.append(line)
            if fh:
                fh.write(line)
            if timeout and (time.time() - start) > timeout:
                proc.kill()
                warn(f"Zaman aşımı ({timeout}s), süreç sonlandırıldı.")
                break
        proc.wait()
    except KeyboardInterrupt:
        proc.kill()
        warn("Kullanıcı tarafından iptal edildi (Ctrl+C).")
        raise
    finally:
        if fh:
            fh.close()

    return proc.returncode, "".join(collected)
