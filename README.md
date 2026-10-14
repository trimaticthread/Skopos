<div align="center">

# 🛰️ Skopos

**A modular, profile-driven reconnaissance orchestrator for pentesters and bug bounty hunters.**

*Stop typing the same nmap / ffuf / nikto flags by hand. Pick an aggressiveness level, choose your modules, and let Skopos wire the tools together.*

![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux-333)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-alpha-orange)
![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen)

</div>

---

## What is Skopos?

Skopos (Greek *σκοπός* — "watcher, lookout") wraps the tools you already run by
hand — **nmap, ffuf/gobuster, subfinder, whatweb, nikto, nuclei, BloodHound**,
plus built-in OSINT (crt.sh, DNS, live HTTP probing) — behind a single command.
You choose *how aggressive* the scan should be and *which* modules to run;
Skopos builds the correct flags for each tool, **chains results between them**
(nmap's open web ports and discovered subdomains automatically become
probe / fuzzing / nuclei targets), and then **opens a live web viewer** where
every finding is one filterable, severity-rated list with plain-language headings.

The whole thing is built around one idea: **adding a new tool should be writing
a single file.** Every module shares the same profiles, output pipeline,
credential redaction, unified findings model and resource auto-download for free.

```bash
# One line: full recon on a target, aggressive profile, then open the viewer
python -m skopos -t 10.10.10.5 -p aggressive --serve --serve-host 0.0.0.0
```

## ✨ Features

- 🖥️ **Live web viewer** — `skopos serve` (or `--serve` right after a scan) opens a dependency-free localhost page listing every run; per run, findings are grouped under plain-language headings with clickable severity badges, category chips and free-text search — filter down or show everything. Live mode refreshes while a scan is still writing.
- 🎯 **Unified findings model** — every module's raw output is reduced to one severity-rated `Finding` schema (`info → critical`), so the viewer's colours and filters reflect real risk and new modules light up the UI for free.
- 🛰️ **Built-in OSINT** — passive subdomains from crt.sh, DNS records (`dig`), and a threaded live-HTTP probe (pure Python, no extra binary) that validates discovered hosts and **feeds them back into the scan chain** so subdomains are no longer a dead end.
- 🧩 **Plugin architecture** — a new tool is one file + `@register`, auto-discovered at runtime. Shell-out *or* pure-Python (`native`) modules. No wiring, no registries to edit.
- 🎚️ **Aggressiveness profiles** — `stealth` / `normal` / `aggressive` tune timing, threads, wordlist size, port range, NSE scripts, nuclei severity floor and probe depth across *every* module from one place.
- 🔗 **Result chaining** — nmap derives web targets; subdomain/crt.sh gather hosts; probe confirms which are live; fuzzing / web / nuclei scan the enriched set — all via a shared context.
- 🎛️ **Escape hatch** — pass *any* raw tool flag with `-x 'nmap=-sU --min-rate 5000'`. Nothing is locked behind named knobs; the full parameter surface stays reachable.
- 📦 **Auto-fetch resources** — missing wordlists are downloaded on demand from SecLists (HTTPS only), cached locally.
- 🩺 **Environment doctor** — `--setup` reports every missing tool with the exact install command and pre-downloads wordlists.
- 🔒 **Safe by design** — `shell=False` everywhere (no command injection), real wall-clock command timeouts, passwords redacted from logs and dry-runs, downloads restricted to `https`, the viewer binds `127.0.0.1` by default and is never exposed to the VPN.
- 📄 **Structured output** — per-module logs plus a machine-readable `summary.json` (open ports, web assets, findings, severity counts) for every run.

## 🚀 Quick start

> Skopos itself is cross-platform Python; the tools it wraps run on Linux.
> **Kali / Parrot** ship most of them already.

```bash
# 1. Clone
git clone https://github.com/trimaticthread/Skopos.git && cd Skopos

# 2. Install the only dependency (PyYAML).
#    On Kali/Debian the environment is externally managed (PEP 668),
#    so use the system package:
sudo apt install -y python3-yaml
#    …or, on any other system / to keep things isolated, a virtualenv:
#    python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt

# 3. Check your environment: what's installed, what's missing, fetch wordlists
python3 -m skopos --setup

# 4. First scan (scanme.nmap.org is Nmap's official legal test host)
python3 -m skopos -t scanme.nmap.org -m nmap -p normal
```

Prefer a real `skopos` command instead of `python -m skopos`? Install it with
[pipx](https://pipx.pypa.io/) (works cleanly on externally-managed Kali):

```bash
pipx install -e .   # now just run:  skopos -t <target> ...
```

## 🖥️ Live results viewer

Skopos writes a machine-readable `summary.json` for every run; `skopos serve`
turns the whole `output/` tree into a single, filterable web page — no
database, no build step, no dependencies (pure stdlib `http.server`).

```bash
# Scan, then open the viewer automatically when it finishes
python3 -m skopos -t 10.10.11.5 -p aggressive --serve --open

# Or browse everything you've already scanned
python3 -m skopos serve                 # http://127.0.0.1:8777
python3 -m skopos serve --host 0.0.0.0 --port 8777   # reachable from your LAN/VPN
```

In the page you get, per run: clickable **severity badges** (critical → info),
**category chips** (ports, web, content, vulns, subdomains, DNS, …) and a
**search box** — stack them to filter, or hit *"show everything"*. Suggested
next steps and the raw tool logs are one click away. Turn on **live mode** and
the page refreshes itself while a scan is still running.

> By default the viewer binds `127.0.0.1` (local only). Pass `--serve-host` /
> `--host` to expose it — e.g. a Tailscale IP to reach it from your laptop.
> It is read-only and never triggers scans.

## 🎚️ Profiles

Every profile carries per-module knobs, defined in
[`config/default.yaml`](config/default.yaml). Copy it and pass `-c my.yaml` to
override anything.

| Profile        | nmap                         | fuzzing              | web         | nuclei      | bloodhound |
| -------------- | ---------------------------- | -------------------- | ----------- | ----------- | ---------- |
| **stealth**    | `-T2`, top-100 ports         | 10 threads, small WL | nikto off   | high+       | `DCOnly`   |
| **normal**     | `-T4`, top-1000, `-sC`       | 40 threads, med WL   | nikto on    | medium+     | `Default`  |
| **aggressive** | `-T4 -p- -A`, `vuln` scripts | 100 threads, big WL  | nikto on    | all sev.    | `All`      |

## 🧩 Modules

| Module       | Wraps                    | Purpose                                             |
| ------------ | ------------------------ | --------------------------------------------------- |
| `dns`        | dig                      | DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA)             |
| `nmap`       | nmap                     | Port + service/version scan, deep XML parsing       |
| `subdomain`  | subfinder                | Subdomain enumeration (active)                      |
| `crtsh`      | *(pure Python)*          | Passive subdomains from crt.sh certificate logs     |
| `probe`      | *(pure Python)*          | Threaded live-HTTP probe; feeds live hosts to the chain |
| `fuzzing`    | ffuf / gobuster          | Web content (directory/file) discovery              |
| `web`        | whatweb + nikto          | Tech fingerprinting + web vuln scan                 |
| `nuclei`     | nuclei                   | Template-based vulnerability scan (real severities) |
| `bloodhound` | bloodhound-python        | Active Directory data collection *(authenticated)*  |

Modules marked *pure Python* are `native` — they need no external binary and
run entirely in-process (see [Adding a new tool](#-adding-a-new-tool-the-whole-point)).

```bash
python3 -m skopos --list-modules    # see everything registered, with requirements
```

## 🧪 Usage examples

```bash
# Specific modules against a domain
python3 -m skopos -t example.com -m nmap,subdomain,web

# Quiet, low-noise port scan only
python3 -m skopos -t 10.10.10.5 -p stealth -m nmap

# See exactly what would run — without running anything
python3 -m skopos -t example.com --dry-run

# Scan many targets from a file, auto-download any missing wordlists
python3 -m skopos -tL targets.txt -p normal --auto-fetch -y
```

### Sample output

```
========================================
  TARGET: scanme.nmap.org   (output: output/scanme.nmap.org/20260723_2148)
========================================

======================
  Module: nmap — Port and service/version scan
======================
[*] Running: nmap -sV -Pn -T3 --version-intensity 5 --top-ports 1000 --script=default ...
[+] 3 open ports found.
[*]   22/tcp   ssh (OpenSSH 6.6.1p1)
[*]   80/tcp   http (Apache httpd 2.4.7)
[*]   9929/tcp nping-echo
[+] Web targets derived: http://scanme.nmap.org:80
[+] Summary written: output/scanme.nmap.org/20260723_2148/summary.json
```

## 🧙 Interactive mode — build a scan by picking parameters

Don't remember every flag? Run the wizard. Skopos shows each tool's parameters
grouped by intent, each with a plain-language explanation and **context tags**
(`[CTF]`, `[kırmızı takım]`, `[root]`, `[sessiz]`, `[yavaş]`) so you learn *when*
to use them. You pick numbers, it asks for any values, then runs the scan.

```bash
python3 -m skopos -t 10.10.11.5 -m nmap -i
```

```
▸ Tarama Tipi
   1) -sS   SYN taraması — hızlı, yarı-açık, görece sessiz     [root] [sessiz]
   ...
▸ Port Kapsamı
   5) -p-           Tüm 65535 portu tara — HTB'de standart     [CTF] [yavaş]
   6) --top-ports   En yaygın N port (değer sorulacak)         [hızlı]
▸ Firewall/IDS Atlatma
  19) -Pn           Host'u online say, keşif atla              [kırmızı takım]

  Seç (ör. 1,4,7-9): 1,6,9,10,15,19
    → --top-ports için Kaç port? 1000
```

Selection accepts commas, spaces and ranges (`1,4,7-9`). At the end you can
**name the scan** — results are stored under that name
(`output/<name>/<target>/...`) and, if you choose, the exact selection is saved
as a reusable profile:

```bash
python3 -m skopos -t 10.10.11.9 -p htb-quick    # replays your saved selection
```

## 🔌 Adding a new tool (the whole point)

Want `crackmapexec`, `nuclei`, `amass` or `sqlmap`? Drop one file in
`skopos/modules/`:

```python
from ..module_base import BaseModule, Command, register

@register
class NucleiModule(BaseModule):
    name = "nuclei"
    description = "Template-based vulnerability scanner"
    requires = ["nuclei"]

    def build_commands(self):
        p = self.pcfg                       # this module's profile settings
        url = self.ctx.get("web_targets", [self.target])[0]
        argv = ["nuclei", "-u", url, "-c", str(p.get("threads", 25))]
        argv += self.extra_args()           # inherits the -x escape hatch for free
        return [Command(label="scan", argv=argv)]
```

That's it. It's auto-discovered, inherits profiles, credential redaction,
`--dry-run`, output handling and the `-x` escape hatch — no other file changes.
Read from `self.ctx` to consume what earlier modules discovered; write to it to
share with later ones.

## 🎛️ The escape hatch: every flag stays reachable

Profiles expose the *common* knobs. For anything else, pass raw arguments —
from the CLI or from YAML — and they're appended on top:

```bash
python3 -m skopos -t 10.10.10.5 -m nmap,fuzzing \
  -x 'nmap=-sU --source-port 53' \
  -x 'fuzzing=-mc 200,301,403 -recursion -recursion-depth 2'
```

```yaml
# config/default.yaml
profiles:
  aggressive:
    nmap:
      extra_args: ["-sU", "--min-rate", "5000"]
```

## 📂 Output layout

```
output/[<profile>/]<target>/<timestamp>/
├── nmap_portscan.log      # raw output of each command
├── nmap.xml               # parsed nmap XML
├── fuzzing_dirscan0.log
├── nuclei.jsonl           # structured nuclei results
├── probe_probe.log        # live-HTTP probe results
├── ozet.txt               # curated, human-readable summary
├── report.html            # self-contained static report
└── summary.json           # open ports, web assets, findings[], severity_counts, status
```

The live viewer (`skopos serve`) reads these `summary.json` files directly, so
every past run is browsable without re-scanning.

## 🗺️ Roadmap

- [x] Test suite (stdlib `unittest`, no deps) — characterization + unit tests
- [x] Unified, severity-rated findings model across all modules
- [x] Live, filterable web viewer (`skopos serve`)
- [x] Built-in OSINT: crt.sh, DNS, live HTTP probe
- [x] `nuclei` module (template-based vuln scanning)
- [x] Real wall-clock command timeouts
- [ ] CI (run the test suite on push)
- [ ] Parallel execution across independent modules / targets
- [ ] Scope guard (refuse out-of-scope targets)
- [ ] Shodan / Censys OSINT (API-key, optional)
- [ ] More modules: `crackmapexec`/`netexec`, `enum4linux`, `katana`

## ⚖️ Disclaimer & legal use

Skopos is provided strictly for **authorized security testing and educational
purposes**.

- Use it **only** against systems you **own** or have **explicit, written
  permission** to test — your own lab, contracted engagements, CTFs, or bug
  bounty programs within their defined scope.
- Running these scans against systems without authorization is **illegal** in
  most jurisdictions and may carry criminal penalties.
- The `bloodhound` module requires valid Active Directory credentials and is
  intended for authorized AD assessments only.

> **The author assumes no responsibility or liability for any misuse, damage, or
> illegal activity carried out with this tool — including use by third parties
> into whose hands it may fall.** Skopos is distributed "as is", without warranty
> of any kind (see [LICENSE](LICENSE)). By downloading or using it you accept
> full responsibility for your own actions and agree to comply with all
> applicable laws. If you do not agree, do not use this software.

## 📜 License

MIT — see [LICENSE](LICENSE).
