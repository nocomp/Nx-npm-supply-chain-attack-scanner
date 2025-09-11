# Supply-chain NPM Scanner

Detect compromised NPM dependencies across **web front-ends** and **local disks/servers** — at scale.  
Supports **batch web scanning** via **domain → subdomains** (from CT logs and/or **DNS brute-force with a custom nameserver**), file of URLs, parallel scanning, colorized console triage, and a single aggregated report.

---

## 🔁 Highlights

- `--domain example.com` → enumerate subdomains from **crt.sh** (Certificate Transparency).
- `--ns 10.0.0.53` → also brute-force subdomains via **DNS** using a **specific DNS server** (ideal for **intranet**).
- `--dns-wordlist words.txt` → custom wordlist for DNS brute-force (defaults to a curated small list).
- `--file urls.txt` → scan one URL/host per line.
- `--workers N` → parallelize web scans; `--dns-workers N` → parallel DNS queries.
- Colorized console: **red** (compromised), **yellow** (suspicious/obfuscation), **green** (clean).
- Aggregated **HTML + JSON** report per run.

> ℹ️ The DNS brute-force **does not** attempt zone transfers. It simply resolves `label.domain` for a set of labels (wordlist). If the DNS has **wildcard** enabled, the scanner detects it and warns.

---

## 📛 Report naming (auto)

- **Web (single)** → `report_{WEBHOST}__web_{YYYYmmdd_HHMMSS}.html/json`  
- **Web (batch)** → `report_{FIRSTHOST}+{N-1}__webbatch_{YYYYmmdd_HHMMSS}.html/json`  
- **Local (1 path)** → `report_{HOSTNAME}__{DIRNAME}_{YYYYmmdd_HHMMSS}.html/json`  
- **Local (multi)** → `report_{HOSTNAME}__multi_{YYYYmmdd_HHMMSS}.html/json`  

Override with `--report-prefix` if needed.

---

## 📦 Install

```bash
git clone https://github.com/YOURNAME/supplychain-npm-scanner.git
cd supplychain-npm-scanner
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
Python 3.8+. PyYAML is recommended for PNPM lockfiles.
dnspython is required for --ns (DNS brute-force).

🚀 Usage
Powershell script:
# Scan specific drive
PowerShell -ExecutionPolicy Bypass -File ".\simple_scanner.ps1" -Path "C:\projets\mon-app" -HtmlReport

# Scan many drives
PowerShell -ExecutionPolicy Bypass -File ".\simple_scanner.ps1" -Path "C:\Users\nocom\Documents", "D:\projets" -HtmlReport
1) Web — single URL
bash
Copier le code
python3 supplychain_scanner.py web --url https://app.example.com/
2) Web — domain → subdomains (CT logs only)
bash
Copier le code
python3 supplychain_scanner.py web --domain example.com --workers 10
# Add --limit 200 to cap CT-derived subdomains
3) Web — domain with DNS brute-force (intranet)
bash
Copier le code
# Use a specific DNS server (e.g., corporate resolver) and an optional wordlist
python3 supplychain_scanner.py web --domain corp.local --ns 10.0.0.53 \
  --dns-wordlist words.txt --dns-workers 32 --scheme http
# --scheme controls the URL scheme for targets built from hosts (default https)
If you don’t provide --dns-wordlist, a small default list of common labels is used.
If wildcard DNS is detected, the scanner prints a notice (results may include wildcard matches).

4) Web — file of URLs
bash
Copier le code
# urls.txt contains one URL or host per line (scheme optional)
python3 supplychain_scanner.py web --file urls.txt --workers 8
5) Local — disks/servers
bash
Copier le code
python3 supplychain_scanner.py local /srv/app1 /var/lib/jenkins/workspace
Outputs go to ./scanner_output/reports/ (HTML + JSON).
Downloaded bundles go under ./scanner_output/web_dumps/<host>/.

🔍 Default Indicators
Known compromised versions (Sept 8, 2025)
kotlin
Copier le code
debug@4.4.2
chalk@5.6.1
ansi-styles@6.2.2
strip-ansi@7.1.1
color-convert@3.1.1
ansi-regex@6.2.1
supports-color@10.2.1
wrap-ansi@9.0.1
slice-ansi@7.1.1
color-name@2.0.1
color-string@2.1.1
has-ansi@6.0.1
supports-hyperlinks@4.1.1
chalk-template@1.1.1
backslash@0.2.1
is-arrayish@0.3.3
error-ex@1.3.3
simple-swizzle@0.2.3
Suspicious code patterns (regex)
Web3 probing & environment checks:

rust
Copier le code
typeof\s+window\s*!==\s*['"]undefined['"]
typeof\s+window\.ethereum\s*!==\s*['"]undefined['"]
window\.ethereum\.request\(\{\s*['"]method['"]\s*:\s*['"]eth_accounts['"]\s*\}\)
ethereum\.request\(
walletconnect|metamask|phantom\.|solana\.|keplr\.
Obfuscation hints:

r
Copier le code
new\s+Function\(
atob\(
fromCharCode\([^)]{0,80}\)
const\s+0x[0-9a-fA-F]+\s*=\s*0x[0-9a-fA-F]+;\s*\(function\(\s*_0x[0-9a-fA-F]+,\s*_0x[0-9a-fA-F]+\)\{
_0x[0-9a-fA-F]{4,}\(
Explicit malicious obfuscation snippet
Exact (verbatim):

javascript
Copier le code
const _0x112fa8=_0x180f;(function(_0x13c8b9,_0_35f660){const _0x15b386=_0x180f,
Relaxed regex:

php
Copier le code
const\s+_0x112fa8\s*=\s*_0x180f;\s*\(function\(\s*_0x13c8b9\s*,\s*_0_35f660\s*\)\s*\{\s*const\s+_0x15b386\s*=\s*_0x180f\s*,
IOC reference (for IR)
Compromise window (UTC): 2025-09-08 ~13:00–17:00

Phishing domain: npmjs.help

🖥️ Console triage (colors)
Red → compromised versions detected in bundles

Yellow → suspicious patterns and/or obfuscation snippet hits

Green → no issues found for that target

📊 Report contents
KPIs (sum across targets): bundles analyzed, suspicious hits, compromised hits, obfuscation hits (exact/relaxed), local hits

Per-target web sections with pages, bundles, matches and hashes

Local scan section listing each hit (package, version, location, type)

IOC table + known compromised versions reference

🧯 Remediation
Pin/override to safe versions; rebuild with npm ci

Purge old bundles and invalidate CDN if they were built in the compromise window

Enforce **2FA
