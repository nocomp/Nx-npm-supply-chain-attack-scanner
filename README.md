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
