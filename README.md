# Supply-chain NPM Scanner

Detect compromised NPM dependencies across **web front-ends** (HTTP/HTTPS bundles) and **local disks/servers** (lockfiles, `node_modules`).  
Generates a clean **HTML + JSON report** per run. Report filenames include the **server hostname** and a **directory label** to make remediation easier.

---

## 📛 Report naming (auto)

- **Web mode** → `report_{WEBHOST}__web_{YYYYmmdd_HHMMSS}.html/json`  
  e.g. `report_app.example.com__web_20250909_141020.html`
- **Local mode (single path)** → `report_{HOSTNAME}__{DIRNAME}_{YYYYmmdd_HHMMSS}.html/json`  
  e.g. `report_build-runner-01__myapp_20250909_141534.json`
- **Local mode (multiple paths)** → `report_{HOSTNAME}__multi_{YYYYmmdd_HHMMSS}.html/json`

You can still override with `--report-prefix`.

---

## 🧭 What it does

- **Web scan**: crawls a site (same-origin), downloads JS/MJS/MAP bundles, searches:
  - known compromised **package@version** hints
  - **suspicious patterns** (Web3/wallet probing, obfuscation)
  - a **specific obfuscation snippet** (exact match **and** relaxed regex)
- **Local scan**: recursively parses:
  - `node_modules/*/package.json`
  - `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` (if PyYAML present)
  - flags exact matches of known compromised versions

---

## 📦 Install

```bash
git clone https://github.com/YOURNAME/supplychain-npm-scanner.git
cd supplychain-npm-scanner
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
Requires Python 3.8+.
PyYAML is recommended to parse PNPM lockfiles.

🚀 Usage
Web mode
bash
Copier le code
python3 supplychain_scanner.py web --url https://example.com/
# Auto outputs:
#   ./scanner_output/reports/report_app.example.com__web_YYYYmmdd_HHMMSS.html
#   ./scanner_output/reports/report_app.example.com__web_YYYYmmdd_HHMMSS.json
# Bundles in: ./scanner_output/web_dumps/app.example.com/
Local mode
bash
Copier le code
# Single path → hostname + dirname in filename
python3 supplychain_scanner.py local /srv/myapp

# Multiple paths → hostname + "multi"
python3 supplychain_scanner.py local /srv/app1 /srv/app2 /var/lib/jenkins/workspace
🔍 Default Indicators (what the scanner looks for)
1) Known compromised versions (Sept 8, 2025)
These are matched exactly in lockfiles / node_modules and also surfaced if found as package@version hints in bundles:

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
2) Suspicious code patterns (regex)
Used on downloaded bundles to find wallet probing / obfuscation even when package names/versions are minified out:

Web3 probing & environment checks

rust
Copier le code
typeof\s+window\s*!==\s*['"]undefined['"]
typeof\s+window\.ethereum\s*!==\s*['"]undefined['"]
window\.ethereum\.request\(\{\s*['"]method['"]\s*:\s*['"]eth_accounts['"]\s*\}\)
ethereum\.request\(
walletconnect|metamask|phantom\.|solana\.|keplr\.
Obfuscation hints

r
Copier le code
new\s+Function\(
atob\(
fromCharCode\([^)]{0,80}\)
const\s+0x[0-9a-fA-F]+\s*=\s*0x[0-9a-fA-F]+;\s*\(function\(\s*_0x[0-9a-fA-F]+,\s*_0x[0-9a-fA-F]+\)\{
_0x[0-9a-fA-F]{4,}\(
3) Explicit malicious obfuscation snippet (searched two ways)
Exact substring (verbatim):

javascript
Copier le code
const _0x112fa8=_0x180f;(function(_0x13c8b9,_0_35f660){const _0x15b386=_0x180f,
This is the leading segment of the injected IIFE as observed in compromised builds.

Relaxed regex (tolerates whitespace/minification changes):

php
Copier le code
const\s+_0x112fa8\s*=\s*_0x180f;\s*\(function\(\s*_0x13c8b9\s*,\s*_0_35f660\s*\)\s*\{\s*const\s+_0x15b386\s*=\s*_0x180f\s*,
4) IOC reference (for IR)
Compromise window (UTC): 2025-09-08 ~13:00–17:00

Phishing domain: npmjs.help

📊 Report contents
KPIs: bundles analyzed, suspicious hits, compromised versions (web/local), explicit snippet hits (exact/relaxed)

Web: pages crawled; per-bundle URL, size, SHA256, pattern matches, package@version hints, compromised matches

Local: (package, version, location, type) for each hit + any parse errors

Reference: IOC table and the full list of compromised versions

🧯 Remediation quick tips
Pin/override dependencies to fixed/safe versions; rebuild with npm ci

Purge old bundles and invalidate CDN if built in the compromise window

Enforce 2FA on NPM accounts

Generate SBOMs (Syft/Trivy) and denylist known bad versions in CI

🤝 Contributing
PRs welcome: add new compromised versions, refine regexes, improve crawler robustness, add SBOM/CSV/GitHub Actions samples.
