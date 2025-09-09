# Supply-chain NPM Scanner

> 🔍 Detect malicious or compromised NPM dependencies — across **web front-ends** (HTTP/HTTPS bundles) and **local servers/disks** (lockfiles, `node_modules`).  
> Generates detailed **HTML + JSON reports** for incident response and auditing.

---

## ⚠️ Context

In September 2025, multiple critical **supply-chain compromises** were discovered in the NPM ecosystem. Popular packages like `chalk`, `debug`, `ansi-styles`, `strip-ansi`, and others were published in **malicious versions** after a maintainer’s account was hijacked.

This tool helps defenders:

- Identify if their **servers, repos, or CI builds** pulled compromised versions.
- Inspect **web applications in production** (front-end bundles) for traces of malicious code or version strings.
- Produce a consolidated **report** for remediation and communication.

---

## ✨ Features

- **Menu-driven interface** or **non-interactive CLI**.
- **Web scan (HTTP/HTTPS):**
  - Crawls a target site (same origin).
  - Downloads JS/MJS/MAP bundles.
  - Detects suspicious patterns (e.g., Web3 wallet injection, obfuscation).
  - Extracts `package@version` hints and flags compromised versions.
- **Local scan:**
  - Recursively scans `node_modules/*/package.json`.
  - Parses `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`.
  - Detects known compromised package versions.
- **Reporting:**
  - Clean HTML dashboard (dark theme).
  - Companion JSON file (machine-readable).
  - Bundles saved to disk (`web_dumps/`) with SHA256 hashes.
- **Configurable IOCs:**
  - Easy to add new **packages/versions** or **regex patterns** when new attacks are discovered.

---

## 📦 Installation

```bash
git clone https://github.com/YOURNAME/supplychain-npm-scanner.git
cd supplychain-npm-scanner
python3 -m venv venv
. venv/bin/activate
pip install requests pyyaml


Usage
Interactive menu (default)
python3 supplychain_scanner.py


Menu options:

Scan a website (HTTP/HTTPS)

Scan local directories (servers/disks)

Generate report (HTML + JSON)

Show configuration (bad packages, patterns)

Quit

Non-interactive CLI
python3 supplychain_scanner.py -n --web https://example.com --local /srv/app


Options:

--web URL1 URL2 ... → scan one or more websites

--local PATH1 PATH2 ... → scan one or more local directories

--report-prefix NAME → prefix for output files

Reports will be created in:

./scanner_output/reports/


Example:

report_20250909_113045.html

report_20250909_113045.json

Downloaded bundles (from web scans) are stored under:

./scanner_output/web_dumps/


