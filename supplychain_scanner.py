#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Supply-chain NPM Scanner – Web (HTTP) & Local (disks/servers)
- Web or Local scan, generates an HTML + JSON report per run
- Report filenames now include the server/host and a directory label for remediation clarity:
  * Web:  report_{WEBHOST}__web_{TS}.html/json
  * Local (single path): report_{HOSTNAME}__{BASENAME}_{TS}.html/json
  * Local (multiple):    report_{HOSTNAME}__multi_{TS}.html/json
"""

import os, re, sys, json, datetime, hashlib, queue, argparse, socket
from html import escape
from urllib.parse import urlparse, urljoin

# ---- third-party ----
try:
    import requests
except Exception:
    print("[!] Please install requests: pip install -r requirements.txt")
    sys.exit(1)

try:
    import yaml
    HAVE_YAML = True
except Exception:
    HAVE_YAML = False

# ========================
# Configuration / IOC / Patterns
# ========================

BAD_PACKAGES = {
    "debug": "4.4.2",
    "chalk": "5.6.1",
    "ansi-styles": "6.2.2",
    "strip-ansi": "7.1.1",
    "color-convert": "3.1.1",
    "ansi-regex": "6.2.1",
    "supports-color": "10.2.1",
    "wrap-ansi": "9.0.1",
    "slice-ansi": "7.1.1",
    "color-name": "2.0.1",
    "color-string": "2.1.1",
    "has-ansi": "6.0.1",
    "supports-hyperlinks": "4.1.1",
    "chalk-template": "1.1.1",
    "backslash": "0.2.1",
    "is-arrayish": "0.3.3",
    "error-ex": "1.3.3",
    "simple-swizzle": "0.2.3",
}

PACKAGE_KEYWORDS = list(BAD_PACKAGES.keys()) + [
    "ansi-colors", "kleur", "kleur/colors", "log-symbols", "supports-hyperlinks",
]

SUSPICIOUS_REGEX = [
    r"typeof\s+window\s*!==\s*['\"]undefined['\"]",
    r"typeof\s+window\.ethereum\s*!==\s*['\"]undefined['\"]",
    r"window\.ethereum\.request\(\{\s*['\"]method['\"]\s*:\s*['\"]eth_accounts['\"]\s*\}\)",
    r"ethereum\.request\(",
    r"walletconnect|metamask|phantom\.|solana\.|keplr\.",
    r"new\s+Function\(",
    r"atob\(",
    r"fromCharCode\([^)]{0,80}\)",
    r"const\s+0x[0-9a-fA-F]+\s*=\s*0x[0-9a-fA-F]+;\s*\(function\(\s*_0x[0-9a-fA-F]+,\s*_0x[0-9a-fA-F]+\)\{",
    r"_0x[0-9a-fA-F]{4,}\(",
]

# Exact & relaxed obfuscation snippet from the incident
OBFUSCATION_SNIPPET_EXACT = (
    "const _0x112fa8=_0x180f;(function(_0x13c8b9,_0_35f660){const _0x15b386=_0x180f,"
)
OBFUSCATION_SNIPPET_REGEX = (
    r"const\s+_0x112fa8\s*=\s*_0x180f;\s*\(function\(\s*_0x13c8b9\s*,\s*_0_35f660\s*\)\s*\{"
    r"\s*const\s+_0x15b386\s*=\s*_0x180f\s*,"
)

IOC_INFO = {
    "compromise_window_utc": "2025-09-08 ~13:00–17:00 UTC",
    "phishing_domain": "npmjs.help",
}

HTTP_TIMEOUT = 12
MAX_PAGE_CRAWL = 20
MAX_JS_PER_SITE = 200
JS_EXTS = (".js", ".mjs", ".map")

LOCAL_IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules/.cache", "dist", "build", ".next", ".nuxt", ".svelte-kit"
}

OUTPUT_DIR = os.path.abspath("./scanner_output")
WEB_DUMP_DIR = os.path.join(OUTPUT_DIR, "web_dumps")
REPORTS_DIR = os.path.join(OUTPUT_DIR, "reports")
LOCAL_CACHE_DIR = os.path.join(OUTPUT_DIR, "local_scan_cache")
for d in (WEB_DUMP_DIR, REPORTS_DIR, LOCAL_CACHE_DIR):
    os.makedirs(d, exist_ok=True)

# ========================
# Utils
# ========================

def now_iso():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def timestamp_tag():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def sha256(data: bytes) -> str:
    import hashlib as _h
    return _h.sha256(data).hexdigest()

def read_text(path, default=None):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return default

def write_text(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)

def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def fetch(url, session=None):
    s = session or requests
    r = s.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
    r.raise_for_status()
    return r

def is_same_origin(base, candidate):
    b, c = urlparse(base), urlparse(candidate)
    return (b.scheme, b.netloc) == (c.scheme, c.netloc)

def safe_join(base_url, link):
    try:
        return urljoin(base_url, link)
    except Exception:
        return None

def guess_scripts_from_html(html: str):
    out = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        out.add(m.group(1))
    for m in re.finditer(r'<link[^>]+rel=["\'](?:modulepreload|preload)["\'][^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        out.add(m.group(1))
    return list(out)

def detect_keywords(text: str, keywords):
    found = []
    for k in keywords:
        if re.search(re.escape(k), text):
            found.append(k)
    return sorted(set(found))

def detect_patterns(text: str, patterns):
    hits = []
    for rx in patterns:
        if re.search(rx, text, flags=re.IGNORECASE):
            hits.append(rx)
    return sorted(set(hits))

def extract_version_hints(text: str, package_names):
    hints = []
    for name in package_names:
        for m in re.finditer(rf"{re.escape(name)}[@:]?\s*['\"]?(\d+\.\d+\.\d+)['\"]?", text):
            hints.append((name, m.group(1)))
        for m in re.finditer(rf'"name"\s*:\s*"{re.escape(name)}"\s*,\s*"version"\s*:\s*"(\d+\.\d+\.\d+)"', text):
            hints.append((name, m.group(1)))
    uniq = {}
    for n, v in hints:
        uniq.setdefault((n, v), 1)
    return sorted([(n, v) for (n, v) in uniq.keys()])

def sanitize_label(s: str, maxlen: int = 40) -> str:
    """Make a filesystem/filename-friendly short label."""
    if not s:
        return "root"
    # Keep alnum and dash; replace others with '-'
    label = re.sub(r"[^A-Za-z0-9\-]+", "-", s)
    # Collapse multiple dashes
    label = re.sub(r"-{2,}", "-", label).strip("-")
    if len(label) > maxlen:
        label = label[:maxlen].rstrip("-")
    return label or "root"

# ========================
# Web scan
# ========================

def crawl_and_collect(base_url: str):
    session = requests.Session()
    to_visit = queue.Queue()
    seen_pages = set()
    seen_js = set()
    results = {
        "base_url": base_url,
        "pages_crawled": [],
        "js_files": [],
    }

    try:
        r0 = fetch(base_url, session)
        base_html = r0.text
        results["pages_crawled"].append({"url": base_url, "status": r0.status_code, "size": len(base_html)})
    except Exception as e:
        results["pages_crawled"].append({"url": base_url, "error": str(e)})
        return results

    to_visit.put(base_url)
    seen_pages.add(base_url)

    # first page scripts
    for s in guess_scripts_from_html(base_html):
        full = safe_join(base_url, s)
        if full and full.endswith(JS_EXTS):
            seen_js.add(full)

    # BFS limited crawl
    while not to_visit.empty() and len(results["pages_crawled"]) < MAX_PAGE_CRAWL:
        url = to_visit.get()
        if url != base_url:  # already added base page above
            try:
                r = fetch(url, session)
                html = r.text
                results["pages_crawled"].append({"url": url, "status": r.status_code, "size": len(html)})

                # scripts
                for s in guess_scripts_from_html(html):
                    full = safe_join(url, s)
                    if full and full.endswith(JS_EXTS) and len(seen_js) < MAX_JS_PER_SITE:
                        seen_js.add(full)

                # follow internal links (to discover more pages importing scripts)
                for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
                    link = m.group(1)
                    full = safe_join(url, link)
                    if not full or not is_same_origin(base_url, full):
                        continue
                    if full.endswith(JS_EXTS):
                        if len(seen_js) < MAX_JS_PER_SITE:
                            seen_js.add(full)
                    else:
                        if full not in seen_pages and len(seen_pages) < MAX_PAGE_CRAWL:
                            seen_pages.add(full)
                            to_visit.put(full)

            except Exception as e:
                results["pages_crawled"].append({"url": url, "error": str(e)})

    # Download & analyze JS/MJS/MAP
    dumped = []
    for js_url in sorted(seen_js):
        try:
            r = fetch(js_url, session)
            data = r.content
            text = data.decode("utf-8", errors="replace")
            hprefix = sha256(data)[:12]
            parsed = urlparse(js_url)
            host_dir = os.path.join(WEB_DUMP_DIR, parsed.netloc.replace(":", "_"))
            os.makedirs(host_dir, exist_ok=True)
            fname = os.path.basename(parsed.path) or "bundle.js"
            out_path = os.path.join(host_dir, f"{hprefix}__{fname}")
            with open(out_path, "wb") as f:
                f.write(data)

            keywords = detect_keywords(text, PACKAGE_KEYWORDS)
            suspicious = detect_patterns(text, SUSPICIOUS_REGEX)

            exact_snippet = OBFUSCATION_SNIPPET_EXACT in text
            relaxed_hit = bool(re.search(OBFUSCATION_SNIPPET_REGEX, text))

            versions = extract_version_hints(text, BAD_PACKAGES.keys())
            bad_hits = [(n, v) for (n, v) in versions if BAD_PACKAGES.get(n) == v]

            dumped.append({
                "url": js_url,
                "path": out_path,
                "size": len(data),
                "sha256": sha256(data),
                "keywords": keywords,
                "patterns": suspicious,
                "version_hints": versions,
                "bad_version_match": bad_hits,
                "obfuscation_exact": exact_snippet,
                "obfuscation_relaxed": relaxed_hit,
            })
        except Exception as e:
            dumped.append({"url": js_url, "error": str(e)})

    results["js_files"] = dumped
    return results

# ========================
# Local scan
# ========================

def scan_local_paths(paths):
    results = {
        "roots": [os.path.abspath(p) for p in paths],
        "packages_hits": [],
        "errors": []
    }

    def check_pkg(name, ver, where, typ):
        if name in BAD_PACKAGES and BAD_PACKAGES[name] == ver:
            results["packages_hits"].append(
                {"name": name, "version": ver, "where": where, "type": typ}
            )

    for root in paths:
        root = os.path.abspath(root)
        for dirpath, dirnames, filenames in os.walk(root):
            # ignore noisy dirs
            for ex in list(dirnames):
                if ex in LOCAL_IGNORE_DIRS:
                    dirnames.remove(ex)

            # node_modules package.json
            if "package.json" in filenames and "node_modules" in dirpath:
                pkg_path = os.path.join(dirpath, "package.json")
                try:
                    with open(pkg_path, "r", encoding="utf-8", errors="replace") as f:
                        pkg = json.load(f)
                    name = pkg.get("name")
                    ver = pkg.get("version")
                    if name and ver:
                        check_pkg(name, ver, pkg_path, "node_modules")
                except Exception as e:
                    results["errors"].append(f"{pkg_path}: {e}")

            # lockfiles
            for lf in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
                if lf in filenames:
                    p = os.path.join(dirpath, lf)
                    try:
                        if lf == "package-lock.json":
                            with open(p, "r", encoding="utf-8", errors="replace") as f:
                                pl = json.load(f)

                            def walk(obj):
                                if isinstance(obj, dict):
                                    nm = obj.get("name")
                                    vr = obj.get("version")
                                    if nm and vr:
                                        check_pkg(nm, vr, p, "package-lock.json")
                                    for v in obj.values():
                                        walk(v)
                                elif isinstance(obj, list):
                                    for v in obj:
                                        walk(v)

                            walk(pl)

                        elif lf == "yarn.lock":
                            data = read_text(p, "")
                            for m in re.finditer(r'(^|\n{2})(?P<key>[^:\n]+):\n +version "(?P<ver>[^"]+)"', data):
                                key = m.group("key")
                                ver = m.group("ver")
                                if key.startswith("@"):
                                    parts = key.split("@")
                                    name = "@" + parts[1] if len(parts) >= 2 else "@"
                                else:
                                    name = key.split("@")[0]
                                if name and ver:
                                    check_pkg(name, ver, p, "yarn.lock")

                        else:  # pnpm-lock.yaml
                            if HAVE_YAML:
                                y = yaml.safe_load(read_text(p, "") or "")
                                pkgs = (y or {}).get("packages", {})
                                for k, meta in (pkgs or {}).items():
                                    parts = str(k).strip("/").split("/")
                                    if len(parts) >= 2:
                                        name, ver = parts[0], parts[1]
                                        if name and ver:
                                            check_pkg(name, ver, p, "pnpm-lock.yaml")
                            else:
                                results["errors"].append(f"{p}: PyYAML missing (pip install pyyaml)")

                    except Exception as e:
                        results["errors"].append(f"{p}: {e}")

    return results

# ========================
# Reporting
# ========================

def build_report(web_scan, local_scan, out_html_path, out_json_path):
    ts = now_iso()
    summary = {
        "generated_at": ts,
        "ioc_info": IOC_INFO,
        "bad_packages": BAD_PACKAGES,
        "web_scan": web_scan,
        "local_scan": local_scan,
    }
    write_json(out_json_path, summary)

    # counts
    total_js = 0
    bad_web = 0
    susp_web = 0
    exact_obs = 0
    relaxed_obs = 0
    if web_scan:
        for j in web_scan.get("js_files", []):
            if "size" in j:
                total_js += 1
            if j.get("bad_version_match"):
                bad_web += 1
            if j.get("patterns"):
                susp_web += 1
            if j.get("obfuscation_exact"):
                exact_obs += 1
            if j.get("obfuscation_relaxed"):
                relaxed_obs += 1

    total_local = len(local_scan.get("packages_hits", [])) if local_scan else 0

    css = """
    :root{--bg:#0b1016;--fg:#e9edf4;--muted:#9aa3b2;--card:#121826;--line:#1b2a44;--accent:#7aa2ff;--warn:#fbbf24;--danger:#ff6b6b}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font-family:Inter,Roboto,Arial,sans-serif}
    header{padding:18px 20px;border-bottom:1px solid var(--line)}
    h1{font-size:22px;margin:0 0 6px}.sub{color:var(--muted);font-size:13px}
    .kpis{display:grid;grid-template-columns:repeat(5,minmax(160px,1fr));gap:12px;padding:16px}
    .kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}
    .kpi .n{font-size:28px;font-weight:700}.kpi .l{color:var(--muted);font-size:12px;margin-top:2px}
    section{padding:10px 16px 20px}
    .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;margin-top:12px}
    table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid var(--line);padding:8px 6px;font-size:13px}
    th{color:var(--muted);text-align:left}
    code{background:#0f1725;border:1px solid #1e2a44;border-radius:6px;padding:0 4px}
    .pill{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid var(--line);background:#0f1725;color:var(--muted);font-size:12px}
    .danger{color:var(--danger)}.warn{color:var(--warn)}.ok{color:#36d399}
    footer{color:var(--muted);font-size:12px;padding:16px;border-top:1px solid var(--line)}
    """

    html = []
    html.append("<!doctype html><html><head><meta charset='utf-8'><title>Supply-chain NPM Scanner Report</title>")
    html.append(f"<style>{css}</style></head><body>")
    html.append("<header><h1>Supply-chain NPM Scanner – Report</h1>")
    html.append(f"<div class='sub'>Generated at {escape(ts)}</div></header>")

    # KPIs
    html.append("<div class='kpis'>")
    html.append(f"<div class='kpi'><div class='n'>{1 if web_scan else 0}</div><div class='l'>Web targets</div></div>")
    html.append(f"<div class='kpi'><div class='n'>{total_js}</div><div class='l'>Bundles analyzed</div></div>")
    html.append(f"<div class='kpi'><div class='n warn'>{susp_web}</div><div class='l'>Suspicious patterns</div></div>")
    html.append(f"<div class='kpi'><div class='n danger'>{bad_web}</div><div class='l'>Compromised versions (web)</div></div>")
    html.append(f"<div class='kpi'><div class='n'>{exact_obs}/{relaxed_obs}</div><div class='l'>Obfuscation snippet (exact/relaxed)</div></div>")
    html.append(f"<div class='kpi'><div class='n'>{1 if local_scan else 0}</div><div class='l'>Local targets</div></div>")
    html.append(f"<div class='kpi'><div class='n danger'>{total_local}</div><div class='l'>Compromised versions (local)</div></div>")
    html.append("</div>")

    # IOC reference
    html.append("<section><div class='card'><h3>Incident IOCs / Reference</h3>")
    html.append("<table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>")
    for k, v in IOC_INFO.items():
        html.append(f"<tr><td>{escape(k)}</td><td><code>{escape(v)}</code></td></tr>")
    html.append("</tbody></table></div></section>")

    # Compromised versions table
    html.append("<section><div class='card'><h3>Known Compromised Versions</h3>")
    html.append("<table><thead><tr><th>Package</th><th>Version</th></tr></thead><tbody>")
    for n, v in sorted(BAD_PACKAGES.items()):
        html.append(f"<tr><td><code>{escape(n)}</code></td><td class='danger'><code>{escape(v)}</code></td></tr>")
    html.append("</tbody></table></div></section>")

    # Web details
    html.append("<section><h2>Web Scan</h2>")
    if not web_scan:
        html.append("<div class='card ok'>No web target scanned.</div>")
    else:
        html.append("<div class='card'>")
        html.append(f"<h3>Target: <code>{escape(web_scan.get('base_url',''))}</code></h3>")
        pages = web_scan.get("pages_crawled", [])
        html.append("<details><summary class='pill'>Crawled pages</summary>")
        html.append("<table><thead><tr><th>URL</th><th>Status</th><th>Size</th><th>Error</th></tr></thead><tbody>")
        for p in pages:
            html.append(f"<tr><td>{escape(p.get('url',''))}</td><td>{escape(str(p.get('status','')))}</td><td>{escape(str(p.get('size','')))}</td><td class='danger'>{escape(p.get('error',''))}</td></tr>")
        html.append("</tbody></table></details>")

        html.append("<details open><summary class='pill'>Analyzed bundles</summary>")
        html.append("<table><thead><tr><th>URL</th><th>Keywords</th><th>Suspicious</th><th>Version hints</th><th>Compromised</th><th>Obfus. exact</th><th>Obfus. relaxed</th><th>Size</th><th>SHA256</th></tr></thead><tbody>")
        for j in web_scan.get("js_files", []):
            if "error" in j:
                html.append(f"<tr><td>{escape(j.get('url',''))}</td><td colspan='8' class='danger'>Error: {escape(j['error'])}</td></tr>")
                continue
            vhint = ", ".join([f"{n}@{v}" for (n, v) in j.get("version_hints", [])]) or "-"
            badm = ", ".join([f"{n}@{v}" for (n, v) in j.get("bad_version_match", [])]) or "-"
            html.append("<tr>")
            html.append(f"<td>{escape(j.get('url',''))}</td>")
            html.append(f"<td>{escape(', '.join(j.get('keywords', []) ) or '-')}</td>")
            html.append(f"<td class='warn'>{escape(', '.join(j.get('patterns', []) ) or '-')}</td>")
            html.append(f"<td>{escape(vhint)}</td>")
            html.append(f"<td class='danger'>{escape(badm)}</td>")
            html.append(f"<td>{'✔' if j.get('obfuscation_exact') else '-'}</td>")
            html.append(f"<td>{'✔' if j.get('obfuscation_relaxed') else '-'}</td>")
            html.append(f"<td>{escape(str(j.get('size','')))}</td>")
            html.append(f"<td><code>{escape(j.get('sha256','')[:16])}…</code></td>")
            html.append("</tr>")
        html.append("</tbody></table></details>")
        html.append("</div>")
    html.append("</section>")

    # Local details
    html.append("<section><h2>Local Scan</h2>")
    if not local_scan:
        html.append("<div class='card ok'>No local target scanned.</div>")
    else:
        html.append("<div class='card'>")
        html.append(f"<h3>Roots: <code>{escape(', '.join(local_scan.get('roots', [])))}</code></h3>")
        html.append("<details open><summary class='pill'>Compromised version hits</summary>")
        html.append("<table><thead><tr><th>Package</th><th>Version</th><th>Location</th><th>Type</th></tr></thead><tbody>")
        if not local_scan.get("packages_hits"):
            html.append("<tr><td colspan='4' class='ok'>No hits</td></tr>")
        else:
            for h in local_scan.get("packages_hits", []):
                html.append(f"<tr><td><code>{escape(h['name'])}</code></td><td class='danger'><code>{escape(h['version'])}</code></td><td>{escape(h['where'])}</td><td>{escape(h['type'])}</td></tr>")
        html.append("</tbody></table></details>")

        errs = local_scan.get("errors", [])
        if errs:
            html.append("<details><summary class='pill'>Errors</summary><ul>")
            for e in errs:
                html.append(f"<li class='danger'>{escape(e)}</li>")
            html.append("</ul></details>")
        html.append("</div>")
    html.append("</section>")

    html.append("<footer>Rebuild artifacts after remediation (pin/override versions), invalidate CDN if needed. — Supply-chain NPM Scanner</footer>")
    html.append("</body></html>")

    write_text(out_html_path, "\n".join(html))

# ========================
# CLI / Ergonomics
# ========================

def derive_report_prefix_web(url: str) -> str:
    host = urlparse(url).netloc.split(":")[0] if url else "webhost"
    return f"report_{sanitize_label(host)}__web"

def derive_report_prefix_local(paths: list) -> str:
    hostname = sanitize_label(socket.gethostname())
    if len(paths) == 1:
        base = os.path.basename(os.path.abspath(paths[0])) or "root"
        return f"report_{hostname}__{sanitize_label(base)}"
    return f"report_{hostname}__multi"

def main():
    parser = argparse.ArgumentParser(
        description="Supply-chain NPM Scanner (Web OR Local, generates HTML+JSON report)"
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # Web mode
    pw = sub.add_parser("web", help="Scan a website (HTTP/HTTPS)")
    pw.add_argument("--url", required=True, help="Starting URL, e.g. https://example.com/")
    pw.add_argument("--report-prefix", default=None, help="Prefix for report files (auto if omitted)")

    # Local mode
    pl = sub.add_parser("local", help="Scan local directories (disks/servers)")
    pl.add_argument("paths", nargs="+", help="Paths to scan (one or more)")
    pl.add_argument("--report-prefix", default=None, help="Prefix for report files (auto if omitted)")

    args = parser.parse_args()

    # Derive report prefix automatically if not provided
    if args.mode == "web":
        auto_prefix = derive_report_prefix_web(args.url)
    else:
        auto_prefix = derive_report_prefix_local(args.paths)

    report_prefix = args.report_prefix or auto_prefix
    ts_tag = timestamp_tag()
    out_html = os.path.join(REPORTS_DIR, f"{report_prefix}_{ts_tag}.html")
    out_json = os.path.join(REPORTS_DIR, f"{report_prefix}_{ts_tag}.json")

    web_scan = None
    local_scan = None

    if args.mode == "web":
        print(f"[*] Web scan on: {args.url}")
        web_scan = crawl_and_collect(args.url)

    elif args.mode == "local":
        valid = [p for p in args.paths if os.path.exists(p)]
        if not valid:
            print("[!] No valid paths to scan.")
            sys.exit(2)
        print(f"[*] Local scan on: {', '.join(valid)}")
        local_scan = scan_local_paths(valid)

    build_report(web_scan, local_scan, out_html, out_json)
    print(f"[✔] HTML report: {out_html}")
    print(f"[✔] JSON report: {out_json}")

if __name__ == "__main__":
    main()
