#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Supply-chain NPM Scanner – Web (HTTP) & Local (serveurs/disques)
- Menu interactif
- Scan de sites exposés: récupère HTML, JS/MJS/MAP, motifs malveillants, indices de packages
- Scan local: lockfiles (package-lock.json / yarn.lock / pnpm-lock.yaml), node_modules/*/package.json
- Rapport HTML + JSON consolidés
"""

import os, re, sys, json, time, gzip, shutil, queue, argparse, hashlib, datetime
import subprocess
from urllib.parse import urlparse, urljoin
from html import escape

# --- Dépendances optionnelles ---
try:
    import requests
except Exception:
    print("[!] Il faut installer requests:   pip install requests")
    sys.exit(1)

try:
    import yaml
    HAVE_YAML = True
except Exception:
    HAVE_YAML = False

# ========================
# Configuration / IOC / Patterns
# ========================

# Paquets + versions explicitement ciblés (modifiable au besoin)
BAD_PACKAGES = {
    # nom: version_malveillante
    "chalk": "5.6.1",
    "debug": "4.4.2",
    "ansi-styles": "6.2.2",
    "strip-ansi": "7.1.1",
    "color-convert": "3.1.1",
    "ansi-regex": "6.2.1",
    "wrap-ansi": "9.0.1",
    "supports-color": "10.2.1",
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

# Mots-clés npm à repérer dans les bundles minifiés (indicateurs faibles mais utiles)
PACKAGE_KEYWORDS = list(BAD_PACKAGES.keys()) + [
    "ansi-colors", "kleur", "kleur/colors", "log-symbols", "supports-hyperlinks",
]

# Motifs de code “suspects” fréquents sur les attaques orientées Web3 (ajoutez-en selon vos besoins)
SUSPICIOUS_REGEX = [
    r"window\.ethereum",
    r"ethereum\.request\(",
    r"wallet(connect|connectors?)",
    r"metamask",
    r"phantom\.(solana|provider)?",
    r"solana\.",
    r"keplr\.",
    r"crypto\.(subtle|getRandomValues)\(",
    r"atob\(.{0,80}\)",  # obfuscations
    r"new Function\(",
    r"fromCharCode\(.{0,50}\)",
]

# Extensions de bundles à récupérer
JS_EXTS = (".js", ".mjs", ".map")

# Timeout et limites
HTTP_TIMEOUT = 12
MAX_PAGE_CRAWL = 20      # nombre max de pages HTML à parcourir / site
MAX_JS_PER_SITE = 200    # nombre max de fichiers js/mjs/map à récupérer

# Exclusions de chemins locaux
LOCAL_IGNORE_DIRS = {".git", ".svn", ".hg", "node_modules/.cache", "dist", "build", ".next", ".nuxt", ".svelte-kit"}

# Dossiers de sortie
OUTPUT_DIR = os.path.abspath("./scanner_output")
WEB_DUMP_DIR = os.path.join(OUTPUT_DIR, "web_dumps")
REPORTS_DIR = os.path.join(OUTPUT_DIR, "reports")
LOCAL_CACHE_DIR = os.path.join(OUTPUT_DIR, "local_scan_cache")

os.makedirs(WEB_DUMP_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(LOCAL_CACHE_DIR, exist_ok=True)

# ========================
# Utilitaires
# ========================

def now_iso():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

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
    # petit parseur basique (sans BS4 pour rester minimal)
    # Recherche des balises <script src="..."> + preload/modulepreload
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
    # essaie d'attraper "chalk@5.6.1" ou `"name":"chalk","version":"5.6.1"`
    hints = []
    for name in package_names:
        # pattern direct
        for m in re.finditer(rf"{re.escape(name)}[@:]?\s*['\"]?(\d+\.\d+\.\d+)['\"]?", text):
            hints.append((name, m.group(1)))
        # JSON-ish
        for m in re.finditer(rf'"name"\s*:\s*"{re.escape(name)}"\s*,\s*"version"\s*:\s*"(\d+\.\d+\.\d+)"', text):
            hints.append((name, m.group(1)))
    # uniq + tri
    uniq = {}
    for n, v in hints:
        uniq.setdefault((n, v), 1)
    return sorted([ (n,v) for (n,v) in uniq.keys() ])

def find_html_links(html: str):
    out = set()
    for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        out.add(m.group(1))
    return list(out)

# ========================
# Scan HTTP (Front)
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
        "findings": []
    }
    try:
        r0 = fetch(base_url, session)
        base_html = r0.text
    except Exception as e:
        print(f"[!] Erreur de récupération {base_url}: {e}")
        return results

    # page de départ
    to_visit.put(base_url)
    seen_pages.add(base_url)

    # collect scripts sur la page initiale
    scripts = guess_scripts_from_html(base_html)
    for s in scripts:
        full = safe_join(base_url, s)
        if not full:
            continue
        if full.endswith(JS_EXTS):
            seen_js.add(full)

    # parcours BFS limité
    while not to_visit.empty() and len(results["pages_crawled"]) < MAX_PAGE_CRAWL:
        url = to_visit.get()
        try:
            r = fetch(url, session)
            html = r.text
            results["pages_crawled"].append({"url": url, "status": r.status_code, "size": len(html)})

            # scripts
            scripts = guess_scripts_from_html(html)
            for s in scripts:
                full = safe_join(url, s)
                if full and full.endswith(JS_EXTS) and len(seen_js) < MAX_JS_PER_SITE:
                    seen_js.add(full)

            # liens internes (pour trouver d'autres pages qui importent des scripts)
            for link in find_html_links(html):
                full = safe_join(url, link)
                if not full:
                    continue
                if not is_same_origin(base_url, full):
                    continue
                if full.endswith(JS_EXTS):
                    if len(seen_js) < MAX_JS_PER_SITE:
                        seen_js.add(full)
                    continue
                if full not in seen_pages and len(seen_pages) < MAX_PAGE_CRAWL:
                    seen_pages.add(full)
                    to_visit.put(full)

        except Exception as e:
            results["pages_crawled"].append({"url": url, "error": str(e)})
            continue

    # Téléchargement des JS/MJS/MAP
    dumped = []
    for js_url in sorted(seen_js):
        try:
            r = fetch(js_url, session)
            data = r.content
            h = sha256(data)[:12]
            parsed = urlparse(js_url)
            host_dir = os.path.join(WEB_DUMP_DIR, parsed.netloc.replace(":", "_"))
            os.makedirs(host_dir, exist_ok=True)
            fname = os.path.basename(parsed.path) or "bundle.js"
            out_path = os.path.join(host_dir, f"{h}__{fname}")
            with open(out_path, "wb") as f:
                f.write(data)

            # Analyse rapide
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = ""

            keywords = detect_keywords(text, PACKAGE_KEYWORDS)
            suspicious = detect_patterns(text, SUSPICIOUS_REGEX)
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
            })
        except Exception as e:
            dumped.append({"url": js_url, "error": str(e)})

    results["js_files"] = dumped
    return results

# ========================
# Scan Local (serveurs/disques)
# ========================

def scan_local_paths(paths):
    results = {
        "roots": paths,
        "packages_hits": [],   # (name, version, location, type)
        "lockfile_hits": [],   # (file, package, version)
        "errors": []
    }

    def check_pkg(name, ver, where, typ):
        if name in BAD_PACKAGES and BAD_PACKAGES[name] == ver:
            results["packages_hits"].append({"name": name, "version": ver, "where": where, "type": typ})

    for root in paths:
        root = os.path.abspath(root)
        for dirpath, dirnames, filenames in os.walk(root):
            # exclusions
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
                            # walk recursively
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
                                # clé pourrait contenir "chalk@^5.0.0" etc.
                                # on reconstitue le nom en prenant avant le premier "@", en gérant les scopes
                                if key.startswith("@"):
                                    parts = key.split("@")
                                    name = "@" + parts[1]
                                else:
                                    name = key.split("@")[0]
                                if name and ver:
                                    check_pkg(name, ver, p, "yarn.lock")

                        else:  # pnpm-lock.yaml
                            if HAVE_YAML:
                                with open(p, "r", encoding="utf-8", errors="replace") as f:
                                    y = yaml.safe_load(f)
                                pkgs = (y or {}).get("packages", {})
                                for k, meta in (pkgs or {}).items():
                                    # k like "/chalk/5.6.1"
                                    parts = str(k).strip("/").split("/")
                                    if len(parts) >= 2:
                                        name, ver = parts[0], parts[1]
                                        if name and ver:
                                            # normaliser noms scoped si nécessaire: pnpm garde souvent "@scope/name"
                                            check_pkg(name, ver, p, "pnpm-lock.yaml")
                            else:
                                results["errors"].append(f"{p}: PyYAML non installé, ignorer PNPM (pip install pyyaml).")

                    except Exception as e:
                        results["errors"].append(f"{p}: {e}")

    return results

# ========================
# Rapport
# ========================

def build_report(web_scans, local_scans, out_html_path, out_json_path):
    ts = now_iso()
    summary = {
        "generated_at": ts,
        "web_scans": web_scans,
        "local_scans": local_scans,
        "bad_packages": BAD_PACKAGES
    }
    write_json(out_json_path, summary)

    def count_web_findings():
        total_js = 0
        bad_hits = 0
        suspicious_hits = 0
        for w in web_scans:
            for j in w.get("js_files", []):
                if "size" in j:
                    total_js += 1
                if j.get("bad_version_match"):
                    bad_hits += 1
                if j.get("patterns"):
                    suspicious_hits += 1
        return total_js, bad_hits, suspicious_hits

    def count_local_hits():
        total = 0
        for l in local_scans:
            total += len(l.get("packages_hits", []))
        return total

    total_js, bad_web, susp_web = count_web_findings()
    total_local = count_local_hits()

    # HTML minimaliste (dark)
    css = """
    :root{--bg:#0b1016;--fg:#e9edf4;--muted:#9aa3b2;--card:#121826;--line:#1b2a44;--accent:#7aa2ff;--warn:#fbbf24;--danger:#ff6b6b}
    *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);font-family:Inter,Roboto,Arial,sans-serif}
    header{padding:18px 20px;border-bottom:1px solid var(--line)} h1{font-size:22px;margin:0 0 6px} .sub{color:var(--muted);font-size:13px}
    .kpis{display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:12px;padding:16px}
    .kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}
    .kpi .n{font-size:28px;font-weight:700} .kpi .l{color:var(--muted);font-size:12px;margin-top:2px}
    section{padding:10px 16px 20px}
    .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;margin-top:12px}
    table{width:100%;border-collapse:collapse} th,td{border-bottom:1px solid var(--line);padding:8px 6px;font-size:13px}
    th{color:var(--muted);text-align:left}
    code{background:#0f1725;border:1px solid #1e2a44;border-radius:6px;padding:0 4px}
    .pill{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid var(--line);background:#0f1725;color:var(--muted);font-size:12px}
    .danger{color:var(--danger)} .warn{color:var(--warn)} .ok{color:#36d399}
    footer{color:var(--muted);font-size:12px;padding:16px;border-top:1px solid var(--line)}
    """
    html = []
    html.append("<!doctype html><html><head><meta charset='utf-8'><title>Supply-chain NPM Scanner Report</title>")
    html.append(f"<style>{css}</style></head><body>")
    html.append("<header><h1>Supply-chain NPM Scanner – Rapport</h1>")
    html.append(f"<div class='sub'>Généré le {escape(ts)} • Fichier JSON compagnon fourni</div></header>")

    html.append("<div class='kpis'>")
    html.append(f"<div class='kpi'><div class='n'>{len(web_scans)}</div><div class='l'>Cibles web scannées</div></div>")
    html.append(f"<div class='kpi'><div class='n'>{total_js}</div><div class='l'>Bundles récupérés</div></div>")
    html.append(f"<div class='kpi'><div class='n danger'>{bad_web}</div><div class='l'>Bundles avec <code>versions compromises</code></div></div>")
    html.append(f"<div class='kpi'><div class='n warn'>{susp_web}</div><div class='l'>Bundles avec motifs suspects</div></div>")
    html.append(f"<div class='kpi'><div class='n'>{len(local_scans)}</div><div class='l'>Racines locales scannées</div></div>")
    html.append(f"<div class='kpi'><div class='n danger'>{total_local}</div><div class='l'>Hits versions compromises (local)</div></div>")
    html.append("</div>")

    # BAD PACKAGES reference
    html.append("<section><div class='card'><h3>Référence versions ciblées</h3><table><thead><tr><th>Package</th><th>Version compromise</th></tr></thead><tbody>")
    for n, v in sorted(BAD_PACKAGES.items()):
        html.append(f"<tr><td><code>{escape(n)}</code></td><td><code class='danger'>{escape(v)}</code></td></tr>")
    html.append("</tbody></table></div></section>")

    # WEB DETAILS
    html.append("<section><h2>Analyse Web (HTTP/HTTPS)</h2>")
    for w in web_scans:
        html.append("<div class='card'>")
        html.append(f"<h3>Site: <code>{escape(w.get('base_url',''))}</code></h3>")
        # pages
        pages = w.get("pages_crawled", [])
        html.append("<details><summary class='pill'>Pages parcourues</summary>")
        html.append("<table><thead><tr><th>URL</th><th>Status</th><th>Taille</th><th>Erreur</th></tr></thead><tbody>")
        for p in pages:
            html.append(f"<tr><td>{escape(p.get('url',''))}</td><td>{escape(str(p.get('status','')))}</td><td>{escape(str(p.get('size','')))}</td><td class='danger'>{escape(p.get('error',''))}</td></tr>")
        html.append("</tbody></table></details>")
        # js files
        html.append("<details open><summary class='pill'>Bundles JS analysés</summary>")
        html.append("<table><thead><tr><th>URL</th><th>Keywords</th><th>Motifs suspects</th><th>Versions vues</th><th>Compromises</th><th>Taille</th><th>SHA256</th></tr></thead><tbody>")
        for j in w.get("js_files", []):
            if "error" in j:
                html.append(f"<tr><td>{escape(j.get('url',''))}</td><td colspan='6' class='danger'>Erreur: {escape(j['error'])}</td></tr>")
                continue
            vhint = ", ".join([f"{n}@{v}" for (n,v) in j.get("version_hints", [])]) or "-"
            badm  = ", ".join([f"{n}@{v}" for (n,v) in j.get("bad_version_match", [])]) or "-"
            html.append("<tr>")
            html.append(f"<td>{escape(j.get('url',''))}</td>")
            html.append(f"<td>{escape(', '.join(j.get('keywords',[]) ) or '-')}</td>")
            html.append(f"<td class='warn'>{escape(', '.join(j.get('patterns',[]) ) or '-')}</td>")
            html.append(f"<td>{escape(vhint)}</td>")
            cls = "danger" if j.get("bad_version_match") else ""
            html.append(f"<td class='{cls}'>{escape(badm)}</td>")
            html.append(f"<td>{escape(str(j.get('size','')))}</td>")
            html.append(f"<td><code>{escape(j.get('sha256','')[:16])}…</code></td>")
            html.append("</tr>")
        html.append("</tbody></table></details>")
        html.append("</div>")
    html.append("</section>")

    # LOCAL DETAILS
    html.append("<section><h2>Analyse Locale (serveurs/disques)</h2>")
    for l in local_scans:
        html.append("<div class='card'>")
        html.append(f"<h3>Racines: <code>{escape(', '.join(l.get('roots',[])))}</code></h3>")
        html.append("<details open><summary class='pill'>Versions compromises trouvées</summary>")
        html.append("<table><thead><tr><th>Package</th><th>Version</th><th>Emplacement</th><th>Type</th></tr></thead><tbody>")
        hits = l.get("packages_hits", [])
        if not hits:
            html.append("<tr><td colspan='4' class='ok'>Aucun hit</td></tr>")
        else:
            for h in hits:
                html.append(f"<tr><td><code>{escape(h['name'])}</code></td><td class='danger'><code>{escape(h['version'])}</code></td><td>{escape(h['where'])}</td><td>{escape(h['type'])}</td></tr>")
        html.append("</tbody></table></details>")
        errs = l.get("errors", [])
        if errs:
            html.append("<details><summary class='pill'>Erreurs</summary><ul>")
            for e in errs:
                html.append(f"<li class='danger'>{escape(e)}</li>")
            html.append("</ul></details>")
        html.append("</div>")
    html.append("</section>")

    html.append("<footer>Conseil: re-construire les artefacts après correction (pin/override de versions) et invalider le CDN. • Généré par Supply-chain NPM Scanner.</footer>")
    html.append("</body></html>")

    write_text(out_html_path, "\n".join(html))

# ========================
# Menu
# ========================

def menu():
    web_results = []
    local_results = []

    while True:
        print("\n=== Supply-chain NPM Scanner ===")
        print("1) Scanner un site web (HTTP/HTTPS)")
        print("2) Scanner des dossiers locaux (serveurs/disques)")
        print("3) Générer le rapport (HTML + JSON)")
        print("4) Afficher/éditer la configuration (packages/versions, patterns)")
        print("5) Quitter")
        choice = input("> Votre choix: ").strip()

        if choice == "1":
            url = input("URL de départ (ex: https://exemple.com/): ").strip()
            if not url.lower().startswith(("http://","https://")):
                print("[!] Entrez une URL http(s) valide.")
                continue
            print(f"[*] Crawl et collecte sur {url} ...")
            res = crawl_and_collect(url)
            web_results.append(res)
            print(f"[+] {len(res.get('js_files',[]))} bundles récupérés pour {url}")

        elif choice == "2":
            roots = input("Chemins (séparés par des espaces): ").strip()
            if not roots:
                print("[!] Aucun chemin fourni.")
                continue
            paths = [p for p in roots.split() if os.path.exists(p)]
            if not paths:
                print("[!] Chemins invalides.")
                continue
            print(f"[*] Scan local sur: {', '.join(paths)}")
            res = scan_local_paths(paths)
            local_results.append(res)
            print(f"[+] Hits: {len(res.get('packages_hits',[]))} • Erreurs: {len(res.get('errors',[]))}")

        elif choice == "3":
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            out_html = os.path.join(REPORTS_DIR, f"report_{ts}.html")
            out_json = os.path.join(REPORTS_DIR, f"report_{ts}.json")
            build_report(web_results, local_results, out_html, out_json)
            print(f"[✔] Rapport HTML: {out_html}")
            print(f"[✔] Rapport JSON: {out_json}")

        elif choice == "4":
            print("\n--- BAD_PACKAGES (versions ciblées) ---")
            for n,v in sorted(BAD_PACKAGES.items()):
                print(f"  {n:24s} -> {v}")
            print("\n--- PACKAGE_KEYWORDS (bundle search) ---")
            print(", ".join(PACKAGE_KEYWORDS))
            print("\n--- SUSPICIOUS_REGEX ---")
            for r in SUSPICIOUS_REGEX:
                print(f"  {r}")
            print("\nPour modifier, éditez le script (section Configuration).")

        elif choice == "5":
            break
        else:
            print("Choix invalide.")

# ========================
# Entrée
# ========================

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--no-menu","-n"):
        # mode non-interactif minimal possible
        # ex: python supplychain_scanner.py -n --web https://exemple.com --local /srv/app
        parser = argparse.ArgumentParser(description="Supply-chain NPM Scanner (non-interactif)")
        parser.add_argument("--web", nargs="*", help="URLs à scanner (HTTP/HTTPS)")
        parser.add_argument("--local", nargs="*", help="Chemins locaux à scanner")
        parser.add_argument("--report-prefix", default="report", help="Préfixe du nom de rapport")
        args = parser.parse_args(sys.argv[2:])

        web_results = []
        local_results = []

        if args.web:
            for u in args.web:
                print(f"[*] Web scan: {u}")
                web_results.append(crawl_and_collect(u))

        if args.local:
            print(f"[*] Local scan sur: {', '.join(args.local)}")
            local_results.append(scan_local_paths(args.local))

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_html = os.path.join(REPORTS_DIR, f"{args.report_prefix}_{ts}.html")
        out_json = os.path.join(REPORTS_DIR, f"{args.report_prefix}_{ts}.json")
        build_report(web_results, local_results, out_html, out_json)
        print(f"[✔] Rapport HTML: {out_html}")
        print(f"[✔] Rapport JSON: {out_json}")
        sys.exit(0)

    # mode menu
    menu()
