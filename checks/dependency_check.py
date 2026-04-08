"""
Dependency Security Check
Checks: exposed package.json, outdated JS libraries, CDN without SRI,
known CVE versions in JavaScript libraries.
"""
import re
import json
import requests
from typing import List, Dict, Any

TIMEOUT = 7

# Known vulnerable versions with CVE details
KNOWN_CVES = {
    "jquery": [
        {"below": (3, 5, 0), "cves": ["CVE-2020-11022", "CVE-2020-11023"], "desc": "XSS via HTML injection"},
    ],
    "angular": [
        {"below": (1, 6, 9), "cves": ["CVE-2019-10768"], "desc": "Prototype pollution"},
    ],
    "bootstrap": [
        {"below": (3, 4, 0), "cves": ["CVE-2019-8331"], "desc": "XSS in tooltip/popover"},
    ],
    "lodash": [
        {"below": (4, 17, 21), "cves": ["CVE-2021-23337"], "desc": "Command injection via template"},
    ],
}


def _pass(check_id, title_sr, title_en, desc_sr, desc_en):
    return {
        "id": check_id, "category": "Dependencies", "severity": "INFO", "passed": True,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": "", "recommendation_en": "",
    }


def _fail(check_id, severity, title_sr, title_en, desc_sr, desc_en, rec_sr, rec_en):
    return {
        "id": check_id, "category": "Dependencies", "severity": severity, "passed": False,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": rec_sr, "recommendation_en": rec_en,
    }


def _parse_version(version_str):
    """Parse version string like '3.5.1' into tuple (3, 5, 1)."""
    parts = re.findall(r'\d+', version_str)
    if len(parts) >= 3:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    elif len(parts) == 2:
        return (int(parts[0]), int(parts[1]), 0)
    elif len(parts) == 1:
        return (int(parts[0]), 0, 0)
    return None


def _version_below(version_tuple, threshold_tuple):
    """Check if version_tuple < threshold_tuple."""
    if version_tuple is None or threshold_tuple is None:
        return False
    return version_tuple < threshold_tuple


def _detect_libraries(response_body):
    """Detect JS libraries and their versions from <script src=...> tags."""
    detected = {}
    if not response_body:
        return detected

    # Find all script src attributes
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response_body, re.IGNORECASE)

    for src in script_srcs:
        src_lower = src.lower()

        # jQuery: jquery-1.12.4.min.js, jquery/1.12.4/, jquery@1.12.4
        jquery_match = re.search(r'jquery[/-]?(\d+\.\d+\.\d+)', src_lower)
        if not jquery_match:
            jquery_match = re.search(r'jquery@(\d+\.\d+\.\d+)', src_lower)
        if jquery_match:
            detected["jquery"] = {"version_str": jquery_match.group(1), "src": src[:100]}

        # Bootstrap: bootstrap/3.3.7/, bootstrap@3.3.7, bootstrap-3.3.7
        bootstrap_match = re.search(r'bootstrap[/@-](\d+\.\d+\.\d+)', src_lower)
        if not bootstrap_match:
            bootstrap_match = re.search(r'bootstrap/(\d+\.\d+\.\d+)', src_lower)
        if bootstrap_match:
            detected["bootstrap"] = {"version_str": bootstrap_match.group(1), "src": src[:100]}

        # Angular.js: angular/1.6.0/, angular.js/1.6.0, angular@1.6.0
        angular_match = re.search(r'angular(?:\.js)?[/@-](\d+\.\d+\.\d+)', src_lower)
        if not angular_match:
            angular_match = re.search(r'angular(?:\.js)?/(\d+\.\d+\.\d+)', src_lower)
        if angular_match:
            detected["angular"] = {"version_str": angular_match.group(1), "src": src[:100]}

        # Lodash: lodash/4.17.20/, lodash@4.17.20, lodash-4.17.20
        lodash_match = re.search(r'lodash[/@-](\d+\.\d+\.\d+)', src_lower)
        if not lodash_match:
            lodash_match = re.search(r'lodash/(\d+\.\d+\.\d+)', src_lower)
        if lodash_match:
            detected["lodash"] = {"version_str": lodash_match.group(1), "src": src[:100]}

        # Moment.js: moment/2.29.1/, moment.min.js, moment@2.29.1
        moment_match = re.search(r'moment(?:\.js)?(?:[/@-](\d+\.\d+\.\d+))?', src_lower)
        if moment_match and "moment" in src_lower:
            # Only match if it's truly a moment.js reference (not a random word)
            if re.search(r'moment(?:\.js|\.min\.js|[/@-]\d)', src_lower):
                version_str = moment_match.group(1) if moment_match.group(1) else "unknown"
                detected["moment"] = {"version_str": version_str, "src": src[:100]}

    return detected


def run(base_url: str, response_body: str, session: requests.Session) -> List[Dict[str, Any]]:
    results = []
    base = base_url.rstrip("/")

    # ── 1. Exposed package.json ───────────────────────────────────────
    try:
        resp = session.get(base + "/package.json", timeout=TIMEOUT)
        if resp.status_code == 200 and "dependencies" in resp.text:
            try:
                pkg = json.loads(resp.text)
                deps = list(pkg.get("dependencies", {}).keys())[:10]
                dev_deps = list(pkg.get("devDependencies", {}).keys())[:5]
                dep_list = ", ".join(deps) if deps else "none"
                results.append(_fail("dep_package_json_exposed", "MEDIUM",
                    f"package.json javno dostupan — otkriva {len(deps)} zavisnosti",
                    f"package.json publicly accessible — reveals {len(deps)} dependencies",
                    f"Fajl package.json je dostupan na /package.json i otkriva kompletnu listu zavisnosti: {dep_list}{'...' if len(deps) >= 10 else ''}. Napadac moze koristiti ove informacije za pronalazenje ranjivih biblioteka.",
                    f"File package.json is accessible at /package.json and reveals the complete dependency list: {dep_list}{'...' if len(deps) >= 10 else ''}. An attacker can use this information to find vulnerable libraries.",
                    "Blokirajte pristup package.json u web server konfiguraciji. U Nginx: location = /package.json { deny all; }",
                    "Block access to package.json in web server configuration. In Nginx: location = /package.json { deny all; }"))
            except (json.JSONDecodeError, KeyError):
                results.append(_fail("dep_package_json_exposed", "MEDIUM",
                    "package.json javno dostupan",
                    "package.json publicly accessible",
                    "Fajl package.json je dostupan na /package.json i otkriva informacije o tehnoloskom steku.",
                    "File package.json is accessible at /package.json and reveals technology stack information.",
                    "Blokirajte pristup package.json u web server konfiguraciji.",
                    "Block access to package.json in web server configuration."))
        else:
            results.append(_pass("dep_package_json_ok",
                "package.json nije javno dostupan",
                "package.json is not publicly accessible",
                "Fajl package.json nije pronadjen na /package.json.",
                "File package.json was not found at /package.json."))
    except Exception:
        results.append(_pass("dep_package_json_ok",
            "package.json nije javno dostupan",
            "package.json is not publicly accessible",
            "Fajl package.json nije dostupan.",
            "File package.json is not accessible."))

    # ── 2. Outdated JS Libraries ──────────────────────────────────────
    detected = _detect_libraries(response_body)
    outdated_found = []

    for lib_name, lib_info in detected.items():
        version_str = lib_info["version_str"]
        version = _parse_version(version_str)

        if lib_name == "jquery" and version and _version_below(version, (3, 5, 0)):
            outdated_found.append(("jquery", version_str, "HIGH", "< 3.5.0"))
        elif lib_name == "bootstrap" and version and _version_below(version, (4, 0, 0)):
            outdated_found.append(("bootstrap", version_str, "LOW", "< 4.0"))
        elif lib_name == "angular" and version and _version_below(version, (1, 6, 0)):
            outdated_found.append(("angular", version_str, "HIGH", "< 1.6"))
        elif lib_name == "lodash" and version and _version_below(version, (4, 17, 21)):
            outdated_found.append(("lodash", version_str, "MEDIUM", "< 4.17.21"))
        elif lib_name == "moment":
            outdated_found.append(("moment.js", version_str, "LOW", "deprecated"))

    if outdated_found:
        # Use the highest severity among findings
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        max_severity = max(outdated_found, key=lambda x: severity_order.get(x[2], 0))[2]
        lib_details = "; ".join([f"{name} v{ver} ({threshold})" for name, ver, _, threshold in outdated_found])
        results.append(_fail("dep_outdated_libs", max_severity,
            f"Zastarele JS biblioteke: {len(outdated_found)} pronadjeno",
            f"Outdated JS libraries: {len(outdated_found)} found",
            f"Detektovane zastarele verzije biblioteka: {lib_details}. Stare verzije mogu sadrzati poznate bezbednosne ranjivosti.",
            f"Detected outdated library versions: {lib_details}. Old versions may contain known security vulnerabilities.",
            "Azurirajte sve JavaScript biblioteke na najnovije verzije. Koristite npm audit ili yarn audit za proveru ranjivosti.",
            "Update all JavaScript libraries to the latest versions. Use npm audit or yarn audit to check for vulnerabilities."))
    elif detected:
        libs = ", ".join([f"{k} v{v['version_str']}" for k, v in detected.items()])
        results.append(_pass("dep_libs_ok",
            f"JS biblioteke su azurne: {libs}",
            f"JS libraries are up to date: {libs}",
            "Detektovane JavaScript biblioteke koriste aktuelne verzije.",
            "Detected JavaScript libraries use current versions."))
    else:
        results.append(_pass("dep_no_libs",
            "Nisu detektovane JS biblioteke sa verzijama u URL-u",
            "No JS libraries with versions in URL detected",
            "Nijedna JavaScript biblioteka sa verzijom u src URL-u nije pronadjena.",
            "No JavaScript libraries with version numbers in src URLs were found."))

    # ── 3. CDN Without SRI ────────────────────────────────────────────
    if response_body:
        # Find external <script> tags loading from CDN
        script_tags = re.findall(r'<script\s[^>]*?src=["\']https?://[^"\']+["\'][^>]*?>', response_body, re.IGNORECASE)
        cdn_without_sri = []

        for tag in script_tags:
            src_match = re.search(r'src=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if not src_match:
                continue
            src = src_match.group(1)
            # Check if it's from a CDN
            cdn_patterns = ["cdn.", "cdnjs.", "unpkg.", "jsdelivr.", "googleapis.", "cloudflare.", "bootstrapcdn.", "ajax."]
            if not any(p in src.lower() for p in cdn_patterns):
                continue
            # Check for integrity attribute
            if "integrity=" not in tag.lower():
                cdn_without_sri.append(src[:80])

        if cdn_without_sri:
            examples = ", ".join(cdn_without_sri[:3])
            results.append(_fail("dep_cdn_no_sri", "MEDIUM",
                f"{len(cdn_without_sri)} CDN skripti bez SRI integriteta",
                f"{len(cdn_without_sri)} CDN scripts without SRI integrity",
                f"Pronadjeno je {len(cdn_without_sri)} skripti ucitanih sa CDN-a bez integrity atributa. Primeri: {examples}. Ako CDN bude kompromitovan, zlonamerni kod se automatski ucitava na vas sajt.",
                f"Found {len(cdn_without_sri)} scripts loaded from CDN without integrity attribute. Examples: {examples}. If the CDN is compromised, malicious code is automatically loaded on your site.",
                "Dodajte integrity atribut svakoj CDN skripti: <script src=\"...\" integrity=\"sha384-...\" crossorigin=\"anonymous\">. Koristite https://www.srihash.org/ za generisanje hash-a.",
                "Add integrity attribute to every CDN script: <script src=\"...\" integrity=\"sha384-...\" crossorigin=\"anonymous\">. Use https://www.srihash.org/ to generate hashes."))
        else:
            results.append(_pass("dep_cdn_sri_ok",
                "CDN skripte imaju SRI zastitu ili nisu pronadjene",
                "CDN scripts have SRI protection or none found",
                "Sve skripte ucitane sa CDN-a imaju integrity atribut ili nema eksternih CDN skripti.",
                "All CDN-loaded scripts have integrity attribute or no external CDN scripts found."))
    else:
        results.append(_pass("dep_cdn_no_body",
            "Nema sadrzaja stranice za analizu CDN skripti",
            "No page content to analyze CDN scripts",
            "Telo odgovora je prazno, CDN skripte ne mogu biti analizirane.",
            "Response body is empty, CDN scripts cannot be analyzed."))

    # ── 4. Known CVE Versions ─────────────────────────────────────────
    cve_findings = []

    for lib_name, lib_info in detected.items():
        version = _parse_version(lib_info["version_str"])
        if lib_name in KNOWN_CVES:
            for vuln in KNOWN_CVES[lib_name]:
                if _version_below(version, vuln["below"]):
                    cve_list = ", ".join(vuln["cves"])
                    cve_findings.append({
                        "library": lib_name,
                        "version": lib_info["version_str"],
                        "cves": cve_list,
                        "desc": vuln["desc"],
                    })

    if cve_findings:
        cve_details_sr = "; ".join([
            f"{f['library']} v{f['version']}: {f['cves']} ({f['desc']})"
            for f in cve_findings
        ])
        cve_details_en = cve_details_sr  # CVE IDs and descriptions are universal
        all_cves = ", ".join(set(cve for f in cve_findings for cve in f["cves"].split(", ")))
        results.append(_fail("dep_known_cves", "HIGH",
            f"Poznate ranjivosti (CVE) u {len(cve_findings)} biblioteka",
            f"Known vulnerabilities (CVE) in {len(cve_findings)} libraries",
            f"Detektovane biblioteke sa poznatim bezbednosnim ranjivostima: {cve_details_sr}",
            f"Detected libraries with known security vulnerabilities: {cve_details_en}",
            f"Hitno azurirajte pogodene biblioteke. Ranjivosti: {all_cves}. Proverite https://nvd.nist.gov/ za detalje.",
            f"Urgently update affected libraries. Vulnerabilities: {all_cves}. Check https://nvd.nist.gov/ for details."))
    elif detected:
        results.append(_pass("dep_cves_ok",
            "Nema poznatih CVE ranjivosti u detektovanim bibliotekama",
            "No known CVE vulnerabilities in detected libraries",
            "Nijedna detektovana biblioteka nema poznate bezbednosne ranjivosti u nasoj bazi.",
            "No detected library has known security vulnerabilities in our database."))
    else:
        results.append(_pass("dep_cves_no_libs",
            "Nema detektovanih biblioteka za CVE proveru",
            "No detected libraries for CVE check",
            "Nisu pronadjene JavaScript biblioteke sa verzijama za proveru poznatih ranjivosti.",
            "No JavaScript libraries with versions were found to check for known vulnerabilities."))

    return results
