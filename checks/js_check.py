# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
JavaScript Security Check
Checks: API keys in code, dangerous functions, inline event handlers,
libraries with known CVEs, exposed API endpoints, source maps.
"""
import re
import sys
import os
import requests
from urllib.parse import urlparse
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_utils import safe_head, UnsafeTargetError

TIMEOUT = 7

# Pattern for detecting doc.write usage (used in security scanning context)
_DOC_WRITE_RE = r'document\.write\s*\('


def run(base_url: str, response_body: str,
        session: requests.Session) -> List[Dict[str, Any]]:
    results = []

    # Extract inline scripts (skip those with src= attribute)
    inline_scripts = _extract_inline_scripts(response_body)

    results.extend(_check_api_keys(inline_scripts))
    results.extend(_check_dangerous_functions(inline_scripts))
    results.extend(_check_inline_event_handlers(response_body))
    results.extend(_check_vulnerable_libraries(response_body, inline_scripts))
    results.extend(_check_exposed_api_endpoints(inline_scripts))
    results.extend(_check_source_maps(base_url, response_body, session))

    return results


def _extract_inline_scripts(body):
    """Extract inline script contents, skipping scripts with src= attribute."""
    scripts = []
    for match in re.finditer(r'<script(?:\s[^>]*)?>(.+?)</script>', body, re.DOTALL | re.IGNORECASE):
        tag_start = body[match.start():match.start() + 100]
        if 'src=' not in tag_start.lower():
            content = match.group(1).strip()
            if content:
                scripts.append(content)
    return scripts


# ── API keys in code ────────────────────────────────────────────────────────────
def _check_api_keys(inline_scripts):
    results = []
    all_script_text = "\n".join(inline_scripts)

    if not all_script_text:
        results.append(_pass("js_api_keys",
            "Nema inline skripti za proveru API kljuceva",
            "No inline scripts to check for API keys",
            "Nisu pronadjene inline skripte na stranici.",
            "No inline scripts found on the page."))
        return results

    key_patterns = [
        ("AWS Access Key", r'AKIA[0-9A-Z]{16}'),
        ("Google API Key", r'AIza[0-9A-Za-z\-_]{35}'),
        ("Stripe Secret Key", r'sk_live_[0-9a-zA-Z]{24,}'),
        ("GitHub Token", r'ghp_[0-9a-zA-Z]{36}'),
        ("Private Key", r'private_key'),
        ("Secret Key", r'secret_key'),
        ("API Key Assignment", r'api_key\s*=\s*["\']'),
        ("API Key Object", r'apiKey\s*:\s*["\']'),
    ]

    found_keys = []
    for name, pattern in key_patterns:
        if re.search(pattern, all_script_text):
            found_keys.append(name)

    if found_keys:
        results.append(_fail("js_api_keys", "CRITICAL",
            f"Potencijalni API kljucevi pronadjeni u kodu ({', '.join(found_keys[:3])})",
            f"Potential API keys found in code ({', '.join(found_keys[:3])})",
            f"Detektovani su obrasci koji ukazuju na izlozene API kljuceve u inline JavaScript kodu: {', '.join(found_keys)}. Ovo je kritican bezbednosni propust.",
            f"Patterns indicating exposed API keys detected in inline JavaScript code: {', '.join(found_keys)}. This is a critical security vulnerability.",
            "Odmah uklonite API kljuceve iz klijentskog koda. Koristite server-side proxy za API pozive.",
            "Immediately remove API keys from client-side code. Use a server-side proxy for API calls."))
    else:
        results.append(_pass("js_api_keys",
            "Nisu pronadjeni API kljucevi u inline kodu",
            "No API keys found in inline code",
            "Inline skripte ne sadrze poznate obrasce API kljuceva.",
            "Inline scripts do not contain known API key patterns."))
    return results


# ── Dangerous functions ─────────────────────────────────────────────────────────
def _check_dangerous_functions(inline_scripts):
    results = []
    all_script_text = "\n".join(inline_scripts)

    if not all_script_text:
        results.append(_pass("js_dangerous_funcs",
            "Nema inline skripti za proveru opasnih funkcija",
            "No inline scripts to check for dangerous functions",
            "Nisu pronadjene inline skripte na stranici.",
            "No inline scripts found on the page."))
        return results

    dangerous_patterns = [
        ("DOM write operation", _DOC_WRITE_RE),
        (".innerHTML assignment", r'\.innerHTML\s*='),
        ("setTimeout with string", r'setTimeout\s*\(\s*["\']'),
        ("setInterval with string", r'setInterval\s*\(\s*["\']'),
    ]

    found_dangerous = []
    for name, pattern in dangerous_patterns:
        if re.search(pattern, all_script_text):
            found_dangerous.append(name)

    if found_dangerous:
        results.append(_fail("js_dangerous_funcs", "MEDIUM",
            f"Detektovani opasni obrasci u JavaScript kodu",
            f"Dangerous function patterns detected in JavaScript code",
            f"Pronadjeni su potencijalno opasni obrasci: {', '.join(found_dangerous)}. Ovi obrasci mogu omoguciti XSS napade ako se koriste sa korisnickim unosom.",
            f"Potentially dangerous patterns found: {', '.join(found_dangerous)}. These patterns can enable XSS attacks if used with user input.",
            "Koristite bezbednije alternative: textContent umesto innerHTML, izbegavajte DOM write operacije i string argumente u tajmerima.",
            "Use safer alternatives: textContent instead of innerHTML, avoid DOM write operations and string arguments in timers."))
    else:
        results.append(_pass("js_dangerous_funcs",
            "Nisu detektovani opasni obrasci u JavaScript kodu",
            "No dangerous function patterns detected in JavaScript code",
            "Inline skripte ne sadrze poznate opasne obrasce.",
            "Inline scripts do not contain known dangerous patterns."))
    return results


# ── Inline event handlers ──────────────────────────────────────────────────────
def _check_inline_event_handlers(body):
    results = []
    # Match onclick/onerror/onload with javascript: protocol
    handler_pattern = r'(?:onclick|onerror|onload)\s*=\s*["\'][^"\']*javascript:'
    matches = re.findall(handler_pattern, body, re.IGNORECASE)
    count = len(matches)

    if count > 5:
        results.append(_fail("js_inline_handlers", "LOW",
            f"Veliki broj inline event handlera sa javascript: ({count})",
            f"High number of inline event handlers with javascript: ({count})",
            f"Pronadjeno {count} inline event handlera (onclick, onerror, onload) koji koriste javascript: protokol. Ovo otezava primenu CSP politike.",
            f"Found {count} inline event handlers (onclick, onerror, onload) using javascript: protocol. This makes CSP policy enforcement difficult.",
            "Premestite JavaScript logiku u eksterne fajlove i koristite addEventListener umesto inline handlera.",
            "Move JavaScript logic to external files and use addEventListener instead of inline handlers."))
    else:
        results.append(_pass("js_inline_handlers",
            "Inline event handleri su u prihvatljivom opsegu",
            "Inline event handlers are within acceptable range",
            f"Pronadjeno {count} inline event handlera sa javascript: protokolom (prag: >5).",
            f"Found {count} inline event handlers with javascript: protocol (threshold: >5)."))
    return results


# ── Libraries with known CVEs ──────────────────────────────────────────────────
def _check_vulnerable_libraries(body, inline_scripts):
    results = []
    all_text = body + "\n".join(inline_scripts)
    found_vulns = []

    # jQuery version detection
    jquery_src = re.search(r'jquery[.-](\d+\.\d+\.\d+)', all_text, re.IGNORECASE)
    jquery_inline = re.search(r'\$\.fn\.jquery\s*=\s*["\'](\d+\.\d+\.\d+)', all_text)
    jquery_version = None
    if jquery_src:
        jquery_version = jquery_src.group(1)
    elif jquery_inline:
        jquery_version = jquery_inline.group(1)

    if jquery_version:
        parts = [int(x) for x in jquery_version.split(".")]
        version_num = parts[0] * 10000 + parts[1] * 100 + (parts[2] if len(parts) > 2 else 0)
        if version_num < 30500:  # < 3.5.0
            found_vulns.append(f"jQuery {jquery_version} (CVE-2020-11022, potrebna >=3.5.0)")

    # AngularJS version detection
    ng_app = re.search(r'ng-app', body, re.IGNORECASE)
    if ng_app:
        angular_version = re.search(r'angular[.-](\d+\.\d+\.\d+)', all_text, re.IGNORECASE)
        if angular_version:
            parts = [int(x) for x in angular_version.group(1).split(".")]
            if parts[0] == 1 and parts[1] < 6:
                found_vulns.append(f"AngularJS {angular_version.group(1)} (<1.6, poznate ranjivosti)")

    # Lodash version detection
    lodash_version = re.search(r'lodash[.-](\d+\.\d+\.\d+)', all_text, re.IGNORECASE)
    if lodash_version:
        parts = [int(x) for x in lodash_version.group(1).split(".")]
        version_num = parts[0] * 100000 + parts[1] * 1000 + (parts[2] if len(parts) > 2 else 0)
        if version_num < 417021:  # < 4.17.21
            found_vulns.append(f"Lodash {lodash_version.group(1)} (<4.17.21, poznate ranjivosti)")

    if found_vulns:
        results.append(_fail("js_vuln_libs", "HIGH",
            f"Detektovane biblioteke sa poznatim ranjivostima",
            f"Libraries with known vulnerabilities detected",
            f"Pronadjene ranjive verzije: {'; '.join(found_vulns)}. Ove verzije imaju poznate bezbednosne propuste (CVE).",
            f"Vulnerable versions found: {'; '.join(found_vulns)}. These versions have known security vulnerabilities (CVEs).",
            "Azurirajte sve JavaScript biblioteke na najnovije verzije.",
            "Update all JavaScript libraries to the latest versions."))
    else:
        results.append(_pass("js_vuln_libs",
            "Nisu detektovane biblioteke sa poznatim ranjivostima",
            "No libraries with known vulnerabilities detected",
            "Nije pronadjena nijedna JavaScript biblioteka sa poznatim CVE ranjivostima.",
            "No JavaScript libraries with known CVE vulnerabilities found."))
    return results


# ── Exposed API endpoints ──────────────────────────────────────────────────────
def _check_exposed_api_endpoints(inline_scripts):
    results = []
    all_script_text = "\n".join(inline_scripts)

    if not all_script_text:
        results.append(_pass("js_api_endpoints",
            "Nema inline skripti za proveru API endpoint-a",
            "No inline scripts to check for API endpoints",
            "Nisu pronadjene inline skripte na stranici.",
            "No inline scripts found on the page."))
        return results

    api_patterns = [
        r'fetch\s*\(\s*["\'][^"\']*\/api\/',
        r'axios\.\w+\s*\(\s*["\'][^"\']*\/api\/',
        r'["\']\/api\/v\d+\/',
        r'["\']\/graphql["\']',
    ]

    found_endpoints = []
    for pattern in api_patterns:
        matches = re.findall(pattern, all_script_text, re.IGNORECASE)
        for m in matches:
            endpoint = m.strip("\"' (")[:60]
            if endpoint not in found_endpoints:
                found_endpoints.append(endpoint)

    if found_endpoints:
        results.append(_fail("js_api_endpoints", "LOW",
            f"Izlozeni API endpoint-i u JavaScript kodu ({len(found_endpoints)})",
            f"Exposed API endpoints in JavaScript code ({len(found_endpoints)})",
            f"Pronadjeni API endpoint-i u inline skriptama: {', '.join(found_endpoints[:5])}. Ove informacije mogu pomoci napadacu u mapiranju API-ja.",
            f"API endpoints found in inline scripts: {', '.join(found_endpoints[:5])}. This information can help an attacker map the API.",
            "Razmotrite koriscenje API gateway-a i osigurajte da svi endpoint-i zahtevaju autentifikaciju.",
            "Consider using an API gateway and ensure all endpoints require authentication."))
    else:
        results.append(_pass("js_api_endpoints",
            "Nisu pronadjeni izlozeni API endpoint-i",
            "No exposed API endpoints found",
            "Inline skripte ne sadrze vidljive API putanje.",
            "Inline scripts do not contain visible API paths."))
    return results


# ── Source maps ─────────────────────────────────────────────────────────────────
def _check_source_maps(base_url, body, session):
    results = []
    parsed_base = urlparse(base_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    # Find script src URLs
    script_srcs = re.findall(r'<script\s+[^>]*src=["\']([^"\']+\.js)["\']', body, re.IGNORECASE)

    if not script_srcs:
        results.append(_pass("js_source_maps",
            "Nema eksternih skripti za proveru source mapova",
            "No external scripts to check for source maps",
            "Nisu pronadjene eksterne skripte na stranici.",
            "No external scripts found on the page."))
        return results

    accessible_maps = []
    checked = 0
    for src in script_srcs[:5]:  # Limit checks to avoid too many requests
        # Build absolute URL for the .map file
        if src.startswith("//"):
            map_url = f"{parsed_base.scheme}:{src}.map"
        elif src.startswith("http"):
            map_url = src + ".map"
        elif src.startswith("/"):
            map_url = base_origin + src + ".map"
        else:
            map_url = base_url.rstrip("/") + "/" + src + ".map"

        try:
            # Script srcs come from user-controlled HTML, so safe_head is
            # required — otherwise a malicious page could point us at
            # http://169.254.169.254/... via a fake <script src>.
            resp = safe_head(session, map_url, timeout=TIMEOUT)
            checked += 1
            if resp.status_code == 200:
                accessible_maps.append(map_url[:80])
        except UnsafeTargetError:
            pass  # Script src pointed to a forbidden target — skip
        except Exception:
            pass

    if accessible_maps:
        results.append(_fail("js_source_maps", "MEDIUM",
            f"Source map fajlovi su dostupni ({len(accessible_maps)})",
            f"Source map files are accessible ({len(accessible_maps)})",
            f"Pronadjeni dostupni .map fajlovi: {', '.join(accessible_maps[:3])}. Source mapovi otkrivaju izvorni kod aplikacije.",
            f"Accessible .map files found: {', '.join(accessible_maps[:3])}. Source maps reveal the application source code.",
            "Uklonite .map fajlove sa produkcijskog servera ili ogranicite pristup njima.",
            "Remove .map files from the production server or restrict access to them."))
    else:
        results.append(_pass("js_source_maps",
            "Source map fajlovi nisu javno dostupni",
            "Source map files are not publicly accessible",
            f"Provereno {checked} skripti — nijedan .map fajl nije javno dostupan.",
            f"Checked {checked} scripts — no .map files are publicly accessible."))
    return results


# ── Helpers ─────────────────────────────────────────────────────────────────────
def _pass(check_id, title_sr, title_en, desc_sr, desc_en):
    return {
        "id": check_id, "category": "JavaScript Security", "severity": "INFO", "passed": True,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": "", "recommendation_en": "",
    }


def _fail(check_id, severity, title_sr, title_en, desc_sr, desc_en, rec_sr, rec_en):
    return {
        "id": check_id, "category": "JavaScript Security", "severity": severity, "passed": False,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": rec_sr, "recommendation_en": rec_en,
    }
