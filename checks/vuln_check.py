# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Vulnerability Scan Check
Checks: SQL error leakage, XSS reflection, CSRF protection, insecure forms,
directory listing, default credentials, error page info leak, open redirect.
"""
import re
import sys
import os
import requests
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_utils import safe_get, UnsafeTargetError

TIMEOUT = 7


def run(base_url: str, response_body: str, response_headers: dict,
        session: requests.Session) -> List[Dict[str, Any]]:
    results = []

    results.extend(_check_sql_error_leakage(response_body))
    results.extend(_check_xss_reflection(base_url, response_body))
    results.extend(_check_csrf_protection(response_body))
    results.extend(_check_insecure_forms(response_body))
    results.extend(_check_directory_listing(base_url, response_body, session))
    results.extend(_check_default_credentials(response_body))
    results.extend(_check_error_page_info_leak(response_body))
    results.extend(_check_open_redirect(base_url))

    return results


# ── SQL error leakage ───────────────────────────────────────────────────────────
def _check_sql_error_leakage(body):
    results = []
    sql_patterns = [
        r'mysql_error',
        r'mysql_fetch',
        r'You have an error in your SQL',
        r'ORA-\d{5}',
        r'SQLSTATE\[',
        r'Microsoft OLE DB',
        r'ODBC SQL Server',
        r'PostgreSQL.*ERROR',
        r'sqlite3\.OperationalError',
    ]

    found = []
    for pattern in sql_patterns:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            found.append(match.group()[:40])

    if found:
        results.append(_fail("vuln_sql_leak", "HIGH",
            f"Detektovano curenje SQL gresaka na stranici",
            f"SQL error leakage detected on the page",
            f"Pronadjene SQL greske u telu stranice: {', '.join(found[:3])}. Ovo otkriva informacije o bazi podataka napadacu.",
            f"SQL errors found in page body: {', '.join(found[:3])}. This reveals database information to an attacker.",
            "Iskljucite prikaz gresaka u produkciji i koristite generisane stranice za greske.",
            "Disable error display in production and use generic error pages."))
    else:
        results.append(_pass("vuln_sql_leak",
            "Nije detektovano curenje SQL gresaka",
            "No SQL error leakage detected",
            "Nisu pronadjene poruke o SQL greskama u telu stranice.",
            "No SQL error messages found in the page body."))
    return results


# ── XSS reflection ──────────────────────────────────────────────────────────────
def _check_xss_reflection(base_url, body):
    results = []
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query)

    if not params:
        results.append(_pass("vuln_xss_reflect",
            "Nema URL parametara za proveru XSS refleksije",
            "No URL parameters to check for XSS reflection",
            "URL ne sadrzi query parametre, pa XSS refleksija nije primenljiva.",
            "URL contains no query parameters, so XSS reflection is not applicable."))
        return results

    reflected = []
    for key, values in params.items():
        for val in values:
            if len(val) < 3:
                continue
            # Check if param value appears between < and > (potential HTML context)
            pattern = r'<[^>]*' + re.escape(val) + r'[^>]*>'
            if re.search(pattern, body, re.IGNORECASE):
                reflected.append(f"{key}={val[:30]}")

    if reflected:
        results.append(_fail("vuln_xss_reflect", "MEDIUM",
            f"Potencijalna XSS refleksija detektovana",
            f"Potential XSS reflection detected",
            f"Parametri iz URL-a se pojavljuju u HTML kontekstu bez eskapiranja: {', '.join(reflected[:3])}. Ovo moze omoguciti XSS napad.",
            f"URL parameters appear in HTML context without escaping: {', '.join(reflected[:3])}. This may enable an XSS attack.",
            "Eskejpujte sve korisnicke inpute pre prikazivanja u HTML-u. Koristite template engine sa auto-escaping.",
            "Escape all user inputs before rendering in HTML. Use a template engine with auto-escaping."))
    else:
        results.append(_pass("vuln_xss_reflect",
            "Nije detektovana XSS refleksija parametara",
            "No XSS parameter reflection detected",
            "URL parametri se ne pojavljuju u neeskejpovanom HTML kontekstu.",
            "URL parameters do not appear in unescaped HTML context."))
    return results


# ── CSRF protection ─────────────────────────────────────────────────────────────
def _check_csrf_protection(body):
    results = []
    forms = re.findall(r'<form\b[^>]*>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)

    if not forms:
        results.append(_pass("vuln_csrf",
            "Nema formulara za proveru CSRF zastite",
            "No forms to check for CSRF protection",
            "Na stranici nisu pronadjeni HTML formulari.",
            "No HTML forms found on the page."))
        return results

    csrf_token_pattern = r'<input\s+[^>]*(?:name|id)=["\'][^"\']*(?:csrf|token|_token|csrfmiddlewaretoken)[^"\']*["\'][^>]*type=["\']hidden["\']|<input\s+[^>]*type=["\']hidden["\'][^>]*(?:name|id)=["\'][^"\']*(?:csrf|token|_token|csrfmiddlewaretoken)[^"\']*["\']'
    forms_without_csrf = 0
    total_forms = len(forms)

    for form_content in forms:
        if not re.search(csrf_token_pattern, form_content, re.IGNORECASE):
            forms_without_csrf += 1

    if forms_without_csrf > 0:
        results.append(_fail("vuln_csrf", "MEDIUM",
            f"{forms_without_csrf} formular(a) bez CSRF tokena (od {total_forms})",
            f"{forms_without_csrf} form(s) without CSRF token (of {total_forms})",
            f"Pronadjeno {forms_without_csrf} formulara bez skrivenog CSRF tokena. Bez CSRF zastite, napadac moze napraviti lazne zahteve u ime korisnika.",
            f"Found {forms_without_csrf} forms without a hidden CSRF token. Without CSRF protection, an attacker can forge requests on behalf of users.",
            "Dodajte CSRF token u svaki formular: <input type=\"hidden\" name=\"csrf_token\" value=\"...\">",
            "Add a CSRF token to every form: <input type=\"hidden\" name=\"csrf_token\" value=\"...\">"))
    else:
        results.append(_pass("vuln_csrf",
            f"Svi formulari imaju CSRF zastitu ({total_forms} formulara)",
            f"All forms have CSRF protection ({total_forms} forms)",
            "Svi pronadjeni formulari sadrze CSRF tokene.",
            "All found forms contain CSRF tokens."))
    return results


# ── Insecure forms ──────────────────────────────────────────────────────────────
def _check_insecure_forms(body):
    results = []
    insecure = re.findall(r'<form\s+[^>]*action=["\']http://[^"\']*["\']', body, re.IGNORECASE)

    if insecure:
        actions = []
        for match in insecure[:3]:
            action_match = re.search(r'action=["\']([^"\']*)["\']', match, re.IGNORECASE)
            if action_match:
                actions.append(action_match.group(1)[:50])

        results.append(_fail("vuln_insecure_forms", "HIGH",
            f"{len(insecure)} formular(a) salje podatke preko HTTP",
            f"{len(insecure)} form(s) submit data over HTTP",
            f"Formulari salju podatke na nesigurne HTTP URL-ove: {', '.join(actions)}. Podaci se salju u cistom tekstu.",
            f"Forms submit data to insecure HTTP URLs: {', '.join(actions)}. Data is sent in plain text.",
            "Promenite sve form action URL-ove na HTTPS.",
            "Change all form action URLs to HTTPS."))
    else:
        results.append(_pass("vuln_insecure_forms",
            "Svi formulari koriste bezbednu konekciju",
            "All forms use secure connection",
            "Nijedan formular ne salje podatke na nesiguran HTTP URL.",
            "No form submits data to an insecure HTTP URL."))
    return results


# ── Directory listing ───────────────────────────────────────────────────────────
def _check_directory_listing(base_url, body, session):
    results = []

    # Check current page
    if "Index of /" in body and "Parent Directory" in body:
        results.append(_fail("vuln_dir_listing", "HIGH",
            "Directory listing je omogucen na sajtu",
            "Directory listing is enabled on the site",
            "Stranica prikazuje listu fajlova (Index of /). Ovo otkriva strukturu sajta i moze izloziti osetljive fajlove.",
            "Page shows a file listing (Index of /). This reveals site structure and may expose sensitive files.",
            "Onemogucite directory listing na web serveru (Apache: Options -Indexes, Nginx: autoindex off).",
            "Disable directory listing on the web server (Apache: Options -Indexes, Nginx: autoindex off)."))
        return results

    # Try common directories
    test_paths = ["/icons/", "/images/"]
    for path in test_paths:
        try:
            url = base_url.rstrip("/") + path
            resp = safe_get(session, url, timeout=TIMEOUT)
            if resp.status_code == 200 and "Index of" in resp.text and "Parent Directory" in resp.text:
                results.append(_fail("vuln_dir_listing", "HIGH",
                    f"Directory listing omogucen na {path}",
                    f"Directory listing enabled at {path}",
                    f"Putanja {path} prikazuje listu fajlova. Ovo moze otkriti osetljive fajlove i strukturu aplikacije.",
                    f"Path {path} shows a file listing. This may reveal sensitive files and application structure.",
                    "Onemogucite directory listing na web serveru.",
                    "Disable directory listing on the web server."))
                return results
        except Exception:
            pass

    results.append(_pass("vuln_dir_listing",
        "Directory listing nije detektovan",
        "Directory listing not detected",
        "Nije pronadjen otvoren listing direktorijuma na proverenim putanjama.",
        "No open directory listing found on checked paths."))
    return results


# ── Default credentials ────────────────────────────────────────────────────────
def _check_default_credentials(body):
    results = []
    default_patterns = [
        r'default\s+password',
        r'admin\s*/\s*admin',
        r'root\s*/\s*root',
    ]

    found = []
    body_lower = body.lower()
    for pattern in default_patterns:
        if re.search(pattern, body_lower):
            found.append(pattern.replace(r'\s+', ' ').replace(r'\s*', '').replace(r'/\s*', '/'))

    if found:
        results.append(_fail("vuln_default_creds", "MEDIUM",
            "Detektovani podrazumevani kredencijali na stranici",
            "Default credentials detected on the page",
            "Pronadjeni su tragovi podrazumevanih kredencijala u telu stranice. Ovo moze ukazivati na nepromenjen podrazumevani pristup.",
            "Traces of default credentials found in the page body. This may indicate unchanged default access.",
            "Promenite sve podrazumevane lozinke i uklonite prikaz kredencijala sa stranice.",
            "Change all default passwords and remove credential display from the page."))
    else:
        results.append(_pass("vuln_default_creds",
            "Nisu detektovani podrazumevani kredencijali",
            "No default credentials detected",
            "Nisu pronadjeni tragovi podrazumevanih kredencijala na stranici.",
            "No traces of default credentials found on the page."))
    return results


# ── Error page info leak ───────────────────────────────────────────────────────
def _check_error_page_info_leak(body):
    results = []
    error_patterns = [
        r'Traceback \(most recent call last\)',
        r'at java\.',
        r'at sun\.',
        r'NullPointerException',
        r'Exception in thread',
        r'panic:',
        r'debug\s*=\s*True',
    ]

    found = []
    for pattern in error_patterns:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            found.append(match.group()[:40])

    if found:
        results.append(_fail("vuln_error_leak", "HIGH",
            "Detektovano curenje informacija u porukama o greskama",
            "Information leakage detected in error messages",
            f"Pronadjeni stack trace ili debug informacije: {', '.join(found[:3])}. Ovo otkriva interne detalje aplikacije napadacu.",
            f"Stack trace or debug information found: {', '.join(found[:3])}. This reveals internal application details to an attacker.",
            "Iskljucite debug rezim u produkciji i koristite prilagodjene stranice za greske bez tehnickih detalja.",
            "Disable debug mode in production and use custom error pages without technical details."))
    else:
        results.append(_pass("vuln_error_leak",
            "Nije detektovano curenje informacija u greskama",
            "No information leakage in errors detected",
            "Nisu pronadjeni stack traceovi niti debug informacije na stranici.",
            "No stack traces or debug information found on the page."))
    return results


# ── Open redirect ───────────────────────────────────────────────────────────────
def _check_open_redirect(base_url):
    results = []
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query)

    redirect_params = ["redirect", "url", "next", "return", "returnUrl", "goto"]
    found_redirects = []

    for param_name in redirect_params:
        # Case-insensitive param check
        for key, values in params.items():
            if key.lower() == param_name.lower():
                for val in values:
                    if val.lower().startswith("http"):
                        found_redirects.append(f"{key}={val[:40]}")

    if not params or not any(
        key.lower() in [p.lower() for p in redirect_params]
        for key in params
    ):
        results.append(_pass("vuln_open_redirect",
            "Nema parametara za preusmeravanje u URL-u",
            "No redirect parameters in URL",
            "URL ne sadrzi parametre koji bi mogli da se koriste za open redirect.",
            "URL contains no parameters that could be used for open redirect."))
    elif found_redirects:
        results.append(_fail("vuln_open_redirect", "MEDIUM",
            "Potencijalni open redirect detektovan",
            "Potential open redirect detected",
            f"URL sadrzi parametre za preusmeravanje sa eksternim URL-ovima: {', '.join(found_redirects[:3])}. Ovo moze biti zloupotrebljeno za phishing napade.",
            f"URL contains redirect parameters with external URLs: {', '.join(found_redirects[:3])}. This can be abused for phishing attacks.",
            "Validirajte URL-ove za preusmeravanje — dozvolite samo relativne putanje ili whitelist domena.",
            "Validate redirect URLs — allow only relative paths or whitelisted domains."))
    else:
        results.append(_pass("vuln_open_redirect",
            "Parametri za preusmeravanje su bezbedni",
            "Redirect parameters are safe",
            "URL sadrzi parametre za preusmeravanje, ali ne sadrze eksterne URL-ove.",
            "URL contains redirect parameters, but they do not contain external URLs."))
    return results


# ── Helpers ─────────────────────────────────────────────────────────────────────
def _pass(check_id, title_sr, title_en, desc_sr, desc_en):
    return {
        "id": check_id, "category": "Vulnerability Scan", "severity": "INFO", "passed": True,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": "", "recommendation_en": "",
    }


def _fail(check_id, severity, title_sr, title_en, desc_sr, desc_en, rec_sr, rec_en):
    return {
        "id": check_id, "category": "Vulnerability Scan", "severity": severity, "passed": False,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": rec_sr, "recommendation_en": rec_en,
    }
