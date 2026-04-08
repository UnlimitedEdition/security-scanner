"""
Main Security Scanner Orchestrator
Runs all checks and computes the final score.
"""
import requests
import time
import os
from urllib.parse import urlparse
from typing import Dict, Any, List

# Fix Windows CA bundle issue:
# PostgreSQL installer sets OPENSSL_CONF which points to a missing ca-bundle.crt
# We clear these BEFORE requests/ssl are used anywhere
os.environ.pop("OPENSSL_CONF", None)
os.environ.pop("SSL_CERT_FILE", None)
os.environ.pop("REQUESTS_CA_BUNDLE", None)

# Then try to use certifi if available (best option)
try:
    import certifi
    os.environ["REQUESTS_CA_BUNDLE"] = certifi.where()
    os.environ["SSL_CERT_FILE"] = certifi.where()
except ImportError:
    pass  # Without certifi, requests uses built-in Windows cert store (fine)

from checks import ssl_check, headers_check, dns_check, files_check
from checks import disclosure_check, cookies_check, redirect_check, cms_check
from checks import admin_check, robots_check, ports_check, cors_check, extras_check

# Severity weights for scoring
SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 12,
    "MEDIUM": 6,
    "LOW": 2,
    "INFO": 0,
}

USER_AGENT = (
    "Mozilla/5.0 (compatible; SiteSecurityScanner/1.0; "
    "+https://toske-programer.web.app)"
)


def _normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    # Return base: scheme + netloc
    return f"{parsed.scheme}://{parsed.netloc}"


def _get_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.lstrip("www.")


def compute_score(results: List[Dict]) -> Dict[str, Any]:
    """
    Compute score 0-100 using weighted penalty system.

    Formula:
    - Penalties are proportional, not additive-cliff
    - Each CRITICAL issue deducts up to 20 points (max 3 counted = -60)
    - Each HIGH deducts up to 10 points (max 4 counted = -40)
    - MEDIUM: -5 each (max 4 = -20), LOW: -2 each (max 5 = -10)
    - Minimum floor is 5 (a reachable site is never 0 unless truly broken)
    """
    failed = [r for r in results if not r.get("passed", True)]

    # Group by severity, apply diminishing returns (cap per category)
    by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for item in failed:
        sev = item.get("severity", "LOW")
        if sev in by_sev:
            by_sev[sev].append(item)

    deduction = 0
    deduction += min(len(by_sev["CRITICAL"]), 3) * 20   # max -60
    deduction += min(len(by_sev["HIGH"]), 4) * 10        # max -40
    deduction += min(len(by_sev["MEDIUM"]), 4) * 5       # max -20
    deduction += min(len(by_sev["LOW"]), 5) * 2          # max -10

    # Bonus points for positive checks
    passed = [r for r in results if r.get("passed", False) and r.get("severity") == "INFO"]
    bonus = min(len(passed) * 2, 20)  # up to +20 bonus for good practices

    score = max(5, min(100, 100 - deduction + bonus))
    score = round(score)

    if score >= 90:
        grade = "A"
        grade_color = "#22c55e"
        grade_label = "Odlično / Excellent"
    elif score >= 75:
        grade = "B"
        grade_color = "#84cc16"
        grade_label = "Dobro / Good"
    elif score >= 60:
        grade = "C"
        grade_color = "#eab308"
        grade_label = "Osrednje / Fair"
    elif score >= 40:
        grade = "D"
        grade_color = "#f97316"
        grade_label = "Loše / Poor"
    else:
        grade = "F"
        grade_color = "#ef4444"
        grade_label = "Kritično / Critical"

    counts = {
        "critical": sum(1 for r in failed if r.get("severity") == "CRITICAL"),
        "high": sum(1 for r in failed if r.get("severity") == "HIGH"),
        "medium": sum(1 for r in failed if r.get("severity") == "MEDIUM"),
        "low": sum(1 for r in failed if r.get("severity") == "LOW"),
    }

    return {
        "score": score,
        "grade": grade,
        "grade_color": grade_color,
        "grade_label": grade_label,
        "counts": counts,
    }


def scan(url: str, progress_callback=None) -> Dict[str, Any]:
    """
    Run all security checks on the given URL.
    Returns a dict with all results and the final score.
    """
    start_time = time.time()
    all_results = []
    errors = []

    def update(step: str, pct: int):
        if progress_callback:
            progress_callback(step, pct)

    # --- Normalize URL ---
    base_url = _normalize_url(url)
    domain = _get_domain(base_url)
    is_https = base_url.startswith("https://")

    update("Inicijalizacija konekcije...", 5)

    # Create a session with common headers
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    # --- Initial HTTP request ---
    main_response = None
    response_headers = {}
    response_body = ""

    try:
        update("Učitavanje sajta...", 10)
        main_response = session.get(base_url, timeout=15, allow_redirects=True)
        response_headers = dict(main_response.headers)
        response_body = main_response.text[:50000]  # Cap at 50KB
        final_url = main_response.url
        is_https = final_url.startswith("https://")
    except requests.exceptions.SSLError as e:
        errors.append(f"SSL greška: {str(e)[:100]}")
        is_https = False
    except requests.exceptions.ConnectionError as e:
        errors.append(f"Sajt nije dostupan: {str(e)[:100]}")
        return {
            "url": url,
            "domain": domain,
            "base_url": base_url,
            "scan_time": round(time.time() - start_time, 2),
            "results": [],
            "score": {"score": 0, "grade": "F", "grade_color": "#ef4444",
                      "grade_label": "Nedostupan / Unreachable", "counts": {}},
            "errors": errors,
            "total_checks": 0,
            "failed_checks": 0,
        }
    except Exception as e:
        errors.append(f"Greška: {str(e)[:100]}")

    # --- 1. SSL/TLS Checks ---
    update("Proveravam SSL/TLS sertifikat...", 18)
    try:
        ssl_results = ssl_check.run(domain)
        all_results.extend(ssl_results)
    except Exception as e:
        errors.append(f"SSL check greška: {str(e)[:80]}")

    # --- 2. HTTP Security Headers ---
    update("Proveravam sigurnosne HTTP headere...", 28)
    try:
        hdr_results = headers_check.run(response_headers)
        all_results.extend(hdr_results)
    except Exception as e:
        errors.append(f"Headers check greška: {str(e)[:80]}")

    # --- 3. DNS Security ---
    update("Proveravam DNS sigurnost (SPF, DMARC)...", 40)
    try:
        dns_results = dns_check.run(domain)
        all_results.extend(dns_results)
    except Exception as e:
        errors.append(f"DNS check greška: {str(e)[:80]}")

    # --- 4. Sensitive File Exposure ---
    update("Tražim osetljive fajlove...", 52)
    try:
        files_results = files_check.run(base_url, session)
        all_results.extend(files_results)
    except Exception as e:
        errors.append(f"Files check greška: {str(e)[:80]}")

    # --- 5. Information Disclosure ---
    update("Analiziram otkrivanje informacija o sistemu...", 62)
    try:
        disc_results = disclosure_check.run(response_headers, response_body)
        all_results.extend(disc_results)
    except Exception as e:
        errors.append(f"Disclosure check greška: {str(e)[:80]}")

    # --- 6. Cookie Security ---
    update("Proveravam sigurnost kolačića...", 70)
    try:
        cookie_results = cookies_check.run(response_headers, is_https)
        all_results.extend(cookie_results)
    except Exception as e:
        errors.append(f"Cookie check greška: {str(e)[:80]}")

    # --- 7. Redirect Security ---
    update("Proveravam HTTPS preusmeravanja...", 80)
    try:
        redirect_results = redirect_check.run(domain, session)
        all_results.extend(redirect_results)
    except Exception as e:
        errors.append(f"Redirect check greška: {str(e)[:80]}")

    # --- 8. CMS & Technology ---
    update("Detektujem CMS i tehnologije...", 84)
    try:
        cms_results = cms_check.run(base_url, response_body, session)
        all_results.extend(cms_results)
    except Exception as e:
        errors.append(f"CMS check greška: {str(e)[:80]}")

    # --- 9. Admin Page Exposure ---
    update("Tražim izložene admin stranice...", 88)
    try:
        admin_results = admin_check.run(base_url, session)
        all_results.extend(admin_results)
    except Exception as e:
        errors.append(f"Admin check greška: {str(e)[:80]}")

    # --- 10. robots.txt Analysis ---
    update("Analiziram robots.txt...", 91)
    try:
        robots_results = robots_check.run(base_url, session)
        all_results.extend(robots_results)
    except Exception as e:
        errors.append(f"Robots check greška: {str(e)[:80]}")

    # --- 11. Dangerous Open Ports ---
    update("Proveravam opasne otvorene portove...", 93)
    try:
        ports_results = ports_check.run(domain)
        all_results.extend(ports_results)
    except Exception as e:
        errors.append(f"Ports check greška: {str(e)[:80]}")

    # --- 12. CORS Policy ---
    update("Proveravam CORS politiku...", 95)
    try:
        cors_results = cors_check.run(base_url, response_headers, session)
        all_results.extend(cors_results)
    except Exception as e:
        errors.append(f"CORS check greška: {str(e)[:80]}")

    # --- 13. Extras: security.txt, CAA, SRI ---
    update("Proveravam security.txt, CAA, SRI...", 97)
    try:
        extras_results = extras_check.run(base_url, domain, response_body, session)
        all_results.extend(extras_results)
    except Exception as e:
        errors.append(f"Extras check greška: {str(e)[:80]}")

    update("Izračunavam ocenu...", 99)

    score_data = compute_score(all_results)

    update("Završeno!", 100)

    scan_duration = round(time.time() - start_time, 2)

    # Sort: failed items first, by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_results.sort(key=lambda r: (
        0 if not r.get("passed") else 1,
        severity_order.get(r.get("severity", "INFO"), 4)
    ))

    return {
        "url": url,
        "domain": domain,
        "base_url": base_url,
        "scan_time": scan_duration,
        "results": all_results,
        "score": score_data,
        "errors": errors,
        "total_checks": len(all_results),
        "failed_checks": len([r for r in all_results if not r.get("passed")]),
    }
