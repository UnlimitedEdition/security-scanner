# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Main Security Scanner Orchestrator
Runs all checks and computes the final score.
"""
import requests
import time
import os
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

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
from checks import ct_check, subdomain_check, seo_check
from checks import performance_check, gdpr_check, vuln_check
from checks import js_check, api_check, accessibility_check, dependency_check
from checks import observatory_check, whois_check, tech_stack_check, email_security_check
from checks import takeover_check
from checks import jwt_check
from checks import wpscan_lite
from checks.crawler import crawl
from security_utils import safe_get, assert_safe_target, UnsafeTargetError
import risk_engine

# Hard upper bound on total scan wall-clock time. A malicious target could
# otherwise keep the single scan slot busy indefinitely by responding slowly
# to each individual check. When the deadline is hit, remaining checks are
# skipped and a truncation notice is added to the errors list.
SCAN_DEADLINE_SECONDS = 180

# Severity weights for scoring
SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 12,
    "MEDIUM": 6,
    "LOW": 2,
    "INFO": 0,
}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def _detect_bot_protection(body: str, headers: dict) -> bool:
    """Detect if response is a bot challenge page instead of real content."""
    if not body:
        return False

    body_lower = body.lower()

    # Known challenge page signatures
    challenge_signs = [
        "vercel security checkpoint",
        "checking your browser",
        "just a moment",
        "cf-challenge",
        "__cf_chl",
        "challenge-platform",
        "ray id:",
        "ddos protection by",
        "attention required",
        "enable javascript and cookies to continue",
        "browser verification",
    ]
    for sign in challenge_signs:
        if sign in body_lower:
            return True

    # Very short body with no real HTML structure = likely challenge
    # Real pages have at least some content
    has_title = "<title" in body_lower
    has_body_content = len(body) > 2000
    has_meta = '<meta name="description"' in body_lower or '<meta name="viewport"' in body_lower

    # If page has < 1500 chars and no standard meta tags, likely a challenge
    if len(body) < 1500 and not has_meta and not has_title:
        return True

    # Check for challenge-related headers
    lower_headers = {k.lower(): v for k, v in headers.items()}
    if "cf-mitigated" in lower_headers:
        return True
    server = lower_headers.get("server", "").lower()
    if "cloudflare" in server and "cf-ray" in lower_headers and not has_body_content:
        return True

    return False


def _normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    # Return base: scheme + netloc
    return f"{parsed.scheme}://{parsed.netloc}"


def _get_domain(url: str) -> str:
    # str.lstrip("www.") is a character-set strip, not a prefix strip:
    # "webapp.com".lstrip("www.") == "ebapp.com" (wrong).
    # removeprefix() was added in Python 3.9 and does exactly what we want.
    parsed = urlparse(url)
    netloc = parsed.netloc
    return netloc.removeprefix("www.")


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
    # Exclude SEO results from security score (SEO has its own score in frontend)
    security_results = [r for r in results if r.get("category") not in ("SEO", "Performance", "GDPR", "Accessibility")]
    failed = [r for r in security_results if not r.get("passed", True)]

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


def scan(
    url: str,
    progress_callback=None,
    max_pages: int = 1,
    preselected_pages: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Run all security checks on the given URL.
    Returns a dict with all results and the final score.

    Args:
        url: Target URL to scan.
        progress_callback: Optional fn(step, pct) for incremental progress.
        max_pages: Upper bound on pages to scan. Free tier passes 1
            (homepage only, current behaviour). Pro tier passes up to 10.
            When max_pages > 1 and the crawler discovers additional
            same-origin pages, a subset of page-level checks (headers,
            disclosure, vuln, js, seo) is re-run on each additional
            page with a 0.5s target-side rate limit and per-iteration
            deadline check. Findings from non-homepage pages carry a
            'page_url' field so the UI and PDF can group by URL.
        preselected_pages: Optional explicit list of URLs to scan. When
            provided, the internal crawler step is skipped and the
            multi-page loop uses this list instead. Caller is responsible
            for ensuring all URLs are same-origin with `url` and that
            the list length does not exceed max_pages. Used by the
            /api/discover -> /scan two-phase flow so Pro users can
            pick exactly which pages they want analyzed.
    """
    start_time = time.time()
    deadline = start_time + SCAN_DEADLINE_SECONDS
    all_results = []
    errors = []
    scan_truncated = False

    def update(step: str, pct: int):
        if progress_callback:
            progress_callback(step, pct)

    def _deadline_exceeded() -> bool:
        return time.time() > deadline

    def run_check(step_msg: str, pct: int, name: str, fn) -> None:
        """
        Deadline-aware wrapper around a single check.

        If the overall scan deadline has been exceeded, the check is skipped
        and a single truncation notice is added to errors. Otherwise the
        check runs with unified exception handling — a crash in one check
        never stops the rest of the scan.
        """
        nonlocal scan_truncated
        if _deadline_exceeded():
            if not scan_truncated:
                scan_truncated = True
                errors.append(
                    f"Scan prekoracio vremenski limit od {SCAN_DEADLINE_SECONDS}s — "
                    f"preostali check-ovi preskoceni radi zastite servisa."
                )
            return
        update(step_msg, pct)
        try:
            results = fn()
            if results:
                all_results.extend(results)
        except Exception as e:
            errors.append(f"{name} check greška: {str(e)[:80]}")

    # --- Normalize URL ---
    base_url = _normalize_url(url)
    domain = _get_domain(base_url)
    is_https = base_url.startswith("https://")

    update("Inicijalizacija konekcije...", 2)

    # Create a session with common headers.
    # SSL verification is ALWAYS on — a security scanner that skips cert
    # validation on its own requests is a contradiction. If SSL fails,
    # that IS the finding and we report it, not bypass it.
    session = requests.Session()
    session.verify = True
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,sr;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
    })

    # --- Initial HTTP request ---
    main_response = None
    response_headers = {}
    response_body = ""
    response_time_ms = 0
    page_size_bytes = 0

    bot_blocked = False

    try:
        update("Učitavanje sajta...", 4)
        # safe_get enforces SSRF protection on every redirect hop —
        # an attacker-controlled public host cannot bounce us to 127.0.0.1,
        # 169.254.169.254 (AWS metadata), or any internal service.
        main_response = safe_get(session, base_url, timeout=15)
        response_headers = dict(main_response.headers)
        response_body = main_response.text[:50000]  # Cap at 50KB
        response_time_ms = main_response.elapsed.total_seconds() * 1000
        page_size_bytes = len(main_response.content)
        final_url = main_response.url
        is_https = final_url.startswith("https://")
        # Update base_url to follow redirects (e.g. gradovi.rs -> www.gradovi.rs)
        from urllib.parse import urlparse as _urlparse
        _parsed_final = _urlparse(final_url)
        base_url = f"{_parsed_final.scheme}://{_parsed_final.netloc}"

        # Detect bot protection / challenge pages
        # Special case: Vercel Security Checkpoint — try fetching without some headers
        if "vercel security checkpoint" in response_body.lower():
            try:
                # Retry with minimal headers — sometimes bypasses Vercel challenge
                retry_session = requests.Session()
                retry_session.verify = True
                retry_session.headers.update({
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                })
                retry_resp = safe_get(retry_session, base_url, timeout=15)
                if retry_resp.status_code == 200 and "vercel security checkpoint" not in retry_resp.text.lower() and len(retry_resp.text) > 2000:
                    main_response = retry_resp
                    response_headers = dict(retry_resp.headers)
                    response_body = retry_resp.text[:50000]
                    response_time_ms = retry_resp.elapsed.total_seconds() * 1000
                    page_size_bytes = len(retry_resp.content)
                    session = retry_session  # Use this session for all future requests
            except Exception:
                pass

        bot_blocked = _detect_bot_protection(response_body, response_headers)
        if bot_blocked:
            # If page has real content despite bot detection, keep it (false positive)
            has_real_content = (
                '<title' in response_body.lower()
                and len(response_body) > 3000
                and ('<meta name="description"' in response_body.lower() or '<meta name="viewport"' in response_body.lower())
            )
            if has_real_content:
                bot_blocked = False  # False positive — real page with some challenge-like string
            else:
                errors.append(
                    "Bot zaštita detektovana — sajt prikazuje challenge stranicu "
                    "(npr. Cloudflare, DataDome, PerimeterX). Rezultati za HTTP "
                    "headere i SEO mogu biti nepouzdani. / "
                    "Bot protection detected — the site is showing a challenge "
                    "page (e.g. Cloudflare, DataDome, PerimeterX). HTTP header "
                    "and SEO results may be unreliable."
                )
                # Keep headers for security checks, only clear body
                response_body = ""
                response_time_ms = 0
                page_size_bytes = 0
    except UnsafeTargetError as e:
        errors.append(f"Blokirana adresa (SSRF zaštita): {str(e)[:150]}")
        return {
            "url": url,
            "domain": domain,
            "base_url": base_url,
            "scan_time": round(time.time() - start_time, 2),
            "results": [],
            "score": {"score": 0, "grade": "F", "grade_color": "#ef4444",
                      "grade_label": "Blokirano / Blocked", "counts": {}},
            "errors": errors,
            "total_checks": 0,
            "failed_checks": 0,
        }
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
        errors.append(f"Greška pri učitavanju: {str(e)[:200]}")

    # If we got an empty body despite no exception, give the user a
    # neutral hint without leaking internal flags. The operator can still
    # diagnose through HF Space logs (status code + bot_blocked logged below)
    # and through the lower result count in the audit_log entry.
    if not response_body:
        # Only add a user-facing hint if we haven't already told them about
        # bot protection above — no point duplicating the message.
        if not bot_blocked:
            errors.append(
                "Sadržaj sajta nije mogao biti učitan. Neki rezultati "
                "mogu biti nedostupni. / Site content could not be loaded. "
                "Some results may be unavailable."
            )
        # Operator-facing diagnostic — goes to stderr/HF logs, not user
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "empty_response_body status=%s bot_blocked=%s url=%s",
            main_response.status_code if main_response else "N/A",
            bot_blocked,
            base_url,
        )

    # --- Crawl or honour pre-selected pages ---
    # Two code paths feed the `discovered` list used by the multi-page
    # Pro loop at the bottom of this function:
    #
    #   1. Pre-selected (Pro two-phase flow). The caller already knows
    #      exactly which pages to scan because the user picked them
    #      from a discovery modal. We trust the caller to have validated
    #      same-origin constraint at the API layer - scanner.py does
    #      not re-crawl, and it does not second-guess the list.
    #
    #   2. Auto crawl. Legacy path used by the free tier (1 page) and
    #      by Pro users who hit /scan directly without going through
    #      /api/discover first.
    pages_found = 1
    discovered: List[str] = [base_url]
    if preselected_pages:
        discovered = list(preselected_pages)[:max(max_pages, 1)]
        if base_url not in discovered:
            discovered.insert(0, base_url)
            discovered = discovered[:max(max_pages, 1)]
        pages_found = len(discovered)
    elif not _deadline_exceeded() and not bot_blocked and response_body:
        update("Otkrivam stranice sajta...", 5)
        try:
            # Crawl up to max_pages so Pro users with max_pages=10 get
            # 10 URLs discovered, free users still get 1 (homepage only
            # in results but crawler still reports pages_found for UI).
            discovered = crawl(base_url, session, response_body, limit=max(max_pages, 1))
            pages_found = len(discovered)
        except Exception:
            pass

    # --- All security checks, run through the deadline-aware wrapper ---
    # Each call is independent: a crash or timeout in one check never stops
    # the rest, and once SCAN_DEADLINE_SECONDS is exceeded the remaining
    # checks are skipped entirely instead of piling on more wall-clock time.
    run_check("Proveravam SSL/TLS sertifikat...", 7, "SSL",
              lambda: ssl_check.run(domain))
    run_check("Proveravam sigurnosne HTTP headere...", 11, "Headers",
              lambda: headers_check.run(response_headers))
    run_check("Proveravam DNS sigurnost (SPF, DMARC)...", 15, "DNS",
              lambda: dns_check.run(domain))
    run_check("Tražim osetljive fajlove...", 19, "Files",
              lambda: files_check.run(base_url, session))
    run_check("Analiziram otkrivanje informacija o sistemu...", 23, "Disclosure",
              lambda: disclosure_check.run(response_headers, response_body))
    run_check("Proveravam sigurnost kolačića...", 27, "Cookie",
              lambda: cookies_check.run(response_headers, is_https))
    run_check("Proveravam HTTPS preusmeravanja...", 31, "Redirect",
              lambda: redirect_check.run(domain, session))
    run_check("Detektujem CMS i tehnologije...", 35, "CMS",
              lambda: cms_check.run(base_url, response_body, session))
    run_check("WordPress deep-pass (plugini, useri, xmlrpc)...", 37, "WPScan",
              lambda: wpscan_lite.run(base_url, response_body, session))
    run_check("Tražim izložene admin stranice...", 39, "Admin",
              lambda: admin_check.run(base_url, session))
    run_check("Analiziram robots.txt...", 43, "Robots",
              lambda: robots_check.run(base_url, session))
    run_check("Proveravam opasne otvorene portove...", 47, "Ports",
              lambda: ports_check.run(domain))
    run_check("Proveravam CORS politiku...", 50, "CORS",
              lambda: cors_check.run(base_url, response_headers, session))
    run_check("Proveravam security.txt, CAA, SRI...", 54, "Extras",
              lambda: extras_check.run(base_url, domain, response_body, session))
    run_check("Skeniram ranjivosti (pasivno)...", 58, "Vuln",
              lambda: vuln_check.run(base_url, response_body, response_headers, session))
    run_check("Analiziram JavaScript bezbednost...", 62, "JS",
              lambda: js_check.run(base_url, response_body, session))
    run_check("Analiziram JWT tokene u odgovoru...", 64, "JWT",
              lambda: jwt_check.run(response_body, response_headers, session))
    run_check("Proveravam API bezbednost...", 65, "API",
              lambda: api_check.run(base_url, session))
    run_check("Proveravam zavisnosti i biblioteke...", 69, "Dependency",
              lambda: dependency_check.run(base_url, response_body, session))
    run_check("Analiziram SEO...", 73, "SEO",
              lambda: seo_check.run(base_url, response_body, response_headers, session))
    run_check("Analiziram performanse sajta...", 77, "Performance",
              lambda: performance_check.run(
                  base_url, response_body, response_headers, session,
                  response_time_ms, page_size_bytes))
    run_check("Proveravam GDPR usklađenost...", 80, "GDPR",
              lambda: gdpr_check.run(base_url, response_body, response_headers, session))
    run_check("Proveravam pristupačnost (a11y)...", 84, "Accessibility",
              lambda: accessibility_check.run(response_body))
    run_check("Proveravam WHOIS podatke domena...", 87, "WHOIS",
              lambda: whois_check.run(domain))
    run_check("Detektujem tehnoloski stek...", 89, "Tech stack",
              lambda: tech_stack_check.run(response_body, response_headers))
    run_check("Proveravam email bezbednost...", 91, "Email",
              lambda: email_security_check.run(domain))
    run_check("Mozilla Observatory analiza...", 93, "Observatory",
              lambda: observatory_check.run(domain))
    run_check("Proveravam Certificate Transparency logove...", 97, "CT",
              lambda: ct_check.run(domain))
    run_check("Skeniram subdomene...", 98, "Subdomain",
              lambda: subdomain_check.run(domain))
    run_check("Proveravam dangling CNAME zapise (subdomain takeover)...", 98, "Takeover",
              lambda: takeover_check.run(domain))

    # ─────────────────────────────────────────────────────────────────
    # Multi-page pass (Pro plan only — max_pages > 1)
    # ─────────────────────────────────────────────────────────────────
    # For each additional page discovered by the crawler, re-run the
    # subset of checks that are content-dependent (headers, disclosure,
    # vuln patterns, JS, SEO). Domain-level checks (SSL, DNS, Files,
    # CMS detection, Ports, WHOIS, etc.) already ran once above and do
    # not need to be repeated per page — they would return identical
    # results and waste both our deadline and the target's bandwidth.
    #
    # Target-side rate limit: 0.5s sleep between pages. At max_pages=10
    # this adds ~5s of wall-clock overhead, well within our 180s scan
    # deadline budget. Respecting target sites is part of passive
    # scanning — we don't DoS anyone.
    #
    # Each finding gets tagged with 'page_url' so the frontend and the
    # PDF report can group per-page results visibly. Homepage findings
    # keep no 'page_url' (they represent the whole domain or homepage).
    if max_pages > 1 and len(discovered) > 1 and not _deadline_exceeded():
        # Skip the homepage (index 0 = base_url, already scanned above)
        extra_pages = discovered[1:max_pages]
        total_extra = len(extra_pages)
        for i, page_url in enumerate(extra_pages, start=1):
            if _deadline_exceeded():
                if not scan_truncated:
                    scan_truncated = True
                    errors.append(
                        f"Scan prekoracio vremenski limit od {SCAN_DEADLINE_SECONDS}s — "
                        f"multi-page pass prekinut posle {i-1}/{total_extra} stranica."
                    )
                break

            # Target-side rate limit — be gentle to the scanned site.
            # Not applied on the first iteration because the homepage
            # fetch above already put some delay between now and the
            # first extra page.
            if i > 1:
                time.sleep(0.5)

            # Update UI progress — share the 98-99 range across all
            # extra pages so the score-calculation step still lands at
            # 99, then 100 at the very end.
            step_label = f"Pro: skeniram stranicu {i}/{total_extra}"
            update(step_label, 98)

            try:
                page_resp = safe_get(session, page_url, timeout=10)
                page_body = page_resp.text[:50000] if page_resp.text else ""
                page_headers = dict(page_resp.headers)
            except UnsafeTargetError:
                errors.append(f"Page {page_url} blocked by SSRF guard")
                continue
            except Exception as e:
                errors.append(f"Page {page_url} fetch failed: {str(e)[:80]}")
                continue

            # Run the page-level check subset. Any crash here does not
            # stop the rest of the multi-page loop — matches the
            # single-page run_check() behaviour.
            page_level_checks = [
                ("Headers",    lambda: headers_check.run(page_headers)),
                ("Disclosure", lambda: disclosure_check.run(page_headers, page_body)),
                ("Vuln",       lambda: vuln_check.run(page_url, page_body, page_headers, session)),
                ("JS",         lambda: js_check.run(page_url, page_body, session)),
                ("JWT",        lambda: jwt_check.run(page_body, page_headers, session)),
                ("SEO",        lambda: seo_check.run(page_url, page_body, page_headers, session)),
            ]
            for check_name, check_fn in page_level_checks:
                if _deadline_exceeded():
                    break
                try:
                    page_results = check_fn() or []
                    # Tag each result with the page URL so the UI can
                    # group findings per page.
                    for r in page_results:
                        if isinstance(r, dict):
                            r["page_url"] = page_url
                    all_results.extend(page_results)
                except Exception as e:
                    errors.append(
                        f"{check_name} check on {page_url}: {str(e)[:60]}"
                    )

    update("Izračunavam ocenu...", 99)

    score_data = compute_score(all_results)

    # Risk priorities
    top_priorities = risk_engine.get_top_priorities(all_results, count=5)

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
        "top_priorities": top_priorities,
        "pages_found": pages_found,
    }
