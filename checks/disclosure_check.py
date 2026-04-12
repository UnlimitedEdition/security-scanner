# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Information Disclosure Check
Checks for server/technology version leakage in HTTP headers and HTML.

mode parameter (gate-before-scan model from migrations 014/015):
  * 'full' (default) — Findings include the exact leaked version string
                       (e.g. "Apache/2.4.49") which is what a domain owner
                       needs to fix the issue.
  * 'safe'           — The detection still runs (the body and headers are
                       already in memory from the main fetch), but every
                       finding's title/description/recommendation strips
                       the exact version. The owner sees "Server reveals
                       version (verify ownership to view exact value)"
                       and the attacker gets nothing useful from the
                       summary alone.
"""
import re
import requests
from typing import List, Dict, Any


# Sentinel string used in 'safe' mode wherever the unredacted version
# would normally appear. Bilingual so the frontend can display the same
# label in either language without a separate translation lookup.
_REDACTED_LABEL_SR = "[verifikujte vlasnistvo da vidite tacnu vrednost]"
_REDACTED_LABEL_EN = "[verify ownership to see the exact value]"


def run(
    response_headers: dict,
    response_body: str = "",
    mode: str = "full",
) -> List[Dict[str, Any]]:
    """
    Scan the already-received response headers + body for information
    leakage. mode='safe' produces sumary findings with no exact values;
    mode='full' produces the legacy detailed findings.
    """
    safe_mode = (mode == "safe")
    results = []
    lower_headers = {k.lower(): v for k, v in response_headers.items()}

    # --- Server header ---
    server = lower_headers.get("server", "")
    if server:
        # Check if it reveals version info
        version_pattern = r"\d+\.\d+"
        has_version = bool(re.search(version_pattern, server))
        if has_version:
            # In safe mode the value (e.g. "Apache/2.4.49") is the exploit
            # cheat sheet — strip it to a generic placeholder. The
            # severity, category, and passed flag stay the same so the
            # score and grade come out identical to a full-mode scan.
            shown_value = _REDACTED_LABEL_SR if safe_mode else server[:60]
            shown_value_en = _REDACTED_LABEL_EN if safe_mode else server[:60]
            results.append({
                "id": "disc_server_version",
                "category": "Information Disclosure",
                "severity": "MEDIUM",
                "passed": False,
                "title": f"Server header otkriva verziju: {shown_value}",
                "title_en": f"Server header reveals version: {shown_value_en}",
                "description": "Tačna verzija web servera pomaže napadaču da pronađe poznate ranjivosti za tu verziju.",
                "description_en": "Exact web server version helps attackers find known vulnerabilities for that version.",
                "recommendation": "Sakrijte verziju servera. U Nginx: 'server_tokens off;'. U Apache: 'ServerTokens Prod'.",
                "recommendation_en": "Hide server version. In Nginx: 'server_tokens off;'. In Apache: 'ServerTokens Prod'.",
                "_redacted": safe_mode,
            })
        else:
            # Pass-finding: server header is present but doesn't expose
            # a version. The header value itself is harmless ("nginx",
            # "Apache", "cloudflare") but in the strictest reading we
            # could still consider it a tiny fingerprint. Hide the
            # exact name in safe mode for consistency with the version-
            # leak branch above.
            shown_ok = _REDACTED_LABEL_SR if safe_mode else server[:40]
            shown_ok_en = _REDACTED_LABEL_EN if safe_mode else server[:40]
            results.append({
                "id": "disc_server_ok",
                "category": "Information Disclosure",
                "severity": "INFO",
                "passed": True,
                "title": f"Server header ne otkriva verziju ✓ ({shown_ok})",
                "title_en": f"Server header does not reveal version ✓ ({shown_ok_en})",
                "description": "Server header je prisutan ali ne otkriva tačnu verziju.",
                "description_en": "Server header is present but does not reveal the exact version.",
                "recommendation": "",
                "recommendation_en": "",
                "_redacted": safe_mode,
            })

    # --- X-Powered-By ---
    powered_by = lower_headers.get("x-powered-by", "")
    if powered_by:
        shown_pb = _REDACTED_LABEL_SR if safe_mode else powered_by[:60]
        shown_pb_en = _REDACTED_LABEL_EN if safe_mode else powered_by[:60]
        results.append({
            "id": "disc_powered_by",
            "category": "Information Disclosure",
            "severity": "MEDIUM",
            "passed": False,
            "title": f"X-Powered-By otkriva tehnologiju: {shown_pb}",
            "title_en": f"X-Powered-By reveals technology: {shown_pb_en}",
            "description": "X-Powered-By header otkriva programski jezik i verziju (npr. PHP/8.1, ASP.NET). Napadač ovo koristi za ciljane napade.",
            "description_en": "X-Powered-By header reveals the programming language and version (e.g. PHP/8.1, ASP.NET). Attackers use this for targeted attacks.",
            "recommendation": "Uklonite X-Powered-By header. U PHP: 'expose_php = Off' u php.ini. U Express.js: 'app.disable(\"x-powered-by\")'.",
            "recommendation_en": "Remove X-Powered-By header. In PHP: 'expose_php = Off' in php.ini. In Express.js: 'app.disable(\"x-powered-by\")'.",
            "_redacted": safe_mode,
        })

    # --- X-AspNet-Version ---
    aspnet = lower_headers.get("x-aspnet-version", "") or lower_headers.get("x-aspnetmvc-version", "")
    if aspnet:
        shown_asp = _REDACTED_LABEL_SR if safe_mode else aspnet[:60]
        shown_asp_en = _REDACTED_LABEL_EN if safe_mode else aspnet[:60]
        results.append({
            "id": "disc_aspnet",
            "category": "Information Disclosure",
            "severity": "MEDIUM",
            "passed": False,
            "title": f"ASP.NET verzija otkrivena: {shown_asp}",
            "title_en": f"ASP.NET version disclosed: {shown_asp_en}",
            "description": "Verzija ASP.NET framework-a je javno vidljiva.",
            "description_en": "ASP.NET framework version is publicly visible.",
            "recommendation": "U web.config dodajte: <httpRuntime enableVersionHeader='false'/>",
            "recommendation_en": "In web.config add: <httpRuntime enableVersionHeader='false'/>",
            "_redacted": safe_mode,
        })

    # --- Check for debug information in HTML body ---
    if response_body:
        debug_patterns = [
            (r"(Fatal error|Parse error|Warning:|Notice:)\s+.+\s+on line \d+", "PHP greška vidljiva korisnicima", "PHP error visible to users"),
            (r"Microsoft OLE DB Provider for SQL Server", "SQL Server greška otkrivena", "SQL Server error disclosed"),
            (r"ORA-\d{5}:", "Oracle greška otkrivena", "Oracle error disclosed"),
            (r"Traceback \(most recent call last\)", "Python stack trace otkriven", "Python stack trace disclosed"),
            (r"at [A-Za-z\.]+\([A-Za-z]+\.java:\d+\)", "Java stack trace otkriven", "Java stack trace disclosed"),
        ]

        for pattern, title_sr, title_en in debug_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                # Debug error class names ("PHP error", "Oracle error",
                # "Python stack trace") are themselves a small piece of
                # fingerprint info — in safe mode we collapse them all
                # to a generic label so an unverified caller cannot tell
                # which engine the site is running.
                shown_dbg = _REDACTED_LABEL_SR if safe_mode else title_sr
                shown_dbg_en = _REDACTED_LABEL_EN if safe_mode else title_en
                results.append({
                    "id": "disc_debug_info",
                    "category": "Information Disclosure",
                    "severity": "HIGH",
                    "passed": False,
                    "title": f"Debug informacije vidljive: {shown_dbg}",
                    "title_en": f"Debug information visible: {shown_dbg_en}",
                    "description": "Greške i stack trace-ovi otkrivaju unutrašnju strukturu aplikacije napadaču.",
                    "description_en": "Errors and stack traces reveal the internal application structure to attackers.",
                    "recommendation": "Isključite prikazivanje grešaka u produkciji. Koristite error logging umesto prikazivanja grešaka.",
                    "recommendation_en": "Disable error display in production. Use error logging instead of displaying errors.",
                    "_redacted": safe_mode,
                })
                break

    # --- Check WordPress version in meta tags ---
    if response_body:
        wp_version = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', response_body, re.IGNORECASE)
        if wp_version:
            version = wp_version.group(1)
            # The exact WP version (e.g. "5.8.1") is the entire payload
            # for an attacker — they look it up against a CVE database
            # to pick which exploit to use. In safe mode we hide the
            # number but still report that *some* version is leaked.
            shown_wp = _REDACTED_LABEL_SR if safe_mode else f"v{version}"
            shown_wp_en = _REDACTED_LABEL_EN if safe_mode else f"v{version}"
            desc_wp = (
                "WordPress verzija je vidljiva u source kodu stranice."
                if safe_mode
                else f"WordPress verzija {version} je vidljiva u source kodu stranice. Napadač može proveriti poznate ranjivosti za tu verziju."
            )
            desc_wp_en = (
                "The WordPress version is visible in the page source."
                if safe_mode
                else f"WordPress version {version} is visible in page source. An attacker can check known vulnerabilities for that version."
            )
            results.append({
                "id": "disc_wp_version",
                "category": "Information Disclosure",
                "severity": "MEDIUM",
                "passed": False,
                "title": f"WordPress verzija otkrivena u HTML-u: {shown_wp}",
                "title_en": f"WordPress version disclosed in HTML: {shown_wp_en}",
                "description": desc_wp,
                "description_en": desc_wp_en,
                "recommendation": "Uklonite generator meta tag. Dodajte u functions.php: remove_action('wp_head', 'wp_generator');",
                "recommendation_en": "Remove the generator meta tag. Add to functions.php: remove_action('wp_head', 'wp_generator');",
                "_redacted": safe_mode,
            })

    return results
