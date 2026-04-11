# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
HTTP Security Headers Check
Checks 11 critical security headers that most Serbian sites are missing.
"""
from typing import List, Dict, Any


HEADERS_SPEC = [
    {
        "id": "hdr_hsts",
        "header": "Strict-Transport-Security",
        "severity": "HIGH",
        "title": "Nedostaje HSTS zaštita",
        "title_en": "Missing HSTS Protection",
        "description": "HSTS (HTTP Strict Transport Security) primorava browser da uvek koristi HTTPS. Bez njega, napadač može presresti konekciju (SSL stripping napad).",
        "description_en": "HSTS forces the browser to always use HTTPS. Without it, an attacker can intercept the connection (SSL stripping attack).",
        "recommendation": 'Dodajte header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        "recommendation_en": 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        "good_title": "HSTS zaštita aktivna ✓",
        "good_title_en": "HSTS Protection Active ✓",
    },
    {
        "id": "hdr_csp",
        "header": "Content-Security-Policy",
        "severity": "HIGH",
        "title": "Nedostaje Content Security Policy (CSP)",
        "title_en": "Missing Content Security Policy (CSP)",
        "description": "CSP sprečava XSS napade kontrolišući koje skripte browser sme da izvrši. Bez CSP, napadač može injektovati zlonamerni JavaScript u stranicu.",
        "description_en": "CSP prevents XSS attacks by controlling which scripts the browser may execute. Without CSP, an attacker can inject malicious JavaScript.",
        "recommendation": "Dodajte Content-Security-Policy header. Minimum: Content-Security-Policy: default-src 'self'",
        "recommendation_en": "Add a Content-Security-Policy header. Minimum: Content-Security-Policy: default-src 'self'",
        "good_title": "Content Security Policy definisan ✓",
        "good_title_en": "Content Security Policy defined ✓",
    },
    {
        "id": "hdr_xfo",
        "header": "X-Frame-Options",
        "severity": "MEDIUM",
        "title": "Nedostaje zaštita od Clickjacking napada",
        "title_en": "Missing Clickjacking Protection",
        "description": "Bez X-Frame-Options, napadač može ubaciti vaš sajt u nevidljivi iframe i prevariti korisnike da kliknu na nešto što ne vide (clickjacking).",
        "description_en": "Without X-Frame-Options, an attacker can embed your site in an invisible iframe and trick users into clicking hidden elements.",
        "recommendation": "Dodajte: X-Frame-Options: DENY (ili SAMEORIGIN ako trebate iframes unutar svog domena)",
        "recommendation_en": "Add: X-Frame-Options: DENY (or SAMEORIGIN if you need iframes within your own domain)",
        "good_title": "Clickjacking zaštita aktivna ✓",
        "good_title_en": "Clickjacking Protection Active ✓",
    },
    {
        "id": "hdr_xcto",
        "header": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "title": "Nedostaje X-Content-Type-Options",
        "title_en": "Missing X-Content-Type-Options",
        "description": "Bez ovog headera, browser može pogresno interpretirati tip fajla (MIME sniffing), što napadač može iskoristiti za izvrsavanje zlonamernog koda.",
        "description_en": "Without this header, the browser may misinterpret file types (MIME sniffing), which attackers can exploit to execute malicious code.",
        "recommendation": "Dodajte: X-Content-Type-Options: nosniff",
        "recommendation_en": "Add: X-Content-Type-Options: nosniff",
        "good_title": "MIME Sniffing zaštita aktivna ✓",
        "good_title_en": "MIME Sniffing Protection Active ✓",
    },
    {
        "id": "hdr_rp",
        "header": "Referrer-Policy",
        "severity": "LOW",
        "title": "Nedostaje Referrer-Policy",
        "title_en": "Missing Referrer-Policy",
        "description": "Bez Referrer-Policy, browser šalje pun URL stranice kao Referer header pri svakom klikanju na eksterni link. To može otkriti privatne URL-ove korisnika.",
        "description_en": "Without Referrer-Policy, the browser sends the full page URL as a Referer header on every external link click, potentially leaking private URLs.",
        "recommendation": "Dodajte: Referrer-Policy: strict-origin-when-cross-origin",
        "recommendation_en": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "good_title": "Referrer Policy definisan ✓",
        "good_title_en": "Referrer Policy Defined ✓",
    },
    {
        "id": "hdr_pp",
        "header": "Permissions-Policy",
        "severity": "LOW",
        "title": "Nedostaje Permissions-Policy",
        "title_en": "Missing Permissions-Policy",
        "description": "Permissions-Policy kontroliše pristup browser API-jima (kamera, mikrofon, lokacija). Bez njega, ugrađeni iframeovi mogu pristupati ovim resursima.",
        "description_en": "Permissions-Policy controls access to browser APIs (camera, microphone, location). Without it, embedded iframes may access these resources.",
        "recommendation": "Dodajte: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "recommendation_en": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "good_title": "Permissions Policy definisan ✓",
        "good_title_en": "Permissions Policy Defined ✓",
    },
    {
        "id": "hdr_coop",
        "header": "Cross-Origin-Opener-Policy",
        "severity": "LOW",
        "title": "Nedostaje Cross-Origin-Opener-Policy",
        "title_en": "Missing Cross-Origin-Opener-Policy",
        "description": "Bez COOP, maliciozna strana može dobiti referensu na vaš window objekat kroz popup-ove, što može dovesti do cross-origin napada.",
        "description_en": "Without COOP, a malicious page opened from yours can get a reference to your window object via popups.",
        "recommendation": "Dodajte: Cross-Origin-Opener-Policy: same-origin",
        "recommendation_en": "Add: Cross-Origin-Opener-Policy: same-origin",
        "good_title": "Cross-Origin-Opener-Policy aktivan ✓",
        "good_title_en": "Cross-Origin-Opener-Policy Active ✓",
    },
]


def run(response_headers: dict) -> List[Dict[str, Any]]:
    results = []
    lower_headers = {k.lower(): v for k, v in response_headers.items()}

    for spec in HEADERS_SPEC:
        header_lower = spec["header"].lower()
        present = header_lower in lower_headers
        value = lower_headers.get(header_lower, "")

        if present:
            # Extra validation for HSTS
            if spec["id"] == "hdr_hsts":
                # Check max-age is at least 6 months
                import re
                match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
                if match:
                    max_age = int(match.group(1))
                    if max_age < 15552000:  # 6 months
                        results.append({
                            "id": spec["id"] + "_weak",
                            "category": "Security Headers",
                            "severity": "MEDIUM",
                            "passed": False,
                            "title": f"HSTS max-age je premalo ({max_age}s)",
                            "title_en": f"HSTS max-age is too short ({max_age}s)",
                            "description": f"HSTS je prisutan ali max-age={max_age} je premalo. Minimum preporuka je 6 meseci (15552000s).",
                            "description_en": f"HSTS is present but max-age={max_age} is too short. Minimum recommendation is 6 months.",
                            "recommendation": "Postavite max-age na minimum 31536000 (1 godina) i dodajte includeSubDomains.",
                            "recommendation_en": "Set max-age to at least 31536000 (1 year) and add includeSubDomains.",
                        })
                        continue

            results.append({
                "id": spec["id"],
                "category": "Security Headers",
                "severity": "INFO",
                "passed": True,
                "title": spec["good_title"],
                "title_en": spec["good_title_en"],
                "description": f"Vrednost: {value[:80]}",
                "description_en": f"Value: {value[:80]}",
                "recommendation": "",
                "recommendation_en": "",
            })
        else:
            results.append({
                "id": spec["id"],
                "category": "Security Headers",
                "severity": spec["severity"],
                "passed": False,
                "title": spec["title"],
                "title_en": spec["title_en"],
                "description": spec["description"],
                "description_en": spec["description_en"],
                "recommendation": spec["recommendation"],
                "recommendation_en": spec["recommendation_en"],
            })

    return results
