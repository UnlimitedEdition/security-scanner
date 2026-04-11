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


# ── CSP strict analyzer ────────────────────────────────────────────────────
#
# Roadmap #2: "postoji ali bezvredan" is the most common CSP failure mode in
# production. We parse the policy, then flag eight specific weaknesses: four
# in script-src (unsafe-inline, unsafe-eval, wildcard, data:) and four
# missing directives (object-src, base-uri, frame-ancestors, form-action).
# All eight are collapsed into a single aggregated "weak CSP" finding so
# the scan report stays readable — the severity is the max of all issues.

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _parse_csp(value: str) -> Dict[str, List[str]]:
    """
    Parse a Content-Security-Policy header value into a
    {directive_name: [source_tokens]} dict. Directive names are lowercased;
    source tokens keep their original case (they are matched case-sensitively
    for quoted keywords like 'self', 'none', 'unsafe-inline').
    """
    directives: Dict[str, List[str]] = {}
    for chunk in value.split(";"):
        parts = chunk.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        directives[name] = parts[1:]
    return directives


def _analyze_csp(value: str) -> List[Dict[str, str]]:
    """
    Return a list of weakness dicts found in the policy. Each dict carries
    a severity plus bilingual issue/explanation text. Empty list means the
    policy passes all eight roadmap checks.
    """
    directives = _parse_csp(value)
    weaknesses: List[Dict[str, str]] = []

    # script-src falls back to default-src when absent (CSP spec).
    script_src = directives.get("script-src", directives.get("default-src", []))
    script_src_lower = [s.lower() for s in script_src]

    if "'unsafe-inline'" in script_src_lower:
        weaknesses.append({
            "severity": "HIGH",
            "issue_sr": "script-src dozvoljava 'unsafe-inline'",
            "issue_en": "script-src allows 'unsafe-inline'",
            "explain_sr": "Inline <script> tagovi i inline event handleri mogu se izvršiti — XSS zaštita je praktično onemogućena.",
            "explain_en": "Inline <script> tags and inline event handlers can execute — XSS protection is effectively disabled.",
        })

    if "'unsafe-eval'" in script_src_lower:
        weaknesses.append({
            "severity": "HIGH",
            "issue_sr": "script-src dozvoljava 'unsafe-eval'",
            "issue_en": "script-src allows 'unsafe-eval'",
            "explain_sr": "Dinamičko izvršavanje koda iz stringa je dozvoljeno — napadač može pokrenuti proizvoljan JavaScript preko string-to-code konverzije.",
            "explain_en": "Dynamic code execution from strings is allowed — an attacker can run arbitrary JavaScript through string-to-code conversion.",
        })

    if "*" in script_src_lower:
        weaknesses.append({
            "severity": "CRITICAL",
            "issue_sr": "script-src sadrži wildcard '*'",
            "issue_en": "script-src contains wildcard '*'",
            "explain_sr": "Bilo koji domen sme da servira skripte — CSP nema nikakav efekat kao zaštita od XSS-a.",
            "explain_en": "Any domain may serve scripts — CSP has no effect as XSS protection.",
        })

    if "data:" in script_src_lower:
        weaknesses.append({
            "severity": "HIGH",
            "issue_sr": "script-src dozvoljava 'data:' URI",
            "issue_en": "script-src allows 'data:' URI",
            "explain_sr": "Napadač može isporučiti JavaScript kroz data:text/javascript,... URL — CSP zaobiđen.",
            "explain_en": "Attacker can deliver JavaScript through data:text/javascript,... URLs — CSP bypassed.",
        })

    # object-src falls back to default-src. Only flag if neither is set to
    # 'none' — the CSP best practice is explicit "object-src 'none'".
    if "object-src" not in directives:
        default_src_lower = [s.lower() for s in directives.get("default-src", [])]
        if "'none'" not in default_src_lower:
            weaknesses.append({
                "severity": "MEDIUM",
                "issue_sr": "object-src nije postavljen na 'none'",
                "issue_en": "object-src is not set to 'none'",
                "explain_sr": "Bez 'object-src none' stariji pluginovi (Flash, Java, Silverlight, PDF) mogu se učitati i zaobići CSP kroz <object> tag.",
                "explain_en": "Without 'object-src none' older plugins (Flash, Java, Silverlight, PDF) can load and bypass CSP through <object> tags.",
            })

    # base-uri, frame-ancestors, form-action do NOT fall back to default-src
    # per CSP spec — they must be declared explicitly to take effect.
    if "base-uri" not in directives:
        weaknesses.append({
            "severity": "LOW",
            "issue_sr": "base-uri nije definisan",
            "issue_en": "base-uri is not defined",
            "explain_sr": "Napadač može injektovati <base> tag i preusmeriti sve relativne URL-ove (uključujući script src) ka svom serveru.",
            "explain_en": "An attacker can inject a <base> tag and redirect all relative URLs (including script src) to their own server.",
        })

    if "frame-ancestors" not in directives:
        weaknesses.append({
            "severity": "LOW",
            "issue_sr": "frame-ancestors nije definisan",
            "issue_en": "frame-ancestors is not defined",
            "explain_sr": "Clickjacking zaštita oslanja se samo na legacy X-Frame-Options. CSP-nativan frame-ancestors je pouzdaniji i strožiji.",
            "explain_en": "Clickjacking protection relies only on the legacy X-Frame-Options header. The CSP-native frame-ancestors directive is more reliable and stricter.",
        })

    if "form-action" not in directives:
        weaknesses.append({
            "severity": "LOW",
            "issue_sr": "form-action nije definisan",
            "issue_en": "form-action is not defined",
            "explain_sr": "Napadač koji uspe da injektuje HTML može preusmeriti formu (<form action=...>) ka svom serveru i ukrasti podatke.",
            "explain_en": "An attacker who injects HTML can redirect a form (<form action=...>) to their own server and steal submitted data.",
        })

    return weaknesses


def _build_csp_weak_finding(value: str, weaknesses: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Aggregate a list of CSP weaknesses into a single finding. Severity is
    the max of any individual issue so one wildcard tanks the whole policy
    to CRITICAL, while a policy that only lacks form-action stays at LOW.
    """
    top_sev = max(weaknesses, key=lambda w: _SEVERITY_RANK[w["severity"]])["severity"]

    issues_sr = "\n".join(f"• {w['issue_sr']} — {w['explain_sr']}" for w in weaknesses)
    issues_en = "\n".join(f"• {w['issue_en']} — {w['explain_en']}" for w in weaknesses)
    truncated = value if len(value) <= 240 else value[:240] + "…"

    return {
        "id": "hdr_csp_weak",
        "category": "Security Headers",
        "severity": top_sev,
        "passed": False,
        "title": f"Content Security Policy je definisan ali slab ({len(weaknesses)} problema)",
        "title_en": f"Content Security Policy is defined but weak ({len(weaknesses)} issues)",
        "description": (
            "CSP header je prisutan, ali sledeće slabosti ga čine manje efikasnim:\n\n"
            f"{issues_sr}\n\nTrenutna vrednost: {truncated}"
        ),
        "description_en": (
            "CSP header is present, but the following weaknesses reduce its effectiveness:\n\n"
            f"{issues_en}\n\nCurrent value: {truncated}"
        ),
        "recommendation": (
            "Strog CSP treba da: (1) koristi 'self' ili nonce/hash u script-src umesto 'unsafe-inline'/'unsafe-eval', "
            "(2) eksplicitno postavi object-src 'none', (3) postavi base-uri 'none' ili 'self', "
            "(4) postavi frame-ancestors 'none' ili eksplicitnu listu, (5) ograniči form-action na dozvoljene ciljeve. "
            "Primer strogog CSP-a: \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self'\""
        ),
        "recommendation_en": (
            "A strict CSP should: (1) use 'self' or nonce/hash in script-src instead of 'unsafe-inline'/'unsafe-eval', "
            "(2) explicitly set object-src 'none', (3) set base-uri 'none' or 'self', "
            "(4) set frame-ancestors 'none' or an explicit list, (5) restrict form-action to allowed targets. "
            "Example of a strict CSP: \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self'\""
        ),
    }


def run(response_headers: dict) -> List[Dict[str, Any]]:
    results = []
    lower_headers = {k.lower(): v for k, v in response_headers.items()}

    for spec in HEADERS_SPEC:
        header_lower = spec["header"].lower()
        present = header_lower in lower_headers
        value = lower_headers.get(header_lower, "")

        if present:
            # Extra validation for CSP: parse the policy and flag
            # roadmap-#2 weaknesses as a single aggregated finding.
            if spec["id"] == "hdr_csp":
                csp_weaknesses = _analyze_csp(value)
                if csp_weaknesses:
                    results.append(_build_csp_weak_finding(value, csp_weaknesses))
                    continue

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
