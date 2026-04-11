# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Cookie Security Check
Checks for missing HttpOnly, Secure, SameSite attributes on cookies.
"""
from typing import List, Dict, Any


def run(response_headers: dict, is_https: bool = True) -> List[Dict[str, Any]]:
    results = []
    lower_headers = {k.lower(): v for k, v in response_headers.items()}

    # Collect all Set-Cookie headers
    cookies_raw = []
    for k, v in response_headers.items():
        if k.lower() == "set-cookie":
            if isinstance(v, list):
                cookies_raw.extend(v)
            else:
                cookies_raw.append(v)

    if not cookies_raw:
        results.append({
            "id": "cookies_none",
            "category": "Cookie Security",
            "severity": "INFO",
            "passed": True,
            "title": "Nema kolačića na početnoj stranici",
            "title_en": "No cookies set on the homepage",
            "description": "Nije detektovano postavljanje kolačića na početnoj stranici.",
            "description_en": "No cookie setting detected on the homepage.",
            "recommendation": "",
            "recommendation_en": "",
        })
        return results

    missing_httponly = []
    missing_secure = []
    missing_samesite = []
    missing_prefix = []  # Roadmap #5: session/auth cookies without __Host-/__Secure-

    # Substring markers in the cookie name that identify it as session/auth
    # material and therefore a candidate for the __Host- or __Secure- prefix
    # requirement. Matched case-insensitively against the bare name.
    _SESSION_LIKE_MARKERS = (
        "session", "sess", "sid", "auth", "token",
        "login", "user", "jwt", "access", "refresh",
        "connect.sid", "phpsessid", "asp.net_sessionid",
    )

    for cookie in cookies_raw:
        cookie_lower = cookie.lower()
        # Extract cookie name
        name = cookie.split("=")[0].strip()
        name_lower = name.lower()

        if "httponly" not in cookie_lower:
            missing_httponly.append(name)
        if is_https and "secure" not in cookie_lower:
            missing_secure.append(name)
        if "samesite" not in cookie_lower:
            missing_samesite.append(name)

        # Prefix enforcement: only for session/auth-like cookies served
        # over HTTPS. Non-session cookies (analytics, consent, theme) are
        # intentionally left alone — flagging them would be noise.
        if is_https and any(m in name_lower for m in _SESSION_LIKE_MARKERS):
            if not (name.startswith("__Host-") or name.startswith("__Secure-")):
                missing_prefix.append(name)

    if missing_httponly:
        names = ", ".join(missing_httponly[:5])
        results.append({
            "id": "cookies_no_httponly",
            "category": "Cookie Security",
            "severity": "HIGH",
            "passed": False,
            "title": f"Kolačići bez HttpOnly zastavice: {names}",
            "title_en": f"Cookies missing HttpOnly flag: {names}",
            "description": "Kolačići bez HttpOnly mogu biti ukradeni kroz XSS napad. JavaScript može čitati ove kolačiće i poslati ih napadaču.",
            "description_en": "Cookies without HttpOnly can be stolen via XSS attack. JavaScript can read these cookies and send them to the attacker.",
            "recommendation": "Dodajte HttpOnly zastavicu svim session kolačićima: Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict",
            "recommendation_en": "Add HttpOnly flag to all session cookies: Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict",
        })

    if missing_secure:
        names = ", ".join(missing_secure[:5])
        results.append({
            "id": "cookies_no_secure",
            "category": "Cookie Security",
            "severity": "HIGH",
            "passed": False,
            "title": f"Kolačići bez Secure zastavice: {names}",
            "title_en": f"Cookies missing Secure flag: {names}",
            "description": "Kolačići bez Secure zastavice mogu biti poslati preko HTTP konekcije, gde napadač može presresti saobraćaj i ukrasti sesiju.",
            "description_en": "Cookies without the Secure flag can be sent over HTTP connections, where an attacker can intercept traffic and steal the session.",
            "recommendation": "Dodajte Secure zastavicu svim kolačićima koji sadrže osetljive podatke.",
            "recommendation_en": "Add the Secure flag to all cookies containing sensitive data.",
        })

    if missing_samesite:
        names = ", ".join(missing_samesite[:5])
        results.append({
            "id": "cookies_no_samesite",
            "category": "Cookie Security",
            "severity": "MEDIUM",
            "passed": False,
            "title": f"Kolačići bez SameSite atributa: {names}",
            "title_en": f"Cookies missing SameSite attribute: {names}",
            "description": "Bez SameSite atributa, kolačići se šalju pri cross-site zahtevima, što otvara mogućnost CSRF napada.",
            "description_en": "Without the SameSite attribute, cookies are sent on cross-site requests, enabling CSRF attacks.",
            "recommendation": "Dodajte SameSite=Strict ili SameSite=Lax svim kolačićima.",
            "recommendation_en": "Add SameSite=Strict or SameSite=Lax to all cookies.",
        })

    if missing_prefix:
        names = ", ".join(missing_prefix[:5])
        results.append({
            "id": "cookies_no_host_prefix",
            "category": "Cookie Security",
            "severity": "LOW",
            "passed": False,
            "title": f"Session kolačići bez __Host-/__Secure- prefiksa: {names}",
            "title_en": f"Session cookies without __Host-/__Secure- prefix: {names}",
            "description": (
                "Detektovani session/auth kolačići koji ne koriste __Host- ili "
                "__Secure- prefiks u imenu. __Host- prefiks browser primorava da "
                "kolačić mora biti Secure, Path=/ i bez Domain atributa — što "
                "onemogućava subdomen napade i cookie fixation kroz kompromitovani "
                "sibling subdomen. __Secure- samo garantuje Secure flag."
            ),
            "description_en": (
                "Session/auth cookies detected that do not use the __Host- or "
                "__Secure- name prefix. The __Host- prefix forces the browser to "
                "reject the cookie unless it is Secure, Path=/, and has no Domain "
                "attribute — which blocks subdomain attacks and cookie fixation "
                "through a compromised sibling subdomain. __Secure- only enforces "
                "the Secure flag."
            ),
            "recommendation": (
                "Preimenujte session cookie u '__Host-<originalno_ime>' i postavite "
                "ga kao: Set-Cookie: __Host-session=abc; Secure; HttpOnly; "
                "SameSite=Strict; Path=/ (bez Domain atributa). Ako morate da "
                "koristite Domain (npr. za subdomen sharing), koristite __Secure- "
                "prefiks umesto __Host-."
            ),
            "recommendation_en": (
                "Rename the session cookie to '__Host-<original_name>' and set it "
                "as: Set-Cookie: __Host-session=abc; Secure; HttpOnly; "
                "SameSite=Strict; Path=/ (no Domain attribute). If you must use "
                "Domain (e.g. for subdomain sharing), use the __Secure- prefix "
                "instead of __Host-."
            ),
        })

    if not missing_httponly and not missing_secure and not missing_samesite and not missing_prefix:
        results.append({
            "id": "cookies_all_ok",
            "category": "Cookie Security",
            "severity": "INFO",
            "passed": True,
            "title": "Svi kolačići pravilno konfigurisani ✓",
            "title_en": "All Cookies Properly Configured ✓",
            "description": f"Provereno {len(cookies_raw)} kolačića — svi imaju HttpOnly, Secure i SameSite atribute.",
            "description_en": f"Checked {len(cookies_raw)} cookies — all have HttpOnly, Secure and SameSite attributes.",
            "recommendation": "",
            "recommendation_en": "",
        })

    return results
