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

    for cookie in cookies_raw:
        cookie_lower = cookie.lower()
        # Extract cookie name
        name = cookie.split("=")[0].strip()

        if "httponly" not in cookie_lower:
            missing_httponly.append(name)
        if is_https and "secure" not in cookie_lower:
            missing_secure.append(name)
        if "samesite" not in cookie_lower:
            missing_samesite.append(name)

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

    if not missing_httponly and not missing_secure and not missing_samesite:
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
