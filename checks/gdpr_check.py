# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
GDPR Compliance Check
Checks: privacy policy, cookie consent, third-party trackers, tracking cookies,
terms of service, data collection forms, HTTPS for data transmission.
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


def run(base_url: str, response_body: str, response_headers: dict,
        session: requests.Session) -> List[Dict[str, Any]]:
    results = []

    results.extend(_check_privacy_policy(base_url, response_body, session))
    consent_found = _has_cookie_consent(response_body)
    results.extend(_check_cookie_consent(consent_found))
    results.extend(_check_third_party_trackers(response_body, consent_found))
    results.extend(_check_tracking_cookies(response_headers))
    results.extend(_check_terms_of_service(response_body))
    results.extend(_check_data_collection_forms(response_body))
    results.extend(_check_https(base_url))

    return results


# ── Privacy policy ──────────────────────────────────────────────────────────────
def _check_privacy_policy(base_url, body, session):
    results = []
    privacy_patterns = [
        r'href=["\'][^"\']*(?:privacy|privacy-policy|politika-privatnosti)[^"\']*["\']'
    ]
    found = False
    for pattern in privacy_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            found = True
            break

    if not found:
        # Try fetching common privacy policy URLs
        test_paths = ["/privacy-policy", "/privacy", "/politika-privatnosti"]
        for path in test_paths:
            try:
                url = base_url.rstrip("/") + path
                resp = safe_head(session, url, timeout=TIMEOUT)
                if resp.status_code == 200:
                    found = True
                    break
            except Exception:
                pass

    if found:
        results.append(_pass("gdpr_privacy_policy",
            "Politika privatnosti pronadjena",
            "Privacy policy found",
            "Sajt ima link ka politici privatnosti, sto je obavezno po GDPR.",
            "Site has a link to a privacy policy, which is mandatory under GDPR."))
    else:
        results.append(_fail("gdpr_privacy_policy", "MEDIUM",
            "Politika privatnosti nije pronadjena",
            "Privacy policy not found",
            "Nije pronadjen link ka politici privatnosti. GDPR zahteva jasno vidljivu politiku privatnosti na sajtu.",
            "No privacy policy link found. GDPR requires a clearly visible privacy policy on the site.",
            "Dodajte stranicu sa politikom privatnosti i linkujte je iz footer-a sajta.",
            "Add a privacy policy page and link it from the site footer."))
    return results


# ── Cookie consent ──────────────────────────────────────────────────────────────
def _has_cookie_consent(body):
    """Check for cookie consent mechanisms and return True if found."""
    consent_scripts = [
        "cookieconsent", "onetrust", "cookiebot", "osano",
        "klaro", "tarteaucitron", "quantcast",
        "fundingchoicesmessages", "googlefcpresent", "consent-mode",
        "cookieyes", "iubenda", "complianz", "cookie_notice",
    ]
    consent_classes = [
        "cookie-banner", "cookie-notice", "consent-banner", "gdpr-consent"
    ]

    body_lower = body.lower()
    for script in consent_scripts:
        if script in body_lower:
            return True
    for cls in consent_classes:
        if cls in body_lower:
            return True
    return False


def _check_cookie_consent(consent_found):
    results = []
    if consent_found:
        results.append(_pass("gdpr_cookie_consent",
            "Cookie consent mehanizam pronadjen",
            "Cookie consent mechanism found",
            "Sajt koristi cookie consent baner/dijalog, sto je obavezno po GDPR za sajtove koji koriste kolacice.",
            "Site uses a cookie consent banner/dialog, which is mandatory under GDPR for sites using cookies."))
    else:
        results.append(_fail("gdpr_cookie_consent", "MEDIUM",
            "Cookie consent mehanizam nije pronadjen",
            "Cookie consent mechanism not found",
            "Nije pronadjen cookie consent baner ni dijalog. GDPR zahteva da korisnici daju saglasnost pre postavljanja ne-esencijalnih kolacica.",
            "No cookie consent banner or dialog found. GDPR requires users to give consent before setting non-essential cookies.",
            "Implementirajte cookie consent resenje (npr. CookieConsent, OneTrust, Cookiebot).",
            "Implement a cookie consent solution (e.g., CookieConsent, OneTrust, Cookiebot)."))
    return results


# ── Third-party trackers ────────────────────────────────────────────────────────
def _check_third_party_trackers(body, consent_found):
    results = []
    tracker_patterns = [
        ("Google Analytics", r'google-analytics\.com|googletagmanager\.com|gtag\s*\('),
        ("Facebook", r'facebook\.net|connect\.facebook\.net'),
        ("Hotjar", r'hotjar\.com'),
        ("Microsoft Clarity", r'clarity\.ms'),
        ("DoubleClick", r'doubleclick\.net'),
    ]

    found_trackers = []
    for name, pattern in tracker_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            found_trackers.append(name)

    if not found_trackers:
        results.append(_pass("gdpr_trackers",
            "Nisu pronadjeni third-party trackeri",
            "No third-party trackers found",
            "Nije detektovan nijedan poznati third-party tracker na stranici.",
            "No known third-party trackers detected on the page."))
    elif consent_found:
        results.append(_pass("gdpr_trackers",
            f"Third-party trackeri sa cookie consent ({', '.join(found_trackers)})",
            f"Third-party trackers with cookie consent ({', '.join(found_trackers)})",
            f"Pronadjeni trackeri: {', '.join(found_trackers)}. Cookie consent mehanizam je prisutan, sto je u skladu sa GDPR.",
            f"Trackers found: {', '.join(found_trackers)}. Cookie consent mechanism is present, which complies with GDPR."))
    else:
        results.append(_fail("gdpr_trackers", "HIGH",
            f"Third-party trackeri bez cookie consent ({', '.join(found_trackers)})",
            f"Third-party trackers without cookie consent ({', '.join(found_trackers)})",
            f"Pronadjeni trackeri: {', '.join(found_trackers)}, ali nije detektovan cookie consent mehanizam. Ovo je krsenje GDPR.",
            f"Trackers found: {', '.join(found_trackers)}, but no cookie consent mechanism detected. This violates GDPR.",
            "Dodajte cookie consent baner koji blokira trackere dok korisnik ne da saglasnost.",
            "Add a cookie consent banner that blocks trackers until the user gives consent."))
    return results


# ── Tracking cookies ────────────────────────────────────────────────────────────
def _check_tracking_cookies(headers):
    results = []
    known_tracking = ["_ga", "_gid", "_fbp", "_gcl_au", "NID", "IDE"]

    cookies_raw = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            if isinstance(v, list):
                cookies_raw.extend(v)
            else:
                cookies_raw.append(v)

    found_tracking = []
    for cookie in cookies_raw:
        cookie_name = cookie.split("=")[0].strip()
        if cookie_name in known_tracking:
            found_tracking.append(cookie_name)

    if found_tracking:
        results.append(_fail("gdpr_tracking_cookies", "INFO",
            f"Detektovani tracking kolacici: {', '.join(found_tracking)}",
            f"Tracking cookies detected: {', '.join(found_tracking)}",
            f"Pronadjeni su poznati tracking kolacici: {', '.join(found_tracking)}. Ovi kolacici zahtevaju saglasnost korisnika po GDPR.",
            f"Known tracking cookies found: {', '.join(found_tracking)}. These cookies require user consent under GDPR.",
            "Osigurajte da se tracking kolacici postavljaju tek nakon saglasnosti korisnika.",
            "Ensure tracking cookies are only set after user consent."))
    else:
        results.append(_pass("gdpr_tracking_cookies",
            "Nisu pronadjeni poznati tracking kolacici",
            "No known tracking cookies found",
            "Nisu detektovani poznati tracking kolacici u Set-Cookie headerima.",
            "No known tracking cookies detected in Set-Cookie headers."))
    return results


# ── Terms of service ────────────────────────────────────────────────────────────
def _check_terms_of_service(body):
    results = []
    tos_pattern = r'href=["\'][^"\']*(?:/terms|/uslovi|/terms-of-service|/tos)(?:[/"\'])'
    if re.search(tos_pattern, body, re.IGNORECASE):
        results.append(_pass("gdpr_tos",
            "Uslovi koriscenja pronadjeni",
            "Terms of service found",
            "Sajt ima link ka uslovima koriscenja.",
            "Site has a link to terms of service."))
    else:
        results.append(_fail("gdpr_tos", "LOW",
            "Uslovi koriscenja nisu pronadjeni",
            "Terms of service not found",
            "Nije pronadjen link ka uslovima koriscenja. Preporucljivo je imati jasne uslove koriscenja na sajtu.",
            "No terms of service link found. It is recommended to have clear terms of service on the site.",
            "Dodajte stranicu sa uslovima koriscenja i linkujte je iz footer-a.",
            "Add a terms of service page and link it from the footer."))
    return results


# ── Data collection forms ───────────────────────────────────────────────────────
def _check_data_collection_forms(body):
    results = []
    forms = re.findall(r'<form\s+[^>]*?>(.*?)</form>', body, re.IGNORECASE | re.DOTALL)
    if not forms:
        results.append(_pass("gdpr_forms",
            "Nisu pronadjeni formulari za prikupljanje podataka",
            "No data collection forms found",
            "Na stranici nisu pronadjeni formulari sa osetljivim poljima.",
            "No forms with sensitive fields found on the page."))
        return results

    sensitive_pattern = r'<input\s+[^>]*type=["\'](?:email|password|tel)["\']'
    insecure_forms = []
    secure_forms = 0

    for form_content in forms:
        if re.search(sensitive_pattern, form_content, re.IGNORECASE):
            # Check form action
            form_match = re.search(
                r'<form\s+[^>]*action=["\']([^"\']*)["\']',
                body[body.find(form_content) - 200:body.find(form_content)],
                re.IGNORECASE
            )
            if form_match:
                action = form_match.group(1)
                if action.startswith("http://"):
                    insecure_forms.append(action)
                else:
                    secure_forms += 1
            else:
                secure_forms += 1

    if insecure_forms:
        results.append(_fail("gdpr_forms", "HIGH",
            f"Formular salje podatke preko nezasticene konekcije (HTTP)",
            f"Form submits data over insecure connection (HTTP)",
            f"Pronadjen formular sa osetljivim poljima (email/lozinka/telefon) koji salje podatke na HTTP URL: {insecure_forms[0][:60]}. Ovo izlaze korisnicke podatke presretanju.",
            f"Found form with sensitive fields (email/password/phone) submitting data to HTTP URL: {insecure_forms[0][:60]}. This exposes user data to interception.",
            "Promenite form action na HTTPS URL i omogucite HTTPS na celom sajtu.",
            "Change form action to an HTTPS URL and enable HTTPS across the entire site."))
    elif secure_forms > 0:
        results.append(_pass("gdpr_forms",
            f"Formulari koriste bezbednu konekciju ({secure_forms} formulara)",
            f"Forms use secure connection ({secure_forms} forms)",
            "Formulari sa osetljivim poljima koriste HTTPS za slanje podataka.",
            "Forms with sensitive fields use HTTPS for data submission."))
    else:
        results.append(_pass("gdpr_forms",
            "Formulari bez osetljivih polja",
            "Forms without sensitive fields",
            "Pronadjeni formulari ne sadrze osetljiva polja (email, lozinka, telefon).",
            "Found forms do not contain sensitive fields (email, password, phone)."))
    return results


# ── HTTPS for data ──────────────────────────────────────────────────────────────
def _check_https(base_url):
    results = []
    if base_url.startswith("https://"):
        results.append(_pass("gdpr_https",
            "Sajt koristi HTTPS",
            "Site uses HTTPS",
            "Sav saobracaj je enkriptovan putem HTTPS, sto stiti podatke korisnika u prenosu.",
            "All traffic is encrypted via HTTPS, protecting user data in transit."))
    else:
        results.append(_fail("gdpr_https", "HIGH",
            "Sajt ne koristi HTTPS",
            "Site does not use HTTPS",
            "Sajt koristi HTTP umesto HTTPS. Svi podaci, ukljucujuci lozinke i licne podatke, se salju u cistom tekstu.",
            "Site uses HTTP instead of HTTPS. All data, including passwords and personal information, is sent in plain text.",
            "Omogucite HTTPS sa validnim SSL/TLS sertifikatom. Koristite Let's Encrypt za besplatne sertifikate.",
            "Enable HTTPS with a valid SSL/TLS certificate. Use Let's Encrypt for free certificates."))
    return results


# ── Helpers ─────────────────────────────────────────────────────────────────────
def _pass(check_id, title_sr, title_en, desc_sr, desc_en):
    return {
        "id": check_id, "category": "GDPR", "severity": "INFO", "passed": True,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": "", "recommendation_en": "",
    }


def _fail(check_id, severity, title_sr, title_en, desc_sr, desc_en, rec_sr, rec_en):
    return {
        "id": check_id, "category": "GDPR", "severity": severity, "passed": False,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": rec_sr, "recommendation_en": rec_en,
    }
