"""
WHOIS Domain Information Check
Checks domain registration details: expiry, age, registrar.
Uses socket WHOIS query - no API key needed.
"""
import socket
import re
from datetime import datetime
from typing import List, Dict, Any


WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "rs": "whois.rnids.rs",
    "me": "whois.nic.me",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "xyz": "whois.nic.xyz",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "eu": "whois.eu",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
}


def _query_whois(domain):
    """Raw WHOIS query via socket."""
    tld = domain.rsplit(".", 1)[-1].lower()
    server = WHOIS_SERVERS.get(tld, f"whois.nic.{tld}")

    try:
        sock = socket.create_connection((server, 43), timeout=10)
        sock.sendall((domain + "\r\n").encode())
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        return response.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _parse_date(text):
    """Try to parse a date from various WHOIS formats."""
    patterns = [
        r"(\d{4}-\d{2}-\d{2})",
        r"(\d{2}/\d{2}/\d{4})",
        r"(\d{2}-\w{3}-\d{4})",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            date_str = match.group(1)
            for fmt in ["%Y-%m-%d", "%d/%m/%Y", "%d-%b-%Y"]:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
    return None


def run(domain: str) -> List[Dict[str, Any]]:
    results = []

    # Skip platform domains
    platform_suffixes = [
        ".vercel.app", ".netlify.app", ".github.io", ".hf.space",
        ".web.app", ".firebaseapp.com", ".herokuapp.com", ".pages.dev",
    ]
    for suffix in platform_suffixes:
        if domain.endswith(suffix):
            results.append(_pass("whois_platform",
                f"WHOIS — platform domen ({domain})",
                f"WHOIS — platform domain ({domain})",
                "Platform domeni nemaju individualne WHOIS zapise.",
                "Platform domains don't have individual WHOIS records."))
            return results

    # Get root domain (e.g., www.github.com -> github.com)
    parts = domain.split(".")
    if len(parts) > 2:
        root_domain = ".".join(parts[-2:])
    else:
        root_domain = domain

    whois_text = _query_whois(root_domain)
    if not whois_text or len(whois_text) < 50:
        results.append(_fail("whois_unavailable", "LOW",
            "WHOIS podaci nedostupni",
            "WHOIS data unavailable",
            f"Nije moguce dobiti WHOIS podatke za {root_domain}.",
            f"Could not retrieve WHOIS data for {root_domain}.",
            "Proverite da li je domen registrovan i da li WHOIS server radi.",
            "Check if the domain is registered and if the WHOIS server is available."))
        return results

    whois_lower = whois_text.lower()

    # Check domain expiry
    expiry_patterns = [
        r"(?:expir|expiration|paid-till|valid until|renewal)[^\n]*?[:]\s*(.+)",
        r"Registry Expiry Date:\s*(.+)",
    ]
    expiry_date = None
    for pattern in expiry_patterns:
        match = re.search(pattern, whois_text, re.IGNORECASE)
        if match:
            expiry_date = _parse_date(match.group(1))
            if expiry_date:
                break

    if expiry_date:
        days_left = (expiry_date - datetime.utcnow()).days
        if days_left < 0:
            results.append(_fail("whois_expired", "CRITICAL",
                f"Domen je istekao pre {abs(days_left)} dana!",
                f"Domain expired {abs(days_left)} days ago!",
                "Registracija domena je istekla. Sajt moze prestati da radi u svakom trenutku.",
                "Domain registration has expired. The site may stop working at any time.",
                "Odmah obnovite registraciju domena kod vaseg registrara.",
                "Immediately renew domain registration with your registrar."))
        elif days_left < 30:
            results.append(_fail("whois_expiring", "HIGH",
                f"Domen istice za {days_left} dana!",
                f"Domain expires in {days_left} days!",
                f"Registracija domena istice {expiry_date.strftime('%d.%m.%Y')}. Ako ne obnovite, gubite domen.",
                f"Domain registration expires {expiry_date.strftime('%Y-%m-%d')}. If not renewed, you lose the domain.",
                "Obnovite registraciju domena sto pre.",
                "Renew domain registration as soon as possible."))
        elif days_left < 90:
            results.append(_fail("whois_expiring_soon", "MEDIUM",
                f"Domen istice za {days_left} dana",
                f"Domain expires in {days_left} days",
                f"Registracija domena istice {expiry_date.strftime('%d.%m.%Y')}.",
                f"Domain registration expires {expiry_date.strftime('%Y-%m-%d')}.",
                "Planirajte obnovu registracije domena.",
                "Plan domain registration renewal."))
        else:
            results.append(_pass("whois_expiry_ok",
                f"Domen validan jos {days_left} dana (istice {expiry_date.strftime('%d.%m.%Y')})",
                f"Domain valid for {days_left} days (expires {expiry_date.strftime('%Y-%m-%d')})",
                "Registracija domena je aktivna.",
                "Domain registration is active."))

    # Check domain age
    creation_patterns = [
        r"(?:creation|created|registered|registration)[^\n]*?[:]\s*(.+)",
        r"Created Date:\s*(.+)",
    ]
    creation_date = None
    for pattern in creation_patterns:
        match = re.search(pattern, whois_text, re.IGNORECASE)
        if match:
            creation_date = _parse_date(match.group(1))
            if creation_date:
                break

    if creation_date:
        age_days = (datetime.utcnow() - creation_date).days
        age_years = round(age_days / 365.25, 1)
        if age_days < 90:
            results.append(_fail("whois_new_domain", "MEDIUM",
                f"Nov domen — registrovan pre {age_days} dana",
                f"New domain — registered {age_days} days ago",
                "Veoma novi domeni su cesto povezani sa spam, phishing ili prevarama. Korisnici mogu biti oprezni.",
                "Very new domains are often associated with spam, phishing or scams. Users may be cautious.",
                "Novi domen nije nuzno los — samo je potrebno vreme za reputaciju.",
                "A new domain is not necessarily bad — it just needs time to build reputation."))
        else:
            results.append(_pass("whois_age_ok",
                f"Domen star {age_years} godina (od {creation_date.strftime('%d.%m.%Y')})",
                f"Domain age {age_years} years (since {creation_date.strftime('%Y-%m-%d')})",
                "Stariji domeni imaju vecu reputaciju kod pretrazivaca i korisnika.",
                "Older domains have higher reputation with search engines and users."))

    # Check registrar
    registrar_match = re.search(r"Registrar:\s*(.+)", whois_text, re.IGNORECASE)
    if registrar_match:
        registrar = registrar_match.group(1).strip()[:80]
        results.append(_pass("whois_registrar",
            f"Registrar: {registrar}",
            f"Registrar: {registrar}",
            f"Domen je registrovan kod: {registrar}.",
            f"Domain is registered with: {registrar}."))

    # Check DNSSEC in WHOIS
    if "dnssec: signeddelegation" in whois_lower or "dnssec: yes" in whois_lower:
        results.append(_pass("whois_dnssec",
            "DNSSEC aktivan prema WHOIS",
            "DNSSEC active per WHOIS",
            "WHOIS potvrduje da je DNSSEC konfigurisan za ovaj domen.",
            "WHOIS confirms DNSSEC is configured for this domain."))

    return results


def _pass(check_id, title_sr, title_en, desc_sr, desc_en):
    return {
        "id": check_id, "category": "WHOIS / Domain", "severity": "INFO", "passed": True,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": "", "recommendation_en": "",
    }


def _fail(check_id, severity, title_sr, title_en, desc_sr, desc_en, rec_sr, rec_en):
    return {
        "id": check_id, "category": "WHOIS / Domain", "severity": severity, "passed": False,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": rec_sr, "recommendation_en": rec_en,
    }
