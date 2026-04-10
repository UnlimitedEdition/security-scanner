"""
Admin Page Exposure Check
Checks if common admin panels are publicly accessible.

IMPORTANT: Uses content fingerprinting to avoid false positives.
Shared hosting often exposes cPanel/phpMyAdmin at server level — we verify
that the content ACTUALLY belongs to that specific tool before flagging.
"""
import re
import sys
import os
import requests
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_utils import safe_get, UnsafeTargetError

TIMEOUT = 7

# Each entry: (path, display_name, severity, content_fingerprints)
# content_fingerprints: list of strings that MUST appear in the body
# to confirm the panel is real (not just a hosting redirect or custom 404)
ADMIN_PATHS = [
    (
        "/wp-admin/",
        "WordPress Admin Panel",
        "CRITICAL",
        ["wp-login", "wordpress", "user_login", "log in &laquo; wordpress", "wp-includes"],
    ),
    (
        "/wp-login.php",
        "WordPress Login stranica",
        "HIGH",
        ["user_login", "user_pass", "wp-login", "wordpress"],
    ),
    (
        "/administrator/",
        "Joomla Admin Panel",
        "CRITICAL",
        ["joomla", "com_login", "administrator", "mod_login"],
    ),
    (
        "/phpmyadmin/",
        "phpMyAdmin — direktan pristup bazi podataka",
        "CRITICAL",
        ["phpmyadmin", "pmalogo", "pmahomme", "token", "phpMyAdmin"],
    ),
    (
        "/pma/",
        "phpMyAdmin (alternativna putanja)",
        "CRITICAL",
        ["phpmyadmin", "pmalogo", "pmahomme", "phpMyAdmin"],
    ),
    (
        "/adminer.php",
        "Adminer DB menadžer",
        "CRITICAL",
        ["adminer", "elastic-addinstance", "elastic-addtable", "db=", "Adminer"],
    ),
    (
        "/cpanel/",
        "cPanel Hosting Panel",
        "HIGH",
        ["cpanel", "cPanel", "whostmgr", "login to cpanel", "cpanel login"],
    ),
    (
        "/webmail/",
        "Webmail interfejs",
        "MEDIUM",
        ["webmail", "roundcube", "horde", "squirrelmail", "compose", "inbox"],
    ),
]

# Generic paths — VERY strict fingerprinting to avoid false positives on SPAs
# These require multiple specific signals to fire
GENERIC_PATHS = [
    ("/admin/login", "Admin Login stranica", "HIGH",
     # Must have BOTH a form AND admin-specific keywords — very specific
     ["<form", "admin panel", "administration", "control panel"]),
    ("/adminer.php", "Adminer (alternativna putanja)", "CRITICAL",
     ["adminer", "Adminer &mdash;", "elastic-addinstance"]),
]


def _is_same_as_homepage(resp_body: str, homepage_body: str) -> bool:
    """Check if the response is basically the same as the homepage (SPA routing)."""
    if not homepage_body or not resp_body:
        return False
    # Compare first 200 chars to detect if it's the same React/SPA app
    return resp_body[:200].strip() == homepage_body[:200].strip()


def _has_fingerprint(body: str, fingerprints: list) -> bool:
    """Return True only if at least TWO fingerprints are found in body.
    Single-word matches like 'login' are too generic — require multiple signals."""
    body_lower = body.lower()
    matches = sum(1 for fp in fingerprints if fp.lower() in body_lower)
    return matches >= 2


def run(base_url: str, session: requests.Session) -> List[Dict[str, Any]]:
    results = []
    exposed = []

    # Fetch homepage for SPA false-positive detection
    homepage_body = ""
    try:
        hp = safe_get(session, base_url, timeout=TIMEOUT)
        homepage_body = hp.text[:1000]
    except Exception:
        pass

    # --- Check CMS-specific admin paths with fingerprinting ---
    for path, name, severity, fingerprints in ADMIN_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = safe_get(session, url, timeout=TIMEOUT)

            if resp.status_code == 200 and len(resp.content) > 100:
                body = resp.text[:3000]

                # Skip if it looks like the same SPA page (React routing)
                if _is_same_as_homepage(body, homepage_body):
                    continue

                # Must have content fingerprint to confirm it's real
                if _has_fingerprint(body, fingerprints):
                    exposed.append({
                        "path": path,
                        "name": name,
                        "severity": severity,
                        "url": url,
                        "is_cms": True,
                    })

            elif resp.status_code in (401, 403):
                # Panel exists but requires auth — good, but worth noting for CMS panels
                if path in ("/wp-admin/", "/phpmyadmin/", "/administrator/"):
                    results.append({
                        "id": f"admin_protected_{path.strip('/').replace('/', '_')}",
                        "category": "Admin Exposure",
                        "severity": "INFO",
                        "passed": True,
                        "title": f"{name} postoji ali je zaštićen ({resp.status_code}) ✓",
                        "title_en": f"{name} exists but is protected ({resp.status_code}) ✓",
                        "description": f"Putanja {path} vraća {resp.status_code} — pristup zahteva autentifikaciju.",
                        "description_en": f"Path {path} returns {resp.status_code} — access requires authentication.",
                        "recommendation": "",
                        "recommendation_en": "",
                    })

        except requests.exceptions.RequestException:
            pass

    # --- Check generic admin paths ---
    for path, name, severity, fingerprints in GENERIC_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = safe_get(session, url, timeout=TIMEOUT)
            if resp.status_code == 200 and len(resp.content) > 100:
                body = resp.text[:3000]

                # Skip SPA pages
                if _is_same_as_homepage(body, homepage_body):
                    continue

                # Must show login form content
                if _has_fingerprint(body, fingerprints):
                    exposed.append({
                        "path": path,
                        "name": name,
                        "severity": severity,
                        "url": url,
                        "is_cms": False,
                    })
        except requests.exceptions.RequestException:
            pass

    # --- Build results ---
    for item in exposed:
        path = item["path"]
        name = item["name"]
        severity = item["severity"]

        if "phpmyadmin" in path.lower() or "adminer" in path.lower() or "pma" in path.lower():
            desc = f"KRITIČNO: {name} je javno dostupan! Napadač može direktno pristupiti bazi podataka bez ikakve zaštite."
            desc_en = f"CRITICAL: {name} is publicly accessible! An attacker can directly access the database without any protection."
            rec = f"Odmah blokirajte {path} u web server konfiguraciji. Nikad ne ostavljajte DB alate na javnoj putanji."
            rec_en = f"Immediately block {path} in your web server config. Never leave DB tools on a public path."
        elif "wp-admin" in path or "wp-login" in path:
            desc = f"WordPress admin panel je dostupan svima. Napadači automatski skeniraju /wp-admin/ i pokušavaju brute-force napade."
            desc_en = f"WordPress admin panel is accessible to everyone. Attackers automatically scan /wp-admin/ and attempt brute-force attacks."
            rec = "Dodajte IP ograničenje za /wp-admin/ u .htaccess ili Nginx. Koristite plugin poput 'Limit Login Attempts'."
            rec_en = "Add IP restriction for /wp-admin/ in .htaccess or Nginx. Use a plugin like 'Limit Login Attempts'."
        elif "administrator" in path:
            desc = f"Joomla admin panel je javno dostupan. Skeneri rutinski probaju /administrator/ na svim sajtovima."
            desc_en = f"Joomla admin panel is publicly accessible. Scanners routinely probe /administrator/ on all sites."
            rec = "Promenite URL admin panela ili dodajte HTTP Basic Auth ispred /administrator/."
            rec_en = "Change the admin panel URL or add HTTP Basic Auth in front of /administrator/."
        else:
            desc = f"Stranica {path} je javno dostupna i izgleda kao admin/login forma."
            desc_en = f"Page {path} is publicly accessible and appears to be an admin/login form."
            rec = f"Proverite da li {path} treba da bude javno dostupan. Dodajte autentifikaciju ili IP restrikciju."
            rec_en = f"Verify if {path} should be publicly accessible. Add authentication or IP restriction."

        results.append({
            "id": f"admin_exposed_{path.strip('/').replace('/', '_') or 'root'}",
            "category": "Admin Exposure",
            "severity": severity,
            "passed": False,
            "title": f"{name} je dostupan: {path}",
            "title_en": f"{name} is accessible: {path}",
            "description": desc,
            "description_en": desc_en,
            "recommendation": rec,
            "recommendation_en": rec_en,
        })

    if not exposed and not any(r["category"] == "Admin Exposure" and not r["passed"] for r in results):
        results.append({
            "id": "admin_all_protected",
            "category": "Admin Exposure",
            "severity": "INFO",
            "passed": True,
            "title": "Admin stranice nisu eksponirane ✓",
            "title_en": "Admin pages are not exposed ✓",
            "description": f"Provereno {len(ADMIN_PATHS) + len(GENERIC_PATHS)} putanja — nijedna prava admin strana nije javno dostupna.",
            "description_en": f"Checked {len(ADMIN_PATHS) + len(GENERIC_PATHS)} paths — no real admin page is publicly accessible.",
            "recommendation": "",
            "recommendation_en": "",
        })

    return results
