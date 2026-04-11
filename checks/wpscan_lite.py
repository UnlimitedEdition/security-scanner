# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
WPScan-lite — WordPress-specific deep pass.

Only runs when the main CMS detection has already classified the site
as WordPress (detected via standard markers in the response body).
Probes four WordPress-specific surfaces:

  1. Plugin enumeration — fetch /wp-content/plugins/<slug>/readme.txt
     for ~20 most popular plugins in parallel, parse 'Stable tag:' to
     extract installed version, cross-reference a small curated CVE
     dict and emit a HIGH/CRITICAL finding per match.
  2. REST API user enumeration — /wp-json/wp/v2/users (if 200 and
     returns a JSON array with slug/name fields, usernames leak).
  3. Author-redirect user enumeration — /?author=N produces a 301/302
     to /author/<username>/ when the author exists.
  4. xmlrpc.php exposure — /xmlrpc.php is the legacy XML-RPC endpoint
     that is still a common brute-force target; simply its presence is
     worth flagging as an attack surface.

Entirely passive: every probe is an HTTP GET. No POST, no login
attempts, no payload injection, no exploitation. The plugin probe
pattern mirrors the existing files_check ThreadPoolExecutor approach
and shares the same safe_get wrapper, so SSRF protection is uniform.
"""
import re
import sys
import os
import concurrent.futures
import requests
from typing import List, Dict, Any, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_utils import safe_get, UnsafeTargetError

TIMEOUT = 5
MAX_WORKERS = 5


# Top ~20 popular WordPress plugins by install count. The slug is the
# directory name under /wp-content/plugins/, which is what readme.txt
# lives inside. When a site has the plugin installed, its readme.txt is
# publicly accessible unless the host explicitly blocks it — which
# almost nobody does, since it is the official plugin repository file.
POPULAR_PLUGINS: List[str] = [
    "contact-form-7",
    "wordpress-seo",          # Yoast SEO
    "elementor",
    "woocommerce",
    "jetpack",
    "wpforms-lite",
    "all-in-one-seo-pack",
    "akismet",
    "wordfence",
    "litespeed-cache",
    "updraftplus",
    "classic-editor",
    "really-simple-ssl",
    "advanced-custom-fields",
    "wp-super-cache",
    "w3-total-cache",
    "wp-rocket",
    "nextgen-gallery",
    "ninja-forms",
    "revslider",              # Slider Revolution — legacy CVE target
]


# Curated dict of known-vulnerable plugin version ranges. Kept small
# and conservative on purpose — listing an incorrect CVE in a security
# scanner is worse than not listing one at all. Only entries that are
# well-documented, widely cited, and unambiguous about the affected
# version range are included here. Additional plugins get a generic
# "plugin detected, verify against CVE database" treatment.
#
# Each entry: list of dicts with keys {max_version, cve, severity,
# desc_sr, desc_en}. "max_version" means the CVE applies to versions
# less-than-or-equal-to that version.
KNOWN_VULN_PLUGINS: Dict[str, List[Dict[str, str]]] = {
    "contact-form-7": [
        {
            "max_version": "5.3.1",
            "cve": "CVE-2020-35489",
            "severity": "HIGH",
            "desc_sr": (
                "Neograniceni upload fajlova u Contact Form 7 verzijama do "
                "5.3.1. Autentifikovan napadac moze da ubaci proizvoljne "
                "fajlove (ukljucujuci PHP shell) kroz polje za attachment."
            ),
            "desc_en": (
                "Unrestricted file upload in Contact Form 7 versions up to "
                "5.3.1. An authenticated attacker can upload arbitrary files "
                "(including a PHP shell) through the attachment field."
            ),
        },
    ],
    "revslider": [
        {
            "max_version": "4.2",
            "cve": "CVE-2014-9735",
            "severity": "CRITICAL",
            "desc_sr": (
                "Arbitrary file download u Slider Revolution verzijama do "
                "4.2. Napadac moze direktno da preuzme bilo koji fajl sa "
                "servera (ukljucujuci wp-config.php) kroz 'revslider_show_image' "
                "AJAX akciju — nije potrebna autentifikacija."
            ),
            "desc_en": (
                "Arbitrary file download in Slider Revolution versions up "
                "to 4.2. An attacker can directly download any file from "
                "the server (including wp-config.php) through the "
                "'revslider_show_image' AJAX action — no authentication required."
            ),
        },
    ],
    "updraftplus": [
        {
            "max_version": "1.22.2",
            "cve": "CVE-2022-23337",
            "severity": "HIGH",
            "desc_sr": (
                "Backup file disclosure u UpdraftPlus verzijama do 1.22.2. "
                "Autentifikovan nizi korisnik moze da preuzme cele backup-e "
                "(baza + fajlovi) iako nema odgovarajuce privilegije."
            ),
            "desc_en": (
                "Backup file disclosure in UpdraftPlus versions up to "
                "1.22.2. An authenticated low-privileged user can download "
                "full backups (database + files) despite lacking the proper "
                "privilege level."
            ),
        },
    ],
}


# ── Version parsing ───────────────────────────────────────────────────────


def _parse_version(v: str) -> Tuple[int, int, int, int]:
    """
    Parse a version string into a 4-tuple for lexicographic comparison.
    Non-numeric or missing components become 0. Pads to exactly 4 parts
    so that "5.3" and "5.3.0.0" compare equal (rather than the shorter
    tuple being 'less' under Python's default comparison).
    """
    parts = re.findall(r"\d+", v or "")[:4]
    while len(parts) < 4:
        parts.append("0")
    return (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]))


def _version_le(version: str, max_version: str) -> bool:
    """Return True when version <= max_version."""
    return _parse_version(version) <= _parse_version(max_version)


# ── WordPress detection gate ──────────────────────────────────────────────


def _is_wordpress(body: str) -> bool:
    """
    Quick check whether the already-received response body looks like a
    WordPress site. When False, run() early-exits and does zero probes.
    Keeps the ~26 WP-specific requests strictly off non-WP targets.
    """
    if not body:
        return False
    markers = ("/wp-content/", "/wp-includes/", "wp-json", "WordPress")
    return any(m in body for m in markers)


# ── Probe functions ───────────────────────────────────────────────────────


def _probe_plugin(
    base_url: str,
    session: requests.Session,
    slug: str,
) -> Optional[Dict[str, Any]]:
    """
    Probe a single plugin's readme.txt. Returns {slug, version} on a
    confirmed hit, None otherwise. Version is None when readme.txt is
    present but does not declare a Stable tag (rare but possible for
    work-in-progress plugins).
    """
    url = base_url.rstrip("/") + f"/wp-content/plugins/{slug}/readme.txt"
    try:
        resp = safe_get(session, url, timeout=TIMEOUT, max_redirects=0)
    except (UnsafeTargetError, requests.exceptions.RequestException):
        return None
    except Exception:
        return None

    if resp.status_code != 200:
        return None

    # WordPress plugin readme.txt files always start with "=== Plugin Name ==="
    # as the first non-whitespace line. This rejects SPA catch-all 200 HTML
    # responses that would otherwise look like false positive hits.
    try:
        body = resp.text
    except Exception:
        return None
    if not body.lstrip().startswith("==="):
        return None

    version_match = re.search(
        r"^Stable tag:\s*([^\s\r\n]+)", body, re.IGNORECASE | re.MULTILINE
    )
    version = version_match.group(1) if version_match else None
    # Filter the literal "trunk" marker that WP uses for unreleased plugins
    if version and version.lower() == "trunk":
        version = None

    return {"slug": slug, "version": version}


def _match_cves(slug: str, version: Optional[str]) -> List[Dict[str, str]]:
    """
    Cross-reference a detected plugin against KNOWN_VULN_PLUGINS.
    Returns a list of matching CVE entries, or empty list on no match
    (including the no-version-known case, where we stay silent rather
    than flag uncertain findings).
    """
    if not version:
        return []
    entries = KNOWN_VULN_PLUGINS.get(slug)
    if not entries:
        return []
    return [e for e in entries if _version_le(version, e["max_version"])]


def _check_rest_users(
    base_url: str,
    session: requests.Session,
) -> Optional[List[str]]:
    """
    GET /wp-json/wp/v2/users. If the REST endpoint returns a non-empty
    JSON array of user objects, return their slugs/names. Legitimate
    public REST responses leak usernames that can then be brute-forced.
    """
    url = base_url.rstrip("/") + "/wp-json/wp/v2/users"
    try:
        resp = safe_get(session, url, timeout=TIMEOUT, max_redirects=0)
    except (UnsafeTargetError, requests.exceptions.RequestException):
        return None
    except Exception:
        return None

    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except Exception:
        return None
    if not isinstance(data, list) or not data:
        return None

    users: List[str] = []
    for entry in data[:10]:
        if not isinstance(entry, dict):
            continue
        name = entry.get("slug") or entry.get("name")
        if isinstance(name, str) and name:
            users.append(name)
    return users or None


def _check_author_enum(
    base_url: str,
    session: requests.Session,
) -> List[str]:
    """
    Try /?author=1..3 and collect any usernames leaked via 3xx Location
    headers pointing to /author/<username>/. WordPress does this by
    default on most themes — a fresh install with a single admin user
    will almost always leak the admin username through this redirect.
    Only the first three IDs are probed to keep the request count low.
    """
    users: List[str] = []
    seen = set()
    for n in range(1, 4):
        url = base_url.rstrip("/") + f"/?author={n}"
        try:
            resp = safe_get(session, url, timeout=TIMEOUT, max_redirects=0)
        except (UnsafeTargetError, requests.exceptions.RequestException):
            continue
        except Exception:
            continue

        if resp.status_code not in (301, 302, 307):
            continue
        location = resp.headers.get("Location", "") or ""
        match = re.search(r"/author/([^/?&#]+)/?", location)
        if match:
            username = match.group(1)
            if username and username not in seen:
                seen.add(username)
                users.append(username)
    return users


def _check_xmlrpc(base_url: str, session: requests.Session) -> bool:
    """
    GET /xmlrpc.php. The default WordPress response to a plain GET on
    this endpoint is literally 'XML-RPC server accepts POST requests
    only.' If we see that, the endpoint is enabled and reachable —
    which by itself is a known attack surface for pingback DoS and
    credential brute-force amplification (even without POST-ing to it).
    """
    url = base_url.rstrip("/") + "/xmlrpc.php"
    try:
        resp = safe_get(session, url, timeout=TIMEOUT, max_redirects=0)
    except (UnsafeTargetError, requests.exceptions.RequestException):
        return False
    except Exception:
        return False

    if resp.status_code != 200:
        return False
    try:
        body = resp.text[:500]
    except Exception:
        return False
    return "XML-RPC server" in body


# ── Finding constructors ──────────────────────────────────────────────────


def _finding_plugins_enumerable(
    plugins: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Aggregate finding for "N plugins are enumerable via public readme.txt".
    Lists the detected plugins with their versions so the site owner can
    quickly audit which plugins are visible to the outside world.
    """
    with_versions = [
        f"{p['slug']} v{p['version']}" if p.get("version") else p["slug"]
        for p in plugins
    ]
    listing = ", ".join(with_versions)

    return {
        "id": "wp_plugins_enumerable",
        "category": "WordPress",
        "severity": "LOW",
        "passed": False,
        "title": f"WordPress plugin enumeracija — {len(plugins)} pluginova javno vidljivo",
        "title_en": f"WordPress plugin enumeration — {len(plugins)} plugins publicly visible",
        "description": (
            f"Detektovano {len(plugins)} WordPress pluginova kroz javno "
            "dostupan readme.txt fajl u /wp-content/plugins/<slug>/. Ovo "
            "daje napadacu listu tacno kojih plugin-a imate instalirano, "
            "sa verzijama — direktno olaksava gadjanje sa poznatim CVE-ovima. "
            f"Detektovani plugini: {listing}."
        ),
        "description_en": (
            f"Detected {len(plugins)} WordPress plugins through the publicly "
            "accessible readme.txt file in /wp-content/plugins/<slug>/. "
            "This gives an attacker a precise list of which plugins you "
            "have installed, along with versions — directly simplifying "
            f"targeting known CVEs. Detected plugins: {listing}."
        ),
        "recommendation": (
            "Blokirajte pristup /wp-content/plugins/*/readme.txt na web "
            "serveru. Nginx: 'location ~ /wp-content/plugins/.*/readme\\.txt$ "
            "{ deny all; return 404; }'. Apache: 'RedirectMatch 404 "
            "/wp-content/plugins/.*/readme\\.txt$'. Alternativno, WP security "
            "plugini (Wordfence, iThemes Security) imaju opciju da ih sakriju."
        ),
        "recommendation_en": (
            "Block access to /wp-content/plugins/*/readme.txt on the web "
            "server. Nginx: 'location ~ /wp-content/plugins/.*/readme\\.txt$ "
            "{ deny all; return 404; }'. Apache: 'RedirectMatch 404 "
            "/wp-content/plugins/.*/readme\\.txt$'. Alternatively, WP "
            "security plugins (Wordfence, iThemes Security) have an option "
            "to hide them."
        ),
    }


def _finding_plugin_vulnerable(
    plugin: Dict[str, Any],
    cve: Dict[str, str],
) -> Dict[str, Any]:
    """Per-CVE finding for a detected plugin whose version matches a known vuln."""
    slug = plugin["slug"]
    version = plugin.get("version") or "?"
    return {
        "id": f"wp_plugin_vuln_{slug}_{cve['cve']}",
        "category": "WordPress",
        "severity": cve["severity"],
        "passed": False,
        "title": (
            f"Ranjiv WordPress plugin detektovan: {slug} v{version} "
            f"({cve['cve']})"
        ),
        "title_en": (
            f"Vulnerable WordPress plugin detected: {slug} v{version} "
            f"({cve['cve']})"
        ),
        "description": (
            f"Plugin '{slug}' v{version} detektovan kroz readme.txt. "
            f"Ova verzija je pogodjena {cve['cve']}: {cve['desc_sr']} "
            "Ako je plugin aktivan, sajt je pogodjen ovim javnim CVE-om."
        ),
        "description_en": (
            f"Plugin '{slug}' v{version} detected through readme.txt. "
            f"This version is affected by {cve['cve']}: {cve['desc_en']} "
            "If the plugin is active, the site is affected by this public CVE."
        ),
        "recommendation": (
            f"HITNO azurirajte plugin '{slug}' na najnoviju verziju preko "
            "WordPress admin panela. Ako ne koristite plugin aktivno, "
            "deaktivirajte ga i obrisite ga — neaktivni plugini su cesto "
            "preskočeni pri rutinskim azuriranjima. Proverite access log "
            f"za sumnjiv saobracaj ka {cve['cve']} exploitu."
        ),
        "recommendation_en": (
            f"URGENTLY update plugin '{slug}' to the latest version through "
            "the WordPress admin panel. If the plugin is not actively used, "
            "deactivate AND delete it — inactive plugins are often skipped "
            "during routine updates. Check access logs for suspicious "
            f"traffic related to the {cve['cve']} exploit."
        ),
    }


def _finding_user_enum(
    users: List[str],
    methods: List[str],
) -> Dict[str, Any]:
    """One finding covering both REST API and author-redirect enum methods."""
    user_list = ", ".join(users[:10])
    method_list = " + ".join(methods)
    return {
        "id": "wp_user_enum",
        "category": "WordPress",
        "severity": "MEDIUM",
        "passed": False,
        "title": f"WordPress korisnicka imena izlozena ({len(users)} detektovano)",
        "title_en": f"WordPress usernames exposed ({len(users)} detected)",
        "description": (
            f"Detektovana korisnicka imena WordPress administratora kroz "
            f"{method_list}. Ovo je prvi korak u brute-force napadu: "
            "napadac zna tacno koje username-ove da testira umesto da "
            f"pogadja. Detektovani: {user_list}."
        ),
        "description_en": (
            f"WordPress administrator usernames detected through "
            f"{method_list}. This is step one in a brute-force attack: "
            "the attacker knows exactly which usernames to test instead "
            f"of guessing. Detected: {user_list}."
        ),
        "recommendation": (
            "Blokirajte REST API user endpoint za neautentifikovane "
            "korisnike (dodajte filter na 'rest_authentication_errors' "
            "u functions.php ili koristite security plugin). Za author "
            "redirect, dodajte u .htaccess: 'RewriteCond %{QUERY_STRING} "
            "author=([0-9]+) [NC]' + 'RewriteRule .* - [F,L]'. Uvek "
            "koristite razlicit 'nicename' (display name) od username-a."
        ),
        "recommendation_en": (
            "Block the REST API user endpoint for unauthenticated users "
            "(add a filter on 'rest_authentication_errors' in functions.php "
            "or use a security plugin). For the author redirect, add to "
            ".htaccess: 'RewriteCond %{QUERY_STRING} author=([0-9]+) [NC]' + "
            "'RewriteRule .* - [F,L]'. Always use a 'nicename' (display "
            "name) different from the actual username."
        ),
    }


def _finding_xmlrpc_exposed() -> Dict[str, Any]:
    return {
        "id": "wp_xmlrpc_exposed",
        "category": "WordPress",
        "severity": "MEDIUM",
        "passed": False,
        "title": "WordPress xmlrpc.php je dostupan — attack surface",
        "title_en": "WordPress xmlrpc.php is accessible — attack surface",
        "description": (
            "Endpoint /xmlrpc.php odgovara na zahteve. XML-RPC je legacy "
            "WordPress API koji podrzava pingback amplification napade (mogu "
            "se koristiti za DoS trecih strana) i brute-force login kroz "
            "system.multicall metodu (hiljadu login pokusaja u jednom HTTP "
            "zahtevu — zaobilazi obicne rate limite). Retko kom modernom "
            "sajtu je xmlrpc.php potreban."
        ),
        "description_en": (
            "The /xmlrpc.php endpoint is responding. XML-RPC is a legacy "
            "WordPress API that supports pingback amplification attacks "
            "(usable for DoS against third parties) and brute-force login "
            "through the system.multicall method (thousands of login "
            "attempts per single HTTP request — bypasses common rate "
            "limits). Most modern sites have no use for xmlrpc.php."
        ),
        "recommendation": (
            "Onemogucite xmlrpc.php ako ne koristite Jetpack ili remote "
            "publishing tools. Nginx: 'location = /xmlrpc.php { deny all; "
            "return 404; }'. Apache: 'Files xmlrpc.php' + 'Deny from all'. "
            "Alternativno, WP plugin 'Disable XML-RPC' radi to kroz filter."
        ),
        "recommendation_en": (
            "Disable xmlrpc.php if you are not using Jetpack or remote "
            "publishing tools. Nginx: 'location = /xmlrpc.php { deny all; "
            "return 404; }'. Apache: 'Files xmlrpc.php' + 'Deny from all'. "
            "Alternatively, the WP plugin 'Disable XML-RPC' does this "
            "through a filter."
        ),
    }


# ── Main entry ────────────────────────────────────────────────────────────


def run(
    base_url: str,
    response_body: str,
    session: requests.Session,
) -> List[Dict[str, Any]]:
    """
    Run the WordPress-specific deep pass. Early-exits with [] if the
    passed response body does not look like a WordPress site, keeping
    all ~26 probes strictly off non-WP targets.

    On a WordPress site, runs plugin enumeration in parallel (5 workers
    over POPULAR_PLUGINS), cross-references detected plugins against
    KNOWN_VULN_PLUGINS, then runs the three user-facing probes
    sequentially (REST users, author enum, xmlrpc). Returns a list of
    findings — zero to many depending on what the site exposes.
    """
    if not _is_wordpress(response_body):
        return []

    findings: List[Dict[str, Any]] = []

    # 1. Plugin enumeration — parallel probe of all popular plugins
    detected_plugins: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(_probe_plugin, base_url, session, slug)
            for slug in POPULAR_PLUGINS
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result(timeout=TIMEOUT + 2)
            except Exception:
                continue
            if result:
                detected_plugins.append(result)

    if detected_plugins:
        findings.append(_finding_plugins_enumerable(detected_plugins))

    # Cross-reference detected plugins with known CVE data
    for plugin in detected_plugins:
        cves = _match_cves(plugin["slug"], plugin.get("version"))
        for cve in cves:
            findings.append(_finding_plugin_vulnerable(plugin, cve))

    # 2. User enumeration — REST API and author redirect
    rest_users = _check_rest_users(base_url, session)
    author_users = _check_author_enum(base_url, session)

    methods: List[str] = []
    if rest_users:
        methods.append("REST API /wp-json/wp/v2/users")
    if author_users:
        methods.append("/?author=N redirect")

    if methods:
        combined = list(dict.fromkeys((rest_users or []) + author_users))
        findings.append(_finding_user_enum(combined, methods))

    # 3. xmlrpc.php exposure
    if _check_xmlrpc(base_url, session):
        findings.append(_finding_xmlrpc_exposed())

    return findings
