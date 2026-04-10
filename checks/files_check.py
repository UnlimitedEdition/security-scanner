"""
Sensitive File Exposure Check
Checks for publicly accessible files that should NEVER be public.
All checks are passive HTTP GET requests — no exploitation.
"""
import sys
import os
import concurrent.futures
import requests
from typing import List, Dict, Any, Optional

# Import from parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_utils import safe_get, UnsafeTargetError

# Per-request timeout (short — these are static files, not dynamic pages).
# With MAX_WORKERS=5 parallel probes and 11 files, worst-case wall time is
# roughly (11 / 5) * TIMEOUT ≈ 13 seconds instead of the old 88 seconds.
TIMEOUT = 6
MAX_WORKERS = 5

SENSITIVE_FILES = [
    {
        "id": "file_env",
        "path": "/.env",
        "severity": "CRITICAL",
        "title": ".env fajl je javno dostupan!",
        "title_en": ".env File is Publicly Accessible!",
        "description": ".env fajl sadrži API ključeve, lozinke baze podataka i tajne tokene. Napadač koji dođe do ovog fajla ima potpunu kontrolu nad aplikacijom.",
        "description_en": ".env file contains API keys, database passwords and secret tokens. An attacker who gets this file has full control of the application.",
        "recommendation": "Odmah uklonite .env sa web root-a. Dodajte 'deny all' u Nginx ili .htaccess za ovaj fajl.",
        "recommendation_en": "Immediately remove .env from the web root. Add 'deny all' in Nginx or .htaccess for this file.",
    },
    {
        "id": "file_git_config",
        "path": "/.git/config",
        "severity": "CRITICAL",
        "title": ".git/config je javno dostupan — izložen ceo source code!",
        "title_en": ".git/config is Publicly Accessible — Full Source Code Exposed!",
        "description": "Napadač može preuzeti kompletan izvorni kod aplikacije uključujući sve lozinke, API ključeve i poslovnu logiku.",
        "description_en": "An attacker can download the complete application source code including all passwords, API keys and business logic.",
        "recommendation": "Blokirajte pristup .git direktorijumu: 'location /.git { deny all; }' u Nginx konfiguraciji.",
        "recommendation_en": "Block access to .git directory: 'location /.git { deny all; }' in Nginx config.",
    },
    {
        "id": "file_wp_config",
        "path": "/wp-config.php.bak",
        "severity": "CRITICAL",
        "title": "WordPress backup konfiguracije je dostupan!",
        "title_en": "WordPress Config Backup is Accessible!",
        "description": "Backup fajl WordPress konfiguracije sadrži kredencijale baze podataka.",
        "description_en": "WordPress configuration backup contains database credentials.",
        "recommendation": "Uklonite sve .bak, .old, .backup fajlove sa servera.",
        "recommendation_en": "Remove all .bak, .old, .backup files from the server.",
    },
    {
        "id": "file_phpinfo",
        "path": "/phpinfo.php",
        "severity": "HIGH",
        "title": "phpinfo.php je dostupan — otkrivene sistemske informacije",
        "title_en": "phpinfo.php is Accessible — System Info Exposed",
        "description": "phpinfo() otkriva verziju PHP-a, putanje na serveru, loadovane module i konfiguraciju što napadaču daje detaljan uvid u sistem.",
        "description_en": "phpinfo() reveals PHP version, server paths, loaded modules and configuration, giving an attacker detailed system knowledge.",
        "recommendation": "Odmah uklonite phpinfo.php sa servera.",
        "recommendation_en": "Immediately remove phpinfo.php from the server.",
    },
    {
        "id": "file_htaccess",
        "path": "/.htaccess",
        "severity": "MEDIUM",
        "title": ".htaccess fajl je dostupan",
        "title_en": ".htaccess File is Accessible",
        "description": ".htaccess može otkriti strukturu servera, putanje, rewrite pravila i potencijalno osetljive konfiguracije.",
        "description_en": ".htaccess can reveal server structure, paths, rewrite rules and potentially sensitive configuration.",
        "recommendation": "Dodajte 'FilesMatch \\.htaccess$ { Deny from all }' u Apache konfiguraciju.",
        "recommendation_en": "Add 'FilesMatch \\.htaccess$ { Deny from all }' to Apache configuration.",
    },
    {
        "id": "file_ds_store",
        "path": "/.DS_Store",
        "severity": "LOW",
        "title": ".DS_Store fajl dostupan — otkriva strukturu direktorijuma",
        "title_en": ".DS_Store File Accessible — Directory Structure Revealed",
        "description": ".DS_Store je MacOS metapodatak koji otkriva nazive fajlova i foldera na serveru, što pomaže napadaču u mapiranju sistema.",
        "description_en": ".DS_Store is a macOS metadata file that reveals filenames and folder names on the server, helping an attacker map the system.",
        "recommendation": "Uklonite .DS_Store sa servera. Dodajte ga u .gitignore.",
        "recommendation_en": "Remove .DS_Store from the server. Add it to .gitignore.",
    },
    {
        "id": "file_backup",
        "path": "/backup.zip",
        "severity": "CRITICAL",
        "title": "backup.zip je javno dostupan!",
        "title_en": "backup.zip is Publicly Accessible!",
        "description": "Arhiva sa backup-om sajta je dostupna svima. Može sadržati kompletnu bazu podataka, kodove i lozinke.",
        "description_en": "Site backup archive is accessible to anyone. May contain full database, code and passwords.",
        "recommendation": "Odmah uklonite backup fajlove sa web root-a. Backup-ove čuvajte van public direktorijuma.",
        "recommendation_en": "Immediately remove backup files from the web root. Store backups outside the public directory.",
    },
    {
        "id": "file_sql_backup",
        "path": "/backup.sql",
        "severity": "CRITICAL",
        "title": "SQL dump baze je javno dostupan!",
        "title_en": "SQL Database Dump is Publicly Accessible!",
        "description": "SQL dump fajl sadrži sve podatke iz baze uključujući korisničke podatke, lozinke i poslovne informacije.",
        "description_en": "SQL dump file contains all database data including user data, passwords and business information.",
        "recommendation": "Odmah uklonite SQL fajlove sa web root-a.",
        "recommendation_en": "Immediately remove SQL files from the web root.",
    },
    {
        "id": "file_wp_debug",
        "path": "/wp-content/debug.log",
        "severity": "MEDIUM",
        "title": "WordPress debug.log je dostupan",
        "title_en": "WordPress debug.log is Accessible",
        "description": "Debug log može sadržati putanje na serveru, SQL upite, greške i potencijalno osetljive podatke.",
        "description_en": "Debug log may contain server paths, SQL queries, errors and potentially sensitive data.",
        "recommendation": "Isključite WP_DEBUG u produkciji ili blokirajte pristup debug.log fajlu.",
        "recommendation_en": "Disable WP_DEBUG in production or block access to the debug.log file.",
    },
    {
        "id": "file_composer",
        "path": "/composer.json",
        "severity": "LOW",
        "title": "composer.json je dostupan — otkrivene zavisnosti",
        "title_en": "composer.json is Accessible — Dependencies Revealed",
        "description": "Lista PHP zavisnosti pomaže napadaču da identifikuje potencijalno ranjive pakete.",
        "description_en": "PHP dependency list helps an attacker identify potentially vulnerable packages.",
        "recommendation": "Blokirajte pristup composer.json u web serveru.",
        "recommendation_en": "Block access to composer.json in the web server.",
    },
    {
        "id": "file_package_json",
        "path": "/package.json",
        "severity": "LOW",
        "title": "package.json je dostupan — otkrivene JS zavisnosti",
        "title_en": "package.json is Accessible — JS Dependencies Revealed",
        "description": "Lista Node.js zavisnosti pomaže napadaču da identifikuje ranjive pakete.",
        "description_en": "Node.js dependency list helps attacker identify vulnerable packages.",
        "recommendation": "Blokirajte pristup package.json u produkciji.",
        "recommendation_en": "Block access to package.json in production.",
    },
]


# Per-file content signatures.
#
# A 200 OK alone means nothing — most modern sites return 200 for ANY path
# because SPA routers, custom 404 pages, and WAFs all serve HTML shells.
# So we only flag a file as exposed when its body actually matches the
# expected shape of that file type.
#
# Two modes:
#   signatures_any   — at least one substring must appear in the text body
#   signatures_magic — response.content must START with at least one byte pattern
#
# reject_html=True adds a guard: if the body starts with "<" (i.e. SPA HTML
# shell or default 404 page) the match is rejected regardless of substring
# hits. Disabled for files that legitimately start with "<" (PHP sources).
CONTENT_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "file_env": {
        "signatures_any": [
            "DB_HOST", "DB_USER", "DB_NAME", "DB_PASSWORD", "DB_CONNECTION",
            "APP_ENV", "APP_KEY", "APP_SECRET", "APP_DEBUG",
            "NODE_ENV", "DATABASE_URL", "REDIS_URL", "MAIL_HOST",
            "_KEY=", "_SECRET=", "_TOKEN=", "API_KEY", "SECRET_KEY",
        ],
        "reject_html": True,
    },
    "file_git_config": {
        "signatures_any": [
            "[core]", "[remote \"", "repositoryformatversion",
            "filemode", "bare =", "[branch \"",
        ],
        "reject_html": True,
    },
    "file_wp_config": {
        # PHP source files legitimately start with "<?php" so reject_html
        # would false-negative here. We rely on WP-specific constants instead.
        "signatures_any": [
            "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST",
            "table_prefix", "wp-settings.php", "ABSPATH",
            "AUTH_KEY", "SECURE_AUTH_KEY", "NONCE_KEY",
        ],
    },
    "file_phpinfo": {
        "signatures_any": [
            "PHP Version", "phpinfo()", "PHP Logo",
            "System ", "Build Date", "Configure Command",
            "Server API", "Loaded Configuration File",
        ],
    },
    "file_htaccess": {
        "signatures_any": [
            "RewriteEngine", "RewriteRule", "RewriteCond",
            "Options ", "Deny from", "Allow from",
            "<IfModule", "AuthType", "AuthName", "Require ",
            "Order allow", "ErrorDocument", "FilesMatch",
        ],
        "reject_html": True,
    },
    "file_ds_store": {
        # Binary macOS metadata file — fixed magic header
        "signatures_magic": [b"\x00\x00\x00\x01Bud1"],
    },
    "file_backup": {
        # ZIP archive magic numbers (local file header / central directory)
        "signatures_magic": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    },
    "file_sql_backup": {
        "signatures_any": [
            "CREATE TABLE", "INSERT INTO", "DROP TABLE",
            "-- MySQL dump", "-- PostgreSQL", "-- SQLite",
            "-- Dump of", "-- Database:",
            "SET SQL_MODE", "LOCK TABLES", "PRAGMA foreign_keys",
        ],
        "reject_html": True,
    },
    "file_wp_debug": {
        "signatures_any": [
            "PHP Notice", "PHP Warning", "PHP Fatal", "PHP Deprecated",
            "WordPress database error", "wp-includes/", "wp-content/",
        ],
        "reject_html": True,
    },
    "file_composer": {
        "signatures_any": [
            "\"require\"", "\"autoload\"", "\"php\":", "\"psr-4\"", "\"psr-0\"",
            "\"type\": \"library\"", "\"type\":\"library\"",
        ],
        "reject_html": True,
    },
    "file_package_json": {
        "signatures_any": [
            "\"dependencies\"", "\"devDependencies\"", "\"scripts\"",
            "\"main\":", "\"version\":", "\"engines\"",
        ],
        "reject_html": True,
    },
}


def _content_matches(resp: requests.Response, spec_id: str) -> bool:
    """
    Return True only when response body looks like the file type we expect.

    A positive-signal match (content actually contains what this file should
    contain) is far more reliable than the old blacklist approach, which
    false-negatived any real .env file that happened to contain the word
    "error" or "not found" in a comment.
    """
    sig = CONTENT_SIGNATURES.get(spec_id)
    if not sig:
        # Unknown file type — fall back to minimal heuristic
        return len(resp.content) > 50

    # Binary signature takes precedence — short-circuit before decoding text
    magic_list = sig.get("signatures_magic")
    if magic_list:
        head = resp.content[:32]
        return any(head.startswith(m) for m in magic_list)

    text_sigs = sig.get("signatures_any", [])
    if not text_sigs:
        return False

    try:
        body = resp.text
    except Exception:
        return False

    # SPA guard: if the body is an HTML shell, the server is catch-all'ing
    # every path. Don't trust substring hits inside HTML for non-HTML files.
    if sig.get("reject_html"):
        stripped = body.lstrip()[:64].lower()
        if stripped.startswith("<!doctype html") or stripped.startswith("<html"):
            return False

    # Only scan the first few KB — real config files are small, and this
    # bounds the work we do for giant SPA bundles that happen to 200 OK.
    scan_window = body[:4000]
    return any(sig_str in scan_window for sig_str in text_sigs)


def _probe_file(base_url: str, session: requests.Session,
                spec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Probe a single sensitive file. Returns a finding dict if the file
    is exposed, or None otherwise. Never raises — intended to be called
    from a ThreadPoolExecutor where one failure must not kill the batch.
    """
    url = base_url.rstrip("/") + spec["path"]
    try:
        resp = safe_get(session, url, timeout=TIMEOUT, max_redirects=0)
    except (UnsafeTargetError, requests.exceptions.RequestException):
        return None
    except Exception:
        return None

    if resp.status_code != 200:
        return None
    if len(resp.content) < 16:
        return None
    if not _content_matches(resp, spec["id"]):
        return None

    return {
        "id": spec["id"],
        "category": "Sensitive Files",
        "severity": spec["severity"],
        "passed": False,
        "title": spec["title"],
        "title_en": spec["title_en"],
        "description": spec["description"] + f" URL: {url}",
        "description_en": spec["description_en"] + f" URL: {url}",
        "recommendation": spec["recommendation"],
        "recommendation_en": spec["recommendation_en"],
    }


def run(base_url: str, session: requests.Session) -> List[Dict[str, Any]]:
    results = []

    # Probe all files in parallel. requests.Session is safe for concurrent
    # GETs on distinct URLs; we never mutate session state across threads.
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(_probe_file, base_url, session, spec)
            for spec in SENSITIVE_FILES
        ]
        for fut in concurrent.futures.as_completed(futures):
            try:
                finding = fut.result(timeout=TIMEOUT + 2)
            except Exception:
                continue
            if finding:
                results.append(finding)

    if not results:
        results.append({
            "id": "files_all_ok",
            "category": "Sensitive Files",
            "severity": "INFO",
            "passed": True,
            "title": "Osetljivi fajlovi su zaštićeni ✓",
            "title_en": "Sensitive Files are Protected ✓",
            "description": f"Proverenih {len(SENSITIVE_FILES)} kritičnih lokacija — nijedan osetljiv fajl nije javno dostupan.",
            "description_en": f"Checked {len(SENSITIVE_FILES)} critical locations — no sensitive file is publicly accessible.",
            "recommendation": "",
            "recommendation_en": "",
        })

    return results
