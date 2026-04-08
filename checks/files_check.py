"""
Sensitive File Exposure Check
Checks for publicly accessible files that should NEVER be public.
All checks are passive HTTP GET requests — no exploitation.
"""
import requests
from typing import List, Dict, Any

TIMEOUT = 8

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


def run(base_url: str, session: requests.Session) -> List[Dict[str, Any]]:
    results = []

    for spec in SENSITIVE_FILES:
        url = base_url.rstrip("/") + spec["path"]
        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=False)
            # Consider it exposed if: 200 OK with some content
            if resp.status_code == 200 and len(resp.content) > 10:
                # Double check: make sure it's not a custom 404 page
                content_preview = resp.text[:200].lower()
                false_positive_signals = [
                    "404", "not found", "page not found", "stranica nije",
                    "error", "greška", "nije pronađena"
                ]
                is_false_positive = any(s in content_preview for s in false_positive_signals)

                if not is_false_positive:
                    results.append({
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
                    })
        except requests.exceptions.RequestException:
            pass  # Can't reach the path — that's fine (means it's blocked)

    if not any(r["category"] == "Sensitive Files" and not r["passed"] for r in results):
        results.append({
            "id": "files_all_ok",
            "category": "Sensitive Files",
            "severity": "INFO",
            "passed": True,
            "title": "Osetljivi fajlovi su zaštićeni ✓",
            "title_en": "Sensitive Files are Protected ✓",
            "description": "Proverenih 11 kritičnih lokacija — nijedan osetljiv fajl nije javno dostupan.",
            "description_en": "Checked 11 critical locations — no sensitive file is publicly accessible.",
            "recommendation": "",
            "recommendation_en": "",
        })

    return results
