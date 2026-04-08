"""
Information Disclosure Check
Checks for server/technology version leakage in HTTP headers and HTML.
"""
import re
import requests
from typing import List, Dict, Any


def run(response_headers: dict, response_body: str = "") -> List[Dict[str, Any]]:
    results = []
    lower_headers = {k.lower(): v for k, v in response_headers.items()}

    # --- Server header ---
    server = lower_headers.get("server", "")
    if server:
        # Check if it reveals version info
        version_pattern = r"\d+\.\d+"
        has_version = bool(re.search(version_pattern, server))
        if has_version:
            results.append({
                "id": "disc_server_version",
                "category": "Information Disclosure",
                "severity": "MEDIUM",
                "passed": False,
                "title": f"Server header otkriva verziju: {server[:60]}",
                "title_en": f"Server header reveals version: {server[:60]}",
                "description": "Tačna verzija web servera pomaže napadaču da pronađe poznate ranjivosti za tu verziju.",
                "description_en": "Exact web server version helps attackers find known vulnerabilities for that version.",
                "recommendation": "Sakrijte verziju servera. U Nginx: 'server_tokens off;'. U Apache: 'ServerTokens Prod'.",
                "recommendation_en": "Hide server version. In Nginx: 'server_tokens off;'. In Apache: 'ServerTokens Prod'.",
            })
        else:
            results.append({
                "id": "disc_server_ok",
                "category": "Information Disclosure",
                "severity": "INFO",
                "passed": True,
                "title": f"Server header ne otkriva verziju ✓ ({server[:40]})",
                "title_en": f"Server header does not reveal version ✓ ({server[:40]})",
                "description": "Server header je prisutan ali ne otkriva tačnu verziju.",
                "description_en": "Server header is present but does not reveal the exact version.",
                "recommendation": "",
                "recommendation_en": "",
            })

    # --- X-Powered-By ---
    powered_by = lower_headers.get("x-powered-by", "")
    if powered_by:
        results.append({
            "id": "disc_powered_by",
            "category": "Information Disclosure",
            "severity": "MEDIUM",
            "passed": False,
            "title": f"X-Powered-By otkriva tehnologiju: {powered_by[:60]}",
            "title_en": f"X-Powered-By reveals technology: {powered_by[:60]}",
            "description": "X-Powered-By header otkriva programski jezik i verziju (npr. PHP/8.1, ASP.NET). Napadač ovo koristi za ciljane napade.",
            "description_en": "X-Powered-By header reveals the programming language and version (e.g. PHP/8.1, ASP.NET). Attackers use this for targeted attacks.",
            "recommendation": "Uklonite X-Powered-By header. U PHP: 'expose_php = Off' u php.ini. U Express.js: 'app.disable(\"x-powered-by\")'.",
            "recommendation_en": "Remove X-Powered-By header. In PHP: 'expose_php = Off' in php.ini. In Express.js: 'app.disable(\"x-powered-by\")'.",
        })

    # --- X-AspNet-Version ---
    aspnet = lower_headers.get("x-aspnet-version", "") or lower_headers.get("x-aspnetmvc-version", "")
    if aspnet:
        results.append({
            "id": "disc_aspnet",
            "category": "Information Disclosure",
            "severity": "MEDIUM",
            "passed": False,
            "title": f"ASP.NET verzija otkrivena: {aspnet[:60]}",
            "title_en": f"ASP.NET version disclosed: {aspnet[:60]}",
            "description": "Verzija ASP.NET framework-a je javno vidljiva.",
            "description_en": "ASP.NET framework version is publicly visible.",
            "recommendation": "U web.config dodajte: <httpRuntime enableVersionHeader='false'/>",
            "recommendation_en": "In web.config add: <httpRuntime enableVersionHeader='false'/>",
        })

    # --- Check for debug information in HTML body ---
    if response_body:
        debug_patterns = [
            (r"(Fatal error|Parse error|Warning:|Notice:)\s+.+\s+on line \d+", "PHP greška vidljiva korisnicima", "PHP error visible to users"),
            (r"Microsoft OLE DB Provider for SQL Server", "SQL Server greška otkrivena", "SQL Server error disclosed"),
            (r"ORA-\d{5}:", "Oracle greška otkrivena", "Oracle error disclosed"),
            (r"Traceback \(most recent call last\)", "Python stack trace otkriven", "Python stack trace disclosed"),
            (r"at [A-Za-z\.]+\([A-Za-z]+\.java:\d+\)", "Java stack trace otkriven", "Java stack trace disclosed"),
        ]

        for pattern, title_sr, title_en in debug_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                results.append({
                    "id": "disc_debug_info",
                    "category": "Information Disclosure",
                    "severity": "HIGH",
                    "passed": False,
                    "title": f"Debug informacije vidljive: {title_sr}",
                    "title_en": f"Debug information visible: {title_en}",
                    "description": "Greške i stack trace-ovi otkrivaju unutrašnju strukturu aplikacije napadaču.",
                    "description_en": "Errors and stack traces reveal the internal application structure to attackers.",
                    "recommendation": "Isključite prikazivanje grešaka u produkciji. Koristite error logging umesto prikazivanja grešaka.",
                    "recommendation_en": "Disable error display in production. Use error logging instead of displaying errors.",
                })
                break

    # --- Check WordPress version in meta tags ---
    if response_body:
        wp_version = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', response_body, re.IGNORECASE)
        if wp_version:
            version = wp_version.group(1)
            results.append({
                "id": "disc_wp_version",
                "category": "Information Disclosure",
                "severity": "MEDIUM",
                "passed": False,
                "title": f"WordPress verzija otkrivena u HTML-u: v{version}",
                "title_en": f"WordPress version disclosed in HTML: v{version}",
                "description": f"WordPress verzija {version} je vidljiva u source kodu stranice. Napadač može proveriti poznate ranjivosti za tu verziju.",
                "description_en": f"WordPress version {version} is visible in page source. An attacker can check known vulnerabilities for that version.",
                "recommendation": "Uklonite generator meta tag. Dodajte u functions.php: remove_action('wp_head', 'wp_generator');",
                "recommendation_en": "Remove the generator meta tag. Add to functions.php: remove_action('wp_head', 'wp_generator');",
            })

    return results
