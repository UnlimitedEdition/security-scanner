"""
CMS & Technology Detection Check
Detects WordPress, Joomla, Drupal, outdated jQuery, etc.
Purely passive — reads only what the site publicly serves.
"""
import re
import requests
from typing import List, Dict, Any

TIMEOUT = 8

# Known vulnerable jQuery versions (below 3.5.0 have known XSS issues)
JQUERY_MIN_SAFE = (3, 5, 0)


def _parse_version(v: str):
    try:
        parts = v.strip().split(".")
        return tuple(int(p) for p in parts[:3])
    except Exception:
        return (0, 0, 0)


def run(base_url: str, response_body: str, session: requests.Session) -> List[Dict[str, Any]]:
    results = []

    # --- WordPress Detection ---
    wp_indicators = [
        "/wp-content/",
        "/wp-includes/",
        "wp-json",
        "WordPress",
    ]
    is_wordpress = any(ind in response_body for ind in wp_indicators)

    if is_wordpress:
        # Check WordPress version
        wp_version_meta = re.search(
            r'<meta name=["\']generator["\'] content=["\']WordPress ([\d.]+)["\']',
            response_body, re.IGNORECASE
        )
        wp_version_feed = None

        # Try RSS feed for version
        try:
            feed_resp = session.get(base_url.rstrip("/") + "/feed/", timeout=TIMEOUT)
            version_match = re.search(r"<generator>https://wordpress\.org/\?v=([\d.]+)</generator>", feed_resp.text)
            if version_match:
                wp_version_feed = version_match.group(1)
        except Exception:
            pass

        version = None
        if wp_version_meta:
            version = wp_version_meta.group(1)
        elif wp_version_feed:
            version = wp_version_feed

        if version:
            results.append({
                "id": "cms_wp_version_exposed",
                "category": "CMS/Technology",
                "severity": "MEDIUM",
                "passed": False,
                "title": f"WordPress detektovan — verzija vidljiva: v{version}",
                "title_en": f"WordPress detected — version visible: v{version}",
                "description": f"WordPress verzija {version} je javno vidljiva. Napadač može proveriti CVE bazu za poznate ranjivosti ove verzije.",
                "description_en": f"WordPress version {version} is publicly visible. An attacker can check the CVE database for known vulnerabilities.",
                "recommendation": "Sakrijte verziju: u functions.php dodajte remove_action('wp_head', 'wp_generator'); i blokirajte pristup readme.html.",
                "recommendation_en": "Hide the version: in functions.php add remove_action('wp_head', 'wp_generator'); and block access to readme.html.",
            })
        else:
            results.append({
                "id": "cms_wp_detected",
                "category": "CMS/Technology",
                "severity": "INFO",
                "passed": True,
                "title": "WordPress detektovan (verzija sakrivena) ✓",
                "title_en": "WordPress detected (version hidden) ✓",
                "description": "WordPress korišćen, ali verzija nije javno vidljiva.",
                "description_en": "WordPress in use, but version is not publicly visible.",
                "recommendation": "",
                "recommendation_en": "",
            })

        # Check for WordPress readme.html
        try:
            readme_resp = session.get(base_url.rstrip("/") + "/readme.html", timeout=TIMEOUT, allow_redirects=False)
            if readme_resp.status_code == 200 and "WordPress" in readme_resp.text:
                results.append({
                    "id": "cms_wp_readme",
                    "category": "CMS/Technology",
                    "severity": "LOW",
                    "passed": False,
                    "title": "WordPress readme.html dostupan",
                    "title_en": "WordPress readme.html Accessible",
                    "description": "readme.html fajl otkriva WordPress verziju i instalacionu istoriju.",
                    "description_en": "readme.html reveals WordPress version and installation history.",
                    "recommendation": "Obrišite readme.html, license.txt i wp-config-sample.php sa servera.",
                    "recommendation_en": "Delete readme.html, license.txt and wp-config-sample.php from the server.",
                })
        except Exception:
            pass

    # --- Joomla Detection ---
    joomla_indicators = ["/administrator/", "Joomla!", "/components/com_"]
    if any(ind in response_body for ind in joomla_indicators):
        results.append({
            "id": "cms_joomla",
            "category": "CMS/Technology",
            "severity": "INFO",
            "passed": True,
            "title": "Joomla CMS detektovan",
            "title_en": "Joomla CMS Detected",
            "description": "Sajt koristi Joomla CMS. Proverite da li je ažuriran na poslednju verziju.",
            "description_en": "Site uses Joomla CMS. Check that it is updated to the latest version.",
            "recommendation": "Redovno ažurirajte Joomla i sve ekstenzije.",
            "recommendation_en": "Regularly update Joomla and all extensions.",
        })

    # --- jQuery version check ---
    jquery_versions = re.findall(
        r'jquery[.-](\d+\.\d+\.?\d*)(\.min)?\.js',
        response_body, re.IGNORECASE
    )
    # Also check inline version declaration
    jquery_inline = re.findall(r'jQuery v([\d.]+)', response_body)
    all_versions = list(set(jquery_versions and [v[0] for v in jquery_versions] or [] + jquery_inline))

    for ver_str in all_versions[:3]:  # Check max 3
        ver = _parse_version(ver_str)
        if ver < JQUERY_MIN_SAFE and ver > (0, 0, 0):
            results.append({
                "id": "cms_jquery_outdated",
                "category": "CMS/Technology",
                "severity": "MEDIUM",
                "passed": False,
                "title": f"Zastarela jQuery verzija: v{ver_str}",
                "title_en": f"Outdated jQuery Version: v{ver_str}",
                "description": f"jQuery {ver_str} ima poznate XSS ranjivosti (CVE-2020-11022, CVE-2020-11023). Napadač može injektovati HTML kroz ove ranjivosti.",
                "description_en": f"jQuery {ver_str} has known XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023). An attacker can inject HTML through these vulnerabilities.",
                "recommendation": "Ažurirajte jQuery na verziju 3.6.0 ili noviju.",
                "recommendation_en": "Update jQuery to version 3.6.0 or newer.",
            })

    # --- Mixed content check ---
    http_resources = re.findall(r'src=["\']http://[^"\']+["\']', response_body, re.IGNORECASE)
    http_resources += re.findall(r'href=["\']http://[^"\']+\.css["\']', response_body, re.IGNORECASE)

    if http_resources and base_url.startswith("https"):
        examples = http_resources[:3]
        results.append({
            "id": "cms_mixed_content",
            "category": "CMS/Technology",
            "severity": "MEDIUM",
            "passed": False,
            "title": f"Mešoviti sadržaj (Mixed Content): {len(http_resources)} HTTP resursa na HTTPS sajtu",
            "title_en": f"Mixed Content: {len(http_resources)} HTTP resources on HTTPS site",
            "description": f"HTTPS sajt učitava resurse preko nesigurnog HTTP-a. Browser blokira ove resurse ili prikazuje upozorenje. Primeri: {', '.join(examples[:2])[:100]}",
            "description_en": f"HTTPS site loads resources over insecure HTTP. Browser blocks these resources or shows a warning. Examples: {', '.join(examples[:2])[:100]}",
            "recommendation": "Zamenite sve http:// linkove sa https:// ili relativnim putanjama.",
            "recommendation_en": "Replace all http:// links with https:// or relative paths.",
        })

    return results
