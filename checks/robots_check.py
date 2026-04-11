# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
robots.txt Security Analysis
Checks if robots.txt reveals sensitive paths or is misconfigured.
"""
import re
import sys
import os
import requests
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_utils import safe_get, UnsafeTargetError

TIMEOUT = 7

# Paths in robots.txt that indicate sensitive areas
SENSITIVE_PATTERNS = [
    (r"/admin", "Admin putanja u robots.txt", "MEDIUM"),
    (r"/backup", "Backup putanja u robots.txt", "HIGH"),
    (r"/config", "Konfiguracija putanja u robots.txt", "MEDIUM"),
    (r"/database", "Database putanja u robots.txt", "HIGH"),
    (r"/private", "Private putanja u robots.txt", "MEDIUM"),
    (r"/secret", "Secret putanja u robots.txt", "HIGH"),
    (r"/api/", "API putanja u robots.txt", "LOW"),
    (r"/\.env", ".env putanja u robots.txt", "CRITICAL"),
    (r"/wp-admin", "WordPress admin u robots.txt", "LOW"),
    (r"/phpmyadmin", "phpMyAdmin putanja u robots.txt", "HIGH"),
    (r"/uploads", "Uploads putanja u robots.txt", "LOW"),
    (r"/sql", "SQL putanja u robots.txt", "HIGH"),
]


def run(base_url: str, session: requests.Session) -> List[Dict[str, Any]]:
    results = []
    url = base_url.rstrip("/") + "/robots.txt"

    try:
        resp = safe_get(session, url, timeout=TIMEOUT, max_redirects=0)

        if resp.status_code == 404 or len(resp.content) < 5:
            results.append({
                "id": "robots_missing",
                "category": "robots.txt",
                "severity": "LOW",
                "passed": False,
                "title": "robots.txt ne postoji",
                "title_en": "robots.txt does not exist",
                "description": "robots.txt govori pretraživačima koje stranice da indeksiraju. Bez njega, možete imati duplirani sadržaj u indeksu.",
                "description_en": "robots.txt tells search engines which pages to index. Without it, you may have duplicate content in the index.",
                "recommendation": "Kreirajte robots.txt fajl. Minimum: User-agent: * / Allow: /",
                "recommendation_en": "Create a robots.txt file. Minimum: User-agent: * / Allow: /",
            })
            return results

        if resp.status_code != 200:
            return results

        content = resp.text
        lines = content.split("\n")

        # Check for "Disallow: /" — blocks all crawlers (bad for SEO but ok for private)
        blocks_all = any(
            re.match(r"^Disallow:\s*/\s*$", line.strip(), re.IGNORECASE)
            for line in lines
        )
        if blocks_all:
            results.append({
                "id": "robots_blocks_all",
                "category": "robots.txt",
                "severity": "MEDIUM",
                "passed": False,
                "title": "robots.txt blokira sve pretraživače (Disallow: /)",
                "title_en": "robots.txt blocks all crawlers (Disallow: /)",
                "description": "Sajt je potpuno blokiran za pretraživače. Google, Bing i ostali ne mogu indeksirati sadržaj.",
                "description_en": "The site is completely blocked for crawlers. Google, Bing and others cannot index the content.",
                "recommendation": "Ako je ovo namerno (private sajt), OK. Ako ne, uklonite 'Disallow: /' ili ograničite na specifične putanje.",
                "recommendation_en": "If intentional (private site), OK. If not, remove 'Disallow: /' or limit to specific paths.",
            })

        # Check for sensitive paths being revealed
        sensitive_found = []
        for pattern, label, severity in SENSITIVE_PATTERNS:
            for line in lines:
                if re.search(pattern, line, re.IGNORECASE) and (
                    line.strip().startswith("Disallow:") or line.strip().startswith("Allow:")
                ):
                    sensitive_found.append((label, severity, line.strip()))
                    break

        if sensitive_found:
            # Group by severity — only show the worst
            worst_severity = "LOW"
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            for _, sev, _ in sensitive_found:
                if order.get(sev, 3) < order.get(worst_severity, 3):
                    worst_severity = sev

            examples = [f"`{item[2]}`" for item in sensitive_found[:4]]
            results.append({
                "id": "robots_reveals_paths",
                "category": "robots.txt",
                "severity": worst_severity,
                "passed": False,
                "title": f"robots.txt otkriva {len(sensitive_found)} osetljivih putanja",
                "title_en": f"robots.txt reveals {len(sensitive_found)} sensitive paths",
                "description": f"robots.txt Disallow liste mogu biti vodič za napadača. Osetljive putanje: {', '.join(examples)}",
                "description_en": f"robots.txt Disallow lists can be a guide for attackers. Sensitive paths: {', '.join(examples)}",
                "recommendation": "Uklonite osetljive putanje iz robots.txt. Bezbednost kroz prikrivanje nije rešenje — pravo rešenje je auth.",
                "recommendation_en": "Remove sensitive paths from robots.txt. Security through obscurity is not a solution — proper auth is.",
            })

        if not sensitive_found and not blocks_all:
            results.append({
                "id": "robots_ok",
                "category": "robots.txt",
                "severity": "INFO",
                "passed": True,
                "title": "robots.txt je prisutan i izgleda bezbedno ✓",
                "title_en": "robots.txt is present and looks safe ✓",
                "description": "robots.txt postoji i ne otkriva osetljive putanje.",
                "description_en": "robots.txt exists and does not reveal sensitive paths.",
                "recommendation": "",
                "recommendation_en": "",
            })

    except requests.exceptions.RequestException:
        pass

    return results
