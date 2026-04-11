# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Redirect & HTTPS Enforcement Check
Checks: HTTP->HTTPS redirect, www/non-www consistency, redirect chain length.
"""
import sys
import os
import requests
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_utils import safe_get, UnsafeTargetError

TIMEOUT = 10


def run(domain: str, session: requests.Session) -> List[Dict[str, Any]]:
    results = []

    # --- HTTP → HTTPS redirect ---
    try:
        http_url = f"http://{domain}/"
        resp = safe_get(session, http_url, timeout=TIMEOUT)

        # Check if final URL is HTTPS
        final_url = resp.url
        if final_url.startswith("https://"):
            # Check redirect chain length
            chain_length = len(resp.history)
            if chain_length > 3:
                results.append({
                    "id": "redirect_long_chain",
                    "category": "Redirects",
                    "severity": "LOW",
                    "passed": False,
                    "title": f"Predugačak redirect lanac ({chain_length} koraka)",
                    "title_en": f"Too long redirect chain ({chain_length} steps)",
                    "description": f"HTTP → HTTPS redirect prolazi kroz {chain_length} koraka. Svaki korak usporava učitavanje sajta i loš je za SEO.",
                    "description_en": f"HTTP → HTTPS redirect goes through {chain_length} steps. Each step slows down the site and is bad for SEO.",
                    "recommendation": "Konfigurišite direktan 301 redirect sa HTTP na HTTPS bez međukoraka.",
                    "recommendation_en": "Configure a direct 301 redirect from HTTP to HTTPS without intermediate steps.",
                })
            else:
                results.append({
                    "id": "redirect_https_ok",
                    "category": "Redirects",
                    "severity": "INFO",
                    "passed": True,
                    "title": "HTTP → HTTPS preusmeravanje radi ✓",
                    "title_en": "HTTP → HTTPS redirect works ✓",
                    "description": f"Sajt ispravno preusmerava HTTP na HTTPS ({chain_length} hop).",
                    "description_en": f"Site correctly redirects HTTP to HTTPS ({chain_length} hop).",
                    "recommendation": "",
                    "recommendation_en": "",
                })
        else:
            results.append({
                "id": "redirect_no_https",
                "category": "Redirects",
                "severity": "CRITICAL",
                "passed": False,
                "title": "HTTP saobraćaj se NE preusmerava na HTTPS!",
                "title_en": "HTTP traffic is NOT redirected to HTTPS!",
                "description": "Korisnici koji posete http:// verziju sajta ne bivaju automatski preusmereni na sigurnu https:// verziju. Podaci se prenose nešifrovano.",
                "description_en": "Users visiting the http:// version are not automatically redirected to the secure https:// version. Data is transmitted unencrypted.",
                "recommendation": "Dodajte 301 redirect sa HTTP na HTTPS u Nginx: 'return 301 https://$host$request_uri;'",
                "recommendation_en": "Add a 301 redirect from HTTP to HTTPS in Nginx: 'return 301 https://$host$request_uri;'",
            })
    except requests.exceptions.ConnectionError:
        results.append({
            "id": "redirect_http_unreachable",
            "category": "Redirects",
            "severity": "INFO",
            "passed": True,
            "title": "HTTP port nije dostupan (potencijalno OK)",
            "title_en": "HTTP port not accessible (potentially OK)",
            "description": "Port 80 (HTTP) nije dostupan — moguće je da je namerno blokiran.",
            "description_en": "Port 80 (HTTP) is not accessible — possibly intentionally blocked.",
            "recommendation": "",
            "recommendation_en": "",
        })
    except Exception as e:
        pass

    # --- www vs non-www consistency ---
    try:
        has_www = domain.startswith("www.")
        alt_domain = domain[4:] if has_www else f"www.{domain}"

        try:
            alt_resp = safe_get(session, f"https://{alt_domain}/", timeout=TIMEOUT)
            # Check if both work and redirect to same canonical
            final = alt_resp.url
            main_domain_in_final = domain.replace("www.", "") in final
            alt_domain_clean = alt_domain.replace("www.", "")

            # If alt domain is accessible and doesn't redirect to main, could be duplicate content
            if alt_resp.status_code == 200 and alt_domain in alt_resp.url:
                results.append({
                    "id": "redirect_www_split",
                    "category": "Redirects",
                    "severity": "LOW",
                    "passed": False,
                    "title": f"www i non-www verzije su oba dostupna bez preusmeravanja",
                    "title_en": "Both www and non-www versions accessible without redirect",
                    "description": f"I {domain} i {alt_domain} su dostupni. Ovo može uzrokovati dupliran sadržaj (SEO penalizacija) i zbunjuje bezbednosne alate.",
                    "description_en": f"Both {domain} and {alt_domain} are accessible. This can cause duplicate content (SEO penalty) and confuses security tools.",
                    "recommendation": "Izaberite jednu kanonsku URL (www ili non-www) i preusmerite drugu.",
                    "recommendation_en": "Choose one canonical URL (www or non-www) and redirect the other.",
                })
        except Exception:
            pass

    except Exception:
        pass

    return results
