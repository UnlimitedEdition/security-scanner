# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Subdomain Enumeration Check
Resolves common subdomains and flags potentially dangerous ones.
Detects wildcard DNS to avoid false positives.
"""
import dns.resolver
import random
import string
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "shop", "cdn", "webmail", "remote", "vpn", "portal",
    "db", "database", "phpmyadmin", "cpanel", "git", "jenkins",
    "jira", "grafana", "prometheus", "kibana", "elastic",
]

DANGEROUS = {
    "admin": ("MEDIUM", "Administratorski panel", "Administrator panel"),
    "phpmyadmin": ("HIGH", "PHPMyAdmin interfejs za bazu", "PHPMyAdmin database interface"),
    "cpanel": ("MEDIUM", "cPanel hosting kontrola", "cPanel hosting control"),
    "db": ("HIGH", "Baza podataka", "Database server"),
    "database": ("HIGH", "Baza podataka", "Database server"),
    "staging": ("MEDIUM", "Staging okruzenje (cesto bez zastite)", "Staging environment (often unprotected)"),
    "test": ("MEDIUM", "Test okruzenje", "Test environment"),
    "dev": ("LOW", "Development okruzenje", "Development environment"),
    "remote": ("MEDIUM", "Remote access", "Remote access service"),
    "ftp": ("MEDIUM", "FTP server", "FTP server"),
    "git": ("HIGH", "Git repozitorijum", "Git repository"),
    "jenkins": ("HIGH", "Jenkins CI/CD", "Jenkins CI/CD server"),
    "jira": ("LOW", "Jira project management", "Jira project management"),
    "grafana": ("MEDIUM", "Grafana monitoring", "Grafana monitoring dashboard"),
    "prometheus": ("HIGH", "Prometheus metrike", "Prometheus metrics endpoint"),
    "kibana": ("MEDIUM", "Kibana log viewer", "Kibana log viewer"),
    "elastic": ("HIGH", "Elasticsearch", "Elasticsearch instance"),
}


def _resolve(subdomain, domain):
    full = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(full, "A", lifetime=3)
        ips = [str(r) for r in answers]
        return (subdomain, full, ips)
    except Exception:
        return None


def _has_wildcard_dns(domain):
    """Check if domain has wildcard DNS by resolving a random nonsense subdomain."""
    random_sub = "".join(random.choices(string.ascii_lowercase, k=12))
    full = f"{random_sub}.{domain}"
    try:
        answers = dns.resolver.resolve(full, "A", lifetime=3)
        return True, [str(r) for r in answers]
    except Exception:
        return False, []


def _subdomain_has_unique_content(full_domain, wildcard_ips):
    """Check if a subdomain serves different content than the wildcard catch-all."""
    try:
        answers = dns.resolver.resolve(full_domain, "A", lifetime=3)
        sub_ips = [str(r) for r in answers]
        # If IPs are the same as wildcard, it's a catch-all
        if set(sub_ips) == set(wildcard_ips):
            return False
        return True
    except Exception:
        return False


def run(domain: str) -> List[Dict[str, Any]]:
    results = []

    # Step 1: Check for wildcard DNS
    is_wildcard, wildcard_ips = _has_wildcard_dns(domain)

    if is_wildcard:
        # Wildcard DNS detected - all subdomains resolve, no real findings
        results.append({
            "id": "subdomain_wildcard",
            "category": "Subdomain Enumeration",
            "severity": "INFO",
            "passed": True,
            "title": "Wildcard DNS detektovan - preskacemo subdomen skeniranje",
            "title_en": "Wildcard DNS detected - skipping subdomain scanning",
            "description": f"Domen {domain} koristi wildcard DNS (*.{domain} resolvuje). Svi subdomeni automatski resolvuju na istu adresu, sto znaci da nema pravih subdomena za prijaviti.",
            "description_en": f"Domain {domain} uses wildcard DNS (*.{domain} resolves). All subdomains automatically resolve to the same address, meaning there are no real subdomains to report.",
            "recommendation": "",
            "recommendation_en": "",
        })
        return results

    # Step 2: No wildcard - proceed with normal scanning
    found_subs = []
    dangerous_found = []

    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(_resolve, sub, domain): sub for sub in COMMON_SUBDOMAINS}
        for future in as_completed(futures):
            res = future.result()
            if res:
                sub, full, ips = res
                found_subs.append(sub)
                if sub in DANGEROUS:
                    dangerous_found.append((sub, full, DANGEROUS[sub]))

    for sub, full, (severity, desc_sr, desc_en) in dangerous_found:
        results.append({
            "id": f"subdomain_{sub}",
            "category": "Subdomain Enumeration",
            "severity": severity,
            "passed": False,
            "title": f"Otkriven subdomen: {full}",
            "title_en": f"Subdomain discovered: {full}",
            "description": f"{desc_sr} je javno dostupan na {full}. Ovo moze otkriti interne servise napadacu.",
            "description_en": f"{desc_en} is publicly accessible at {full}. This may expose internal services to attackers.",
            "recommendation": f"Proverite da li {full} treba da bude javno dostupan. Ako ne, uklonite DNS zapis ili stavite iza VPN-a.",
            "recommendation_en": f"Check if {full} should be publicly accessible. If not, remove the DNS record or place behind a VPN.",
        })

    if not dangerous_found:
        safe_count = len(found_subs)
        results.append({
            "id": "subdomain_ok",
            "category": "Subdomain Enumeration",
            "severity": "INFO",
            "passed": True,
            "title": f"Nema otkrivenih opasnih subdomena ({safe_count} ukupno pronadjeno)",
            "title_en": f"No dangerous subdomains discovered ({safe_count} total found)",
            "description": f"Od {len(COMMON_SUBDOMAINS)} proverenih subdomena, pronadjeno {safe_count}, nijedan nije potencijalno opasan.",
            "description_en": f"Of {len(COMMON_SUBDOMAINS)} subdomains checked, {safe_count} found, none are potentially dangerous.",
            "recommendation": "",
            "recommendation_en": "",
        })

    return results
