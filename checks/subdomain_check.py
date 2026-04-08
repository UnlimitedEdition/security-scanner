"""
Subdomain Enumeration Check
Resolves common subdomains and flags potentially dangerous ones.
"""
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "shop", "cdn", "webmail", "remote", "vpn", "portal",
    "db", "database", "phpmyadmin", "cpanel", "git", "jenkins",
    "jira", "grafana", "prometheus", "kibana", "elastic",
]

DANGEROUS = {
    "admin": ("MEDIUM", "Administratorski panel"),
    "phpmyadmin": ("HIGH", "PHPMyAdmin interfejs za bazu"),
    "cpanel": ("MEDIUM", "cPanel hosting kontrola"),
    "db": ("HIGH", "Baza podataka"),
    "database": ("HIGH", "Baza podataka"),
    "staging": ("MEDIUM", "Staging okruzenje (cesto bez zastite)"),
    "test": ("MEDIUM", "Test okruzenje"),
    "dev": ("LOW", "Development okruzenje"),
    "remote": ("MEDIUM", "Remote access"),
    "ftp": ("MEDIUM", "FTP server"),
    "git": ("HIGH", "Git repozitorijum"),
    "jenkins": ("HIGH", "Jenkins CI/CD"),
    "jira": ("LOW", "Jira project management"),
    "grafana": ("MEDIUM", "Grafana monitoring"),
    "prometheus": ("HIGH", "Prometheus metrike"),
    "kibana": ("MEDIUM", "Kibana log viewer"),
    "elastic": ("HIGH", "Elasticsearch"),
}


def _resolve(subdomain, domain):
    full = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(full, "A", lifetime=3)
        ips = [str(r) for r in answers]
        return (subdomain, full, ips)
    except Exception:
        return None


def run(domain: str) -> List[Dict[str, Any]]:
    results = []
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

    for sub, full, (severity, desc_sr) in dangerous_found:
        desc_en = {
            "admin": "Administrator panel",
            "phpmyadmin": "PHPMyAdmin database interface",
            "cpanel": "cPanel hosting control",
            "db": "Database server",
            "database": "Database server",
            "staging": "Staging environment (often unprotected)",
            "test": "Test environment",
            "dev": "Development environment",
            "remote": "Remote access service",
            "ftp": "FTP server",
            "git": "Git repository",
            "jenkins": "Jenkins CI/CD server",
            "jira": "Jira project management",
            "grafana": "Grafana monitoring dashboard",
            "prometheus": "Prometheus metrics endpoint",
            "kibana": "Kibana log viewer",
            "elastic": "Elasticsearch instance",
        }.get(sub, "Potentially sensitive service")

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
