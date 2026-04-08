"""
Extras: security.txt, CAA DNS record, Subresource Integrity, HTTP/2
"""
import re
import socket
import requests
import dns.resolver
from typing import List, Dict, Any

TIMEOUT = 7


def _check_security_txt(base_url: str, session: requests.Session) -> List[Dict[str, Any]]:
    """Check if security.txt exists (industry standard for vulnerability disclosure)."""
    results = []
    urls_to_try = [
        base_url.rstrip("/") + "/.well-known/security.txt",
        base_url.rstrip("/") + "/security.txt",
    ]

    found = False
    for url in urls_to_try:
        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=False)
            if resp.status_code == 200 and "contact:" in resp.text.lower():
                found = True
                break
        except Exception:
            pass

    if found:
        results.append({
            "id": "extras_security_txt_ok",
            "category": "Best Practices",
            "severity": "INFO",
            "passed": True,
            "title": "security.txt prisutan ✓",
            "title_en": "security.txt Present ✓",
            "description": "Sajt ima security.txt — istraživači bezbednosti znaju kome da prijave ranjivosti.",
            "description_en": "Site has security.txt — security researchers know who to report vulnerabilities to.",
            "recommendation": "",
            "recommendation_en": "",
        })
    else:
        results.append({
            "id": "extras_security_txt_missing",
            "category": "Best Practices",
            "severity": "LOW",
            "passed": False,
            "title": "security.txt ne postoji",
            "title_en": "security.txt Missing",
            "description": "security.txt (RFC 9116) je standard koji kaže bezbednosnim istraživačima kome da prijave ranjivost. 99% srpskih sajtova ga nema.",
            "description_en": "security.txt (RFC 9116) is a standard that tells security researchers who to contact to report vulnerabilities.",
            "recommendation": "Kreirajte /.well-known/security.txt sa: Contact: mailto:security@vasajt.com / Expires: 2026-12-31T23:59:00z",
            "recommendation_en": "Create /.well-known/security.txt with: Contact: mailto:security@yourdomain.com / Expires: 2026-12-31T23:59:00z",
        })

    return results


def _check_caa(domain: str) -> List[Dict[str, Any]]:
    """Check CAA DNS record — controls which CAs can issue SSL certificates."""
    results = []
    try:
        answers = dns.resolver.resolve(domain, "CAA")
        issuers = []
        for rdata in answers:
            issuers.append(str(rdata))
        results.append({
            "id": "extras_caa_ok",
            "category": "Best Practices",
            "severity": "INFO",
            "passed": True,
            "title": f"CAA DNS record prisutan ✓ ({len(issuers)} pravila)",
            "title_en": f"CAA DNS Record Present ✓ ({len(issuers)} rules)",
            "description": "CAA record ograničava koji sertifikacioni autoritet (CA) sme da izda SSL sertifikat za vaš domen. Sprečava neovlašćeno izdavanje sertifikata.",
            "description_en": "CAA record restricts which Certificate Authority (CA) may issue an SSL certificate for your domain. Prevents unauthorized certificate issuance.",
            "recommendation": "",
            "recommendation_en": "",
        })
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results.append({
            "id": "extras_caa_missing",
            "category": "Best Practices",
            "severity": "LOW",
            "passed": False,
            "title": "CAA DNS record nedostaje",
            "title_en": "CAA DNS Record Missing",
            "description": "Bez CAA recorda, BILO koji sertifikacioni autoritet na svetu može izdati SSL sertifikat za vaš domen. Napadač koji kompromituje CA može dobiti lažni sertifikat.",
            "description_en": "Without a CAA record, ANY certificate authority in the world can issue an SSL certificate for your domain.",
            "recommendation": 'Dodajte CAA record: 0 issue "letsencrypt.org" (ili koji CA koristite)',
            "recommendation_en": 'Add CAA record: 0 issue "letsencrypt.org" (or whichever CA you use)',
        })
    except Exception:
        pass

    return results


def _check_sri(response_body: str) -> List[Dict[str, Any]]:
    """Check for CDN scripts without Subresource Integrity (SRI) hashes."""
    results = []
    if not response_body:
        return results

    # Find external script tags
    external_scripts = re.findall(
        r'<script[^>]+src=["\']https?://(?!(?:www\.)?[^"\']*?(?:localhost|127\.0\.0\.1))[^"\']+["\'][^>]*>',
        response_body, re.IGNORECASE
    )

    scripts_without_sri = []
    for script in external_scripts[:20]:
        has_integrity = "integrity=" in script.lower()
        if not has_integrity:
            # Extract src for display
            src_match = re.search(r'src=["\']([^"\']+)["\']', script, re.IGNORECASE)
            if src_match:
                src = src_match.group(1)
                # Only flag CDN scripts (not same-domain)
                cdn_patterns = ["cdn.", "cdnjs.", "unpkg.", "jsdelivr.", "googleapis.", "cloudflare."]
                if any(p in src for p in cdn_patterns):
                    scripts_without_sri.append(src[:80])

    if scripts_without_sri:
        results.append({
            "id": "extras_sri_missing",
            "category": "Best Practices",
            "severity": "MEDIUM",
            "passed": False,
            "title": f"CDN skripte bez SRI zaštite: {len(scripts_without_sri)} pronađeno",
            "title_en": f"CDN scripts without SRI protection: {len(scripts_without_sri)} found",
            "description": f"Skripte sa CDN-a nemaju integrity hash. Ako CDN bude kompromitovan, vaš sajt automatski učitava zlonamerni kod. Primeri: {', '.join(scripts_without_sri[:2])}",
            "description_en": f"CDN scripts lack integrity hashes. If the CDN is compromised, your site automatically loads malicious code. Examples: {', '.join(scripts_without_sri[:2])}",
            "recommendation": 'Dodajte integrity atribut: <script src="..." integrity="sha384-xxxx" crossorigin="anonymous">. Generator: https://www.srihash.org/',
            "recommendation_en": 'Add integrity attribute: <script src="..." integrity="sha384-xxxx" crossorigin="anonymous">. Generator: https://www.srihash.org/',
        })
    elif external_scripts:
        results.append({
            "id": "extras_sri_ok",
            "category": "Best Practices",
            "severity": "INFO",
            "passed": True,
            "title": "Eksterni skripti imaju SRI zaštitu ✓",
            "title_en": "External Scripts Have SRI Protection ✓",
            "description": "CDN skripte imaju integrity hash koji browser proverava.",
            "description_en": "CDN scripts have integrity hashes that the browser verifies.",
            "recommendation": "",
            "recommendation_en": "",
        })

    return results


def _check_http2(domain: str) -> List[Dict[str, Any]]:
    """Check if the server supports HTTP/2."""
    results = []
    try:
        import ssl
        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                proto = ssock.selected_alpn_protocol()
                if proto == "h2":
                    results.append({
                        "id": "extras_http2_ok",
                        "category": "Best Practices",
                        "severity": "INFO",
                        "passed": True,
                        "title": "HTTP/2 podržan ✓",
                        "title_en": "HTTP/2 Supported ✓",
                        "description": "Server podržava HTTP/2 — brže učitavanje stranica, multipleksovanje zahteva.",
                        "description_en": "Server supports HTTP/2 — faster page loading, request multiplexing.",
                        "recommendation": "",
                        "recommendation_en": "",
                    })
                else:
                    results.append({
                        "id": "extras_http2_missing",
                        "category": "Best Practices",
                        "severity": "LOW",
                        "passed": False,
                        "title": "HTTP/2 nije podržan",
                        "title_en": "HTTP/2 Not Supported",
                        "description": "Server koristi HTTP/1.1. HTTP/2 je brži, efikasniji i standard na svim modernim sajtovima.",
                        "description_en": "Server uses HTTP/1.1. HTTP/2 is faster, more efficient and standard on all modern sites.",
                        "recommendation": "Aktivirajte HTTP/2 u Nginx: 'listen 443 ssl http2;'",
                        "recommendation_en": "Enable HTTP/2 in Nginx: 'listen 443 ssl http2;'",
                    })
    except Exception:
        pass

    return results


def run(base_url: str, domain: str, response_body: str, session: requests.Session) -> List[Dict[str, Any]]:
    results = []
    results.extend(_check_security_txt(base_url, session))
    results.extend(_check_caa(domain))
    results.extend(_check_sri(response_body))
    results.extend(_check_http2(domain))
    return results
