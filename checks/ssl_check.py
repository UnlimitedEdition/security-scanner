# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
SSL/TLS Security Checks
Checks: certificate validity, expiry, TLS version, cipher strength
"""
import ssl
import socket
import json
import urllib.request
import urllib.parse
from datetime import datetime
from typing import List, Dict, Any, Optional


def _check_hsts_preload(hostname: str) -> Optional[str]:
    """
    Roadmap #7. Query the hstspreload.org API v2 to check whether the
    domain is in the Chromium HSTS preload list. Returns one of:
      - "preloaded"  — domain is currently in the preload list
      - "pending"    — domain is submitted but not yet shipped in Chrome
      - "unknown"    — domain is not in the list
      - None         — API call failed (network error, timeout, unexpected
                       shape). On failure we return None and the caller
                       skips emitting any finding, rather than falsely
                       reporting "not preloaded".

    The API is public, unauthenticated, and effectively serves as a
    read-only lookup table. One extra lightweight HTTP request per scan.
    """
    try:
        url = f"https://hstspreload.org/api/v2/status?domain={urllib.parse.quote(hostname)}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "WebSecurityScanner/1.0 (https://web-security-scanner.com)",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        status = data.get("status")
        if status not in ("preloaded", "pending", "unknown"):
            return None
        return status
    except Exception:
        return None


def run(hostname: str) -> List[Dict[str, Any]]:
    results = []
    port = 443

    # --- 1. HTTPS reachable at all ---
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher = ssock.cipher()  # (name, protocol, bits)

        # --- 2. Certificate expiry ---
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.utcnow()).days
            if days_left < 0:
                results.append({
                    "id": "ssl_cert_expired",
                    "category": "SSL/TLS",
                    "severity": "CRITICAL",
                    "passed": False,
                    "title": "SSL sertifikat je istekao / SSL Certificate Expired",
                    "title_en": "SSL Certificate Expired",
                    "description": f"Sertifikat je istekao pre {abs(days_left)} dana. Posetioci vide upozorenje u browseru.",
                    "description_en": f"Certificate expired {abs(days_left)} days ago. Visitors see a browser warning.",
                    "recommendation": "Odmah obnovite SSL sertifikat. Koristite Let's Encrypt (besplatno).",
                    "recommendation_en": "Renew your SSL certificate immediately. Use Let's Encrypt (free).",
                })
            elif days_left < 14:
                results.append({
                    "id": "ssl_cert_expiring_soon",
                    "category": "SSL/TLS",
                    "severity": "CRITICAL",
                    "passed": False,
                    "title": f"SSL sertifikat ističe za {days_left} dana!",
                    "title_en": f"SSL Certificate expires in {days_left} days!",
                    "description": "Ako ne obnovite, sajt će biti nedostupan korisnicima.",
                    "description_en": "If not renewed, the site will become inaccessible.",
                    "recommendation": "Odmah obnovite sertifikat.",
                    "recommendation_en": "Renew the certificate immediately.",
                })
            elif days_left < 30:
                results.append({
                    "id": "ssl_cert_expiring_soon",
                    "category": "SSL/TLS",
                    "severity": "HIGH",
                    "passed": False,
                    "title": f"SSL sertifikat ističe za {days_left} dana",
                    "title_en": f"SSL Certificate expires in {days_left} days",
                    "description": "Planirajte obnovu sertifikata uskoro.",
                    "description_en": "Plan certificate renewal soon.",
                    "recommendation": "Obnovite sertifikat pre isteka.",
                    "recommendation_en": "Renew the certificate before expiry.",
                })
            else:
                results.append({
                    "id": "ssl_cert_valid",
                    "category": "SSL/TLS",
                    "severity": "INFO",
                    "passed": True,
                    "title": f"SSL sertifikat validan (ističe za {days_left} dana)",
                    "title_en": f"SSL Certificate valid ({days_left} days remaining)",
                    "description": "Sertifikat je validan i nema potrebe za akcijom.",
                    "description_en": "Certificate is valid.",
                    "recommendation": "",
                    "recommendation_en": "",
                })

        # --- 3. TLS version ---
        weak_tls = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
        if tls_version in weak_tls:
            results.append({
                "id": "ssl_weak_tls",
                "category": "SSL/TLS",
                "severity": "HIGH",
                "passed": False,
                "title": f"Zastarela TLS verzija: {tls_version}",
                "title_en": f"Outdated TLS version in use: {tls_version}",
                "description": f"{tls_version} je zvanično povučen i ranjiv na napade (POODLE, BEAST). Moderni browseri ga blokuju.",
                "description_en": f"{tls_version} is officially deprecated and vulnerable to attacks (POODLE, BEAST).",
                "recommendation": "Isključite TLS 1.0 i 1.1. Aktivirajte samo TLS 1.2 i TLS 1.3.",
                "recommendation_en": "Disable TLS 1.0 and 1.1. Enable only TLS 1.2 and TLS 1.3.",
            })
        else:
            results.append({
                "id": "ssl_tls_version_ok",
                "category": "SSL/TLS",
                "severity": "INFO",
                "passed": True,
                "title": f"TLS verzija: {tls_version} ✓",
                "title_en": f"TLS version: {tls_version} ✓",
                "description": "Koristi se moderna TLS verzija.",
                "description_en": "Modern TLS version in use.",
                "recommendation": "",
                "recommendation_en": "",
            })

        # --- 4. Cipher strength ---
        if cipher:
            cipher_name, _, bits = cipher
            weak_ciphers = ["RC4", "DES", "3DES", "EXPORT", "NULL", "MD5", "anon"]
            is_weak = any(w in cipher_name.upper() for w in weak_ciphers)
            if is_weak or (bits and bits < 128):
                results.append({
                    "id": "ssl_weak_cipher",
                    "category": "SSL/TLS",
                    "severity": "HIGH",
                    "passed": False,
                    "title": f"Slab cipher suite: {cipher_name}",
                    "title_en": f"Weak cipher suite: {cipher_name}",
                    "description": "Sajt podržava kriptografski slab cipher koji napadač može dekriptovati.",
                    "description_en": "The site supports a cryptographically weak cipher that can be broken.",
                    "recommendation": "Isključite RC4, DES, 3DES ciphers. Koristite AES-GCM, ChaCha20.",
                    "recommendation_en": "Disable RC4, DES, 3DES ciphers. Use AES-GCM, ChaCha20.",
                })

    except ssl.SSLCertVerificationError as e:
        results.append({
            "id": "ssl_cert_invalid",
            "category": "SSL/TLS",
            "severity": "CRITICAL",
            "passed": False,
            "title": "Neispravan SSL sertifikat / Invalid SSL Certificate",
            "title_en": "Invalid SSL Certificate",
            "description": f"Browser ne veruje sertifikatu: {str(e)[:120]}",
            "description_en": f"Browser does not trust the certificate: {str(e)[:120]}",
            "recommendation": "Instalirajte validan sertifikat od pouzdanog CA (Let's Encrypt, Sectigo, DigiCert).",
            "recommendation_en": "Install a valid certificate from a trusted CA (Let's Encrypt, Sectigo, DigiCert).",
        })
    except ConnectionRefusedError:
        results.append({
            "id": "ssl_no_https",
            "category": "SSL/TLS",
            "severity": "CRITICAL",
            "passed": False,
            "title": "HTTPS nije dostupan na portu 443!",
            "title_en": "HTTPS not available on port 443!",
            "description": "Sajt ne prihvata HTTPS konekcije. Svi podaci se prenose nešifrovano.",
            "description_en": "Site does not accept HTTPS connections. All data is transmitted unencrypted.",
            "recommendation": "Odmah instalirajte SSL sertifikat. Let's Encrypt je besplatan i automatizovan.",
            "recommendation_en": "Install an SSL certificate immediately. Let's Encrypt is free and automated.",
        })
    except Exception as e:
        results.append({
            "id": "ssl_check_error",
            "category": "SSL/TLS",
            "severity": "HIGH",
            "passed": False,
            "title": "SSL nije moguće proveriti",
            "title_en": "SSL could not be verified",
            "description": f"Greška pri proveri SSL: {str(e)[:120]}",
            "description_en": f"Error checking SSL: {str(e)[:120]}",
            "recommendation": "Proverite da li je HTTPS ispravno konfigurisan.",
            "recommendation_en": "Verify HTTPS is correctly configured.",
        })

    # ── HSTS preload list check (Roadmap #7) ─────────────────────────────
    # Runs regardless of whether the earlier TLS probe succeeded — the
    # lookup is purely a DNS-level check against the Chromium list, so
    # even TLS-misconfigured domains still give useful data.
    preload_status = _check_hsts_preload(hostname)
    if preload_status == "preloaded":
        results.append({
            "id": "ssl_hsts_preloaded",
            "category": "SSL/TLS",
            "severity": "INFO",
            "passed": True,
            "title": "Domen je u Chromium HSTS preload listi ✓",
            "title_en": "Domain is in the Chromium HSTS preload list ✓",
            "description": (
                "Domen je hardkodovan u Chromium preload listi, što znači da "
                "svaki moderan browser (Chrome, Edge, Firefox, Safari, Opera) "
                "odbija HTTP konekciju ka ovom domenu PRE bilo kakvog TLS "
                "handshake-a. Prva poseta korisnika koji nikad nije bio na "
                "sajtu je automatski zaštićena od SSL strip napada."
            ),
            "description_en": (
                "The domain is hardcoded into the Chromium preload list, "
                "which means every modern browser (Chrome, Edge, Firefox, "
                "Safari, Opera) refuses HTTP connections to this domain "
                "BEFORE any TLS handshake. A first-time visitor who has "
                "never been to the site is automatically protected from "
                "SSL stripping attacks."
            ),
            "recommendation": "",
            "recommendation_en": "",
        })
    elif preload_status == "pending":
        results.append({
            "id": "ssl_hsts_preload_pending",
            "category": "SSL/TLS",
            "severity": "INFO",
            "passed": True,
            "title": "Domen je submitted za HSTS preload listu (pending)",
            "title_en": "Domain is submitted to HSTS preload list (pending)",
            "description": (
                "Domen je prijavljen za uključivanje u Chromium preload listu "
                "ali još nije shipped u stable verziji browser-a. Tipicno traje "
                "6-12 nedelja od submit-a do aktivnog preload-a."
            ),
            "description_en": (
                "The domain is submitted for inclusion in the Chromium preload "
                "list but has not yet shipped in a stable browser release. "
                "Typical turnaround is 6-12 weeks from submission to active "
                "preload."
            ),
            "recommendation": "",
            "recommendation_en": "",
        })
    elif preload_status == "unknown":
        results.append({
            "id": "ssl_hsts_not_preloaded",
            "category": "SSL/TLS",
            "severity": "LOW",
            "passed": False,
            "title": "Domen nije u HSTS preload listi",
            "title_en": "Domain is not in the HSTS preload list",
            "description": (
                "Domen nije u Chromium HSTS preload listi. HSTS header alone "
                "štiti samo posetioce koji su već bili na sajtu (first-visit "
                "je ranjiv na SSL stripping). Preload lista eliminise taj "
                "'first visit' prozor jer browser zna unapred da je domen "
                "HTTPS-only, pre nego što bilo kakav zahtev ode."
            ),
            "description_en": (
                "The domain is not in the Chromium HSTS preload list. An HSTS "
                "header alone only protects visitors who have already been to "
                "the site (the first visit is still vulnerable to SSL "
                "stripping). The preload list eliminates that first-visit "
                "window because the browser knows in advance that the domain "
                "is HTTPS-only, before any request goes out."
            ),
            "recommendation": (
                "Prijavite domen na https://hstspreload.org/ nakon što postavite "
                "HSTS header sa: max-age=31536000 (1 godina ili više), "
                "includeSubDomains, preload — i uverite se da SVE subdomene "
                "rade preko HTTPS-a jer preload pokriva ceo prostor domena."
            ),
            "recommendation_en": (
                "Submit the domain at https://hstspreload.org/ after setting "
                "an HSTS header with: max-age=31536000 (1 year or more), "
                "includeSubDomains, preload — and verify that ALL subdomains "
                "work over HTTPS, because preload covers the entire domain "
                "space."
            ),
        })
    # preload_status is None → API failed, skip silently (no finding)

    return results
