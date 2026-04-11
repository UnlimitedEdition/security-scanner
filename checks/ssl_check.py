# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
SSL/TLS Security Checks
Checks: certificate validity, expiry, TLS version, cipher strength
"""
import ssl
import socket
from datetime import datetime
from typing import List, Dict, Any


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

    return results
