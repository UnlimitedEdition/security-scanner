# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Email Security Check
Checks MX records, email authentication, and mail server security.
"""
import dns.resolver
import ssl
import socket
from typing import List, Dict, Any

TIMEOUT = 5


def run(domain: str) -> List[Dict[str, Any]]:
    results = []

    # Skip platform domains
    platform_suffixes = [
        ".vercel.app", ".netlify.app", ".github.io", ".hf.space",
        ".web.app", ".firebaseapp.com", ".herokuapp.com", ".pages.dev",
    ]
    for suffix in platform_suffixes:
        if domain.endswith(suffix):
            results.append(_pass("email_platform",
                "Email — platform domen",
                "Email — platform domain",
                "Platform domeni obicno ne koriste email.",
                "Platform domains typically don't use email."))
            return results

    # Check MX records
    mx_records = []
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=TIMEOUT)
        for rdata in answers:
            mx_records.append({
                "priority": rdata.preference,
                "server": str(rdata.exchange).rstrip("."),
            })
        mx_records.sort(key=lambda x: x["priority"])
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results.append(_fail("email_no_mx", "MEDIUM",
            "MX zapisi ne postoje — domen ne prima email",
            "MX records not found — domain does not receive email",
            "Domen nema MX zapise sto znaci da ne moze primati email. Ako koristite email na ovom domenu, ovo je problem.",
            "Domain has no MX records which means it cannot receive email. If you use email on this domain, this is an issue.",
            "Dodajte MX zapise kod vaseg DNS provajdera.",
            "Add MX records at your DNS provider."))
        return results
    except dns.exception.Timeout:
        return results
    except Exception:
        return results

    if mx_records:
        mx_list = ", ".join([f"{mx['server']} (pri:{mx['priority']})" for mx in mx_records[:5]])
        results.append(_pass("email_mx_ok",
            f"MX zapisi pronadjeni ({len(mx_records)} servera)",
            f"MX records found ({len(mx_records)} servers)",
            f"Mail serveri: {mx_list}",
            f"Mail servers: {mx_list}"))

        # Detect email provider
        primary_mx = mx_records[0]["server"].lower()
        provider = "Unknown"
        if "google" in primary_mx or "gmail" in primary_mx:
            provider = "Google Workspace"
        elif "outlook" in primary_mx or "microsoft" in primary_mx:
            provider = "Microsoft 365"
        elif "zoho" in primary_mx:
            provider = "Zoho Mail"
        elif "protonmail" in primary_mx or "proton" in primary_mx:
            provider = "ProtonMail"
        elif "yandex" in primary_mx:
            provider = "Yandex Mail"
        elif "mxlogin" in primary_mx or "mailgun" in primary_mx:
            provider = "Mailgun"
        elif "sendgrid" in primary_mx:
            provider = "SendGrid"

        if provider != "Unknown":
            results.append(_pass("email_provider",
                f"Email provajder: {provider}",
                f"Email provider: {provider}",
                f"Primarni MX server ({primary_mx}) pripada servisu {provider}.",
                f"Primary MX server ({primary_mx}) belongs to {provider}."))

        # Check if primary MX supports STARTTLS
        try:
            mx_host = mx_records[0]["server"]
            sock = socket.create_connection((mx_host, 25), timeout=TIMEOUT)
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.sendall(b"EHLO scanner.test\r\n")
            ehlo_resp = sock.recv(4096).decode("utf-8", errors="ignore")
            sock.close()

            if "STARTTLS" in ehlo_resp.upper():
                results.append(_pass("email_starttls",
                    "Mail server podrzava STARTTLS enkripciju",
                    "Mail server supports STARTTLS encryption",
                    f"{mx_host} podrzava STARTTLS — email se moze slati enkriptovano.",
                    f"{mx_host} supports STARTTLS — email can be sent encrypted."))
            else:
                results.append(_fail("email_no_starttls", "MEDIUM",
                    "Mail server ne podrzava STARTTLS",
                    "Mail server does not support STARTTLS",
                    f"{mx_host} ne podrzava STARTTLS. Email se salje necifrovano.",
                    f"{mx_host} does not support STARTTLS. Email is sent unencrypted.",
                    "Omogucite STARTTLS na mail serveru za enkriptovanu komunikaciju.",
                    "Enable STARTTLS on the mail server for encrypted communication."))
        except Exception:
            pass

    # Check BIMI record (Brand Indicators for Message Identification)
    bimi_found = False
    try:
        bimi_domain = f"default._bimi.{domain}"
        answers = dns.resolver.resolve(bimi_domain, "TXT", lifetime=TIMEOUT)
        for rdata in answers:
            txt = str(rdata).strip('"')
            if "v=BIMI1" in txt:
                bimi_found = True
                results.append(_pass("email_bimi",
                    "BIMI record pronadjen — brend logo u email klijentima",
                    "BIMI record found — brand logo in email clients",
                    "BIMI omogucava prikaz vaseg loga pored emailova u podrzanim klijentima (Gmail, Apple Mail).",
                    "BIMI enables display of your logo next to emails in supported clients (Gmail, Apple Mail)."))
                break
    except Exception:
        pass

    # Check MTA-STS DNS record + HTTPS policy file (Roadmap #4)
    mta_sts_dns_found = False
    try:
        mta_sts_domain = f"_mta-sts.{domain}"
        answers = dns.resolver.resolve(mta_sts_domain, "TXT", lifetime=TIMEOUT)
        for rdata in answers:
            txt = str(rdata).strip('"')
            if "v=STSv1" in txt:
                mta_sts_dns_found = True
                break
    except Exception:
        pass

    # MTA-STS requires BOTH a DNS record AND a policy file hosted at
    # https://mta-sts.<domain>/.well-known/mta-sts.txt. The DNS record
    # alone is not enough — mail servers fetch the actual policy to
    # decide which hosts to accept TLS from.
    mta_sts_policy_ok = False
    if mta_sts_dns_found:
        try:
            import urllib.request as _urlreq
            import urllib.parse as _urlparse
            url = f"https://mta-sts.{_urlparse.quote(domain)}/.well-known/mta-sts.txt"
            req = _urlreq.Request(
                url,
                headers={
                    "User-Agent": "WebSecurityScanner/1.0",
                    "Accept": "text/plain",
                },
            )
            with _urlreq.urlopen(req, timeout=6) as resp:
                if resp.status == 200:
                    body = resp.read(4096).decode("utf-8", errors="replace").lower()
                    if "version: stsv1" in body and "mode:" in body:
                        mta_sts_policy_ok = True
        except Exception:
            pass

    if mta_sts_policy_ok:
        results.append(_pass("email_mta_sts",
            "MTA-STS konfigurisan (DNS + policy fajl) — zastita od downgrade napada",
            "MTA-STS configured (DNS + policy file) — protection against downgrade attacks",
            "MTA-STS sprecava napadaca da presretne email komunikaciju uklanjanjem STARTTLS-a. DNS record i policy fajl su oba pravilno postavljeni.",
            "MTA-STS prevents attackers from intercepting email by stripping STARTTLS. Both the DNS record and the policy file are correctly configured."))
    elif mta_sts_dns_found and not mta_sts_policy_ok:
        results.append(_fail("email_mta_sts_policy_missing", "MEDIUM",
            "MTA-STS DNS postoji ali policy fajl nije dostupan",
            "MTA-STS DNS exists but policy file is unreachable",
            f"DNS record _mta-sts.{domain} postoji, ali policy fajl na https://mta-sts.{domain}/.well-known/mta-sts.txt se ne može preuzeti (ili ne sadrži validne 'version: STSv1' i 'mode:' polja). MTA-STS radi samo kad su oba prisutna.",
            f"DNS record _mta-sts.{domain} exists, but the policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt cannot be fetched (or lacks valid 'version: STSv1' and 'mode:' fields). MTA-STS only works when both are present.",
            "Postavite policy fajl na https://mta-sts.<domain>/.well-known/mta-sts.txt sa sadržajem: 'version: STSv1\\nmode: enforce\\nmx: mail.example.com\\nmax_age: 604800'",
            "Place a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt with content: 'version: STSv1\\nmode: enforce\\nmx: mail.example.com\\nmax_age: 604800'"))

    # TLS-RPT (SMTP TLS Reporting) — Roadmap #4
    # TXT record at _smtp._tls.<domain> that specifies where SMTP TLS
    # failure reports should be sent. Gives the domain owner visibility
    # into whether STARTTLS negotiations are actually succeeding.
    try:
        tlsrpt_domain = f"_smtp._tls.{domain}"
        tlsrpt_found = False
        answers = dns.resolver.resolve(tlsrpt_domain, "TXT", lifetime=TIMEOUT)
        for rdata in answers:
            txt = str(rdata).strip('"')
            if "v=TLSRPTv1" in txt:
                tlsrpt_found = True
                results.append(_pass("email_tls_rpt",
                    "TLS-RPT konfigurisan — izvestaji o neuspehu STARTTLS-a",
                    "TLS-RPT configured — STARTTLS failure reporting",
                    "TLS-RPT daje vlasniku domena uvid u to koje su TLS konekcije ka vasem mail serveru propale i zasto (downgrade napad, istekao sertifikat, loš cipher).",
                    "TLS-RPT gives the domain owner visibility into failed TLS connections to your mail server and why (downgrade attack, expired cert, bad cipher)."))
                break
    except Exception:
        pass

    # DANE TLSA check — Roadmap #4
    # TLSA record at _25._tcp.<primary_mx> proves the expected certificate
    # or public key via DNSSEC. Resistant to MITM even if CA is compromised.
    if mx_records:
        try:
            mx_host = mx_records[0]["server"]
            tlsa_domain = f"_25._tcp.{mx_host}"
            answers = dns.resolver.resolve(tlsa_domain, "TLSA", lifetime=TIMEOUT)
            tlsa_count = sum(1 for _ in answers)
            if tlsa_count > 0:
                results.append(_pass("email_dane",
                    f"DANE TLSA zapisi postoje ({tlsa_count} zapisa)",
                    f"DANE TLSA records present ({tlsa_count} records)",
                    f"DANE omogucava mail serveru posiljaoca da verifikuje sertifikat vaseg mail servera direktno kroz DNSSEC — zaobilazi se CA infrastruktura u potpunosti, sto je otporno na kompromitaciju CA-a.",
                    f"DANE allows the sending mail server to verify your mail server's certificate directly through DNSSEC — bypassing the CA infrastructure entirely, which is resistant to CA compromise."))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        except Exception:
            pass

    return results


def _pass(check_id, title_sr, title_en, desc_sr, desc_en):
    return {
        "id": check_id, "category": "Email Security", "severity": "INFO", "passed": True,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": "", "recommendation_en": "",
    }


def _fail(check_id, severity, title_sr, title_en, desc_sr, desc_en, rec_sr, rec_en):
    return {
        "id": check_id, "category": "Email Security", "severity": severity, "passed": False,
        "title": title_sr, "title_en": title_en,
        "description": desc_sr, "description_en": desc_en,
        "recommendation": rec_sr, "recommendation_en": rec_en,
    }
