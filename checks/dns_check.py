# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
DNS Security Checks
Checks: SPF, DMARC, DNSSEC
These protect against email spoofing and DNS attacks.
"""
import dns.resolver
from typing import List, Dict, Any, Optional


# ── Roadmap #3: DMARC deep parser ──────────────────────────────────────────
#
# A DMARC TXT record is a semicolon-separated list of tag=value pairs:
#   v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com; sp=reject
#
# The existing code only checked "p=none" as a substring, which missed
# several other common weakness modes: pct<100 (partial enforcement),
# missing rua (no aggregate reports — the site owner cannot monitor
# whether the policy is actually working), and sp=none (subdomains
# unprotected even when the main domain is). The parser below extracts
# every tag the site owner might care about, and the analyzer emits a
# list of weaknesses — aggregated into a single finding so the report
# stays readable.


def _parse_dmarc(txt: str) -> Dict[str, str]:
    """Parse a DMARC TXT record into a {tag: value} dict, lowercased keys."""
    tags: Dict[str, str] = {}
    for chunk in txt.split(";"):
        chunk = chunk.strip()
        if "=" not in chunk:
            continue
        key, _, value = chunk.partition("=")
        tags[key.strip().lower()] = value.strip()
    return tags


def _analyze_dmarc(tags: Dict[str, str]) -> List[Dict[str, str]]:
    """
    Return a list of weakness entries for a parsed DMARC record. Empty
    list means the policy passes all deep checks.
    """
    issues: List[Dict[str, str]] = []

    p = tags.get("p", "").lower()
    if p == "none":
        issues.append({
            "severity": "MEDIUM",
            "desc_sr": "Policy 'p=none' — DMARC samo monitoring, ne blokira spoofovane email-ove. Receiver serveri vide DMARC rezultat ali ga ne koriste za odluku šta raditi sa porukom.",
            "desc_en": "Policy 'p=none' — DMARC only monitors, does not block spoofed emails. Receiving servers see the DMARC result but do not use it to decide what to do with the message.",
        })
    elif p == "":
        issues.append({
            "severity": "HIGH",
            "desc_sr": "DMARC record postoji ali 'p=' tag nedostaje — policy je nedefinisana.",
            "desc_en": "DMARC record exists but the 'p=' tag is missing — the policy is undefined.",
        })

    pct_raw = tags.get("pct", "100")
    try:
        pct_int = int(pct_raw)
        if pct_int < 100 and p not in ("none", ""):
            issues.append({
                "severity": "LOW",
                "desc_sr": f"Samo {pct_int}% email-ova je pod DMARC enforcement-om (pct={pct_int}). Ostatak prolazi bez provere.",
                "desc_en": f"Only {pct_int}% of emails are under DMARC enforcement (pct={pct_int}). The rest pass through unchecked.",
            })
    except ValueError:
        pass

    if "rua" not in tags or not tags.get("rua"):
        issues.append({
            "severity": "LOW",
            "desc_sr": "Nema 'rua' taga (aggregate reports URI) — ne možete pratiti efikasnost DMARC politike niti videti ko šalje poruke u vaše ime.",
            "desc_en": "No 'rua' tag (aggregate reports URI) — you cannot monitor DMARC effectiveness or see who is sending messages in your name.",
        })

    sp = tags.get("sp", "").lower()
    if sp == "none":
        issues.append({
            "severity": "LOW",
            "desc_sr": "Subdomain policy 'sp=none' — subdomeni nisu zaštićeni. Napadač može spoofovati 'mail.yourdomain.com' iako 'yourdomain.com' ima reject policy.",
            "desc_en": "Subdomain policy 'sp=none' — subdomains are not protected. An attacker can spoof 'mail.yourdomain.com' even though 'yourdomain.com' has a reject policy.",
        })

    return issues


def _build_dmarc_weak_finding(
    txt: str, tags: Dict[str, str], issues: List[Dict[str, str]]
) -> Dict[str, Any]:
    """Aggregate DMARC weaknesses into a single finding."""
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    top_sev = max(issues, key=lambda i: rank.get(i["severity"], 0))["severity"]

    issues_sr = "\n".join(f"• {i['desc_sr']}" for i in issues)
    issues_en = "\n".join(f"• {i['desc_en']}" for i in issues)
    truncated = txt if len(txt) <= 200 else txt[:200] + "…"

    return {
        "id": "dns_dmarc_weak",
        "category": "DNS Security",
        "severity": top_sev,
        "passed": False,
        "title": f"DMARC je definisan ali slab ({len(issues)} problema)",
        "title_en": f"DMARC is defined but weak ({len(issues)} issues)",
        "description": (
            "DMARC record postoji ali sledeće slabosti ga čine manje efikasnim:\n\n"
            f"{issues_sr}\n\nTrenutna vrednost: {truncated}"
        ),
        "description_en": (
            "DMARC record exists but the following weaknesses reduce its effectiveness:\n\n"
            f"{issues_en}\n\nCurrent value: {truncated}"
        ),
        "recommendation": (
            "Strog DMARC za produkcioni domen treba: (1) p=quarantine ili p=reject (ne 'none'), "
            "(2) pct=100 (pun enforcement), (3) rua=mailto:dmarc@yourdomain.com za aggregate "
            "izveštaje, (4) sp=quarantine ili sp=reject za subdomene. "
            "Primer: 'v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com; sp=reject'"
        ),
        "recommendation_en": (
            "A strict production DMARC should: (1) p=quarantine or p=reject (not 'none'), "
            "(2) pct=100 (full enforcement), (3) rua=mailto:dmarc@yourdomain.com for aggregate "
            "reports, (4) sp=quarantine or sp=reject for subdomains. "
            "Example: 'v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com; sp=reject'"
        ),
    }


PLATFORM_DOMAINS = [
    ".vercel.app", ".netlify.app", ".github.io", ".gitlab.io",
    ".herokuapp.com", ".hf.space", ".web.app", ".firebaseapp.com",
    ".azurewebsites.net", ".cloudfront.net", ".pages.dev",
    ".onrender.com", ".fly.dev", ".railway.app",
]


def _is_platform_domain(domain: str) -> bool:
    for suffix in PLATFORM_DOMAINS:
        if domain.endswith(suffix):
            return True
    return False


def _has_mx_records(domain: str) -> bool:
    """True if the domain advertises MX records (i.e. receives email).
    Failure-modes (NXDOMAIN, NoAnswer, timeout, etc.) all mean 'no MX'."""
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return any(True for _ in answers)
    except Exception:
        return False


def run(domain: str) -> List[Dict[str, Any]]:
    results = []
    is_platform = _is_platform_domain(domain)
    has_mx = _has_mx_records(domain)
    # When there is no MX, SPF/DMARC missing is a much weaker signal —
    # spoofing protections matter only if the domain actually sends mail.
    no_mail_severity = "LOW"
    no_mail_note_sr = " (domen nema MX zapise pa email spoofing nije aktivan rizik — preporučeno je dodati ipak za zaštitu od podvaljivanja imena)."
    no_mail_note_en = " (domain has no MX records so email spoofing isn't an active risk — still recommended to add as protection against name impersonation)."

    # --- SPF Check ---
    try:
        spf_found = False
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=spf1"):
                spf_found = True
                # Check for dangerous all mechanism
                if "+all" in txt:
                    results.append({
                        "id": "dns_spf_permissive",
                        "category": "DNS Security",
                        "severity": "CRITICAL",
                        "passed": False,
                        "title": "SPF record dozvoljava sve (+all) — opasno!",
                        "title_en": "SPF record allows all (+all) — dangerous!",
                        "description": "SPF record ima '+all' što znači da BILO KO može slati email sa vašeg domena.",
                        "description_en": "SPF record has '+all' meaning ANYONE can send email from your domain.",
                        "recommendation": "Promenite '+all' u '-all' da blokirate neovlašćene pošiljaoce.",
                        "recommendation_en": "Change '+all' to '-all' to block unauthorized senders.",
                    })
                elif "~all" in txt:
                    # Softfail — better than +all but weaker than -all
                    results.append({
                        "id": "dns_spf_softfail",
                        "category": "DNS Security",
                        "severity": "LOW",
                        "passed": False,
                        "title": "SPF koristi ~all (softfail) umesto -all (hardfail)",
                        "title_en": "SPF uses ~all (softfail) instead of -all (hardfail)",
                        "description": f"SPF postoji ali završava sa '~all' (softfail) — email serveri primaju sumnjive emailove ali ih označavaju. Sa '-all' bi ih potpuno odbijali. Vrednost: {txt[:80]}",
                        "description_en": f"SPF exists but ends with '~all' (softfail) — mail servers accept suspicious emails but mark them. With '-all' they would be fully rejected. Value: {txt[:80]}",
                        "recommendation": "Promenite '~all' u '-all' za strožu zaštitu od email spoofing-a.",
                        "recommendation_en": "Change '~all' to '-all' for stricter email spoofing protection.",
                    })
                    # Also check for overly permissive +a +mx
                    if "+a" in txt or "+mx" in txt:
                        results.append({
                            "id": "dns_spf_permissive_mechanisms",
                            "category": "DNS Security",
                            "severity": "LOW",
                            "passed": False,
                            "title": "SPF: +a i +mx mehanizmi su previše permisivni",
                            "title_en": "SPF: +a and +mx mechanisms are overly permissive",
                            "description": f"'+a' i '+mx' dozvoljavaju svim serverima koji su u A/MX recordima da šalju email. Koristite samo eksplicitne IP adrese ili include: mehanizme. Vrednost: {txt[:80]}",
                            "description_en": f"'+a' and '+mx' allow all servers in A/MX records to send email. Use only explicit IP addresses or include: mechanisms. Value: {txt[:80]}",
                            "recommendation": "Promenite '+a +mx +ip4:...' u samo 'ip4:... include:mailprovider.com -all'.",
                            "recommendation_en": "Change '+a +mx +ip4:...' to just 'ip4:... include:mailprovider.com -all'.",
                        })
                elif "-all" in txt:
                    results.append({
                        "id": "dns_spf_ok",
                        "category": "DNS Security",
                        "severity": "INFO",
                        "passed": True,
                        "title": "SPF record prisutan i strogo konfigurisan ✓",
                        "title_en": "SPF Record Present and Strictly Configured ✓",
                        "description": f"SPF: {txt[:100]}",
                        "description_en": f"SPF: {txt[:100]}",
                        "recommendation": "",
                        "recommendation_en": "",
                    })
                else:
                    results.append({
                        "id": "dns_spf_ok",
                        "category": "DNS Security",
                        "severity": "INFO",
                        "passed": True,
                        "title": "SPF record prisutan ✓",
                        "title_en": "SPF Record Present ✓",
                        "description": f"SPF: {txt[:100]}",
                        "description_en": f"SPF: {txt[:100]}",
                        "recommendation": "",
                        "recommendation_en": "",
                    })
                break

        if not spf_found:
            if is_platform:
                results.append({
                    "id": "dns_spf_platform",
                    "category": "DNS Security",
                    "severity": "INFO",
                    "passed": True,
                    "title": "SPF \u2014 platform domen (DNS kontroli\u0161e hosting provajder)",
                    "title_en": "SPF \u2014 platform domain (DNS controlled by hosting provider)",
                    "description": f"{domain} je platform domen \u2014 SPF/DMARC konfigurise hosting provajder, ne korisnik.",
                    "description_en": f"{domain} is a platform domain \u2014 SPF/DMARC is configured by the hosting provider, not the user.",
                    "recommendation": "Za punu kontrolu koristite sopstveni domen.",
                    "recommendation_en": "For full control, use your own custom domain.",
                })
            else:
                results.append({
                    "id": "dns_spf_missing",
                    "category": "DNS Security",
                    "severity": "HIGH" if has_mx else no_mail_severity,
                    "passed": False,
                    "title": "SPF record nedostaje \u2014 email spoofing mogu\u0107",
                    "title_en": "SPF Record Missing \u2014 Email Spoofing Possible",
                    "description": "Bez SPF recorda, napada\u010d mo\u017ee poslati email koji izgleda kao da dolazi sa va\u0161eg domena. Klijenti mogu dobiti la\u017ene fakture ili phishing emailove." + ("" if has_mx else no_mail_note_sr),
                    "description_en": "Without an SPF record, anyone can send email that appears to come from your domain. Clients may receive fake invoices or phishing emails." + ("" if has_mx else no_mail_note_en),
                    "recommendation": 'Dodajte TXT record: v=spf1 include:_spf.yourmailprovider.com ~all',
                    "recommendation_en": 'Add TXT record: v=spf1 include:_spf.yourmailprovider.com ~all',
                })
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        if is_platform:
            results.append({
                "id": "dns_spf_platform",
                "category": "DNS Security",
                "severity": "INFO",
                "passed": True,
                "title": "SPF \u2014 platform domen (DNS kontroli\u0161e hosting provajder)",
                "title_en": "SPF \u2014 platform domain (DNS controlled by hosting provider)",
                "description": f"{domain} je platform domen \u2014 SPF/DMARC konfigurise hosting provajder.",
                "description_en": f"{domain} is a platform domain \u2014 SPF/DMARC is configured by the hosting provider.",
                "recommendation": "",
                "recommendation_en": "",
            })
        else:
            results.append({
                "id": "dns_spf_missing",
                "category": "DNS Security",
                "severity": "HIGH" if has_mx else no_mail_severity,
                "passed": False,
                "title": "SPF record nedostaje",
                "title_en": "SPF Record Missing",
                "description": "Nije prona\u0111en SPF TXT record za ovaj domen." + ("" if has_mx else no_mail_note_sr),
                "description_en": "No SPF TXT record found for this domain." + ("" if has_mx else no_mail_note_en),
                "recommendation": "Dodajte SPF record da za\u0161titite domen od email spoofing-a.",
                "recommendation_en": "Add an SPF record to protect your domain from email spoofing.",
            })

    # --- DMARC Check ---
    try:
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_found = False
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=DMARC1"):
                dmarc_found = True
                # Roadmap #3: deep parse instead of the old p=none substring.
                tags = _parse_dmarc(txt)
                issues = _analyze_dmarc(tags)
                if issues:
                    results.append(_build_dmarc_weak_finding(txt, tags, issues))
                else:
                    results.append({
                        "id": "dns_dmarc_ok",
                        "category": "DNS Security",
                        "severity": "INFO",
                        "passed": True,
                        "title": "DMARC zaštita aktivna ✓",
                        "title_en": "DMARC Protection Active ✓",
                        "description": f"DMARC: {txt[:100]}",
                        "description_en": f"DMARC: {txt[:100]}",
                        "recommendation": "",
                        "recommendation_en": "",
                    })
                break

        if not dmarc_found:
            if is_platform:
                results.append({
                    "id": "dns_dmarc_platform",
                    "category": "DNS Security",
                    "severity": "INFO",
                    "passed": True,
                    "title": "DMARC \u2014 platform domen (DNS kontroli\u0161e hosting provajder)",
                    "title_en": "DMARC \u2014 platform domain (DNS controlled by hosting provider)",
                    "description": f"{domain} je platform domen \u2014 DMARC konfigurise hosting provajder.",
                    "description_en": f"{domain} is a platform domain \u2014 DMARC is configured by the hosting provider.",
                    "recommendation": "Za punu kontrolu koristite sopstveni domen.",
                    "recommendation_en": "For full control, use your own custom domain.",
                })
            else:
                results.append({
                    "id": "dns_dmarc_missing",
                    "category": "DNS Security",
                    "severity": "HIGH" if has_mx else no_mail_severity,
                    "passed": False,
                    "title": "DMARC record nedostaje",
                    "title_en": "DMARC Record Missing",
                    "description": "Bez DMARC-a nema izve\u0161tavanja o poku\u0161ajima spoofing-a i emailovi sa va\u0161eg domena lak\u0161e prolaze spam filtere napada\u010da." + ("" if has_mx else no_mail_note_sr),
                    "description_en": "Without DMARC there is no reporting on spoofing attempts and spoofed emails from your domain more easily pass spam filters." + ("" if has_mx else no_mail_note_en),
                    "recommendation": 'Dodajte TXT record na _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
                    "recommendation_en": 'Add TXT record at _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com',
                })
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        if is_platform:
            results.append({
                "id": "dns_dmarc_platform",
                "category": "DNS Security",
                "severity": "INFO",
                "passed": True,
                "title": "DMARC \u2014 platform domen (DNS kontroli\u0161e hosting provajder)",
                "title_en": "DMARC \u2014 platform domain (DNS controlled by hosting provider)",
                "description": f"{domain} je platform domen.",
                "description_en": f"{domain} is a platform domain.",
                "recommendation": "",
                "recommendation_en": "",
            })
        else:
            results.append({
                "id": "dns_dmarc_missing",
                "category": "DNS Security",
                "severity": "HIGH" if has_mx else no_mail_severity,
                "passed": False,
                "title": "DMARC record nedostaje",
                "title_en": "DMARC Record Missing",
                "description": "Nije prona\u0111en DMARC record za ovaj domen." + ("" if has_mx else no_mail_note_sr),
                "description_en": "No DMARC record found for this domain." + ("" if has_mx else no_mail_note_en),
                "recommendation": "Dodajte DMARC record na _dmarc.yourdomain.com.",
                "recommendation_en": "Add a DMARC record at _dmarc.yourdomain.com.",
            })

    # --- DNSSEC Check ---
    try:
        dnskey_answers = dns.resolver.resolve(domain, "DNSKEY", lifetime=5)
        has_dnskey = len(dnskey_answers) > 0
        if has_dnskey:
            results.append({
                "id": "dns_dnssec_ok",
                "category": "DNS Security",
                "severity": "INFO",
                "passed": True,
                "title": "DNSSEC je aktivan \u2713",
                "title_en": "DNSSEC is active \u2713",
                "description": f"Domen {domain} ima DNSKEY zapise \u2014 DNS odgovori su kriptografski potpisani.",
                "description_en": f"Domain {domain} has DNSKEY records \u2014 DNS responses are cryptographically signed.",
                "recommendation": "",
                "recommendation_en": "",
            })
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.name.EmptyLabel):
        if is_platform:
            results.append({
                "id": "dns_dnssec_platform",
                "category": "DNS Security",
                "severity": "INFO",
                "passed": True,
                "title": "DNSSEC \u2014 platform domen (kontroli\u0161e hosting provajder)",
                "title_en": "DNSSEC \u2014 platform domain (controlled by hosting provider)",
                "description": f"{domain} je platform domen \u2014 DNSSEC konfigurise provajder.",
                "description_en": f"{domain} is a platform domain \u2014 DNSSEC is configured by the provider.",
                "recommendation": "",
                "recommendation_en": "",
            })
            return results
        results.append({
            "id": "dns_dnssec_missing",
            "category": "DNS Security",
            "severity": "MEDIUM",
            "passed": False,
            "title": "DNSSEC nije konfigurisan",
            "title_en": "DNSSEC is not configured",
            "description": "Domen nema DNSKEY zapise \u2014 DNS odgovori nisu kriptografski potpisani. Napada\u010d mo\u017ee izvr\u0161iti DNS spoofing/cache poisoning.",
            "description_en": "Domain has no DNSKEY records \u2014 DNS responses are not cryptographically signed. Attacker can perform DNS spoofing/cache poisoning.",
            "recommendation": "Aktivirajte DNSSEC kod va\u0161eg registrara ili DNS provajdera (Cloudflare, Route53 imaju automatski DNSSEC).",
            "recommendation_en": "Enable DNSSEC at your domain registrar or DNS provider (Cloudflare, Route53 have automatic DNSSEC).",
        })
    except dns.exception.Timeout:
        pass
    except Exception:
        pass

    return results
