"""
DNS Security Checks
Checks: SPF, DMARC, DNSSEC
These protect against email spoofing and DNS attacks.
"""
import dns.resolver
from typing import List, Dict, Any


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


def run(domain: str) -> List[Dict[str, Any]]:
    results = []
    is_platform = _is_platform_domain(domain)

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
                    "severity": "HIGH",
                    "passed": False,
                    "title": "SPF record nedostaje \u2014 email spoofing mogu\u0107",
                    "title_en": "SPF Record Missing \u2014 Email Spoofing Possible",
                    "description": "Bez SPF recorda, napada\u010d mo\u017ee poslati email koji izgleda kao da dolazi sa va\u0161eg domena. Klijenti mogu dobiti la\u017ene fakture ili phishing emailove.",
                    "description_en": "Without an SPF record, anyone can send email that appears to come from your domain. Clients may receive fake invoices or phishing emails.",
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
                "severity": "HIGH",
                "passed": False,
                "title": "SPF record nedostaje",
                "title_en": "SPF Record Missing",
                "description": "Nije prona\u0111en SPF TXT record za ovaj domen.",
                "description_en": "No SPF TXT record found for this domain.",
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
                # Check policy
                if "p=none" in txt:
                    results.append({
                        "id": "dns_dmarc_weak",
                        "category": "DNS Security",
                        "severity": "MEDIUM",
                        "passed": False,
                        "title": "DMARC postoji ali samo nadgleda (p=none)",
                        "title_en": "DMARC exists but only monitors (p=none)",
                        "description": "DMARC je konfigurisan na p=none što samo loguje, ali ne blokira lažne emailove.",
                        "description_en": "DMARC is configured with p=none which only logs, but does not block spoofed emails.",
                        "recommendation": "Promenite na p=quarantine ili p=reject za aktivnu zaštitu.",
                        "recommendation_en": "Change to p=quarantine or p=reject for active protection.",
                    })
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
                    "severity": "HIGH",
                    "passed": False,
                    "title": "DMARC record nedostaje",
                    "title_en": "DMARC Record Missing",
                    "description": "Bez DMARC-a nema izve\u0161tavanja o poku\u0161ajima spoofing-a i emailovi sa va\u0161eg domena lak\u0161e prolaze spam filtere napada\u010da.",
                    "description_en": "Without DMARC there is no reporting on spoofing attempts and spoofed emails from your domain more easily pass spam filters.",
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
                "severity": "HIGH",
                "passed": False,
                "title": "DMARC record nedostaje",
                "title_en": "DMARC Record Missing",
                "description": "Nije prona\u0111en DMARC record za ovaj domen.",
                "description_en": "No DMARC record found for this domain.",
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
