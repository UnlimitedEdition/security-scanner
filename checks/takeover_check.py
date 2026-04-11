# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Subdomain Takeover Detection Check

Detects dangling DNS records (CNAMEs) that point to deprovisioned third-party
services an attacker could claim. This is one of the most commonly exploited
issues in real bug-bounty reports and real intrusions, yet automated scanners
in the Serbian market almost never check for it.

Detection philosophy — passive, two-gate:
  1. Resolve CNAME for the root domain and a list of common subdomains.
     If a CNAME points to a known third-party host pattern (GitHub Pages,
     Heroku, S3, Azure, Shopify, Fastly, etc.), the subdomain becomes a
     takeover candidate. CNAME alone is never enough — plenty of perfectly
     healthy sites legitimately CNAME to these services.
  2. For each candidate, issue ONE HTTP GET and look for the service's own
     "this resource is not claimed" error fingerprint in the response body.
     Only if the fingerprint matches do we report a finding. This eliminates
     false positives on legitimately-claimed resources.

We never attempt exploitation. We never claim the resource. We only observe
what is already publicly visible to any attacker running the same probe.

Fingerprints are adapted from the community-maintained can-i-take-over-xyz
project and from public HackerOne / BugCrowd disclosure reports.
"""
import sys
import os
import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_utils import safe_get, UnsafeTargetError

TIMEOUT = 5
MAX_WORKERS = 8

# Subdomains to probe for CNAME records. We deliberately cast a slightly wider
# net than subdomain_check.py because takeover candidates often live on
# forgotten "help", "support", "docs", "status" subdomains that got spun up
# on a SaaS trial and abandoned years ago.
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "shop", "cdn", "webmail", "remote", "vpn", "portal",
    "db", "database", "phpmyadmin", "cpanel", "git", "jenkins",
    "jira", "grafana", "prometheus", "kibana", "elastic",
    "support", "help", "docs", "status", "files", "media",
    "static", "assets", "app", "m", "mobile", "old", "legacy",
    "beta", "demo", "sandbox", "preview", "landing", "promo",
    "news", "events", "careers", "jobs", "store", "pay",
]

# Each entry defines one takeover-candidate service:
#   service        — human-readable name for the finding
#   cname_patterns — substrings matched against the resolved CNAME target
#   fingerprints   — HTTP body strings that indicate the resource is unclaimed
#   severity       — impact if the takeover is confirmed
#
# We err on the side of CRITICAL when the service allows full HTML hosting
# under the victim's subdomain (phishing, cookie theft, OAuth callback
# redirection), and HIGH for services where takeover is harder or more
# limited in impact.
TAKEOVER_SIGNATURES = [
    {
        "service": "GitHub Pages",
        "cname_patterns": [".github.io"],
        "fingerprints": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "severity": "CRITICAL",
    },
    {
        "service": "Heroku",
        "cname_patterns": [".herokuapp.com", ".herokudns.com"],
        "fingerprints": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
        "severity": "CRITICAL",
    },
    {
        "service": "AWS S3",
        "cname_patterns": [
            ".s3.amazonaws.com",
            ".s3-website",
            ".s3.dualstack.",
            ".s3-accelerate.amazonaws.com",
        ],
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "severity": "CRITICAL",
    },
    {
        "service": "AWS CloudFront",
        "cname_patterns": [".cloudfront.net"],
        "fingerprints": [
            "Bad request",
            "ERROR: The request could not be satisfied",
        ],
        "severity": "HIGH",
    },
    {
        "service": "Microsoft Azure",
        "cname_patterns": [
            ".azurewebsites.net",
            ".cloudapp.net",
            ".cloudapp.azure.com",
            ".trafficmanager.net",
            ".blob.core.windows.net",
            ".azureedge.net",
            ".azure-api.net",
        ],
        "fingerprints": [
            "404 Web Site not found",
            "Error 404 - Web app not found",
            "The resource you are looking for has been removed",
        ],
        "severity": "CRITICAL",
    },
    {
        "service": "Shopify",
        "cname_patterns": [".myshopify.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable.",
            "Only one step left!",
        ],
        "severity": "CRITICAL",
    },
    {
        "service": "Fastly",
        "cname_patterns": [".fastly.net", ".fastlylb.net"],
        "fingerprints": ["Fastly error: unknown domain"],
        "severity": "CRITICAL",
    },
    {
        "service": "Tumblr",
        "cname_patterns": ["domains.tumblr.com"],
        "fingerprints": [
            "Whatever you were looking for doesn't currently exist at this address.",
            "There's nothing here.",
        ],
        "severity": "CRITICAL",
    },
    {
        "service": "Surge.sh",
        "cname_patterns": [".surge.sh"],
        "fingerprints": ["project not found"],
        "severity": "CRITICAL",
    },
    {
        "service": "Bitbucket",
        "cname_patterns": [".bitbucket.io"],
        "fingerprints": ["Repository not found"],
        "severity": "CRITICAL",
    },
    {
        "service": "Ghost",
        "cname_patterns": [".ghost.io"],
        "fingerprints": [
            "The thing you were looking for is no longer here, or never was",
        ],
        "severity": "CRITICAL",
    },
    {
        "service": "Zendesk",
        "cname_patterns": [".zendesk.com"],
        "fingerprints": ["Help Center Closed"],
        "severity": "HIGH",
    },
    {
        "service": "Unbounce",
        "cname_patterns": [".unbouncepages.com"],
        "fingerprints": ["The requested URL was not found on this server."],
        "severity": "HIGH",
    },
    {
        "service": "Pantheon",
        "cname_patterns": [".pantheonsite.io"],
        "fingerprints": [
            "The gods are wise, but do not know of the site which you seek.",
        ],
        "severity": "CRITICAL",
    },
    {
        "service": "Readme.io",
        "cname_patterns": [".readme.io"],
        "fingerprints": ["Project doesnt exist... yet!"],
        "severity": "CRITICAL",
    },
    {
        "service": "Netlify",
        "cname_patterns": [".netlify.app", ".netlify.com"],
        "fingerprints": [
            "Not Found - Request ID",
            "<title>Page Not Found",
        ],
        "severity": "HIGH",
    },
    {
        "service": "Webflow",
        "cname_patterns": [".webflow.io"],
        "fingerprints": [
            "The page you are looking for doesn't exist or has been moved.",
        ],
        "severity": "CRITICAL",
    },
    {
        "service": "Kinsta",
        "cname_patterns": [".kinsta.cloud"],
        "fingerprints": ["No Site For Domain"],
        "severity": "CRITICAL",
    },
    {
        "service": "Strikingly",
        "cname_patterns": [".s.strikinglydns.com"],
        "fingerprints": [
            "PAGE NOT FOUND.",
            "But if you're looking to build your own website",
        ],
        "severity": "CRITICAL",
    },
    {
        "service": "Helpjuice",
        "cname_patterns": [".helpjuice.com"],
        "fingerprints": ["We could not find what you're looking for."],
        "severity": "HIGH",
    },
    {
        "service": "Tilda",
        "cname_patterns": [".tilda.ws"],
        "fingerprints": ["Please renew your subscription"],
        "severity": "HIGH",
    },
    {
        "service": "Intercom",
        "cname_patterns": [".custom.intercom.help"],
        "fingerprints": ["This page is reserved for artistic dogs."],
        "severity": "HIGH",
    },
]


def _resolve_cname(full_domain: str) -> Optional[str]:
    """
    Resolve the CNAME record for a domain. Returns the CNAME target
    (lowercased, trailing dot stripped) or None if no CNAME exists or
    resolution fails.

    We only care about the direct CNAME — chasing the whole chain can
    produce false matches when a legitimate SaaS CNAME chains through
    one of our vulnerable patterns before landing on a healthy CDN.
    """
    try:
        answers = dns.resolver.resolve(full_domain, "CNAME", lifetime=3)
        for rdata in answers:
            return str(rdata.target).rstrip(".").lower()
    except Exception:
        return None
    return None


def _match_signature(cname: str) -> Optional[Dict[str, Any]]:
    """Return the first signature whose CNAME pattern matches the given CNAME."""
    cname_lower = cname.lower()
    for sig in TAKEOVER_SIGNATURES:
        for pattern in sig["cname_patterns"]:
            if pattern in cname_lower:
                return sig
    return None


def _check_takeover(
    session: requests.Session,
    full_domain: str,
    signature: Dict[str, Any],
) -> Optional[Tuple[str, str]]:
    """
    Fetch the candidate domain and look for an "unclaimed resource" fingerprint
    in the response body. Returns (matched_fingerprint, service_name) on hit,
    or None when the resource appears claimed / healthy.

    Tries HTTPS first, then falls back to HTTP — many dangling SaaS resources
    no longer serve valid TLS, so an HTTPS-only probe would miss them.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{full_domain}"
        try:
            # max_redirects=0 — we want the immediate response from the SaaS,
            # not whatever the SaaS redirects to. A redirect away is itself a
            # sign that the service is handling the request (i.e. claimed).
            resp = safe_get(session, url, timeout=TIMEOUT, max_redirects=0)
        except UnsafeTargetError:
            # CNAME landed on a private/internal IP — skip, not a takeover
            return None
        except requests.exceptions.RequestException:
            continue
        except Exception:
            continue

        body = resp.text[:5000] if resp.text else ""
        for fp in signature["fingerprints"]:
            if fp in body:
                return (fp[:80], signature["service"])
    return None


def _scan_one(
    session: requests.Session,
    full_domain: str,
) -> Optional[Dict[str, Any]]:
    """Scan a single (sub)domain. Returns a raw finding dict or None."""
    cname = _resolve_cname(full_domain)
    if not cname:
        return None

    signature = _match_signature(cname)
    if not signature:
        return None

    result = _check_takeover(session, full_domain, signature)
    if not result:
        return None

    matched_fp, service_name = result
    return {
        "full_domain": full_domain,
        "cname": cname,
        "service": service_name,
        "fingerprint": matched_fp,
        "severity": signature["severity"],
    }


def run(domain: str) -> List[Dict[str, Any]]:
    """
    Entry point called from scanner.py. `domain` is the bare apex domain
    (no scheme, no path). Returns a list of finding dicts in the same
    shape every other check module produces.
    """
    results: List[Dict[str, Any]] = []

    session = requests.Session()
    session.verify = True
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (compatible; WebSecurityScanner/1.0; "
            "+takeover-check passive)"
        ),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })

    # Build the probe list: apex + every known subdomain prefix.
    # Duplicates and blanks are already impossible here because the
    # subdomain list is a static constant.
    targets = [domain] + [f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS]

    findings: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_scan_one, session, t): t for t in targets}
        for future in as_completed(futures):
            try:
                res = future.result()
                if res:
                    findings.append(res)
            except Exception:
                # A single DNS/HTTP failure must never stop the whole check
                pass

    if findings:
        for f in findings:
            service_slug = (
                f["service"].lower().replace(" ", "_").replace(".", "_")
            )
            results.append({
                "id": f"takeover_{service_slug}",
                "category": "Subdomain Takeover",
                "severity": f["severity"],
                "passed": False,
                "title": (
                    f"Mogucnost subdomain takeover napada: "
                    f"{f['full_domain']} -> {f['service']}"
                ),
                "title_en": (
                    f"Subdomain takeover possible: "
                    f"{f['full_domain']} -> {f['service']}"
                ),
                "description": (
                    f"Subdomen {f['full_domain']} ima CNAME zapis koji pokazuje "
                    f"na {f['cname']} ({f['service']}), ali taj servis vraca "
                    f"gresku koja pokazuje da resurs nije klejmovan. Napadac "
                    f"moze da registruje resurs pod istim imenom i servira "
                    f"svoj sadrzaj pod vasim subdomenom — ovo otvara vrata za "
                    f"phishing, kradju kolacica, prevare korisnika, i ozbiljnu "
                    f"reputacionu stetu. Otkriveni fingerprint u telu odgovora: "
                    f"'{f['fingerprint']}'."
                ),
                "description_en": (
                    f"Subdomain {f['full_domain']} has a CNAME record pointing "
                    f"to {f['cname']} ({f['service']}), but that service "
                    f"returns an error indicating the resource is not claimed. "
                    f"An attacker can register the resource under the same "
                    f"name and serve arbitrary content under your subdomain — "
                    f"enabling phishing, cookie theft, user deception, and "
                    f"serious reputational damage. Response body fingerprint "
                    f"detected: '{f['fingerprint']}'."
                ),
                "recommendation": (
                    f"Odmah uklonite CNAME zapis za {f['full_domain']} iz DNS "
                    f"zone, ili ga prebacite na aktivan {f['service']} resurs "
                    f"koji vi kontrolisete. Zatim proverite sve ostale "
                    f"subdomene u vasoj zoni za slicne dangling CNAME zapise "
                    f"— ako je jedan ostao, verovatno ih ima jos."
                ),
                "recommendation_en": (
                    f"Immediately remove the CNAME record for "
                    f"{f['full_domain']} from your DNS zone, or repoint it to "
                    f"an active {f['service']} resource you control. Then "
                    f"audit all other subdomains in your zone for similar "
                    f"dangling CNAME records — if one slipped through, "
                    f"others probably did too."
                ),
                "fingerprint_match": f["fingerprint"],
            })
    else:
        results.append({
            "id": "takeover_ok",
            "category": "Subdomain Takeover",
            "severity": "INFO",
            "passed": True,
            "title": (
                "Nije detektovana mogucnost subdomain takeover napada"
            ),
            "title_en": "No subdomain takeover opportunity detected",
            "description": (
                f"Provereno je {len(targets)} (sub)domena na CNAME zapise "
                f"koji bi mogli da pokazuju na nezatrazene resurse kod "
                f"{len(TAKEOVER_SIGNATURES)} poznatih ranjivih servisa "
                f"(GitHub Pages, Heroku, S3, Azure, Shopify, Fastly, "
                f"Netlify, Webflow, i drugi). Nijedan dangling zapis nije "
                f"pronadjen u ovom skeniranju."
            ),
            "description_en": (
                f"Checked {len(targets)} (sub)domains for CNAME records "
                f"that might point to unclaimed resources on "
                f"{len(TAKEOVER_SIGNATURES)} known vulnerable services "
                f"(GitHub Pages, Heroku, S3, Azure, Shopify, Fastly, "
                f"Netlify, Webflow, and others). No dangling records "
                f"found in this scan."
            ),
            "recommendation": "",
            "recommendation_en": "",
        })

    return results
