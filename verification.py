"""
Ownership verification — Function 6.

Before a user can see the full findings of a scan (specific URLs of
exposed files, admin paths, payloads, etc.), they must prove they
control the domain being scanned. This module implements three proof
mechanisms, any one of which is sufficient:

  1. meta — add a <meta name="scanner-verify" content="TOKEN"> tag to
            the homepage HTML
  2. file — publish https://<domain>/.well-known/scanner-verify.txt
            with the token as the body
  3. dns  — create a TXT record at _scanner-verify.<domain> with the
            token as the value

All HTTP fetches go through security_utils.safe_get() so they respect
SSRF protection — the scanner will never probe localhost, link-local,
or private ranges even during verification. DNS lookups use dnspython
with a short timeout and a public resolver chain.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional, Tuple

import requests

from security_utils import safe_get, UnsafeTargetError


def _new_session() -> requests.Session:
    """
    Build a short-lived requests.Session configured the same way the
    main scanner uses. Verification checks are infrequent (only when a
    user explicitly initiates one), so per-call sessions are fine and
    avoid any risk of state leaking between checks.

    Explicitly pins `verify` to certifi.where() so local dev environments
    with CURL_CA_BUNDLE / REQUESTS_CA_BUNDLE pointing at stale bundles
    (looking at you, PostgreSQL 17 on Windows) don't break the SSL
    handshake. Production containers don't hit this, but silently
    failing on localhost is a bad debug experience.
    """
    s = requests.Session()
    try:
        import certifi
        s.verify = certifi.where()
    except ImportError:
        s.verify = True
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (compatible; WebSecurityScanner-Verifier/1.0; "
            "+https://security-scanner-ruddy.vercel.app)"
        ),
        "Accept": "text/html,application/xhtml+xml,text/plain,*/*;q=0.8",
    })
    return s

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────
META_NAME = "scanner-verify"
WELL_KNOWN_PATH = "/.well-known/scanner-verify.txt"
DNS_PREFIX = "_scanner-verify"
FETCH_TIMEOUT = 10  # seconds
MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB — prevent huge-body DoS on homepage


# ─────────────────────────────────────────────────────────────────────────
# Results
# ─────────────────────────────────────────────────────────────────────────
@dataclass
class VerificationResult:
    ok: bool
    method: str
    reason: str             # human-readable, safe to show user
    details: Optional[str] = None  # for operator logs, may include raw response


# ─────────────────────────────────────────────────────────────────────────
# Domain sanitization
# ─────────────────────────────────────────────────────────────────────────
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$")


def normalize_domain(raw: str) -> Optional[str]:
    """
    Strip scheme, trailing slash, port, and www prefix. Lowercase.
    Returns None if the result isn't a valid-looking domain — the caller
    should 400 the request in that case rather than proceed to a
    verification that will just fail anyway.
    """
    if not raw:
        return None
    d = raw.strip().lower()
    # Strip scheme
    if "://" in d:
        d = d.split("://", 1)[1]
    # Strip path
    d = d.split("/", 1)[0]
    # Strip port
    if ":" in d:
        d = d.split(":", 1)[0]
    # Strip www. prefix
    if d.startswith("www."):
        d = d[4:]
    if not _DOMAIN_RE.match(d):
        return None
    return d


# ─────────────────────────────────────────────────────────────────────────
# Method 1: meta tag on homepage
# ─────────────────────────────────────────────────────────────────────────
def verify_via_meta(domain: str, expected_token: str) -> VerificationResult:
    """
    Fetch https://<domain>/ and look for <meta name="scanner-verify"
    content="TOKEN"> anywhere in the HTML. We do a regex scan rather
    than full HTML parsing because:
      1. BeautifulSoup is heavy for a single lookup
      2. The token is a fixed-width hex string, so regex false positives
         are cryptographically negligible
      3. The regex handles single-quoted, double-quoted, and attribute-
         order variations that HTML parsers sometimes normalize away
    """
    url = f"https://{domain}/"
    try:
        response = safe_get(_new_session(), url, timeout=FETCH_TIMEOUT)
    except UnsafeTargetError as e:
        return VerificationResult(
            ok=False, method="meta",
            reason=f"domain resolves to a blocked IP range: {e}",
        )
    except Exception as e:
        return VerificationResult(
            ok=False, method="meta",
            reason=f"homepage fetch failed: {str(e)[:150]}",
        )

    if response.status_code != 200:
        return VerificationResult(
            ok=False, method="meta",
            reason=f"homepage returned HTTP {response.status_code}",
        )

    # Bound the body we scan — 2 MiB is way more than any legitimate homepage
    body = response.text[:MAX_RESPONSE_BYTES] if hasattr(response, "text") else ""
    if not body:
        return VerificationResult(
            ok=False, method="meta", reason="homepage body was empty",
        )

    # Match both quote styles, both attribute orders, case-insensitive name
    escaped_token = re.escape(expected_token)
    patterns = [
        rf'<meta\s+name=["\']scanner-verify["\']\s+content=["\']{escaped_token}["\']',
        rf'<meta\s+content=["\']{escaped_token}["\']\s+name=["\']scanner-verify["\']',
    ]
    for pattern in patterns:
        if re.search(pattern, body, re.IGNORECASE):
            return VerificationResult(ok=True, method="meta", reason="meta tag found on homepage")

    return VerificationResult(
        ok=False, method="meta",
        reason="meta tag with the expected token was not found on the homepage",
        details=f"scanned {len(body)} bytes from {url}",
    )


# ─────────────────────────────────────────────────────────────────────────
# Method 2: file at /.well-known/scanner-verify.txt
# ─────────────────────────────────────────────────────────────────────────
def verify_via_file(domain: str, expected_token: str) -> VerificationResult:
    """
    GET https://<domain>/.well-known/scanner-verify.txt and require the
    response body to equal the expected token (after stripping whitespace).
    Uses .well-known to follow RFC 8615 convention so the endpoint
    doesn't collide with normal site paths.
    """
    url = f"https://{domain}{WELL_KNOWN_PATH}"
    try:
        response = safe_get(_new_session(), url, timeout=FETCH_TIMEOUT)
    except UnsafeTargetError as e:
        return VerificationResult(
            ok=False, method="file",
            reason=f"domain resolves to a blocked IP range: {e}",
        )
    except Exception as e:
        return VerificationResult(
            ok=False, method="file",
            reason=f"file fetch failed: {str(e)[:150]}",
        )

    if response.status_code == 404:
        return VerificationResult(
            ok=False, method="file",
            reason=f"file not found at {WELL_KNOWN_PATH}",
        )
    if response.status_code != 200:
        return VerificationResult(
            ok=False, method="file",
            reason=f"file returned HTTP {response.status_code}",
        )

    body = (response.text if hasattr(response, "text") else "").strip()
    # Accept either exact match or first non-empty line matching
    # (handles editors that add trailing newlines)
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    first_line = lines[0] if lines else ""

    if first_line == expected_token:
        return VerificationResult(ok=True, method="file", reason="challenge file contents matched")

    return VerificationResult(
        ok=False, method="file",
        reason="challenge file exists but contents did not match the expected token",
        details=f"first line was {len(first_line)} chars, expected {len(expected_token)}",
    )


# ─────────────────────────────────────────────────────────────────────────
# Method 3: DNS TXT record at _scanner-verify.<domain>
# ─────────────────────────────────────────────────────────────────────────
def verify_via_dns(domain: str, expected_token: str) -> VerificationResult:
    """
    Query DNS for TXT records at _scanner-verify.<domain> and require
    at least one record to equal the expected token. Uses dnspython
    (already a scanner dependency) with a short timeout so slow or
    broken authoritative servers don't hang the request.

    TXT records in DNS can have multiple strings — dnspython joins them
    automatically in .to_text(), but we also check the raw string list
    to be safe.
    """
    try:
        import dns.resolver  # type: ignore
        import dns.exception  # type: ignore
    except ImportError:
        return VerificationResult(
            ok=False, method="dns",
            reason="dnspython is not installed on the server",
        )

    query_name = f"{DNS_PREFIX}.{domain}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        # Explicit public resolvers so local DNS cache can't be poisoned
        # with a fake TXT record pointing at an attacker
        resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        answer = resolver.resolve(query_name, "TXT")
    except dns.resolver.NXDOMAIN:
        return VerificationResult(
            ok=False, method="dns",
            reason=f"no TXT record at {query_name} (NXDOMAIN)",
        )
    except dns.resolver.NoAnswer:
        return VerificationResult(
            ok=False, method="dns",
            reason=f"{query_name} exists but has no TXT records",
        )
    except dns.exception.Timeout:
        return VerificationResult(
            ok=False, method="dns",
            reason=f"DNS query for {query_name} timed out (retry in a minute)",
        )
    except Exception as e:
        return VerificationResult(
            ok=False, method="dns",
            reason=f"DNS query failed: {str(e)[:150]}",
        )

    for rdata in answer:
        # Each TXT rdata is a list of byte strings; join + decode
        try:
            raw_strings = getattr(rdata, "strings", [])
            joined = b"".join(raw_strings).decode("utf-8", errors="replace")
        except Exception:
            joined = str(rdata).strip('"')
        if joined.strip() == expected_token:
            return VerificationResult(ok=True, method="dns", reason="DNS TXT record matched")

    return VerificationResult(
        ok=False, method="dns",
        reason=f"TXT records found at {query_name} but none matched the expected token",
        details=f"found {len(answer)} TXT record(s)",
    )


# ─────────────────────────────────────────────────────────────────────────
# Dispatch
# ─────────────────────────────────────────────────────────────────────────
def run_verification(method: str, domain: str, token: str) -> VerificationResult:
    """
    Dispatch to the right verify_via_* function based on method.
    Safe for any method string; unknown methods return a clean error
    result rather than raising.
    """
    if method == "meta":
        return verify_via_meta(domain, token)
    if method == "file":
        return verify_via_file(domain, token)
    if method == "dns":
        return verify_via_dns(domain, token)
    return VerificationResult(
        ok=False, method=method,
        reason=f"unsupported verification method: {method!r}",
    )


# ─────────────────────────────────────────────────────────────────────────
# Instruction builder — human-friendly text sent back to the frontend
# ─────────────────────────────────────────────────────────────────────────
def build_instructions(domain: str, token: str, method: str) -> dict:
    """
    Returns a dict the frontend can render as a step-by-step challenge.
    Includes `check_url` or `dns_name` so automated clients can verify
    their own configuration before calling /verify/check.
    """
    if method == "meta":
        return {
            "title": "Add a meta tag to your homepage",
            "language_hint": "sr",
            "steps": [
                "Otvorite HTML vase pocetne strane (index.html ili sablon).",
                "Dodajte sledeci red unutar <head> sekcije (bilo gde unutar nje).",
                "Sacuvajte i objavite promenu (ako koristite CMS, cachevi mozda treba da se ocite).",
                "Kada je tag vidljiv, pozovite POST /verify/check sa dobijenim tokenom.",
            ],
            "snippet": f'<meta name="scanner-verify" content="{token}">',
            "check_url": f"https://{domain}/",
            "expected_value": token,
        }
    if method == "file":
        return {
            "title": "Upload a challenge file",
            "language_hint": "sr",
            "steps": [
                f"Kreirajte fajl u web root-u vaseg sajta sa tacnom putanjom: {WELL_KNOWN_PATH}",
                "Sadrzaj fajla mora biti tacno sledeci token (bez navodnika, bez razmaka).",
                "Fajl mora biti javno dostupan preko HTTPS-a (status 200).",
                "Kada je fajl objavljen, pozovite POST /verify/check sa dobijenim tokenom.",
            ],
            "file_path": WELL_KNOWN_PATH,
            "file_content": token,
            "check_url": f"https://{domain}{WELL_KNOWN_PATH}",
            "expected_value": token,
        }
    if method == "dns":
        return {
            "title": "Create a DNS TXT record",
            "language_hint": "sr",
            "steps": [
                f"U panelu vaseg DNS provider-a kreirajte novi TXT zapis.",
                f"Host / Name: {DNS_PREFIX}",
                f"Value / Content: {token}",
                "TTL: 300 (ili najnizi dozvoljen).",
                "Sacuvajte i sacekajte 1-5 minuta za propagaciju (ponekad duze).",
                "Pozovite POST /verify/check kada je zapis aktivan. Ako prvo ne uspe, sacekajte jos minut i probajte opet.",
            ],
            "dns_name": f"{DNS_PREFIX}.{domain}",
            "dns_type": "TXT",
            "dns_value": token,
            "expected_value": token,
        }
    return {
        "title": "Unknown method",
        "steps": [f"Unsupported method: {method}. Expected one of: meta, file, dns."],
    }
