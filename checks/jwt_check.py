# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
JWT Exposure & Weakness Check

Passively scans the already-received response body, headers, and session
cookies for JWT tokens, then analyzes each one for critical weaknesses:

  - 'alg: none'  (CRITICAL — instant forgery, server accepts any token)
  - HS256/384/512 with a weak secret
    (CRITICAL — offline dictionary attack cracks the secret)
  - Missing 'exp' claim  (LOW — token lasts forever once stolen)
  - 'exp' further than 1 year in the future  (LOW — effectively no expiry)

The check is 100% passive: zero new HTTP requests, zero bytes sent to
the target. The dictionary attack runs purely in-process against a
curated wordlist of ~55 known-weak JWT secrets. Roughly 55 HMAC
operations per token, well under a millisecond.

mode parameter (gate-before-scan model from migrations 014/015):
  * 'full' (default) — Findings include the token contents (masked first
                       24 chars), the exact algorithm, and the cracked
                       secret string. The owner needs all of this to fix
                       the issue.
  * 'safe'           — The detection still runs (it is in-process and
                       cannot leak anything to the target by definition),
                       but findings strip the masked token, the exact
                       alg, the cracked secret, and the source. The
                       summary becomes "JWT vulnerability detected
                       (verify ownership to view details)" — the
                       attacker learns nothing actionable.
"""
import re
import json
import time
import hmac
import base64
import hashlib
from typing import List, Dict, Any, Optional, Tuple


# JWT pattern: three base64url segments separated by dots. The third
# segment may be empty (that is the valid shape of an 'alg:none' token).
# Minimum 10 characters per meaningful segment reduces false positives
# from random base64-looking strings in SPA bundles.
_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"
)

# Curated list of commonly-seen weak JWT HMAC secrets. Sources: the
# 'jwt-secrets' community wordlist plus SecLists, filtered to entries
# that are specifically JWT-adjacent (generic "password" lists would
# inflate the list with items that almost never appear as JWT secrets).
# The offline dictionary attack runs these against the HS* signature
# in-process — every iteration is a single HMAC operation on bytes we
# already have, so the entire pass completes in well under a millisecond.
_WEAK_JWT_SECRETS: List[str] = [
    "", "secret", "Secret", "SECRET",
    "password", "Password", "123456", "12345678",
    "key", "Key", "KEY",
    "jwt", "jwt-secret", "jwt_secret", "jwtsecret",
    "jwtkey", "jwt-key", "jwt_key",
    "secret-key", "secret_key", "secretkey",
    "your-256-bit-secret", "your_256_bit_secret",
    "mysecret", "my-secret", "my_secret",
    "test", "testing", "test-secret",
    "admin", "administrator",
    "dev", "development", "production", "prod",
    "default", "defaultsecret", "default-secret",
    "supersecret", "super-secret", "super_secret",
    "changeme", "change-me", "changeme123",
    "example", "example-secret",
    "demo", "demo-secret",
    "token", "tokensecret",
    "auth", "authsecret",
    "signingkey", "signing-key",
    "hmac", "hmac-secret",
    "hs256", "HS256", "hs384", "HS384",
]


# ── Low-level helpers ──────────────────────────────────────────────────────


def _base64url_decode(s: str) -> bytes:
    """Decode a base64url string, tolerating missing padding."""
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(padded)


def _decode_jwt_parts(
    token: str,
) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], str]]:
    """
    Split a JWT into (header_dict, payload_dict, signature_b64). Returns
    None on any decoding failure (malformed token, non-UTF8 bytes, bad
    JSON, or parts that don't parse as dicts).
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header_bytes = _base64url_decode(parts[0])
        payload_bytes = _base64url_decode(parts[1])
        header = json.loads(header_bytes.decode("utf-8", errors="replace"))
        payload = json.loads(payload_bytes.decode("utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, parts[2]


def _crack_hs_secret(token: str, alg: str) -> Optional[str]:
    """
    Offline HMAC dictionary attack on an HS256/HS384/HS512 token. Returns
    the weak secret string on a match, None otherwise. Runs purely
    in-process against bytes we already have — no network activity.
    """
    hash_fn = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }.get(alg.upper())
    if not hash_fn:
        return None

    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_payload = f"{parts[0]}.{parts[1]}"

    try:
        expected_sig = _base64url_decode(parts[2])
    except Exception:
        return None

    signing_input = header_payload.encode("ascii", errors="replace")
    for secret in _WEAK_JWT_SECRETS:
        computed = hmac.new(
            secret.encode("utf-8"), signing_input, hash_fn
        ).digest()
        if hmac.compare_digest(computed, expected_sig):
            return secret
    return None


# ── Token collection ───────────────────────────────────────────────────────


def _collect_jwts(
    body: str,
    headers: Dict[str, Any],
    session: Any,
) -> List[Tuple[str, str]]:
    """
    Return [(token, source_description), ...] of unique JWTs found in the
    response body, response headers, and session cookies. Duplicates
    across sources are collapsed to a single entry to keep findings clean.
    """
    found: List[Tuple[str, str]] = []
    seen = set()

    def _add(token: str, source: str) -> None:
        if token and token not in seen:
            seen.add(token)
            found.append((token, source))

    if body:
        for match in _JWT_RE.finditer(body[:50000]):
            _add(match.group(0), "response body")

    for hname, hvalue in headers.items():
        if not isinstance(hvalue, str):
            continue
        for match in _JWT_RE.finditer(hvalue):
            _add(match.group(0), f"{hname} header")

    if session is not None:
        try:
            for cookie in session.cookies:
                val = getattr(cookie, "value", None)
                if val and isinstance(val, str):
                    for match in _JWT_RE.finditer(val):
                        _add(match.group(0), f"cookie '{cookie.name}'")
        except Exception:
            pass

    return found


def _mask(token: str) -> str:
    """Return the first 24 chars of a token plus an ellipsis marker."""
    return token[:24] + "…" if len(token) > 24 else token


# ── Finding constructors ───────────────────────────────────────────────────


# Sentinel labels used in safe-mode findings. The token, source, alg, and
# cracked secret are exactly the values an attacker needs — strip them all
# to a single placeholder so the safe-mode summary tells the owner WHAT
# was detected without telling an unverified caller WHERE.
_REDACTED_LABEL_SR = "[verifikujte vlasnistvo da vidite tacne podatke]"
_REDACTED_LABEL_EN = "[verify ownership to see exact data]"


def _finding_alg_none(source: str, token: str, mode: str = "full") -> Dict[str, Any]:
    safe_mode = (mode == "safe")
    src_show = _REDACTED_LABEL_SR if safe_mode else source
    src_show_en = _REDACTED_LABEL_EN if safe_mode else source
    tok_show = _REDACTED_LABEL_SR if safe_mode else _mask(token)
    tok_show_en = _REDACTED_LABEL_EN if safe_mode else _mask(token)
    return {
        "id": "jwt_alg_none",
        "category": "JWT Security",
        "severity": "CRITICAL",
        "passed": False,
        "title": "JWT koristi 'alg: none' — autentikacija je trivijalno zaobidljiva",
        "title_en": "JWT uses 'alg: none' — authentication is trivially bypassable",
        "description": (
            f"Detektovan JWT u {src_show} koji koristi 'alg: none'. Token nema "
            "kriptografski potpis — napadač može u trenutku iskonstruisati "
            "proizvoljan token (promeniti korisničko ime, privilegije, role) "
            f"i server će ga prihvatiti kao validan. Token: {tok_show}"
        ),
        "description_en": (
            f"JWT detected in {src_show_en} using 'alg: none'. The token has no "
            "cryptographic signature — an attacker can instantly forge any "
            "token (change username, privileges, roles) and the server will "
            f"accept it as valid. Token: {tok_show_en}"
        ),
        "recommendation": (
            "HITNO onemogućite 'none' algoritam u JWT biblioteci. Koristite "
            "RS256 (asimetrični) ili HS256 sa jakim randomizovanim 256-bit "
            "secretom. Uvek eksplicitno navedite dozvoljene algoritme "
            "(whitelist) u biblioteci umesto da se oslanjate na 'alg' iz "
            "token header-a — header kontroliše napadač."
        ),
        "recommendation_en": (
            "URGENTLY disable the 'none' algorithm in your JWT library. Use "
            "RS256 (asymmetric) or HS256 with a strong randomized 256-bit "
            "secret. Always explicitly specify allowed algorithms "
            "(whitelist) in your library instead of trusting the 'alg' from "
            "the token header — the header is attacker-controlled."
        ),
        "_redacted": safe_mode,
    }


def _finding_weak_secret(
    source: str, token: str, secret: str, alg: str, mode: str = "full"
) -> Dict[str, Any]:
    safe_mode = (mode == "safe")
    shown = secret if secret else "(empty string)"
    secret_show = _REDACTED_LABEL_SR if safe_mode else f"'{shown}'"
    secret_show_en = _REDACTED_LABEL_EN if safe_mode else f"'{shown}'"
    src_show = _REDACTED_LABEL_SR if safe_mode else source
    src_show_en = _REDACTED_LABEL_EN if safe_mode else source
    tok_show = _REDACTED_LABEL_SR if safe_mode else _mask(token)
    tok_show_en = _REDACTED_LABEL_EN if safe_mode else _mask(token)
    alg_show = "[REDACTED]" if safe_mode else alg
    return {
        "id": "jwt_weak_secret",
        "category": "JWT Security",
        "severity": "CRITICAL",
        "passed": False,
        "title": f"JWT {alg_show} secret je pronadjen u listi slabih secrets ({secret_show})",
        "title_en": f"JWT {alg_show} secret found in weak-secrets list ({secret_show_en})",
        "description": (
            f"Detektovan JWT u {src_show} koji koristi {alg_show} sa slabim secretom. "
            f"Secret {secret_show} pronadjen je u curated listi od ~55 javno "
            "poznatih slabih JWT secrets i verifikacija je obavljena potpuno "
            "offline (nula mreznog saobracaja ka vasem serveru — samo HMAC "
            "racunanje nad vec primljenim token bajtovima). Sa ovim secretom "
            "napadac moze da falsifikuje bilo koji JWT koji ce vas server "
            f"prihvatiti. Token: {tok_show}"
        ),
        "description_en": (
            f"JWT detected in {src_show_en} using {alg_show} with a weak secret. The "
            f"secret {secret_show_en} was found in a curated list of ~55 publicly "
            "known weak JWT secrets, and the verification ran entirely "
            "offline (zero network traffic to your server — only HMAC "
            "computation over the already-received token bytes). With this "
            "secret, an attacker can forge any JWT your server will accept. "
            f"Token: {tok_show_en}"
        ),
        "recommendation": (
            "HITNO rotirajte JWT secret i invalidirajte postojece tokene. "
            "Generisite randomizovan 256-bit secret: 'openssl rand -hex 32' "
            "ili 'python -c \"import secrets; print(secrets.token_hex(32))\"'. "
            "Nikad ne koristite reci iz recnika, imena servisa, ili genericke "
            "stringove kao JWT secret — takve vrednosti su prve u javnim "
            "napadackim listama."
        ),
        "recommendation_en": (
            "URGENTLY rotate the JWT secret and invalidate existing tokens. "
            "Generate a random 256-bit secret: 'openssl rand -hex 32' or "
            "'python -c \"import secrets; print(secrets.token_hex(32))\"'. "
            "Never use dictionary words, service names, or generic strings "
            "as a JWT secret — those are the first entries in every public "
            "attacker wordlist."
        ),
        "_redacted": safe_mode,
    }


def _finding_missing_exp(source: str, token: str, mode: str = "full") -> Dict[str, Any]:
    safe_mode = (mode == "safe")
    src_show = _REDACTED_LABEL_SR if safe_mode else source
    src_show_en = _REDACTED_LABEL_EN if safe_mode else source
    tok_show = _REDACTED_LABEL_SR if safe_mode else _mask(token)
    tok_show_en = _REDACTED_LABEL_EN if safe_mode else _mask(token)
    return {
        "id": "jwt_missing_exp",
        "category": "JWT Security",
        "severity": "LOW",
        "passed": False,
        "title": "JWT nema 'exp' claim — token traje zauvek",
        "title_en": "JWT has no 'exp' claim — token lasts forever",
        "description": (
            f"Detektovan JWT u {src_show} koji ne sadrži 'exp' claim. Token bez "
            "isteka je aktivan zauvek — ako napadač jednom dobije token (npr. "
            "kroz XSS, leaked log, ili kompromitovanu tastaturu), može ga "
            "koristiti do kraja vremena osim ako ga eksplicitno ne revokujete "
            f"na backend strani. Token: {tok_show}"
        ),
        "description_en": (
            f"JWT detected in {src_show_en} with no 'exp' claim. A token without "
            "expiration is valid forever — if an attacker ever obtains the "
            "token (through XSS, leaked log, or a compromised device), they "
            "can use it indefinitely unless you explicitly revoke it "
            f"server-side. Token: {tok_show_en}"
        ),
        "recommendation": (
            "Dodajte 'exp' claim u sve JWT tokene. Za access token: 15–60 "
            "minuta. Za refresh token: 7–30 dana uz obaveznu mogucnost "
            "revokacije na serveru. Kratak lifetime znaci da ukraden token "
            "ima uzak prozor iskoristivosti."
        ),
        "recommendation_en": (
            "Add an 'exp' claim to every JWT token. Access tokens: 15–60 "
            "minutes. Refresh tokens: 7–30 days with mandatory server-side "
            "revocation support. A short lifetime means that a stolen token "
            "has a narrow usable window."
        ),
        "_redacted": safe_mode,
    }


def _finding_long_exp(
    source: str, token: str, seconds_ahead: int, mode: str = "full"
) -> Dict[str, Any]:
    safe_mode = (mode == "safe")
    days = seconds_ahead // 86400
    days_show = _REDACTED_LABEL_SR if safe_mode else f"{days} dana"
    days_show_en = _REDACTED_LABEL_EN if safe_mode else f"{days} days"
    src_show = _REDACTED_LABEL_SR if safe_mode else source
    src_show_en = _REDACTED_LABEL_EN if safe_mode else source
    tok_show = _REDACTED_LABEL_SR if safe_mode else _mask(token)
    tok_show_en = _REDACTED_LABEL_EN if safe_mode else _mask(token)
    return {
        "id": "jwt_exp_too_long",
        "category": "JWT Security",
        "severity": "LOW",
        "passed": False,
        "title": f"JWT 'exp' je predug ({days_show} u buducnosti)",
        "title_en": f"JWT 'exp' is too far in the future ({days_show_en} ahead)",
        "description": (
            f"Detektovan JWT u {src_show} ciji 'exp' claim istice za {days_show}. "
            "Predugi tokeni su prakticno isto sto i tokeni bez "
            "isteka — ukraden token ostaje validan mesecima ili godinama, "
            f"sto znatno povecava posledice bilo kakvog leak-a. Token: "
            f"{tok_show}"
        ),
        "description_en": (
            f"JWT detected in {src_show_en} with an 'exp' claim {days_show_en} in "
            "the future. Very long-lived tokens are effectively equivalent "
            "to tokens with no expiration — a stolen token stays valid for "
            "months or years, significantly amplifying the impact of any "
            f"leak. Token: {tok_show_en}"
        ),
        "recommendation": (
            "Smanjite JWT lifetime na minimum potreban za funkciju: 15–60 "
            "minuta za access token, 7–30 dana za refresh token (uz obaveznu "
            "revokaciju na serveru)."
        ),
        "recommendation_en": (
            "Reduce JWT lifetime to the minimum required: 15–60 minutes for "
            "access tokens, 7–30 days for refresh tokens (with mandatory "
            "server-side revocation)."
        ),
        "_redacted": safe_mode,
    }


# ── Main entry ─────────────────────────────────────────────────────────────


def run(
    response_body: str,
    response_headers: Dict[str, Any],
    session: Any = None,
    mode: str = "full",
) -> List[Dict[str, Any]]:
    """
    Scan the already-received response for exposed JWTs and analyze each
    one. Input: body, headers, session — all produced by the main scan,
    no new HTTP requests are made. The in-process dictionary attack on
    HS* secrets runs against the ~55-entry curated wordlist.

    mode='safe' produces sumary findings that strip the masked token,
    source location, alg name, and cracked secret. mode='full' returns
    the legacy detailed findings.

    Returns a list of findings. Empty list means either no JWT was found
    or every JWT passed all four checks. Findings are de-duplicated per
    issue type: five tokens with the same weakness produce one aggregated
    entry, not five.
    """
    jwts = _collect_jwts(response_body or "", response_headers or {}, session)
    if not jwts:
        return []

    findings: List[Dict[str, Any]] = []
    seen_issues: set = set()
    now = time.time()
    one_year = 365 * 86400

    def _once(key: str, finding: Dict[str, Any]) -> None:
        if key in seen_issues:
            return
        seen_issues.add(key)
        findings.append(finding)

    for token, source in jwts:
        parts = _decode_jwt_parts(token)
        if parts is None:
            continue
        header, payload, _sig = parts

        alg_raw = header.get("alg", "")
        alg = alg_raw.upper() if isinstance(alg_raw, str) else ""

        # Check 1 — alg:none (or empty alg) is instant forgery
        if alg == "NONE" or alg == "":
            _once("alg_none", _finding_alg_none(source, token, mode=mode))
            continue

        # Check 2 — weak HS* secret cracked offline
        if alg in ("HS256", "HS384", "HS512"):
            cracked = _crack_hs_secret(token, alg)
            if cracked is not None:
                _once(
                    f"weak_secret_{alg}",
                    _finding_weak_secret(source, token, cracked, alg, mode=mode),
                )
                continue

        # Check 3 — missing exp claim
        exp = payload.get("exp")
        if exp is None:
            _once("missing_exp", _finding_missing_exp(source, token, mode=mode))
            continue

        # Check 4 — exp too far in the future
        if isinstance(exp, (int, float)) and exp > now + one_year:
            ahead = int(exp - now)
            _once("long_exp", _finding_long_exp(source, token, ahead, mode=mode))

    return findings
