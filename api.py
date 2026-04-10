# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Security Scanner API
FastAPI backend — run with: uvicorn api:app --host 0.0.0.0 --port 8000
"""
import os

# ============================================================
# FIX: PostgreSQL sets OPENSSL_CONF which breaks requests SSL
# Must be cleared BEFORE any import of requests/ssl/httpx
#
# CURL_CA_BUNDLE is added because PostgreSQL 17 on Windows points it
# at a non-existent path that pip / requests / urllib3 will try to
# use before falling back to certifi. See:
# https://github.com/psf/requests/blob/main/src/requests/sessions.py
# (DEFAULT_CA_BUNDLE_PATH resolution order).
# ============================================================
os.environ.pop("OPENSSL_CONF", None)
os.environ.pop("SSL_CERT_FILE", None)
os.environ.pop("REQUESTS_CA_BUNDLE", None)
os.environ.pop("CURL_CA_BUNDLE", None)
try:
    import certifi
    os.environ["REQUESTS_CA_BUNDLE"] = certifi.where()
    os.environ["SSL_CERT_FILE"] = certifi.where()
except ImportError:
    pass

import uuid
import time
import threading
from collections import defaultdict
from datetime import datetime
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl, field_validator
import re

import scanner
import db
import verification
import subscription
import secrets as _secrets
from security_utils import is_safe_target

# Public defaults — can be overridden via env vars if we ever need to tune
# rate limits per environment without code changes.
_RATE_LIMIT = int(os.environ.get("RATE_LIMIT_MAX", "5"))
_RATE_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "1800"))

app = FastAPI(
    title="Web Security Scanner API",
    description="Passive security analysis for websites — no exploitation, read-only.",
    version="1.0.0",
)

app.add_middleware(GZipMiddleware, minimum_size=500)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # CSP: use WILDCARD host patterns for the Google advertising stack
        # rather than listing individual subdomains. AdSense uses many
        # subdomains (pagead2, tpc, ep1, ep2, googleads, securepubads,
        # stats, pubads, etc.) and maintaining an explicit list is a
        # losing game — every few months Google adds a new one and we
        # get CSP violations in user devtools.
        #
        # The wildcards cover:
        #   *.googlesyndication.com    — pagead2, tpc, securepubads, etc.
        #   *.g.doubleclick.net        — googleads, stats, pubads, securepubads
        #   *.adtrafficquality.google  — ep1, ep2 (ad quality sandbox)
        #
        # Non-ad Google endpoints (fonts, analytics, tag services) stay
        # explicit so we can see exactly which capabilities we allow.
        #
        # script-src MUST include *.adtrafficquality.google because
        # AdSense loads sodar2.js from ep2.adtrafficquality.google for
        # quality verification; without it, the ad request returns 403.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' "
            "https://fonts.googleapis.com https://www.gstatic.com "
            "https://*.googlesyndication.com https://*.g.doubleclick.net "
            "https://*.adtrafficquality.google "
            "https://www.googletagservices.com https://www.googletagmanager.com "
            "https://adservice.google.com https://fundingchoicesmessages.google.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://unlimitededition-web-security-scanner.hf.space "
            "https://*.googlesyndication.com https://*.g.doubleclick.net "
            "https://*.adtrafficquality.google "
            # Funding Choices (Google consent framework) fetches
            # /el/... endpoints from fundingchoicesmessages — needs
            # both script-src (script load) AND connect-src (fetch).
            "https://fundingchoicesmessages.google.com "
            "https://www.google.com https://www.googletagservices.com "
            "https://www.googletagmanager.com https://csi.gstatic.com; "
            "frame-src https://*.googlesyndication.com https://*.g.doubleclick.net "
            "https://*.adtrafficquality.google https://www.google.com; "
            "frame-ancestors 'self' https://huggingface.co https://*.hf.space"
        )
        response.headers["X-Frame-Options"] = "ALLOW-FROM https://huggingface.co"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        if "server" in response.headers:
            del response.headers["server"]
        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]
        return response


app.add_middleware(SecurityHeadersMiddleware)

# In-memory scan cache — fast path for the hot /scan/{id} polling loop.
# The authoritative copy of each scan lives in the Supabase `scans` table
# when db.is_configured(). Cache misses fall back to db.get_scan_from_db().
scans: Dict[str, Dict[str, Any]] = {}

# In-memory rate-limit backstop. db.check_rate_limit() is the primary
# enforcement point when the DB is reachable; _rate_store only kicks in
# if the DB is not configured or a write fails.
_rate_store: Dict[str, list] = defaultdict(list)

# Queue system: max 1 concurrent scan
_scan_queue: list = []
_active_scan: Dict[str, Any] = {"id": None}
_MAX_CONCURRENT = 1


def _check_rate_limit_in_memory(ip: str) -> bool:
    """
    Legacy sliding-window limiter — kept as a fallback when the DB is
    unreachable. Not used as the primary path when db.is_configured().
    """
    now = time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < _RATE_WINDOW]
    if len(_rate_store[ip]) >= _RATE_LIMIT:
        return False
    _rate_store[ip].append(now)
    return True


def _check_rate_limit(ip: str) -> bool:
    """
    Primary rate-limit gate. Consults the DB first (db.check_rate_limit);
    if the DB path returns "fail-open" (None) or raises, falls back to
    the in-memory limiter so a DB outage can't both lose persistence AND
    disable the rate limit entirely.
    """
    if db.is_configured():
        allowed, _count = db.check_rate_limit(
            ip=ip, max_count=_RATE_LIMIT, window_seconds=_RATE_WINDOW
        )
        if not allowed:
            return False
        # Still run the in-memory limiter as a belt-and-suspenders check.
        return _check_rate_limit_in_memory(ip)
    return _check_rate_limit_in_memory(ip)


def _make_progress_cb(scan_id: str):
    """
    Returns a progress callback closure that updates the in-memory cache
    on every tick but only writes to the DB when progress crosses a 10%
    threshold. This keeps DB write volume bounded to ~10 writes per scan
    instead of ~100+.
    """
    last_db_pct = [0]  # mutable closure holder

    def cb(step: str, pct: int):
        scans[scan_id]["step"] = step
        scans[scan_id]["progress"] = pct
        # Debounced DB write: only on 10% thresholds
        if db.is_configured() and pct - last_db_pct[0] >= 10:
            last_db_pct[0] = pct
            db.update_scan_progress(scan_id, pct, step)

    return cb


def _run_scan_inline(scan_id: str, url: str, client_ip: str, user_agent: Optional[str]):
    """
    Executes a single scan. Shared between the "start immediately" path
    in /scan and the "pull from queue" path in _process_queue, so both
    share identical DB + audit-log semantics.
    """
    # Transition to running (both in-memory and DB)
    scans[scan_id]["status"] = "running"
    scans[scan_id]["step"] = "Pokretanje skeniranja..."
    db.mark_scan_running(scan_id)
    db.log_audit_event(
        event="scan_start",
        ip=client_ip,
        ua=user_agent,
        scan_id=scan_id,
        domain=scans[scan_id].get("domain"),
    )

    progress_cb = _make_progress_cb(scan_id)
    try:
        result = scanner.scan(url, progress_callback=progress_cb)
        scans[scan_id]["status"] = "completed"
        scans[scan_id]["progress"] = 100
        scans[scan_id]["result"] = result
        db.mark_scan_completed(scan_id, result)

        # Detect deadline truncation from scanner.py's errors list
        errors = (result or {}).get("errors") or []
        truncated = any("vremenski limit" in (e or "").lower() or "prekoracio" in (e or "").lower() for e in errors)
        if truncated:
            db.log_audit_event(
                event="scan_truncated_deadline",
                ip=client_ip, ua=user_agent,
                scan_id=scan_id, domain=scans[scan_id].get("domain"),
                details={"errors": errors[:5]},
            )
        db.log_audit_event(
            event="scan_complete",
            ip=client_ip, ua=user_agent,
            scan_id=scan_id, domain=scans[scan_id].get("domain"),
            details={"score": (result or {}).get("score"), "truncated": truncated},
        )
    except Exception as e:
        msg = str(e)[:200]
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"] = msg
        db.mark_scan_error(scan_id, msg)
        db.log_audit_event(
            event="scan_error",
            ip=client_ip, ua=user_agent,
            scan_id=scan_id, domain=scans[scan_id].get("domain"),
            details={"error": msg},
        )
    finally:
        _active_scan["id"] = None
        _process_queue()


def _process_queue():
    """Process the next scan in queue if no active scan."""
    if _active_scan["id"] is not None:
        # Check if active scan is still running
        active = scans.get(_active_scan["id"])
        if active and active["status"] in ("completed", "error"):
            _active_scan["id"] = None
        else:
            return

    if not _scan_queue:
        return

    scan_id = _scan_queue.pop(0)
    scan = scans.get(scan_id)
    if not scan:
        return

    _active_scan["id"] = scan_id

    thread = threading.Thread(
        target=_run_scan_inline,
        args=(scan_id, scan["url"], scan.get("client_ip", "unknown"), scan.get("user_agent")),
        daemon=True,
    )
    thread.start()


class ScanRequest(BaseModel):
    url: str
    # Consent is optional for backward compat with the current frontend.
    # When the frontend is updated to send the checkbox state + version,
    # we can tighten this to `consent_accepted: bool` (no default) and
    # reject non-consenting scans at the pydantic layer.
    consent_accepted: bool = False
    consent_version: Optional[str] = None
    session_id: Optional[str] = None
    fingerprint_hash: Optional[str] = None

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL ne sme biti prazan.")
        # Add https:// if missing
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        # Basic domain check
        domain_pattern = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        if not re.match(domain_pattern, v):
            raise ValueError("Neispravan URL format.")
        # SSRF protection: resolve DNS, block private/reserved ranges,
        # loopback, link-local (AWS metadata), IPv6 ULA, etc.
        # This runs again inside safe_get() for every redirect hop.
        safe, reason = is_safe_target(v)
        if not safe:
            raise ValueError(
                "Ciljna adresa nije dozvoljena (interna, privatna ili "
                f"nerazrešiva). / Target not allowed: {reason}"
            )
        return v


@app.api_route("/", methods=["GET", "HEAD"])
@app.api_route("/index.html", methods=["GET", "HEAD"])
def root():
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    return {"status": "ok", "service": "Web Security Scanner"}


@app.api_route("/privacy.html", methods=["GET", "HEAD"])
def privacy():
    path = os.path.join(os.path.dirname(__file__), "privacy.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.api_route("/terms.html", methods=["GET", "HEAD"])
def terms():
    path = os.path.join(os.path.dirname(__file__), "terms.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.api_route("/abuse-report.html", methods=["GET", "HEAD"])
def abuse_report_page():
    """Dedicated abuse-report page (form + FAQ + process explanation)."""
    path = os.path.join(os.path.dirname(__file__), "abuse-report.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.api_route("/refund-policy.html", methods=["GET", "HEAD"])
def refund_policy_page():
    """Dedicated refund policy page (Pro plan refund terms)."""
    path = os.path.join(os.path.dirname(__file__), "refund-policy.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.api_route("/pricing.html", methods=["GET", "HEAD"])
def pricing_page():
    """Dedicated pricing page (Pro plan feature comparison, buy buttons, FAQ)."""
    path = os.path.join(os.path.dirname(__file__), "pricing.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.api_route("/blog-common.css", methods=["GET", "HEAD"])
def blog_common_css():
    path = os.path.join(os.path.dirname(__file__), "blog-common.css")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/css")
    raise HTTPException(status_code=404, detail="File not found")


@app.api_route("/blog-common.js", methods=["GET", "HEAD"])
def blog_common_js():
    path = os.path.join(os.path.dirname(__file__), "blog-common.js")
    if os.path.exists(path):
        return FileResponse(path, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="File not found")


@app.api_route("/blog-{page}.html", methods=["GET", "HEAD"])
def blog_page(page: str):
    path = os.path.join(os.path.dirname(__file__), f"blog-{page}.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")


# NOTE: these static-file routes use api_route(methods=["GET","HEAD"])
# instead of @app.get(...) because Google's AdSense crawler (and
# other web crawlers like Googlebot, Search Console verifier, Bing,
# etc.) do a HEAD request BEFORE a GET to check file existence and
# size. FastAPI's @app.get decorator only binds GET, so HEAD returned
# 405 Method Not Allowed — the crawler interprets that as "file does
# not exist" and refuses to validate ads.txt / robots.txt / the
# verification files. That was blocking multiple integrations silently.

@app.api_route("/google739403949172c6ee.html", methods=["GET", "HEAD"])
def google_verify():
    path = os.path.join(os.path.dirname(__file__), "google739403949172c6ee.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.api_route("/google6b954a0930cdbbcc.html", methods=["GET", "HEAD"])
def google_verify2():
    path = os.path.join(os.path.dirname(__file__), "google6b954a0930cdbbcc.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.api_route("/ads.txt", methods=["GET", "HEAD"])
def ads_txt():
    path = os.path.join(os.path.dirname(__file__), "ads.txt")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/plain")


@app.api_route("/robots.txt", methods=["GET", "HEAD"])
def robots():
    path = os.path.join(os.path.dirname(__file__), "robots.txt")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/plain")


@app.api_route("/sitemap.xml", methods=["GET", "HEAD"])
def sitemap():
    path = os.path.join(os.path.dirname(__file__), "sitemap.xml")
    if os.path.exists(path):
        return FileResponse(path, media_type="application/xml")


@app.api_route("/.well-known/security.txt", methods=["GET", "HEAD"])
def security_txt():
    path = os.path.join(os.path.dirname(__file__), ".well-known", "security.txt")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/plain")


# ═══════════════════════════════════════════════════════════════════════
# Abuse reports — Function 3
# ═══════════════════════════════════════════════════════════════════════
# When a site owner sees their domain in our scan logs (e.g. via a bot
# crawling the results page, or via Cloudflare alert firing on our scan
# UA), they need a way to say "stop". This endpoint is that channel.
#
# The submitted report lands in `abuse_reports` with status='open'.
# The operator triages reports through the Supabase dashboard and
# manually transitions them to 'reviewed' → 'confirmed' or 'dismissed'.
# Confirmed reports block any future scans of the reported domain via
# `is_domain_blocked()` checked in /scan.
#
# When the reporter cites specific scan_ids, we flag the corresponding
# audit_log rows to exempt them from 90-day pruning. They then persist
# as legal evidence for as long as the operator needs them.
#
# There's no rate limit specifically for abuse reports separate from
# the global /scan rate limit, because legitimate reporters won't
# submit hundreds of reports. Malicious floods would show up in the
# audit log under abuse_report_submitted and can be handled manually.

# Maximum length for free-text fields (chars). DB column is TEXT but
# we guard at the API layer too to prevent trivial storage blowup.
MAX_REPORT_DESCRIPTION = 4000
MAX_REPORT_EMAIL = 320  # RFC 5321 max practical length
MAX_RELATED_SCAN_IDS = 20


class AbuseReport(BaseModel):
    reported_domain: str
    description: str
    reporter_email: Optional[str] = None
    related_scan_ids: Optional[list] = None

    @field_validator("reported_domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        normalized = verification.normalize_domain(v)
        if not normalized:
            raise ValueError("Neispravan format domena.")
        return normalized

    @field_validator("description")
    @classmethod
    def validate_description(cls, v: str) -> str:
        v = (v or "").strip()
        if len(v) < 10:
            raise ValueError("Opis prijave mora imati bar 10 karaktera.")
        if len(v) > MAX_REPORT_DESCRIPTION:
            raise ValueError(f"Opis ne sme biti duzi od {MAX_REPORT_DESCRIPTION} karaktera.")
        return v

    @field_validator("reporter_email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v.strip() == "":
            return None
        v = v.strip()
        if len(v) > MAX_REPORT_EMAIL:
            raise ValueError(f"Email predug (max {MAX_REPORT_EMAIL}).")
        # Minimal sanity check — not a full RFC validator, just "looks
        # like an email". If the operator needs to contact back, they'll
        # notice if it's broken.
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("Email nije u ispravnom formatu.")
        return v

    @field_validator("related_scan_ids")
    @classmethod
    def validate_scan_ids(cls, v: Optional[list]) -> Optional[list]:
        if not v:
            return None
        if len(v) > MAX_RELATED_SCAN_IDS:
            raise ValueError(f"Najvise {MAX_RELATED_SCAN_IDS} scan ID-jeva po prijavi.")
        # scan_ids are 8-char hex from uuid4[:8]
        cleaned = []
        for sid in v:
            if not isinstance(sid, str):
                raise ValueError("scan_ids mora biti lista stringova.")
            sid = sid.strip()
            if not re.match(r"^[a-f0-9]{8}$", sid):
                raise ValueError(f"Neispravan scan_id format: {sid[:12]}")
            cleaned.append(sid)
        return cleaned


@app.post("/abuse-report")
def abuse_report_endpoint(req: AbuseReport, request: Request):
    """
    Accept an abuse report from a site owner. Creates an abuse_reports
    row with status='open', flags any cited scan_ids' audit_log rows
    for legal retention, and emits an audit event.
    """
    reporter_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:500] or None

    # Global rate limit applies — same check as /scan to prevent a
    # single IP from flooding the abuse queue
    if not _check_rate_limit(reporter_ip):
        db.log_audit_event(
            event="scan_blocked_rate_limit",
            ip=reporter_ip, ua=user_agent,
            details={
                "endpoint": "/abuse-report",
                "reported_domain": req.reported_domain,
            },
        )
        raise HTTPException(
            status_code=429,
            detail="Previse zahteva. Pokusajte ponovo za nekoliko minuta.",
        )

    row = db.create_abuse_report(
        reported_domain=req.reported_domain,
        description=req.description,
        reporter_ip=reporter_ip,
        reporter_email=req.reporter_email,
        related_scan_ids=req.related_scan_ids,
    )

    # Flag any cited scans' audit_log rows for legal-hold retention
    flagged_count = 0
    if req.related_scan_ids:
        flagged_count = db.flag_audit_rows_for_scans(req.related_scan_ids)

    db.log_audit_event(
        event="abuse_report_submitted",
        ip=reporter_ip, ua=user_agent, domain=req.reported_domain,
        details={
            "report_id": (row or {}).get("id"),
            "has_email": bool(req.reporter_email),
            "related_scan_count": len(req.related_scan_ids or []),
            "audit_rows_flagged": flagged_count,
        },
    )

    return {
        "ok": True,
        "report_id": (row or {}).get("id"),
        "reported_domain": req.reported_domain,
        "status": "open",
        "message": (
            "Prijava je primljena i bice pregledana u roku od 72 sata. "
            "Ako ste ostavili email, kontaktiracemo vas sa ishodom."
        ),
    }


# ═══════════════════════════════════════════════════════════════════════
# Function 6 — ownership verification
# ═══════════════════════════════════════════════════════════════════════
# Before a user can see the full scan findings (URLs of exposed files,
# admin paths, payload hints, etc.), they must prove they control the
# domain. Three methods are supported: meta tag on homepage, file at
# /.well-known/scanner-verify.txt, or a DNS TXT record. Any one is
# sufficient. Successful verification binds the domain to the requester's
# IP hash for 30 days in the `verified_domains` table. Unverified scans
# still run and still store full results in the DB — only the GET
# endpoint redacts sensitive fields before returning them.

# Cap on verification attempts per token before we kill it, to prevent
# an attacker from brute-forcing the meta tag / file path of a domain
# they don't control by iterating through many scan tokens.
MAX_VERIFY_ATTEMPTS = 5

# Check-id prefixes whose findings expose specific attack surface
# (file locations, admin URLs, exploitable vulnerabilities, API
# endpoints, server fingerprints). These are hidden from unverified
# callers — the mere existence of a "file_env" finding tells an
# attacker there's a .env at /.env even if we scrub the description.
#
# Hardening-level findings (missing HSTS, weak SPF, SEO issues,
# accessibility gaps, etc.) stay visible because they describe
# *what's missing* rather than *where to attack*, and seeing them is
# the whole value of running the scan.
SENSITIVE_CHECK_PREFIXES = (
    "file_",   # exposed sensitive files — exact path is the exploit
    "admin_",  # discovered admin panels — exact URL is the login target
    "vuln_",   # actively detected vulnerabilities
    "api_",    # exposed API endpoints (GraphQL introspection, swagger, etc.)
    "disc_",   # information disclosure (server version, debug info, etc.)
)

REDACTION_PLACEHOLDER = (
    "[Verifikujte vlasnistvo domena da vidite detalje. / "
    "Verify domain ownership to see details.]"
)


def _is_sensitive_finding(finding: Dict[str, Any]) -> bool:
    """
    True if this finding's check_id starts with any of the sensitive
    prefixes. Unknown / missing IDs default to "not sensitive" — we
    don't want a typo in the check catalog to accidentally mask a
    hardening finding.
    """
    fid = str(finding.get("id") or "").lower()
    return any(fid.startswith(p) for p in SENSITIVE_CHECK_PREFIXES)


def _redact_finding(finding: Any) -> Any:
    """
    For sensitive findings, return a stub that preserves the useful
    public facts (severity, category, passed) but replaces all
    human-readable fields with a placeholder. Non-sensitive findings
    pass through unchanged so the user still sees their full
    hardening report.
    """
    if not isinstance(finding, dict):
        return finding
    if not _is_sensitive_finding(finding):
        return finding
    return {
        "id": "redacted",
        "category": finding.get("category", "Locked"),
        "severity": finding.get("severity", "UNKNOWN"),
        "passed": finding.get("passed", False),
        "title": REDACTION_PLACEHOLDER,
        "title_en": REDACTION_PLACEHOLDER,
        "description": REDACTION_PLACEHOLDER,
        "description_en": REDACTION_PLACEHOLDER,
        "recommendation": REDACTION_PLACEHOLDER,
        "recommendation_en": REDACTION_PLACEHOLDER,
        "_was_redacted": True,
    }


def _redact_result(result: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Returns a shallow copy of the scan result with sensitive findings
    replaced by stubs. score, grade, counts, and errors are preserved
    — those are the public summary a visitor is allowed to see.

    Adds `_redacted_count` so the frontend can render a "N findings
    hidden, verify to unlock" hint without re-scanning the list.
    """
    if not isinstance(result, dict):
        return result
    redacted = dict(result)
    findings = result.get("results")
    redacted_count = 0
    if isinstance(findings, list):
        new_findings = []
        for f in findings:
            new_f = _redact_finding(f)
            if isinstance(new_f, dict) and new_f.get("_was_redacted"):
                redacted_count += 1
            new_findings.append(new_f)
        redacted["results"] = new_findings
    redacted["_redacted"] = True
    redacted["_redacted_count"] = redacted_count
    redacted["_redaction_notice"] = (
        "Specificni pronalazi vezani za izlozene fajlove, admin stranice, "
        "ranjivosti, API endpoint-e i otkrivanje sistemskih informacija su "
        "sakriveni dok ne verifikujete vlasnistvo domena. Koristite "
        "POST /verify/request da pokrenete verifikaciju. "
        "/ Specific findings related to exposed files, admin pages, "
        "vulnerabilities, API endpoints and information disclosure are "
        "hidden until you verify ownership of the domain. Use "
        "POST /verify/request to start."
    )
    return redacted


class VerifyRequest(BaseModel):
    domain: str
    method: str  # "meta" | "file" | "dns"

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        if v not in ("meta", "file", "dns"):
            raise ValueError("Metoda mora biti meta, file ili dns.")
        return v


class VerifyCheckRequest(BaseModel):
    token: str

    @field_validator("token")
    @classmethod
    def validate_token(cls, v: str) -> str:
        v = (v or "").strip()
        # Tokens are 32 hex chars (secrets.token_hex(16)). Reject anything
        # that doesn't look like one to fail fast on malformed input.
        if not re.match(r"^[a-f0-9]{32}$", v):
            raise ValueError("Neispravan format tokena.")
        return v


def _client_ip(request: Request) -> str:
    """Extract real client IP honoring proxy headers (Vercel/HF/Cloudflare)."""
    return (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or request.headers.get("x-real-ip", "")
        or request.headers.get("cf-connecting-ip", "")
        or (request.client.host if request.client else "unknown")
    )


def _get_pro_subscription(request: Request) -> Optional[Dict[str, Any]]:
    """
    Look up the active Pro subscription for this request, or None.

    Reads X-License-Key header and resolves via subscription module.
    Returns the raw row only if is_active() passes. Used by feature
    gates that need to know "can this request bypass the free-tier
    rate limit / use multi-page scan / export PDF".

    Fail-closed: any error or missing header returns None.
    """
    license_key = (request.headers.get("x-license-key") or "").strip()
    if not license_key:
        return None
    try:
        return subscription.get_active_by_license_key(license_key)
    except Exception:
        return None


@app.post("/verify/request")
def verify_request_endpoint(req: VerifyRequest, request: Request):
    """
    Generate a verification challenge. The user picks a method, we return
    a token and human-readable instructions for how to present it.
    """
    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:500] or None

    domain = verification.normalize_domain(req.domain)
    if not domain:
        raise HTTPException(
            status_code=400,
            detail="Neispravan format domena. / Invalid domain format."
        )

    token = _secrets.token_hex(16)  # 32 hex chars = 128 bits
    row = db.create_verification_token(
        token=token, domain=domain, method=req.method, ip=client_ip, ttl_seconds=3600,
    )

    db.log_audit_event(
        event="verify_request",
        ip=client_ip, ua=user_agent, domain=domain,
        details={"method": req.method, "token_prefix": token[:8]},
    )

    return {
        "token": token,
        "domain": domain,
        "method": req.method,
        "expires_in_seconds": 3600,
        "instructions": verification.build_instructions(domain, token, req.method),
    }


@app.post("/verify/check")
def verify_check_endpoint(req: VerifyCheckRequest, request: Request):
    """
    Execute the verification check for a pending token. If successful,
    the token is marked 'verified' and an entry is added to
    verified_domains so the requester's IP hash gets 30 days of
    unredacted scan results for that domain.
    """
    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:500] or None

    token_row = db.get_verification_token(req.token)
    if not token_row:
        db.log_audit_event(
            event="verify_failure",
            ip=client_ip, ua=user_agent,
            details={"reason": "token_not_found"},
        )
        raise HTTPException(status_code=404, detail="Token ne postoji ili je istekao.")

    domain = token_row["domain"]
    method = token_row["method"]

    # Terminal states
    if token_row["status"] == "verified":
        return {
            "verified": True,
            "domain": domain,
            "method": method,
            "note": "token was already verified",
        }
    if token_row["status"] in ("expired", "failed"):
        raise HTTPException(
            status_code=410,
            detail=f"Token je u stanju {token_row['status']}. Zatrazite novi.",
        )

    # Expiry check (client-side — pg_cron also sweeps stale pending rows)
    from datetime import datetime as _dt
    expires_at = token_row.get("expires_at") or ""
    try:
        exp_dt = _dt.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        from datetime import timezone as _tz
        if exp_dt < _dt.now(_tz.utc):
            raise HTTPException(status_code=410, detail="Token je istekao.")
    except HTTPException:
        raise
    except Exception:
        pass  # If parsing fails, fall through to the check — worst case pg_cron will clean it up

    # Attempt cap
    attempts = int(token_row.get("attempts") or 0)
    if attempts >= MAX_VERIFY_ATTEMPTS:
        db.mark_token_failed(req.token)
        db.log_audit_event(
            event="verify_failure",
            ip=client_ip, ua=user_agent, domain=domain,
            details={"reason": "attempts_exhausted", "attempts": attempts},
        )
        raise HTTPException(
            status_code=429,
            detail="Previse pokusaja za ovaj token. Zatrazite novi."
        )

    # Run the actual check
    db.increment_verification_attempts(req.token)
    result = verification.run_verification(method, domain, req.token)

    if result.ok:
        db.mark_token_verified(req.token)
        db.upsert_verified_domain(domain=domain, ip=client_ip, method=method, ttl_days=30)
        db.log_audit_event(
            event="verify_success",
            ip=client_ip, ua=user_agent, domain=domain,
            details={"method": method, "reason": result.reason},
        )
        return {
            "verified": True,
            "domain": domain,
            "method": method,
            "valid_for_days": 30,
            "reason": result.reason,
        }

    db.log_audit_event(
        event="verify_failure",
        ip=client_ip, ua=user_agent, domain=domain,
        details={
            "method": method,
            "reason": result.reason,
            "attempts_made": attempts + 1,
            "attempts_remaining": max(0, MAX_VERIFY_ATTEMPTS - attempts - 1),
        },
    )
    return {
        "verified": False,
        "domain": domain,
        "method": method,
        "reason": result.reason,
        "attempts_remaining": max(0, MAX_VERIFY_ATTEMPTS - attempts - 1),
    }


@app.post("/scan")
def start_scan(req: ScanRequest, request: Request):
    """Start a new scan. Returns scan_id immediately."""
    # Get real IP from proxy headers (Vercel/Cloudflare/HF forward real IP)
    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:500] or None

    # Pro plan check — if the caller has an active Pro subscription,
    # they bypass the free-tier rate limit. We still log the scan and
    # run all the other safety checks (SSRF, domain block, etc.) —
    # Pro means "more scans", not "no oversight".
    pro_sub = _get_pro_subscription(request)

    # Audit: every request is logged, even rejected ones, so abuse patterns
    # are visible in forensics. Rate-limited/SSRF-blocked scans get their
    # own event types below.
    if not pro_sub and not _check_rate_limit(client_ip):
        db.log_audit_event(
            event="scan_blocked_rate_limit",
            ip=client_ip, ua=user_agent,
            details={"url": req.url, "limit": _RATE_LIMIT, "window_s": _RATE_WINDOW},
        )
        raise HTTPException(
            status_code=429,
            detail=(
                "Previše zahteva. Maksimalno 5 skeniranja po 30 minuta. "
                "Pretplatite se na Pro za neograničene skenove. / "
                "Too many requests. Max 5 scans per 30 minutes. "
                "Upgrade to Pro for unlimited scans."
            ),
        )

    scan_id = str(uuid.uuid4())[:8]

    # Extract domain for grouping — mirrors scanner.py._get_domain
    try:
        from urllib.parse import urlparse
        parsed = urlparse(req.url)
        domain = parsed.netloc.removeprefix("www.") or req.url
    except Exception:
        domain = req.url

    # Domain block check — if someone has submitted a confirmed abuse
    # report for this domain, refuse to scan it. Logs the block attempt
    # so the operator can see recurring attempts against blocked domains.
    if db.is_domain_blocked(domain):
        db.log_audit_event(
            event="abuse_block_applied",
            ip=client_ip, ua=user_agent, domain=domain,
            details={"url": req.url, "reason": "confirmed_abuse_report"},
        )
        raise HTTPException(
            status_code=403,
            detail=(
                "Ovaj domen je na listi za blokadu na osnovu prijave zloupotrebe. "
                "Ako ste vlasnik domena i smatrate da je ovo greška, kontaktirajte nas. "
                "/ This domain is blocked based on an abuse report. "
                "If you're the owner and believe this is wrong, contact us."
            ),
        )

    # Determine queue position
    queue_position = len(_scan_queue) + (1 if _active_scan["id"] else 0)

    scans[scan_id] = {
        "id": scan_id,
        "url": req.url,
        "domain": domain,
        "status": "queued" if queue_position > 0 else "running",
        "progress": 0,
        "step": "",
        "queue_position": queue_position,
        "created_at": datetime.utcnow().isoformat(),
        "result": None,
        "error": None,
        # Stash the requester info so _process_queue can pick the scan up
        # later and still have the full context for audit logging.
        "client_ip": client_ip,
        "user_agent": user_agent,
    }

    # Persist the scan + log the request. Both are best-effort — DB
    # outages degrade persistence but don't break the scan.
    db.create_scan(
        scan_id=scan_id,
        url=req.url,
        domain=domain,
        ip=client_ip,
        user_agent=user_agent,
        consent_accepted=req.consent_accepted,
        consent_version=req.consent_version,
        session_id=req.session_id,
        fingerprint_hash=req.fingerprint_hash,
        status="queued" if queue_position > 0 else "running",
    )
    db.log_audit_event(
        event="scan_request",
        ip=client_ip, ua=user_agent,
        scan_id=scan_id, domain=domain,
        session_id=req.session_id,
        fingerprint_hash=req.fingerprint_hash,
        details={
            "url": req.url,
            "queue_position": queue_position,
            "consent_accepted": req.consent_accepted,
        },
    )

    if queue_position > 0:
        scans[scan_id]["step"] = f"U redu za skeniranje... pozicija {queue_position}"
        _scan_queue.append(scan_id)
    else:
        # Start immediately
        _active_scan["id"] = scan_id
        scans[scan_id]["step"] = "Pokretanje skeniranja..."
        thread = threading.Thread(
            target=_run_scan_inline,
            args=(scan_id, req.url, client_ip, user_agent),
            daemon=True,
        )
        thread.start()

    return {"scan_id": scan_id, "status": scans[scan_id]["status"], "queue_position": queue_position}


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str, request: Request):
    """
    Get scan status and results.

    Hot path: in-memory cache (~99% of polls hit here).
    Cold path: Supabase fallback — used when the worker has restarted
    and the cache is empty but the scan completed before the restart.

    Gate: if the requester's IP hash is not in verified_domains for the
    scan's domain, sensitive fields inside result.results[] are replaced
    with a placeholder. Score, grade, counts, and check IDs are always
    visible — those are the public summary anyone gets to see.
    """
    requester_ip = _client_ip(request)
    scan = scans.get(scan_id)

    if not scan:
        # Cache miss — try the DB
        db_row = db.get_scan_from_db(scan_id)
        if not db_row:
            raise HTTPException(status_code=404, detail="Skeniranje nije pronađeno.")

        # Derive domain for the verification gate
        try:
            from urllib.parse import urlparse
            parsed = urlparse(db_row["url"])
            cold_domain = parsed.netloc.removeprefix("www.") or db_row["url"]
        except Exception:
            cold_domain = db_row["url"]

        verified = db.is_domain_verified(cold_domain, requester_ip)
        result_out = db_row.get("result") if verified else _redact_result(db_row.get("result"))
        return {
            "id": db_row["id"],
            "url": db_row["url"],
            "status": db_row["status"],
            "progress": db_row.get("progress") or 0,
            "step": db_row.get("step") or "",
            "queue_position": 0,
            "result": result_out,
            "error": db_row.get("error"),
            "verified": verified,
        }

    # Update queue position
    if scan["status"] == "queued":
        if scan_id in _scan_queue:
            scan["queue_position"] = _scan_queue.index(scan_id) + 1
            scan["step"] = f"U redu za skeniranje... pozicija {scan['queue_position']}"
        else:
            # Was in queue, now should be processing
            scan["queue_position"] = 0

    scan_domain = scan.get("domain") or ""
    verified = bool(scan_domain) and db.is_domain_verified(scan_domain, requester_ip)
    raw_result = scan.get("result")
    result_out = raw_result if verified else _redact_result(raw_result)

    return {
        "id": scan["id"],
        "url": scan["url"],
        "status": scan["status"],
        "progress": scan["progress"],
        "step": scan["step"],
        "queue_position": scan.get("queue_position", 0),
        "result": result_out,
        "error": scan.get("error"),
        "verified": verified,
    }


# ─────────────────────────────────────────────────────────────────────────
# Pro plan — license key auth + subscription status
# ─────────────────────────────────────────────────────────────────────────
def _subscription_public(row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Project a subscriptions row into the shape the frontend consumes.
    Deliberately omits lemon_* identifiers and the raw license_key — the
    frontend already has the key (it just sent it), no reason to echo
    back anything that isn't operationally useful.
    """
    if not row or not subscription.is_active(row):
        return {
            "active": False,
            "plan": "free",
            "features": {
                "unlimited_scans": False,
                "multi_page_scan": False,
                "max_pages": 1,
                "pdf_export": False,
                "scan_history_days": 0,
            },
        }
    plan = row.get("plan_name") or "pro_monthly"
    return {
        "active": True,
        "plan": plan,                              # 'pro_monthly' | 'pro_yearly'
        "status": row.get("status"),               # 'active' | 'on_trial' | 'cancelled'
        "email": row.get("email"),
        "current_period_end": row.get("current_period_end"),
        "trial_ends_at": row.get("trial_ends_at"),
        "features": {
            "unlimited_scans": True,
            "multi_page_scan": True,
            "max_pages": 10,
            "pdf_export": True,
            "scan_history_days": 30,
        },
    }


class LicenseActivateRequest(BaseModel):
    license_key: str

    @field_validator("license_key")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = (v or "").strip()
        if not v or len(v) > 128:
            raise ValueError("Invalid license key")
        return v


@app.post("/api/auth/license")
def api_auth_license(req: LicenseActivateRequest, request: Request):
    """
    Validate a license key and return the Pro subscription status.

    The frontend calls this once when the user pastes a key into the
    "Activate Pro" modal. On success, the frontend stores the key in
    localStorage and sends it as X-License-Key on subsequent calls.

    We do not set a cookie — license key is the bearer token and lives
    in localStorage. That keeps the auth model stateless and avoids
    CSRF considerations.
    """
    row = subscription.get_active_by_license_key(req.license_key)
    if not row:
        # Fail in 200 with active=false rather than 401, so the frontend
        # can show a friendly "key not recognized" message without a
        # generic HTTP error being swallowed by the browser.
        return _subscription_public(None)
    return _subscription_public(row)


@app.get("/api/subscription/me")
def api_subscription_me(request: Request):
    """
    Return the Pro subscription status for the current caller.

    Authentication: X-License-Key header. If missing or invalid, returns
    the 'free' shape — never raises 401, because unauthenticated callers
    are perfectly valid (they are free-tier users).
    """
    license_key = (request.headers.get("x-license-key") or "").strip()
    if not license_key:
        return _subscription_public(None)
    row = subscription.get_active_by_license_key(license_key)
    return _subscription_public(row)


class CheckoutCreateRequest(BaseModel):
    plan: str                              # 'pro_monthly' | 'pro_yearly'
    email: Optional[str] = None

    @field_validator("plan")
    @classmethod
    def _validate_plan(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in ("pro_monthly", "pro_yearly"):
            raise ValueError("plan must be pro_monthly or pro_yearly")
        return v

    @field_validator("email")
    @classmethod
    def _validate_email(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return None
        v = v.strip().lower()
        if len(v) > 254 or "@" not in v or "." not in v:
            raise ValueError("invalid email")
        return v


# Pre-built checkout URLs from the Lemon Squeezy dashboard. These are
# "Buy URLs" that each variant exposes; no API call is needed to use
# them. Set as env vars after creating the variants.
_LEMON_BUY_URL_MONTHLY = os.environ.get("LEMON_BUY_URL_MONTHLY", "").strip()
_LEMON_BUY_URL_YEARLY = os.environ.get("LEMON_BUY_URL_YEARLY", "").strip()


@app.post("/api/checkout/create")
def api_checkout_create(req: CheckoutCreateRequest, request: Request):
    """
    Return a Lemon Squeezy checkout URL for the requested plan.

    V1 implementation: uses pre-configured "Buy URLs" from env vars and
    appends the customer email as a query param. No Lemon Squeezy API
    call needed, so this endpoint works even if LEMON_API_KEY is unset.

    The frontend redirects window.location.href to this URL.
    """
    base = _LEMON_BUY_URL_MONTHLY if req.plan == "pro_monthly" else _LEMON_BUY_URL_YEARLY
    if not base:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Checkout not configured for plan={req.plan}. "
                f"Set LEMON_BUY_URL_MONTHLY / LEMON_BUY_URL_YEARLY env vars."
            ),
        )

    # Append email pre-fill if provided. Lemon Squeezy's buy URL schema
    # uses checkout[email] as a reserved param for prefilling the email
    # field on the hosted checkout page.
    from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl
    parsed = urlparse(base)
    existing_params = dict(parse_qsl(parsed.query))
    if req.email:
        existing_params["checkout[email]"] = req.email
    # Optional: pass the scanner's session as custom_data so the webhook
    # can tie the purchase back to an anonymous scan session later.
    session_id = request.headers.get("x-session-id")
    if session_id:
        existing_params["checkout[custom][session_id]"] = session_id[:64]

    checkout_url = urlunparse(parsed._replace(query=urlencode(existing_params)))
    return {"checkout_url": checkout_url, "plan": req.plan}


# ─────────────────────────────────────────────────────────────────────────
# Lemon Squeezy webhook receiver (Pro plan subscription events)
# ─────────────────────────────────────────────────────────────────────────
@app.post("/webhooks/lemon")
async def lemon_webhook(request: Request):
    """
    Receive a Lemon Squeezy webhook for Pro plan subscription lifecycle.

    The full idempotent processing pipeline lives in subscription.py;
    this endpoint is a thin adapter: read raw body, verify HMAC signature,
    parse JSON, dispatch, translate result to HTTP status.

    Important notes on HTTP contract:
      - 200 for ok/skipped/ignored — Lemon Squeezy marks as delivered
      - 401 for bad signature — caller is not Lemon, do NOT retry
      - 500 for processing errors — Lemon Squeezy retries up to 3 times

    Dedup strategy:
      Lemon Squeezy does not send a unique event ID header, so we derive
      one from SHA-256 of the raw body. Retries of the same event carry
      the same body, so the same hash, so the UNIQUE constraint on
      lemon_webhook_events.lemon_event_id fires on the second insert
      and process_webhook_event returns 'skipped'.
    """
    # Read the body as raw bytes BEFORE parsing JSON — HMAC is computed
    # over the exact bytes Lemon sent, any whitespace difference would
    # break the signature check.
    raw_body = await request.body()

    # Verify signature. Fail closed: missing or bad signature → 401.
    signature = request.headers.get("x-signature", "")
    if not subscription.verify_webhook_signature(raw_body, signature):
        # Log the attempt but do not echo the signature or body in the
        # response — don't help a probe narrow down what's missing.
        import logging as _log
        _log.getLogger(__name__).warning(
            "lemon_webhook: signature verification failed "
            "(event=%s, ip=%s)",
            request.headers.get("x-event-name", "<none>"),
            _client_ip(request),
        )
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse JSON now that we know it's a legitimate request
    try:
        import json as _json
        payload = _json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

    event_name = request.headers.get("x-event-name") or (
        (payload.get("meta") or {}).get("event_name") or "unknown"
    )

    # Derive a stable event ID for dedup: SHA-256 of the raw body.
    # Lemon retries reuse the exact same body, so retries hit the dedup.
    import hashlib as _hashlib
    event_id = _hashlib.sha256(raw_body).hexdigest()

    result, error_msg = subscription.process_webhook_event(
        event_id=event_id,
        event_name=event_name,
        payload=payload,
    )

    if result in ("ok", "skipped", "ignored"):
        return {"received": True, "result": result}

    # result == 'error' — return 500 so Lemon Squeezy retries
    raise HTTPException(
        status_code=500,
        detail=f"Webhook processing failed: {error_msg or 'unknown error'}",
    )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "scans_in_memory": len(scans),
        "queue_length": len(_scan_queue),
        "active_scan": _active_scan["id"] is not None,
        "db": db.health_check(),
        "lemon": subscription.health_check(),
    }
