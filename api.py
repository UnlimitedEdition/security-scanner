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
from typing import Dict, Any, List, Optional

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
            "https://api.ipify.org https://api64.ipify.org https://icanhazip.com "
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


# ── SSRF audit logging for Pydantic validation errors ────────────────
# Pydantic validators run before the handler, so SSRF blocks from
# is_safe_target() surface as 422 ValidationError. We intercept these
# to log scan_blocked_ssrf events with the caller's IP.
from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request: Request, exc: RequestValidationError):
    # Check if any error message contains our SSRF marker
    ssrf_markers = ("Target not allowed", "nije dozvoljena")
    is_ssrf = any(
        any(m in str(e.get("msg", "")) for m in ssrf_markers)
        for e in exc.errors()
    )
    if is_ssrf:
        client_ip = _client_ip(request)
        user_agent = request.headers.get("user-agent", "")[:500] or None
        url_value = None
        try:
            body = await request.json()
            url_value = body.get("url", "")[:200]
        except Exception:
            pass
        db.log_audit_event(
            event="scan_blocked_ssrf",
            ip=client_ip, ua=user_agent,
            details={"url": url_value, "errors": [str(e) for e in exc.errors()[:3]]},
        )
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )


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


def _run_scan_inline(
    scan_id: str,
    url: str,
    client_ip: str,
    user_agent: Optional[str],
    max_pages: int = 1,
    preselected_pages: Optional[List[str]] = None,
    mode: str = "safe",
    scan_request_id: Optional[str] = None,
):
    """
    Executes a single scan. Shared between the "start immediately" path
    in /scan and the "pull from queue" path in _process_queue, so both
    share identical DB + audit-log semantics.

    max_pages controls the Pro multi-page pass in scanner.scan():
      - 1 (default): free tier behaviour, homepage only
      - up to 10: Pro tier, scanner.py will loop page-level checks on
        each additional page discovered by the crawler

    preselected_pages, if provided, is a list of URLs the user already
    picked via the discovery flow. scanner.scan() will skip its internal
    crawler and scan exactly this list.

    mode (gate-before-scan model from migrations 014/015):
      - 'safe' (default): only the SAFE / SAFE+REDACTED checks run.
        scanner.py refuses to send any probe to private surface
        (no /.env, /wp-admin/, port scan, vuln scan, GraphQL
        introspection, etc.). The 3 SAFE+REDACTED checks
        (disclosure, js, jwt) emit sumary-only findings.
      - 'full': every check runs at full fidelity. Only allowed
        when the scan was authorized through the wizard flow
        (POST /scan/request → consent → verify → execute) and the
        caller's IP hash is recorded in verified_domains for the
        target domain. The /scan/request/{id}/execute endpoint
        is the only path that should pass mode='full'.

    scan_request_id, if provided, links this scan back to the
    scan_requests row that authorized it. Used to mark the wizard
    state machine as 'completed' once the scanner finishes.
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
        session_id=scans[scan_id].get("session_id"),
        fingerprint_hash=scans[scan_id].get("fingerprint_hash"),
        details={"mode": mode, "scan_request_id": scan_request_id},
    )

    progress_cb = _make_progress_cb(scan_id)
    try:
        result = scanner.scan(
            url,
            progress_callback=progress_cb,
            max_pages=max_pages,
            preselected_pages=preselected_pages,
            mode=mode,
        )
        scans[scan_id]["status"] = "completed"
        scans[scan_id]["progress"] = 100
        scans[scan_id]["result"] = result
        db.mark_scan_completed(scan_id, result)

        # If this scan was authorized through the wizard flow, flip the
        # scan_requests row from 'executing' to 'completed'. Best-effort:
        # a DB outage here doesn't fail the scan, but it does mean the
        # wizard row will sit in 'executing' until the next reconciliation
        # (no functional impact — the user already has results).
        if scan_request_id:
            db.mark_scan_request_completed(scan_request_id)

        # Detect deadline truncation from scanner.py's errors list
        errors = (result or {}).get("errors") or []
        truncated = any("vremenski limit" in (e or "").lower() or "prekoracio" in (e or "").lower() for e in errors)
        _sid = scans[scan_id].get("session_id")
        _fph = scans[scan_id].get("fingerprint_hash")
        if truncated:
            db.log_audit_event(
                event="scan_truncated_deadline",
                ip=client_ip, ua=user_agent,
                scan_id=scan_id, domain=scans[scan_id].get("domain"),
                session_id=_sid, fingerprint_hash=_fph,
                details={"errors": errors[:5]},
            )
        db.log_audit_event(
            event="scan_complete",
            ip=client_ip, ua=user_agent,
            scan_id=scan_id, domain=scans[scan_id].get("domain"),
            session_id=_sid, fingerprint_hash=_fph,
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
            session_id=scans[scan_id].get("session_id"),
            fingerprint_hash=scans[scan_id].get("fingerprint_hash"),
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
        args=(
            scan_id,
            scan["url"],
            scan.get("client_ip", "unknown"),
            scan.get("user_agent"),
            int(scan.get("max_pages") or 1),
            scan.get("preselected_pages"),
            scan.get("mode", "safe"),
            scan.get("scan_request_id"),
        ),
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
    # Pro two-phase flow: frontend calls POST /api/discover first to get
    # a list of pages, user ticks up to 10, frontend sends them back in
    # this field. When present and caller is Pro, the scanner skips its
    # internal crawler and scans exactly these URLs.
    selected_pages: Optional[List[str]] = None
    # Gate-before-scan model (migrations 014/015). When the frontend
    # hits POST /scan directly (the legacy / "Brzi javni sken" path),
    # mode is forced to 'safe' regardless of what the body says — full
    # mode requires going through POST /scan/request → wizard → execute,
    # which is the only place a server-side full mode flag gets set.
    # Including the field in this model allows the legacy endpoint to
    # accept and ignore it without raising a validation error.
    mode: Optional[str] = None

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


@app.api_route("/user-rights.html", methods=["GET", "HEAD"])
def user_rights_page():
    """Dedicated user rights page (GDPR rights specific to this service)."""
    path = os.path.join(os.path.dirname(__file__), "user-rights.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.api_route("/pricing.html", methods=["GET", "HEAD"])
def pricing_page():
    """Dedicated pricing page (Pro plan feature comparison, buy buttons, FAQ)."""
    path = os.path.join(os.path.dirname(__file__), "pricing.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.api_route("/account.html", methods=["GET", "HEAD"])
def account_page():
    """Pro account page — subscription info + scan history. Client-side
    access control: the page loads for anyone, but its JS fetches
    /api/subscription/me and redirects free-tier visitors back to /pricing."""
    path = os.path.join(os.path.dirname(__file__), "account.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.api_route("/404.html", methods=["GET", "HEAD"])
def not_found_page():
    """Explicit route for the branded 404 page (also served by the exception
    handler below for any unknown route requested with an HTML Accept header)."""
    path = os.path.join(os.path.dirname(__file__), "404.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html", status_code=404)


@app.exception_handler(404)
async def custom_404_handler(request: Request, exc):
    """
    Return the branded 404.html for browser requests, JSON for API clients.

    The Accept header is the signal: if the caller wants HTML (browser
    navigation, search engine crawler), we serve the styled error page.
    API clients (curl, monitoring, the frontend's fetch() calls) get the
    default JSON shape with a 'detail' field — same as before this
    handler existed, so we don't break any existing code path.
    """
    accept = (request.headers.get("accept") or "").lower()
    if "text/html" in accept:
        path = os.path.join(os.path.dirname(__file__), "404.html")
        if os.path.exists(path):
            return FileResponse(path, media_type="text/html", status_code=404)
    return JSONResponse(
        status_code=404,
        content={"detail": getattr(exc, "detail", "Not found")},
    )


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


@app.api_route("/cookie-consent.js", methods=["GET", "HEAD"])
def cookie_consent_js():
    """GDPR cookie consent script shared across all pages."""
    path = os.path.join(os.path.dirname(__file__), "cookie-consent.js")
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

    # IP binding — token must be verified from the same IP that created it.
    # Without this, an attacker who intercepts a token string could verify
    # from their own IP and grant themselves 30 days of full scan access.
    token_ip_hash = token_row.get("ip_hash")
    caller_ip_hash = db.hash_ip(client_ip)
    if token_ip_hash and token_ip_hash != caller_ip_hash:
        db.log_audit_event(
            event="verify_failure",
            ip=client_ip, ua=user_agent, domain=domain,
            details={"reason": "ip_mismatch", "token_prefix": req.token[:8]},
        )
        raise HTTPException(
            status_code=403,
            detail=(
                "Verifikacija mora biti izvrsena sa iste IP adrese "
                "sa koje je token zahteven. / "
                "Verification must be performed from the same IP "
                "that requested the token."
            ),
        )

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


# ═══════════════════════════════════════════════════════════════════════
# Wizard endpoints — gate-before-scan ownership flow (migrations 014/015)
# ═══════════════════════════════════════════════════════════════════════
# The 6 endpoints below back the new "Puni sken (vlasnici)" button on
# index.html. They walk a state machine stored in the scan_requests
# table — every transition is server-validated, so a malicious frontend
# cannot skip any step.
#
# State machine:
#
#   pending_consent ──set_consent×3──▶ pending_consent
#                   ──finalize──▶ consent_recorded
#                                ──verify (success)──▶ verified
#                                                       ──execute──▶ executing
#                                                                    ──scanner done──▶ completed
#                   ──abandon──▶ abandoned
#                   ──(24h, no execute)──▶ pruned by cron
#
# Why 6 endpoints instead of 1 monolithic /scan/full:
#   1. Each step is auditable on its own (audit_log gets a row per click)
#   2. The frontend wizard can show partial state if the user reloads
#   3. Backend never trusts frontend to have done the previous step —
#      every endpoint re-reads the row and validates the precondition
#   4. Race conditions are bounded: each transition is one UPDATE with
#      a WHERE clause that filters on the expected source state
#
# Privacy: scan_requests stores only DATE (no TIMESTAMPTZ), and the
# /consent endpoint never returns timestamps. Even a full DB exfiltration
# cannot reveal what time of day a user clicked which checkbox.

# Per-IP rate limit on POST /scan/request — prevents one IP from filling
# the table with abandoned wizards. Counted against the existing
# `count_active_scan_requests_for_ip` query in db.py.
_MAX_ACTIVE_SCAN_REQUESTS_PER_IP = 5


class ScanRequestCreate(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("URL ne sme biti prazan.")
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        if not re.match(r"^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", v):
            raise ValueError("Neispravan URL format.")
        safe, reason = is_safe_target(v)
        if not safe:
            raise ValueError(
                f"Ciljna adresa nije dozvoljena. / Target not allowed: {reason}"
            )
        return v


class ScanRequestConsent(BaseModel):
    consent_num: int

    @field_validator("consent_num")
    @classmethod
    def validate_consent_num(cls, v: int) -> int:
        if v not in (1, 2, 3):
            raise ValueError("consent_num mora biti 1, 2 ili 3.")
        return v


class ScanRequestVerify(BaseModel):
    method: str
    fingerprint_hash: Optional[str] = None

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        if v not in ("meta", "file", "dns"):
            raise ValueError("Metoda mora biti meta, file ili dns.")
        return v


def _get_scan_request_or_404(request_id: str) -> Dict[str, Any]:
    """
    Common helper for the wizard endpoints. Loads the scan_requests row
    by id and 404s if it does not exist. Returns the dict on success.
    """
    if not re.match(r"^[a-f0-9]{8}$", request_id or ""):
        raise HTTPException(status_code=400, detail="Neispravan format ID-ja.")
    row = db.get_scan_request(request_id)
    if not row:
        raise HTTPException(
            status_code=404,
            detail="Scan request ne postoji ili je istekao."
        )
    return row


@app.post("/scan/request")
def create_scan_request_endpoint(req: ScanRequestCreate, request: Request):
    """
    Step 1 of the Full Scan wizard: create a pending scan_requests row.

    The user has clicked "Puni sken (vlasnici)" with a domain typed in.
    We validate the URL, normalize the domain, check the per-IP active
    request limit, create the row in 'pending_consent' status, and
    return the request_id. The frontend then opens the consent wizard.

    Audit: scan_request_created event with the URL and IP hash. Domain
    block check applies here too — a domain on the abuse block list
    cannot be scanned in any mode, including the wizard flow.
    """
    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:500] or None

    # Per-IP rate limit on active wizards
    active = db.count_active_scan_requests_for_ip(client_ip)
    if active >= _MAX_ACTIVE_SCAN_REQUESTS_PER_IP:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Imate {active} aktivnih wizarda u toku. "
                f"Maksimalno {_MAX_ACTIVE_SCAN_REQUESTS_PER_IP}. "
                "Zavrsite ili ponistite jedan pre nego pokrenete novi. / "
                f"You have {active} active wizards in progress. "
                f"Maximum {_MAX_ACTIVE_SCAN_REQUESTS_PER_IP}. "
                "Finish or cancel one before starting another."
            ),
        )

    # Normalize domain
    try:
        from urllib.parse import urlparse as _urlparse
        parsed = _urlparse(req.url)
        domain = parsed.netloc.removeprefix("www.").lower()
    except Exception:
        raise HTTPException(status_code=400, detail="Neispravan URL.")

    if not domain:
        raise HTTPException(status_code=400, detail="Domen se nije mogao odrediti iz URL-a.")

    # Resume check: if this IP already has an active wizard for this
    # exact domain, return the existing one instead of creating a new
    # row. This is what makes the "leave to add meta tag, come back,
    # enter same domain, click Full Scan" flow work seamlessly.
    ip_hash = db.hash_ip(client_ip)
    existing = db.get_active_scan_request_for_domain_ip(domain, ip_hash)
    if existing:
        status = existing.get("status", "")
        if status == "pending_consent":
            step = 1
        elif status == "consent_recorded":
            step = 2
        elif status == "verified":
            step = 3
        else:
            step = 1
        return {
            "request_id": existing.get("id"),
            "domain": domain,
            "url": existing.get("url"),
            "status": status,
            "resumed": True,
            "step": step,
            "consent_1_given": bool(existing.get("consent_1_given")),
            "consent_2_given": bool(existing.get("consent_2_given")),
            "consent_3_given": bool(existing.get("consent_3_given")),
            "verify_method": existing.get("verify_method"),
            "verify_passed": bool(existing.get("verify_passed")),
        }

    # Domain block check (consistent with /scan)
    if db.is_domain_blocked(domain):
        db.log_audit_event(
            event="abuse_block_applied",
            ip=client_ip, ua=user_agent, domain=domain,
            details={"url": req.url, "reason": "confirmed_abuse_report", "via": "scan_request"},
        )
        raise HTTPException(
            status_code=403,
            detail="Domen je blokiran na osnovu prijave zloupotrebe.",
        )

    request_id = uuid.uuid4().hex[:8]
    row = db.create_scan_request(
        request_id=request_id,
        domain=domain,
        url=req.url,
        ip=client_ip,
        user_agent=user_agent,
    )
    if not row:
        raise HTTPException(
            status_code=503,
            detail="Baza nije dostupna. Pokusajte ponovo za minut.",
        )

    db.log_audit_event(
        event="scan_request_created",
        ip=client_ip, ua=user_agent, domain=domain,
        details={"request_id": request_id, "url": req.url},
    )

    return {
        "request_id": request_id,
        "domain": domain,
        "url": req.url,
        "status": "pending_consent",
        "next_step": "consent",
    }


@app.post("/scan/request/{request_id}/consent")
def set_scan_request_consent_endpoint(
    request_id: str,
    req: ScanRequestConsent,
    request: Request,
):
    """
    Step 2 of the Full Scan wizard: tick one consent checkbox.

    The frontend sends one POST per checkbox click. The backend updates
    the appropriate consent_N_given column to TRUE and audit-logs the
    event. The wizard's [Nastavi →] button is disabled until all 3
    consents are recorded server-side — frontend cannot lie about
    state because the next endpoint (/consent/finalize) re-reads the
    row.
    """
    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:500] or None

    row = _get_scan_request_or_404(request_id)
    if row.get("status") != "pending_consent":
        raise HTTPException(
            status_code=409,
            detail=(
                "Saglasnosti se mogu menjati samo dok je wizard u stanju "
                "'pending_consent'. Trenutno: " + str(row.get("status"))
            ),
        )

    ok = db.set_scan_request_consent(request_id, req.consent_num)
    if not ok:
        raise HTTPException(status_code=500, detail="Saglasnost nije zapisana.")

    db.log_audit_event(
        event="consent_set",
        ip=client_ip, ua=user_agent, domain=row.get("domain"),
        details={"request_id": request_id, "consent_num": req.consent_num},
    )

    # IMPORTANT: We deliberately DO NOT return a timestamp. The whole
    # point of using DATE-only in scan_requests is that consent click
    # timing is never exposed. The response is the new state, nothing
    # more.
    return {
        "request_id": request_id,
        "consent_num": req.consent_num,
        "set": True,
    }


@app.post("/scan/request/{request_id}/consent/finalize")
def finalize_scan_request_consent_endpoint(request_id: str, request: Request):
    """
    Step 3 of the Full Scan wizard: lock in all 3 consents.

    Re-reads the row, verifies all 3 consent_N_given flags are TRUE,
    and atomically transitions status from 'pending_consent' to
    'consent_recorded'. Returns 400 if any consent is missing.
    """
    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:500] or None

    row = _get_scan_request_or_404(request_id)
    if row.get("status") != "pending_consent":
        raise HTTPException(
            status_code=409,
            detail="Wizard nije u stanju za finalizaciju saglasnosti.",
        )
    if not (row.get("consent_1_given") and row.get("consent_2_given") and row.get("consent_3_given")):
        raise HTTPException(
            status_code=400,
            detail="Sva 3 polja saglasnosti moraju biti potvrdjena.",
        )

    ok = db.finalize_scan_request_consents(request_id)
    if not ok:
        raise HTTPException(status_code=500, detail="Finalizacija nije uspela.")

    db.log_audit_event(
        event="consent_finalized",
        ip=client_ip, ua=user_agent, domain=row.get("domain"),
        details={"request_id": request_id},
    )

    return {
        "request_id": request_id,
        "status": "consent_recorded",
        "next_step": "verify",
    }


@app.post("/scan/request/{request_id}/verify")
def scan_request_verify_endpoint(
    request_id: str,
    req: ScanRequestVerify,
    request: Request,
):
    """
    Step 4 of the Full Scan wizard: run ownership verification.

    Pre-condition: scan_request must be in 'consent_recorded' status.
    The wizard cannot run verification before consents are finalized.

    Internally this composes the existing verification module:
      1. db.create_verification_token(domain, method, ip) — issues a
         random token bound to (domain, ip)
      2. verification.run_verification(method, domain, token) — checks
         the meta tag / file / DNS TXT
      3. On success, also calls db.upsert_verified_domain so the
         requester gets the standard 30-day cache for unrelated /scan
         calls (consistent with the legacy verify flow)
      4. Stores the verify result on the scan_request row via
         db.attach_verify_to_scan_request

    Returns the same shape as the legacy /verify/check endpoint plus
    the request_id and a next_step hint for the wizard.
    """
    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:500] or None

    row = _get_scan_request_or_404(request_id)
    status = row.get("status")
    if status not in ("consent_recorded", "verified"):
        raise HTTPException(
            status_code=409,
            detail=(
                "Verifikacija se moze pokrenuti samo nakon finalizacije "
                "saglasnosti. Trenutno: " + str(status)
            ),
        )

    domain = row.get("domain")
    if not domain:
        raise HTTPException(status_code=500, detail="Wizard row nema domain.")

    # Reuse existing token if the wizard row already has one (user is
    # retrying after placing the meta tag / DNS record). Only issue a
    # new token if this is the first verify attempt for this wizard or
    # if the previous token has expired.
    existing_token = row.get("verify_token")
    token = None
    if existing_token:
        existing_row = db.get_verification_token(existing_token)
        if existing_row and existing_row.get("status") == "pending":
            token = existing_token  # reuse — user already placed this one

    if not token:
        token = _secrets.token_hex(16)  # 32 hex chars = 128 bits
        token_row = db.create_verification_token(
            token=token,
            domain=domain,
            method=req.method,
            ip=client_ip,
            ttl_seconds=3600,
        )
        if not token_row:
            raise HTTPException(
                status_code=503,
                detail="Verifikacija nije mogla da se inicijalizuje.",
            )

    # Run the actual ownership check (HTTP fetch / DNS query — through
    # safe_get / dnspython, both SSRF-protected)
    db.increment_verification_attempts(token)
    result = verification.run_verification(req.method, domain, token)

    # Persist the outcome on the wizard row regardless of pass/fail —
    # the user can retry on failure, the row stays in 'consent_recorded'.
    db.attach_verify_to_scan_request(
        request_id=request_id,
        method=req.method,
        token=token,
        passed=bool(result.ok),
    )

    if result.ok:
        # Mark the legacy token verified AND grant the 30-day cache
        # entry — the latter so an owner who later hits POST /scan
        # directly for the same domain still gets unredacted results
        # without going through another wizard.
        db.mark_token_verified(token)
        db.upsert_verified_domain(
            domain=domain, ip=client_ip, method=req.method, ttl_days=30,
            fingerprint_hash=req.fingerprint_hash,
        )
        db.log_audit_event(
            event="verify_success",
            ip=client_ip, ua=user_agent, domain=domain,
            details={
                "request_id": request_id,
                "method": req.method,
                "via": "wizard",
                "reason": result.reason,
            },
        )
        return {
            "request_id": request_id,
            "verified": True,
            "domain": domain,
            "method": req.method,
            "valid_for_days": 30,
            "reason": result.reason,
            "next_step": "execute",
        }

    # Verification failed — wizard stays in consent_recorded so the user
    # can pick a different method or retry.
    db.log_audit_event(
        event="verify_failure",
        ip=client_ip, ua=user_agent, domain=domain,
        details={
            "request_id": request_id,
            "method": req.method,
            "via": "wizard",
            "reason": result.reason,
        },
    )
    return {
        "request_id": request_id,
        "verified": False,
        "domain": domain,
        "method": req.method,
        "token": token,
        "reason": result.reason,
        "next_step": "verify",  # try again
    }


@app.post("/scan/request/{request_id}/execute")
def execute_scan_request_endpoint(request_id: str, request: Request):
    """
    Step 5 of the Full Scan wizard: kick off the actual full-mode scan.

    Re-validates EVERY precondition server-side before launching the
    scanner — even if the frontend has been compromised, this endpoint
    will refuse unless:
      * scan_request status == 'verified'
      * all 3 consent_N_given == TRUE
      * verify_passed == TRUE
      * db.is_domain_verified(domain, client_ip) == TRUE
      * created_date is today (rows older than 24h are abandoned by cron
        but this is a defensive belt-and-suspenders check)

    Only after all of those pass does it call db.mark_scan_request_executed
    (which atomically transitions to 'executing' with the same WHERE
    clause re-validation), creates a scans row, and starts the scanner
    in mode='full'.
    """
    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:500] or None

    row = _get_scan_request_or_404(request_id)

    # Server-side re-validation of every wizard precondition. The DB
    # also re-validates these in mark_scan_request_executed's WHERE
    # clause (race-condition safety), but checking here gives the user
    # a clean error message instead of a 500.
    if row.get("status") != "verified":
        raise HTTPException(
            status_code=409,
            detail=(
                "Wizard nije u 'verified' stanju. Trenutno: "
                + str(row.get("status"))
            ),
        )
    if not (row.get("consent_1_given") and row.get("consent_2_given") and row.get("consent_3_given")):
        raise HTTPException(
            status_code=400,
            detail="Sva 3 polja saglasnosti moraju biti aktivna.",
        )
    if not row.get("verify_passed"):
        raise HTTPException(
            status_code=400,
            detail="Verifikacija vlasnistva nije zavrsena uspesno.",
        )

    domain = row.get("domain")
    url = row.get("url")
    if not domain or not url:
        raise HTTPException(status_code=500, detail="Wizard row je nepotpun.")

    # Domain block check — defensive (also done at /scan/request creation)
    if db.is_domain_blocked(domain):
        raise HTTPException(
            status_code=403,
            detail="Domen je blokiran na osnovu prijave zloupotrebe.",
        )

    # Cross-check verified_domains: the IP or fingerprint that ran verify
    # must match. This covers both static IP users (matched by ip_hash)
    # and dynamic IP users (matched by fingerprint_hash after router restart).
    caller_fingerprint = request.headers.get("x-fingerprint-hash", "")[:128] or None
    if not db.is_domain_verified(domain, client_ip, fingerprint_hash=caller_fingerprint):
        raise HTTPException(
            status_code=403,
            detail=(
                "Vasa IP adresa ili fingerprint nisu autorizovani za ovaj domen. "
                "Verifikacija se mora pokrenuti sa istog uredjaja. / "
                "Your IP or fingerprint is not authorized for this domain. "
                "Verification must come from the same device."
            ),
        )

    # Create a normal scan row + queue, but tagged with mode='full' and
    # scan_request_id. From this point on, the wizard cannot reach
    # /execute again because mark_scan_request_executed flips status
    # to 'executing'.
    scan_id = uuid.uuid4().hex[:8]
    queue_position = len(_scan_queue) + (1 if _active_scan["id"] else 0)

    # Pro plan multi-page support — wizard scans get full Pro budget if
    # the caller has an active subscription. Otherwise homepage only,
    # same as the free /scan path.
    pro_sub = _get_pro_subscription(request)
    max_pages = 10 if pro_sub else 1

    # Create the scans row FIRST — scan_requests.scan_id has a FK to
    # scans.id, so the parent row must exist before we can set the FK.
    db.create_scan(
        scan_id=scan_id,
        url=url,
        domain=domain,
        ip=client_ip,
        user_agent=user_agent,
        consent_accepted=True,
        consent_version="2026-04-12-v3",
        status="queued" if queue_position > 0 else "running",
        subscription_id=(pro_sub.get("id") if pro_sub else None),
    )

    # NOW atomically flip the wizard row to 'executing' and link the
    # scan_id FK. This is the last point at which the wizard can be
    # aborted — once status is 'executing', the scanner thread is in flight.
    flipped = db.mark_scan_request_executed(request_id, scan_id)
    if not flipped:
        raise HTTPException(
            status_code=409,
            detail=(
                "Wizard ne moze da se pokrene — moguce je da je vec "
                "izvrsen, ponisten, ili da neki uslov nije ispunjen."
            ),
        )

    scans[scan_id] = {
        "id": scan_id,
        "url": url,
        "domain": domain,
        "status": "queued" if queue_position > 0 else "running",
        "progress": 0,
        "step": "",
        "queue_position": queue_position,
        "created_at": datetime.utcnow().isoformat(),
        "result": None,
        "error": None,
        "client_ip": client_ip,
        "user_agent": user_agent,
        "max_pages": max_pages,
        "is_pro": bool(pro_sub),
        "preselected_pages": None,
        # Wizard authorization — full mode is permitted because every
        # precondition above has been re-validated server-side.
        "mode": "full",
        "scan_request_id": request_id,
    }

    db.log_audit_event(
        event="scan_request_executed",
        ip=client_ip, ua=user_agent, domain=domain,
        scan_id=scan_id,
        details={
            "request_id": request_id,
            "url": url,
            "queue_position": queue_position,
        },
    )

    if queue_position > 0:
        scans[scan_id]["step"] = f"U redu za skeniranje... pozicija {queue_position}"
        _scan_queue.append(scan_id)
    else:
        _active_scan["id"] = scan_id
        scans[scan_id]["step"] = "Pokretanje punog skena..."
        thread = threading.Thread(
            target=_run_scan_inline,
            args=(scan_id, url, client_ip, user_agent, max_pages, None, "full", request_id),
            daemon=True,
        )
        thread.start()

    return {
        "request_id": request_id,
        "scan_id": scan_id,
        "status": scans[scan_id]["status"],
        "queue_position": queue_position,
        "mode": "full",
    }


@app.post("/scan/request/{request_id}/abandon")
def abandon_scan_request_endpoint(request_id: str, request: Request):
    """
    Step 6 of the Full Scan wizard: explicit cancel by the user.

    Backed by db.abandon_scan_request which only flips wizard-active
    rows ('pending_consent', 'consent_recorded', 'verified') to
    'abandoned'. Rows that already reached 'executing' or 'completed'
    cannot be abandoned — at that point the scan is in flight or done
    and the user has to wait it out (or contact support for a refund
    if it's a Pro mistake, but that's out-of-band).

    The hourly cron prune job (migration 015) deletes abandoned rows
    the next day, but flipping the status here removes the row from
    the active rate-limit count immediately so the user can start a
    new wizard if they want to.
    """
    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:500] or None

    row = _get_scan_request_or_404(request_id)
    ok = db.abandon_scan_request(request_id)
    if not ok:
        # Either the row was already terminal, or DB write failed.
        # Return 409 in both cases — same user-facing meaning ("can't
        # abandon now").
        raise HTTPException(
            status_code=409,
            detail="Wizard se ne moze ponistiti u trenutnom stanju.",
        )

    db.log_audit_event(
        event="scan_request_abandoned",
        ip=client_ip, ua=user_agent, domain=row.get("domain"),
        details={"request_id": request_id, "previous_status": row.get("status")},
    )

    return {"request_id": request_id, "status": "abandoned"}


@app.get("/scan/request/active")
def get_active_scan_requests(request: Request):
    """
    Return ALL active (in-progress) wizards for the caller's IP.

    Called by the frontend on every page load. The user may have started
    wizards for multiple domains (e.g. prepared meta tags for 3 sites,
    then came back to verify and scan them one by one). The frontend
    shows a list with domain + current step + resume button for each.

    Lookup is by ip_hash — the same IP that started the wizard must be
    the one asking. Returns up to 10 active wizards.
    """
    client_ip = _client_ip(request)
    ip_hash = db.hash_ip(client_ip)

    rows = db.get_active_scan_requests_for_ip(ip_hash)
    if not rows:
        return {"active": False, "wizards": []}

    wizards = []
    for row in rows:
        status = row.get("status", "")
        if status == "pending_consent":
            step = 1
        elif status == "consent_recorded":
            step = 2
        elif status == "verified":
            step = 3
        else:
            continue
        wizards.append({
            "request_id": row.get("id"),
            "domain": row.get("domain"),
            "url": row.get("url"),
            "status": status,
            "step": step,
            "consent_1_given": bool(row.get("consent_1_given")),
            "consent_2_given": bool(row.get("consent_2_given")),
            "consent_3_given": bool(row.get("consent_3_given")),
            "verify_method": row.get("verify_method"),
            "verify_passed": bool(row.get("verify_passed")),
        })

    return {"active": len(wizards) > 0, "wizards": wizards}


@app.get("/scan/request/{request_id}")
def get_scan_request_endpoint(request_id: str):
    """
    Read the current state of a wizard. Used by the frontend on page
    reload — if the user closes the tab mid-wizard and comes back, the
    frontend can ask "where am I?" and resume from the right step.

    Returns a deliberately small subset of the row: domain, url,
    status, the 3 consent flags, verify_method, verify_passed, and
    final_confirmed. Notably we do NOT return verify_token (it's
    short-lived and the wizard re-issues a fresh one when the user
    picks a method) and we do NOT return any timestamp.
    """
    row = _get_scan_request_or_404(request_id)
    return {
        "request_id": row.get("id"),
        "domain": row.get("domain"),
        "url": row.get("url"),
        "status": row.get("status"),
        "consent_1_given": bool(row.get("consent_1_given")),
        "consent_2_given": bool(row.get("consent_2_given")),
        "consent_3_given": bool(row.get("consent_3_given")),
        "verify_method": row.get("verify_method"),
        "verify_passed": bool(row.get("verify_passed")),
        "final_confirmed": bool(row.get("final_confirmed")),
    }


# ─────────────────────────────────────────────────────────────────────────
# Discovery endpoint — Pro two-phase scan flow (list pages first)
# ─────────────────────────────────────────────────────────────────────────
# Pro users can preview the list of pages the crawler would reach and
# pick exactly which ones to scan. This endpoint is the first half of
# that flow: it crawls the target, caches the result under a short id,
# and returns the list to the frontend. The frontend then shows a
# checkbox modal and submits the user's picks to POST /scan via the
# `selected_pages` field.
#
# The cache is in-memory only and TTLs after 10 minutes. If the user
# takes longer than that to pick pages, they hit a fresh /api/discover.
# No DB state is written by this endpoint — discovery is ephemeral.
_discovery_cache: Dict[str, Dict[str, Any]] = {}
_DISCOVERY_TTL_SECONDS = 600  # 10 minutes


def _prune_discovery_cache() -> None:
    """Drop entries that have expired. Called opportunistically."""
    now = time.time()
    expired = [k for k, v in _discovery_cache.items() if v.get("expires_at", 0) < now]
    for k in expired:
        _discovery_cache.pop(k, None)


class DiscoverRequest(BaseModel):
    url: str
    consent_accepted: bool = False

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL ne sme biti prazan.")
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        domain_pattern = r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        if not re.match(domain_pattern, v):
            raise ValueError("Neispravan URL format.")
        safe, reason = is_safe_target(v)
        if not safe:
            raise ValueError(f"Target not allowed: {reason}")
        return v


@app.post("/api/discover")
def api_discover(req: DiscoverRequest, request: Request):
    """
    Crawl the target site and return the list of discovered same-origin
    pages. Pro-only. Result is cached under a short id so the frontend
    can reference it when the user submits their final scan selection,
    but scanner.scan() itself does not read this cache — it re-validates
    each URL in `selected_pages` at scan time.
    """
    if not req.consent_accepted:
        raise HTTPException(
            status_code=400,
            detail=(
                "Morate prihvatiti uslove koriscenja. / "
                "You must accept the terms of service."
            ),
        )

    pro_sub = _get_pro_subscription(request)
    if not pro_sub:
        raise HTTPException(
            status_code=402,
            detail=(
                "Discovery (lista stranica pre skeniranja) je Pro opcija. / "
                "Page discovery is a Pro feature. See /pricing for details."
            ),
        )

    client_ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")[:500] or None

    # Normalize URL the same way scanner.py does, so the discovery URL
    # matches what the scan step will see. This means the user sees the
    # exact same set of pages they'll end up scanning.
    from urllib.parse import urlparse as _urlparse
    parsed = _urlparse(req.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    domain = parsed.netloc.removeprefix("www.") or req.url

    if db.is_domain_blocked(domain):
        db.log_audit_event(
            event="abuse_block_applied",
            ip=client_ip, ua=user_agent, domain=domain,
            details={"url": req.url, "reason": "confirmed_abuse_report", "endpoint": "discover"},
        )
        raise HTTPException(status_code=403, detail="Domain blocked by abuse report.")

    # Fetch homepage to extract initial links for the crawler
    try:
        temp_session = requests.Session()
        temp_session.verify = True
        temp_session.headers.update({
            "User-Agent": scanner.USER_AGENT if hasattr(scanner, "USER_AGENT") else "Mozilla/5.0 (compatible; WebSecurityScanner/Pro)",
            "Accept": "text/html,application/xhtml+xml",
        })
        from security_utils import safe_get as _safe_get
        resp = _safe_get(temp_session, base_url, timeout=15)
        body = resp.text[:50000] if resp.text else ""
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Could not fetch target site: {str(e)[:200]}",
        )

    # Run the crawler
    from checks.crawler import crawl as _crawl
    try:
        pages = _crawl(base_url, temp_session, body, limit=20)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Crawler failed: {str(e)[:200]}",
        )

    if not pages:
        pages = [base_url]

    # Cache the result
    _prune_discovery_cache()
    discovery_id = uuid.uuid4().hex[:12]
    expires_at = time.time() + _DISCOVERY_TTL_SECONDS
    _discovery_cache[discovery_id] = {
        "url": base_url,
        "domain": domain,
        "pages": pages,
        "ip_hash": db.hash_ip(client_ip),
        "expires_at": expires_at,
    }

    # Audit
    db.log_audit_event(
        event="scan_request",
        ip=client_ip, ua=user_agent,
        domain=domain,
        details={
            "endpoint": "discover",
            "pages_found": len(pages),
            "consent_accepted": req.consent_accepted,
        },
    )

    return {
        "discovery_id": discovery_id,
        "domain": domain,
        "homepage_url": base_url,
        "pages": pages,
        "pages_count": len(pages),
        "max_selectable": 10,
        "expires_at": datetime.utcfromtimestamp(expires_at).isoformat() + "Z",
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

    # Server-side consent check — reject scans without explicit consent.
    # Without this, someone could POST /scan with consent_accepted=false
    # via curl/script and bypass the frontend checkbox entirely.
    if not req.consent_accepted:
        raise HTTPException(
            status_code=400,
            detail=(
                "Morate prihvatiti uslove koriscenja pre skeniranja. / "
                "You must accept the terms of service before scanning."
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

    # Pro plan page budget: Pro subscribers scan up to 10 pages per
    # request, free tier scans only the homepage. If the request body
    # includes a `selected_pages` list, the scanner will honour it; if
    # it does not, scanner.scan() falls back to auto-picking the first
    # N pages discovered by the crawler.
    max_pages = 10 if pro_sub else 1

    # Validate selected_pages if the caller provided any
    validated_selected: Optional[List[str]] = None
    if req.selected_pages:
        if not pro_sub:
            raise HTTPException(
                status_code=402,
                detail=(
                    "Izbor stranica za skeniranje je Pro opcija. / "
                    "Per-page selection is a Pro feature. "
                    "See /pricing for details."
                ),
            )
        # Trim to max_pages, strip empties
        cleaned = [p.strip() for p in req.selected_pages if p and p.strip()]
        if len(cleaned) > max_pages:
            raise HTTPException(
                status_code=400,
                detail=f"Too many pages selected. Max is {max_pages}.",
            )
        # Same-origin check — every URL must belong to the same domain
        # as the primary url. This matches the crawler's same-origin
        # rule and prevents a Pro user from using the multi-page pass
        # as a multi-target scanner against unrelated sites.
        from urllib.parse import urlparse as _urlparse
        primary_netloc = _urlparse(req.url).netloc.lower().removeprefix("www.")
        for page in cleaned:
            try:
                page_netloc = _urlparse(page).netloc.lower().removeprefix("www.")
            except Exception:
                page_netloc = ""
            if page_netloc != primary_netloc:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Page {page} is not same-origin with {req.url}. "
                        "All selected pages must share the primary domain."
                    ),
                )
            # Each URL goes through SSRF check. A malicious user cannot
            # trick us into scanning 127.0.0.1 even by including it in
            # selected_pages — safe_get inside scanner would block it,
            # but we fail fast here for a cleaner error.
            safe, reason = is_safe_target(page)
            if not safe:
                db.log_audit_event(
                    event="scan_blocked_ssrf",
                    ip=client_ip, ua=user_agent, domain=domain,
                    details={"url": page, "reason": reason, "via": "selected_pages"},
                )
                raise HTTPException(
                    status_code=400,
                    detail=f"Page {page} failed safety check: {reason}",
                )
        validated_selected = cleaned

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
        # Pro plan state — read by _run_scan_inline and _process_queue
        "max_pages": max_pages,
        "is_pro": bool(pro_sub),
        "preselected_pages": validated_selected,
        # Gate-before-scan: this endpoint is the LEGACY / "Brzi javni
        # sken" path and ALWAYS runs in safe mode. Full mode requires
        # going through POST /scan/request → wizard → execute. Even
        # if the request body claims mode='full', it is ignored here:
        # full mode is set server-side, only by /scan/request/{id}/execute.
        "mode": "safe",
        "scan_request_id": None,
    }

    # Persist the scan + log the request. Both are best-effort — DB
    # outages degrade persistence but don't break the scan. When the
    # caller is Pro, we tag the scan with their subscription_id so
    # the /api/subscription/scans endpoint can build a history view
    # for the account page.
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
        subscription_id=(pro_sub.get("id") if pro_sub else None),
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
            args=(scan_id, req.url, client_ip, user_agent, max_pages, validated_selected, "safe", None),
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

        req_fp = request.headers.get("x-fingerprint-hash", "")[:128] or None
        verified = db.is_domain_verified(cold_domain, requester_ip, fingerprint_hash=req_fp)
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
    req_fp = request.headers.get("x-fingerprint-hash", "")[:128] or None
    verified = bool(scan_domain) and db.is_domain_verified(scan_domain, requester_ip, fingerprint_hash=req_fp)
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
# PDF report export — Pro feature (gated on license key + ownership)
# ─────────────────────────────────────────────────────────────────────────
@app.get("/api/scan/{scan_id}/pdf")
def download_scan_pdf(scan_id: str, request: Request):
    """
    Generate a branded PDF report for a completed scan.

    Dual gate - both must pass:
      1. Caller has an active Pro subscription (X-License-Key header)
      2. Caller's IP hash is in verified_domains for the scan's domain
         (Function 6 ownership verification)

    Rationale for gate 2 even for Pro users: the ownership model exists
    to prevent the scanner from being used as an exploit cheat sheet
    against third-party sites. Paying for Pro buys you extra features
    on your OWN scans, not a bypass of the ownership check.
    """
    # Gate 1: Pro subscription
    pro_sub = _get_pro_subscription(request)
    if not pro_sub:
        raise HTTPException(
            status_code=402,  # Payment Required
            detail=(
                "PDF izvoz zahteva aktivnu Pro pretplatu. / "
                "PDF export requires an active Pro subscription. "
                "See /pricing for details."
            ),
        )

    # Look up scan (hot path: memory, cold path: DB)
    scan = scans.get(scan_id)
    if not scan:
        db_row = db.get_scan_from_db(scan_id)
        if not db_row:
            raise HTTPException(status_code=404, detail="Skeniranje nije pronadjeno.")
        scan = db_row

    if scan.get("status") != "completed" or not scan.get("result"):
        raise HTTPException(
            status_code=409,  # Conflict - scan not ready
            detail="Scan not complete yet. PDF export requires a finished scan.",
        )

    # Gate 2: ownership verification
    requester_ip = _client_ip(request)
    scan_domain = scan.get("domain") or ""
    if not scan_domain:
        try:
            from urllib.parse import urlparse as _urlparse
            scan_domain = (_urlparse(scan.get("url", "")).netloc.removeprefix("www.") or "")
        except Exception:
            scan_domain = ""

    pdf_fp = request.headers.get("x-fingerprint-hash", "")[:128] or None
    verified = bool(scan_domain) and db.is_domain_verified(scan_domain, requester_ip, fingerprint_hash=pdf_fp)
    if not verified:
        raise HTTPException(
            status_code=403,
            detail=(
                "PDF izvoz zahteva verifikaciju vlasnistva domena. "
                "Verifikujte se kroz meta tag, DNS TXT, ili fajl u /.well-known/. / "
                "PDF export requires domain ownership verification. "
                "Verify via meta tag, DNS TXT, or /.well-known/ file."
            ),
        )

    # Generate the PDF
    try:
        import pdf_report
        pdf_bytes = pdf_report.generate_pdf(scan)
    except Exception as e:
        import logging as _logging
        _logging.getLogger(__name__).exception("PDF generation failed for scan %s", scan_id)
        raise HTTPException(
            status_code=500,
            detail=f"PDF generation error: {str(e)[:200]}",
        )

    # Audit log the export
    db.log_audit_event(
        event="scan_complete",  # reuse existing enum; details carries the action
        ip=requester_ip,
        ua=request.headers.get("user-agent", "")[:500] or None,
        scan_id=scan_id,
        domain=scan_domain,
        details={
            "action": "pdf_export",
            "plan": pro_sub.get("plan_name"),
            "pdf_bytes": len(pdf_bytes),
        },
    )

    safe_domain = "".join(c if c.isalnum() or c in "-._" else "_" for c in scan_domain)[:60] or "scan"
    filename = f"scanner-report-{safe_domain}-{scan_id[:8]}.pdf"

    from fastapi.responses import Response
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "private, no-store",
        },
    )


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


@app.get("/api/status")
def api_status():
    """
    Public status endpoint — lets the frontend know whether Pro
    checkout is live or still in a 'coming soon' state.

    'pro_available' is true only when BOTH Lemon Squeezy buy URLs
    are configured as environment variables. Before launch day,
    those env vars are empty and the pricing page renders a 'Coming
    Soon' badge on the buy buttons instead of letting visitors
    click into a 503 error.

    The same env vars are also checked at /api/checkout/create —
    this endpoint exists purely so the frontend can change the
    rendered state without making a failed checkout call first.

    Auto-flip on launch day: the operator sets LEMON_BUY_URL_MONTHLY
    and LEMON_BUY_URL_YEARLY in HF Space Variables, factory reboots
    the Space, and this endpoint immediately starts reporting
    pro_available=true. No code change, no redeploy, no new commit.
    """
    buy_monthly = os.environ.get("LEMON_BUY_URL_MONTHLY", "").strip()
    buy_yearly = os.environ.get("LEMON_BUY_URL_YEARLY", "").strip()
    pro_available = bool(buy_monthly and buy_yearly)
    return {
        "pro_available": pro_available,
        "reason": None if pro_available else "pro_launch_pending",
        "scanner": "operational",
    }


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


@app.get("/api/subscription/scans")
def api_subscription_scans(request: Request):
    """
    Return the Pro user's scan history (last 30 days, max 30 entries).

    Auth: X-License-Key header. If missing or invalid, returns 402
    Payment Required — only Pro subscribers have scan history.

    Response shape is deliberately light (metadata + score summary,
    no full findings list). To see detailed findings, the frontend
    makes a second call to GET /scan/{id} which applies the usual
    ownership verification gate.
    """
    license_key = (request.headers.get("x-license-key") or "").strip()
    if not license_key:
        raise HTTPException(
            status_code=402,
            detail="Scan history requires an active Pro subscription.",
        )
    row = subscription.get_active_by_license_key(license_key)
    if not row:
        raise HTTPException(
            status_code=402,
            detail="Scan history requires an active Pro subscription.",
        )

    scans_list = db.get_scans_by_subscription(
        subscription_id=row.get("id"),
        limit=30,
        since_days=30,
    )
    return {
        "subscription": _subscription_public(row),
        "scans": scans_list,
        "count": len(scans_list),
    }


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
