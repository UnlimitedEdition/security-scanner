"""
Security Scanner API
FastAPI backend — run with: uvicorn api:app --host 0.0.0.0 --port 8000
"""
import os

# ============================================================
# FIX: PostgreSQL sets OPENSSL_CONF which breaks requests SSL
# Must be cleared BEFORE any import of requests/ssl/httpx
# ============================================================
os.environ.pop("OPENSSL_CONF", None)
os.environ.pop("SSL_CERT_FILE", None)
os.environ.pop("REQUESTS_CA_BUNDLE", None)
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
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl, field_validator
import re

import scanner

app = FastAPI(
    title="Web Security Scanner API",
    description="Passive security analysis for websites — no exploitation, read-only.",
    version="1.0.0",
)

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
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://pagead2.googlesyndication.com https://www.googletagservices.com https://adservice.google.com https://tpc.googlesyndication.com https://fundingchoicesmessages.google.com https://www.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https://unlimitededition-web-security-scanner.hf.space http://localhost:8000 https://pagead2.googlesyndication.com; frame-src https://googleads.g.doubleclick.net https://tpc.googlesyndication.com https://www.google.com; frame-ancestors 'self' https://huggingface.co https://*.hf.space"
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

# In-memory scan store (use Redis in production)
scans: Dict[str, Dict[str, Any]] = {}

# Rate limiter: max 10 scans per IP per hour
_rate_store: Dict[str, list] = defaultdict(list)
_RATE_LIMIT = 2
_RATE_WINDOW = 1800


def _check_rate_limit(ip: str) -> bool:
    now = time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < _RATE_WINDOW]
    if len(_rate_store[ip]) >= _RATE_LIMIT:
        return False
    _rate_store[ip].append(now)
    return True


class ScanRequest(BaseModel):
    url: str

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
        # Block private/local addresses
        blocked = ["localhost", "127.0.0.1", "0.0.0.0", "::1",
                   "192.168.", "10.", "172.16.", "169.254."]
        for b in blocked:
            if b in v:
                raise ValueError("Lokalne adrese nisu dozvoljene.")
        return v


@app.get("/")
def root():
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    return {"status": "ok", "service": "Web Security Scanner"}


@app.get("/privacy.html")
def privacy():
    path = os.path.join(os.path.dirname(__file__), "privacy.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.get("/google739403949172c6ee.html")
def google_verify():
    path = os.path.join(os.path.dirname(__file__), "google739403949172c6ee.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.get("/ads.txt")
def ads_txt():
    path = os.path.join(os.path.dirname(__file__), "ads.txt")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/plain")


@app.get("/robots.txt")
def robots():
    path = os.path.join(os.path.dirname(__file__), "robots.txt")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/plain")


@app.get("/sitemap.xml")
def sitemap():
    path = os.path.join(os.path.dirname(__file__), "sitemap.xml")
    if os.path.exists(path):
        return FileResponse(path, media_type="application/xml")


@app.get("/.well-known/security.txt")
def security_txt():
    path = os.path.join(os.path.dirname(__file__), ".well-known", "security.txt")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/plain")


@app.post("/scan")
def start_scan(req: ScanRequest, request: Request):
    """Start a new scan. Returns scan_id immediately."""
    # Get real IP from proxy headers (Vercel/Cloudflare/HF forward real IP)
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or request.headers.get("x-real-ip", "")
        or request.headers.get("cf-connecting-ip", "")
        or (request.client.host if request.client else "unknown")
    )
    if not _check_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Previše zahteva. Maksimalno 10 skeniranja po satu. / Too many requests. Max 10 scans per hour."
        )
    scan_id = str(uuid.uuid4())[:8]
    scans[scan_id] = {
        "id": scan_id,
        "url": req.url,
        "status": "running",
        "progress": 0,
        "step": "Pokretanje skeniranja...",
        "created_at": datetime.utcnow().isoformat(),
        "result": None,
        "error": None,
    }

    def run_scan():
        def progress_cb(step: str, pct: int):
            scans[scan_id]["step"] = step
            scans[scan_id]["progress"] = pct

        try:
            result = scanner.scan(req.url, progress_callback=progress_cb)
            scans[scan_id]["status"] = "completed"
            scans[scan_id]["progress"] = 100
            scans[scan_id]["result"] = result
        except Exception as e:
            scans[scan_id]["status"] = "error"
            scans[scan_id]["error"] = str(e)[:200]

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return {"scan_id": scan_id, "status": "running"}


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    """Get scan status and results."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Skeniranje nije pronađeno.")

    scan = scans[scan_id]
    return {
        "id": scan["id"],
        "url": scan["url"],
        "status": scan["status"],
        "progress": scan["progress"],
        "step": scan["step"],
        "result": scan.get("result"),
        "error": scan.get("error"),
    }


@app.get("/health")
def health():
    return {"status": "ok", "scans_in_memory": len(scans)}
