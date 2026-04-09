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
from fastapi.middleware.gzip import GZipMiddleware
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

# Rate limiter: max 5 scans per IP per 30 min
_rate_store: Dict[str, list] = defaultdict(list)
_RATE_LIMIT = 5
_RATE_WINDOW = 1800

# Queue system: max 1 concurrent scan
_scan_queue: list = []
_active_scan: Dict[str, Any] = {"id": None}
_MAX_CONCURRENT = 1


def _check_rate_limit(ip: str) -> bool:
    now = time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < _RATE_WINDOW]
    if len(_rate_store[ip]) >= _RATE_LIMIT:
        return False
    _rate_store[ip].append(now)
    return True


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
    scan["status"] = "running"
    scan["step"] = "Pokretanje skeniranja..." if True else "Starting scan..."

    def run_scan():
        def progress_cb(step: str, pct: int):
            scans[scan_id]["step"] = step
            scans[scan_id]["progress"] = pct

        try:
            result = scanner.scan(scan["url"], progress_callback=progress_cb)
            scans[scan_id]["status"] = "completed"
            scans[scan_id]["progress"] = 100
            scans[scan_id]["result"] = result
        except Exception as e:
            scans[scan_id]["status"] = "error"
            scans[scan_id]["error"] = str(e)[:200]
        finally:
            _active_scan["id"] = None
            _process_queue()

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()


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
@app.get("/index.html")
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


@app.get("/blog-common.css")
def blog_common_css():
    path = os.path.join(os.path.dirname(__file__), "blog-common.css")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/css")
    raise HTTPException(status_code=404, detail="File not found")


@app.get("/blog-common.js")
def blog_common_js():
    path = os.path.join(os.path.dirname(__file__), "blog-common.js")
    if os.path.exists(path):
        return FileResponse(path, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="File not found")


@app.get("/blog-{page}.html")
def blog_page(page: str):
    path = os.path.join(os.path.dirname(__file__), f"blog-{page}.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")


@app.get("/google739403949172c6ee.html")
def google_verify():
    path = os.path.join(os.path.dirname(__file__), "google739403949172c6ee.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")


@app.get("/google6b954a0930cdbbcc.html")
def google_verify2():
    path = os.path.join(os.path.dirname(__file__), "google6b954a0930cdbbcc.html")
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
            detail="Previše zahteva. Maksimalno 5 skeniranja po 30 minuta. / Too many requests. Max 5 scans per 30 minutes."
        )
    scan_id = str(uuid.uuid4())[:8]

    # Determine queue position
    queue_position = len(_scan_queue) + (1 if _active_scan["id"] else 0)

    scans[scan_id] = {
        "id": scan_id,
        "url": req.url,
        "status": "queued" if queue_position > 0 else "running",
        "progress": 0,
        "step": "",
        "queue_position": queue_position,
        "created_at": datetime.utcnow().isoformat(),
        "result": None,
        "error": None,
    }

    if queue_position > 0:
        # Add to queue
        scans[scan_id]["step"] = f"U redu za skeniranje... pozicija {queue_position}"
        _scan_queue.append(scan_id)
    else:
        # Start immediately
        _active_scan["id"] = scan_id
        scans[scan_id]["step"] = "Pokretanje skeniranja..."

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
            finally:
                _active_scan["id"] = None
                _process_queue()

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

    return {"scan_id": scan_id, "status": scans[scan_id]["status"], "queue_position": queue_position}


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    """Get scan status and results."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Skeniranje nije pronađeno.")

    scan = scans[scan_id]

    # Update queue position
    if scan["status"] == "queued":
        if scan_id in _scan_queue:
            scan["queue_position"] = _scan_queue.index(scan_id) + 1
            scan["step"] = f"U redu za skeniranje... pozicija {scan['queue_position']}"
        else:
            # Was in queue, now should be processing
            scan["queue_position"] = 0

    return {
        "id": scan["id"],
        "url": scan["url"],
        "status": scan["status"],
        "progress": scan["progress"],
        "step": scan["step"],
        "queue_position": scan.get("queue_position", 0),
        "result": scan.get("result"),
        "error": scan.get("error"),
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "scans_in_memory": len(scans),
        "queue_length": len(_scan_queue),
        "active_scan": _active_scan["id"] is not None,
    }
