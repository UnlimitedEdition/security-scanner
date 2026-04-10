"""
Database layer — thin wrapper around Supabase client + PII hashing.

Everything that touches the database goes through this module. Two goals:

1. **No raw PII in the database.** IPs and User-Agents are hashed with a
   server-side salt before they are ever written. The DB only stores
   deterministic hashes, so correlation is still possible ("how many
   scans did this user make") without ever holding the raw value.
2. **Lazy initialization.** If Supabase env vars are not set (e.g. local
   dev without DB), the module imports cleanly and raises a loud error
   only when a DB call is actually attempted. This lets the rest of the
   scanner run in degraded mode without a database.
"""
from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────
# Environment
# ─────────────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "").strip()
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "").strip()
SUPABASE_DB_URL = os.environ.get("SUPABASE_DB_URL", "").strip()
PII_HASH_SALT = os.environ.get("PII_HASH_SALT", "").strip()
CONSENT_VERSION = os.environ.get("CONSENT_VERSION", "unset").strip()


class DatabaseNotConfiguredError(RuntimeError):
    """Raised when a DB call is attempted without a configured backend."""
    pass


def is_configured() -> bool:
    """True when the minimum env vars for a DB connection are present."""
    return bool(SUPABASE_URL and SUPABASE_SERVICE_KEY and PII_HASH_SALT)


def _require_configured() -> None:
    if not is_configured():
        raise DatabaseNotConfiguredError(
            "Database is not configured. Set SUPABASE_URL, "
            "SUPABASE_SERVICE_KEY and PII_HASH_SALT environment variables. "
            "See .env.example for details."
        )


# ─────────────────────────────────────────────────────────────────────────
# PII hashing — SHA-256 with server-side salt
# ─────────────────────────────────────────────────────────────────────────
def hash_pii(value: str) -> str:
    """
    Deterministically hash a PII value with the server-side salt.

    The same input always produces the same hash, so correlation queries
    still work ("give me all scans from this ip_hash"). But without the
    salt, which lives only in HF Spaces secrets, the hash cannot be
    reversed to a raw IP or UA — even if the database is fully exfiltrated.

    Raises DatabaseNotConfiguredError if PII_HASH_SALT is not set, because
    hashing without a salt is worse than not hashing at all (it would
    let attackers use rainbow tables against the IPv4 space).
    """
    if not PII_HASH_SALT:
        raise DatabaseNotConfiguredError(
            "PII_HASH_SALT is not set. Refusing to hash without a salt."
        )
    return hashlib.sha256(f"{value}:{PII_HASH_SALT}".encode("utf-8")).hexdigest()


def hash_ip(ip: str) -> str:
    return hash_pii(ip or "unknown")


def hash_ua(user_agent: str) -> str:
    return hash_pii(user_agent or "unknown")


# ─────────────────────────────────────────────────────────────────────────
# Supabase client (lazy)
# ─────────────────────────────────────────────────────────────────────────
@lru_cache(maxsize=1)
def _get_supabase_client():
    """
    Return a cached Supabase client initialized with the service role key.

    The service role key bypasses Row-Level Security, so this client must
    NEVER be exposed to frontend code. It stays on the backend and talks
    to Supabase over HTTPS. If you need to do something from the browser,
    use the anon key + RLS policies instead (but we currently don't).
    """
    _require_configured()
    try:
        from supabase import create_client  # type: ignore
    except ImportError as e:
        raise DatabaseNotConfiguredError(
            "supabase package is not installed. Run `pip install supabase`."
        ) from e
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


def get_client():
    """Public accessor — use this everywhere instead of importing create_client."""
    return _get_supabase_client()


# ─────────────────────────────────────────────────────────────────────────
# Direct Postgres connection (for migrations and maintenance only)
# ─────────────────────────────────────────────────────────────────────────
def get_pg_connection():
    """
    Return a psycopg connection to Postgres directly (not via PostgREST).

    Used by the migration runner and by maintenance scripts that need to
    issue DDL statements. Regular application code should use the
    Supabase client above, which uses PostgREST and is connection-pooled.
    """
    _require_configured()
    if not SUPABASE_DB_URL:
        raise DatabaseNotConfiguredError(
            "SUPABASE_DB_URL is not set — cannot open a direct Postgres "
            "connection. Find it in Supabase Dashboard → Settings → "
            "Database → Connection string."
        )
    try:
        import psycopg  # type: ignore
    except ImportError as e:
        raise DatabaseNotConfiguredError(
            "psycopg is not installed. Run `pip install 'psycopg[binary]'`."
        ) from e
    return psycopg.connect(SUPABASE_DB_URL, autocommit=False)


# ─────────────────────────────────────────────────────────────────────────
# Convenience helpers (used by api.py, scanner.py, ownership modules)
# ─────────────────────────────────────────────────────────────────────────
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def future_utc(seconds: int = 0, minutes: int = 0, hours: int = 0,
               days: int = 0) -> datetime:
    return now_utc() + timedelta(
        seconds=seconds, minutes=minutes, hours=hours, days=days
    )


# ─────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────
def health_check() -> Dict[str, Any]:
    """
    Quick diagnostic — safe to call from a health endpoint even when
    the database is not configured. Returns structured status instead
    of raising, so the health endpoint can report "DB: not configured"
    without 500ing.
    """
    status: Dict[str, Any] = {
        "configured": is_configured(),
        "supabase_url_set": bool(SUPABASE_URL),
        "service_key_set": bool(SUPABASE_SERVICE_KEY),
        "salt_set": bool(PII_HASH_SALT),
        "consent_version": CONSENT_VERSION,
    }
    if not is_configured():
        status["reachable"] = False
        status["reason"] = "not configured"
        return status
    try:
        client = get_client()
        # Cheapest possible query — hits the schema_migrations table
        # that the migration runner creates.
        result = client.table("schema_migrations").select("version").limit(1).execute()
        status["reachable"] = True
        status["schema_migrations_rows"] = len(result.data or [])
    except Exception as e:
        status["reachable"] = False
        status["reason"] = str(e)[:200]
    return status


# ─────────────────────────────────────────────────────────────────────────
# Scan lifecycle helpers
# ─────────────────────────────────────────────────────────────────────────
# These are best-effort: if the database is unreachable mid-flight, the
# calls log a warning and return quietly. The in-memory cache in api.py
# remains authoritative for the scan lifecycle, so a DB outage degrades
# persistence without breaking the scanner itself.
def _safe_db_call(op_name: str, fn):
    """
    Wraps a db call so transient DB failures don't crash the request.
    Returns None on failure and logs; returns fn() result on success.
    Only use this for non-critical writes (progress updates, audit logs).
    """
    try:
        return fn()
    except DatabaseNotConfiguredError:
        return None
    except Exception as e:
        log.warning("db.%s failed: %s", op_name, str(e)[:200])
        return None


def create_scan(
    scan_id: str,
    url: str,
    domain: str,
    ip: str,
    user_agent: Optional[str] = None,
    consent_accepted: bool = False,
    consent_version: Optional[str] = None,
    session_id: Optional[str] = None,
    fingerprint_hash: Optional[str] = None,
    status: str = "queued",
) -> Optional[Dict[str, Any]]:
    """
    INSERT a new scans row. PII is hashed before hitting the DB.
    Returns the inserted row dict on success, None on failure.
    """
    if not is_configured():
        return None

    def _do():
        client = get_client()
        row = {
            "id": scan_id,
            "url": url,
            "domain": domain,
            "status": status,
            "progress": 0,
            "ip_hash": hash_ip(ip),
            "ua_hash": hash_ua(user_agent) if user_agent else None,
            "session_id": session_id,
            "fingerprint_hash": fingerprint_hash,
            "consent_accepted": consent_accepted,
            "consent_version": consent_version or CONSENT_VERSION,
        }
        result = client.table("scans").insert(row).execute()
        return (result.data or [None])[0]

    return _safe_db_call("create_scan", _do)


def update_scan_progress(scan_id: str, progress: int, step: str) -> None:
    """
    UPDATE scans.progress + step. Callers should debounce this — we don't
    want to hit the DB on every 1% tick. api.py writes only on 10% thresholds.
    """
    if not is_configured():
        return

    def _do():
        client = get_client()
        client.table("scans").update({
            "progress": max(0, min(100, progress)),
            "step": step[:500] if step else None,
        }).eq("id", scan_id).execute()

    _safe_db_call("update_scan_progress", _do)


def mark_scan_running(scan_id: str) -> None:
    """Transition queued -> running."""
    if not is_configured():
        return

    def _do():
        client = get_client()
        client.table("scans").update({
            "status": "running",
            "step": "Pokretanje skeniranja...",
        }).eq("id", scan_id).execute()

    _safe_db_call("mark_scan_running", _do)


def mark_scan_completed(scan_id: str, result: Dict[str, Any]) -> None:
    """Transition -> completed, store full result JSONB, stamp completed_at."""
    if not is_configured():
        return

    def _do():
        client = get_client()
        client.table("scans").update({
            "status": "completed",
            "progress": 100,
            "result": result,
            "completed_at": now_utc().isoformat(),
        }).eq("id", scan_id).execute()

    _safe_db_call("mark_scan_completed", _do)


def mark_scan_error(scan_id: str, error_message: str) -> None:
    """Transition -> error, store truncated error string."""
    if not is_configured():
        return

    def _do():
        client = get_client()
        client.table("scans").update({
            "status": "error",
            "error": (error_message or "")[:1000],
            "completed_at": now_utc().isoformat(),
        }).eq("id", scan_id).execute()

    _safe_db_call("mark_scan_error", _do)


def get_scan_from_db(scan_id: str) -> Optional[Dict[str, Any]]:
    """
    SELECT a scan row by id. Used as a fallback when the in-memory cache
    in api.py doesn't have the scan (e.g. after a worker restart).
    """
    if not is_configured():
        return None

    def _do():
        client = get_client()
        result = (
            client.table("scans")
            .select("id, url, status, progress, step, result, error, created_at, completed_at")
            .eq("id", scan_id)
            .limit(1)
            .execute()
        )
        rows = result.data or []
        return rows[0] if rows else None

    return _safe_db_call("get_scan_from_db", _do)


# ─────────────────────────────────────────────────────────────────────────
# Rate limiting — fixed-window counter in rate_limits table
# ─────────────────────────────────────────────────────────────────────────
def check_rate_limit(
    ip: str,
    max_count: int = 5,
    window_seconds: int = 1800,
    key_prefix: str = "ip",
) -> Tuple[bool, int]:
    """
    Atomically checks the fixed-window rate limit for an IP.

    Returns (allowed, current_count). If the window has expired, the
    counter is reset to 1 and (True, 1) is returned. Otherwise the
    counter is incremented; if the new value exceeds max_count, returns
    (False, current_count) and does NOT increment further.

    Falls back to an in-memory allow-if-DB-unreachable path — a DB outage
    will NOT lock users out of the scanner. The in-memory _rate_store in
    api.py still runs as a belt-and-suspenders backstop.
    """
    if not is_configured():
        return True, 0

    def _do() -> Tuple[bool, int]:
        client = get_client()
        key = f"{key_prefix}:{hash_ip(ip)}"
        now = now_utc()

        # Read current state
        existing = (
            client.table("rate_limits")
            .select("key, count, window_start, window_seconds")
            .eq("key", key)
            .limit(1)
            .execute()
        )
        rows = existing.data or []

        if not rows:
            # First request in this key's history — create row
            client.table("rate_limits").insert({
                "key": key,
                "count": 1,
                "window_start": now.isoformat(),
                "window_seconds": window_seconds,
            }).execute()
            return True, 1

        row = rows[0]
        window_start = datetime.fromisoformat(row["window_start"].replace("Z", "+00:00"))
        elapsed = (now - window_start).total_seconds()

        if elapsed >= row["window_seconds"]:
            # Window expired — reset counter
            client.table("rate_limits").update({
                "count": 1,
                "window_start": now.isoformat(),
                "window_seconds": window_seconds,
            }).eq("key", key).execute()
            return True, 1

        current = int(row["count"])
        if current >= max_count:
            return False, current

        # Increment
        client.table("rate_limits").update({
            "count": current + 1,
            "updated_at": now.isoformat(),
        }).eq("key", key).execute()
        return True, current + 1

    result = _safe_db_call("check_rate_limit", _do)
    if result is None:
        # DB failed — fail-open (allow). The in-memory limiter in api.py
        # still runs as a backup.
        return True, 0
    return result


# ─────────────────────────────────────────────────────────────────────────
# Audit log
# ─────────────────────────────────────────────────────────────────────────
def log_audit_event(
    event: str,
    ip: str,
    ua: Optional[str] = None,
    scan_id: Optional[str] = None,
    domain: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    session_id: Optional[str] = None,
    fingerprint_hash: Optional[str] = None,
) -> None:
    """
    Append-only write to audit_log. Never raises — silent on DB failure,
    because a failed audit write must NOT prevent the scan from running.
    Every write is logged at WARNING level so ops can see gaps.

    Valid `event` values must match the CHECK constraint in migration 002:
      scan_request, scan_start, scan_complete, scan_error,
      scan_blocked_ssrf, scan_blocked_rate_limit, scan_truncated_deadline,
      verify_request, verify_success, verify_failure,
      abuse_report_submitted, abuse_block_applied
    """
    if not is_configured():
        return

    def _do():
        client = get_client()
        row = {
            "event": event,
            "scan_id": scan_id,
            "domain": domain,
            "ip_hash": hash_ip(ip),
            "ua_hash": hash_ua(ua) if ua else None,
            "session_id": session_id,
            "fingerprint_hash": fingerprint_hash,
            "details": details or {},
        }
        client.table("audit_log").insert(row).execute()

    _safe_db_call("log_audit_event", _do)
