# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
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
    subscription_id: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    INSERT a new scans row. PII is hashed before hitting the DB.
    Returns the inserted row dict on success, None on failure.

    subscription_id is populated only for Pro-initiated scans; it is
    the FK to subscriptions.id added in migration 012 and is what the
    /api/subscription/scans endpoint queries against to build the
    Pro user's scan history.
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
        if subscription_id is not None:
            row["subscription_id"] = int(subscription_id)
        result = client.table("scans").insert(row).execute()
        return (result.data or [None])[0]

    return _safe_db_call("create_scan", _do)


def get_scans_by_subscription(
    subscription_id: int,
    limit: int = 30,
    since_days: int = 30,
) -> List[Dict[str, Any]]:
    """
    Return the most recent scans linked to a Pro subscription.

    Used by GET /api/subscription/scans to populate the account
    history page. Only returns scan metadata (id, url, domain,
    status, score summary, created/completed timestamps) — NOT
    the full findings payload, so the response stays small even
    when the user has dozens of scans. To see detailed findings,
    the user clicks a row and the frontend fetches /scan/{id}
    which still applies the ownership verification gate.

    Pro scans retention matches the rest of the scans table (no
    automatic deletion), but this query caps at `since_days` so
    the account view doesn't become unwieldy as it accumulates.
    """
    if not subscription_id or not is_configured():
        return []

    def _do() -> List[Dict[str, Any]]:
        client = get_client()
        cutoff = future_utc(days=-int(since_days)).isoformat()
        result = (
            client.table("scans")
            .select(
                "id, url, domain, status, progress, error, created_at, completed_at, result"
            )
            .eq("subscription_id", int(subscription_id))
            .gte("created_at", cutoff)
            .order("created_at", desc=True)
            .limit(int(limit))
            .execute()
        )
        rows = result.data or []

        # Keep the payload light: drop the heavy `result.results` list
        # and keep only the score summary + counts so the history list
        # renders instantly.
        trimmed: List[Dict[str, Any]] = []
        for row in rows:
            result_blob = row.get("result") or {}
            score = (result_blob or {}).get("score") or {}
            trimmed.append({
                "id": row.get("id"),
                "url": row.get("url"),
                "domain": row.get("domain"),
                "status": row.get("status"),
                "progress": row.get("progress") or 0,
                "error": row.get("error"),
                "created_at": row.get("created_at"),
                "completed_at": row.get("completed_at"),
                "score": {
                    "score": score.get("score"),
                    "grade": score.get("grade"),
                    "grade_label": score.get("grade_label"),
                    "counts": score.get("counts") or {},
                },
                "pages_scanned": (result_blob or {}).get("pages_found") or 1,
            })
        return trimmed

    out = _safe_db_call("get_scans_by_subscription", _do)
    return out if isinstance(out, list) else []


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
# ─────────────────────────────────────────────────────────────────────────
# Ownership verification (Function 6)
# ─────────────────────────────────────────────────────────────────────────
def create_verification_token(
    token: str,
    domain: str,
    method: str,
    ip: str,
    ttl_seconds: int = 3600,
) -> Optional[Dict[str, Any]]:
    """
    INSERT a pending verification_tokens row. Caller provides the token
    so it can include it in the response without re-querying. Returns
    the inserted row on success, None on failure.
    """
    if not is_configured():
        return None

    def _do():
        client = get_client()
        expires = future_utc(seconds=ttl_seconds).isoformat()
        row = {
            "token": token,
            "domain": domain,
            "method": method,
            "ip_hash": hash_ip(ip),
            "status": "pending",
            "attempts": 0,
            "expires_at": expires,
        }
        result = client.table("verification_tokens").insert(row).execute()
        return (result.data or [None])[0]

    return _safe_db_call("create_verification_token", _do)


def get_verification_token(token: str) -> Optional[Dict[str, Any]]:
    """
    SELECT the token row if it exists. Returns None if missing, expired,
    or the DB call fails. Callers must still check status ∈ {pending}
    and expires_at > now() — this function does not do that.
    """
    if not is_configured():
        return None

    def _do():
        client = get_client()
        result = (
            client.table("verification_tokens")
            .select("token, domain, method, ip_hash, status, attempts, expires_at, verified_at")
            .eq("token", token)
            .limit(1)
            .execute()
        )
        rows = result.data or []
        return rows[0] if rows else None

    return _safe_db_call("get_verification_token", _do)


def increment_verification_attempts(token: str) -> None:
    """Bump attempts counter on a pending token (for audit / rate-limit)."""
    if not is_configured():
        return

    def _do():
        client = get_client()
        # Read-modify-write is racy but fine here — attempts is advisory
        row = (
            client.table("verification_tokens")
            .select("attempts")
            .eq("token", token)
            .limit(1)
            .execute()
        )
        rows = row.data or []
        current = int((rows[0] or {}).get("attempts") or 0) if rows else 0
        client.table("verification_tokens").update({
            "attempts": current + 1,
        }).eq("token", token).execute()

    _safe_db_call("increment_verification_attempts", _do)


def mark_token_verified(token: str) -> None:
    """Transition verification_tokens.status -> 'verified'."""
    if not is_configured():
        return

    def _do():
        client = get_client()
        client.table("verification_tokens").update({
            "status": "verified",
            "verified_at": now_utc().isoformat(),
        }).eq("token", token).execute()

    _safe_db_call("mark_token_verified", _do)


def mark_token_failed(token: str) -> None:
    """Transition verification_tokens.status -> 'failed' (after too many attempts)."""
    if not is_configured():
        return

    def _do():
        client = get_client()
        client.table("verification_tokens").update({
            "status": "failed",
        }).eq("token", token).execute()

    _safe_db_call("mark_token_failed", _do)


def upsert_verified_domain(
    domain: str,
    ip: str,
    method: str,
    ttl_days: int = 30,
) -> None:
    """
    Insert or refresh a verified_domains row for (domain, ip_hash).
    The table has UNIQUE(domain, ip_hash), so we use ON CONFLICT via
    Supabase's upsert() to atomically extend the TTL on re-verification.
    """
    if not is_configured():
        return

    def _do():
        client = get_client()
        row = {
            "domain": domain,
            "ip_hash": hash_ip(ip),
            "method": method,
            "verified_at": now_utc().isoformat(),
            "expires_at": future_utc(days=ttl_days).isoformat(),
        }
        (
            client.table("verified_domains")
            .upsert(row, on_conflict="domain,ip_hash")
            .execute()
        )

    _safe_db_call("upsert_verified_domain", _do)


def is_domain_verified(domain: str, ip: str) -> bool:
    """
    Returns True if (domain, hash(ip)) has a non-expired row in
    verified_domains. Fail-closed — if DB is unreachable or anything
    raises, returns False, because the safe default for "is this user
    authorized" is NO.
    """
    if not is_configured():
        return False

    def _do() -> bool:
        client = get_client()
        now_iso = now_utc().isoformat()
        result = (
            client.table("verified_domains")
            .select("id, expires_at")
            .eq("domain", domain)
            .eq("ip_hash", hash_ip(ip))
            .gte("expires_at", now_iso)
            .limit(1)
            .execute()
        )
        return bool(result.data)

    out = _safe_db_call("is_domain_verified", _do)
    return bool(out) if out is not None else False


# ─────────────────────────────────────────────────────────────────────────
# Abuse reports (Function 3)
# ─────────────────────────────────────────────────────────────────────────
def create_abuse_report(
    reported_domain: str,
    description: str,
    reporter_ip: str,
    reporter_email: Optional[str] = None,
    related_scan_ids: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    INSERT a new abuse_reports row with status='open'. Returns the
    inserted row (with its new id) on success, None on failure.
    """
    if not is_configured():
        return None

    def _do():
        client = get_client()
        row = {
            "reported_domain": reported_domain,
            "description": (description or "")[:4000],
            "reporter_email": (reporter_email or None),
            "reporter_ip_hash": hash_ip(reporter_ip),
            "status": "open",
            "related_scan_ids": related_scan_ids or None,
        }
        result = client.table("abuse_reports").insert(row).execute()
        return (result.data or [None])[0]

    return _safe_db_call("create_abuse_report", _do)


def flag_audit_rows_for_scans(scan_ids: List[str]) -> int:
    """
    Flag audit_log rows linked to the given scan_ids so the daily
    prune_old_audit_log job skips them. Used when an abuse report
    cites specific scans — we want to keep the forensic trail past
    the normal 90-day retention window as legal evidence.

    Returns the number of rows updated, or 0 on failure.

    Implementation note: audit_log has UPDATE revoked from service_role
    (migration 004 — append-only by default). We bypass this via the
    `flag_audit_rows_for_scan_ids` SECURITY DEFINER RPC added in
    migration 010, which runs as postgres superuser and only permits
    the specific UPDATE we need (flagged = TRUE).
    """
    if not scan_ids or not is_configured():
        return 0

    def _do() -> int:
        client = get_client()
        result = client.rpc(
            "flag_audit_rows_for_scan_ids",
            {"p_scan_ids": list(scan_ids)},
        ).execute()
        # RPC returns the integer count directly
        data = result.data
        if isinstance(data, int):
            return data
        if isinstance(data, list) and data:
            return int(data[0]) if isinstance(data[0], (int, float)) else 0
        return 0

    out = _safe_db_call("flag_audit_rows_for_scans", _do)
    return int(out) if isinstance(out, int) else 0


def is_domain_blocked(domain: str) -> bool:
    """
    True if the given domain has a confirmed abuse_reports row.
    Fail-closed — DB outage returns False (don't block if we can't
    check, to avoid DoSing legitimate scans due to DB flake).
    """
    if not is_configured():
        return False

    def _do() -> bool:
        client = get_client()
        result = (
            client.table("abuse_reports")
            .select("id")
            .eq("reported_domain", domain)
            .eq("status", "confirmed")
            .limit(1)
            .execute()
        )
        return bool(result.data)

    out = _safe_db_call("is_domain_blocked", _do)
    return bool(out) if out is not None else False


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
