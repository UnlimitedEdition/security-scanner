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
import os
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional


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
