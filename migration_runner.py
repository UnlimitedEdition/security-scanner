#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Migration runner — applies SQL files in `migrations/` to the Supabase DB.

Usage:
    python migration_runner.py            # apply all pending migrations
    python migration_runner.py --status   # show applied vs pending
    python migration_runner.py --check    # verify checksums, don't apply

Design rules:
  * Each migration is one .sql file in migrations/.
  * Filenames sort lexicographically → apply order.
  * Applied migrations are tracked in schema_migrations(version, checksum).
  * A migration that exists in schema_migrations AND whose checksum still
    matches the file on disk is skipped.
  * A migration whose on-disk checksum differs from the stored checksum
    is a FATAL error — never silently reapply, and never silently ignore.
    Write a new migration instead.
  * Each migration is wrapped in a single transaction: all or nothing.
"""
from __future__ import annotations

import hashlib
import os
import sys
import time
from pathlib import Path
from typing import List, Tuple

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def _load_env_file() -> None:
    """Minimal .env loader — we don't depend on python-dotenv."""
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _discover_migrations() -> List[Tuple[str, Path, str]]:
    """Return [(version, path, checksum), ...] sorted by version."""
    if not MIGRATIONS_DIR.exists():
        print(f"ERROR: migrations directory not found: {MIGRATIONS_DIR}")
        sys.exit(1)

    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    result = []
    for f in files:
        version = f.stem  # filename without .sql
        checksum = _hash_file(f)
        result.append((version, f, checksum))
    return result


def _connect():
    """Open a psycopg connection using SUPABASE_DB_URL."""
    db_url = os.environ.get("SUPABASE_DB_URL", "").strip()
    if not db_url:
        print(
            "ERROR: SUPABASE_DB_URL is not set.\n"
            "Set it in .env or your environment. See .env.example for the format."
        )
        sys.exit(2)

    try:
        import psycopg  # type: ignore
    except ImportError:
        print(
            "ERROR: psycopg is not installed.\n"
            "Run: pip install 'psycopg[binary]'"
        )
        sys.exit(3)

    try:
        # autocommit=False — we manage transactions explicitly per migration
        return psycopg.connect(db_url, autocommit=False)
    except Exception as e:
        print(f"ERROR: cannot connect to database: {e}")
        sys.exit(4)


def _ensure_migrations_table(conn) -> None:
    """
    Bootstrap the schema_migrations table if it doesn't exist yet.

    This is normally handled by migration 001, but migration 001 itself
    needs this table to record that it has been applied. So we run a
    minimal version of it here in its own transaction before the main
    apply loop.
    """
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version     TEXT PRIMARY KEY,
                applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                checksum    TEXT NOT NULL,
                runtime_ms  INTEGER
            );
        """)
    conn.commit()


def _load_applied(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute("SELECT version, checksum FROM schema_migrations")
        return {row[0]: row[1] for row in cur.fetchall()}


def _apply_migration(conn, version: str, path: Path, checksum: str) -> None:
    print(f"  applying {version} ...", end=" ", flush=True)
    sql = path.read_text(encoding="utf-8")

    start = time.monotonic()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            cur.execute(
                "INSERT INTO schema_migrations (version, checksum, runtime_ms) "
                "VALUES (%s, %s, %s)",
                (version, checksum, int((time.monotonic() - start) * 1000)),
            )
        conn.commit()
    except Exception as e:
        conn.rollback()
        print("FAILED")
        print(f"    {type(e).__name__}: {e}")
        raise

    runtime_ms = int((time.monotonic() - start) * 1000)
    print(f"OK ({runtime_ms}ms)")


def cmd_apply() -> int:
    _load_env_file()
    migrations = _discover_migrations()

    if not migrations:
        print("No migration files found.")
        return 0

    print(f"Discovered {len(migrations)} migration file(s) in {MIGRATIONS_DIR}")

    conn = _connect()
    try:
        _ensure_migrations_table(conn)
        applied = _load_applied(conn)

        pending = []
        for version, path, checksum in migrations:
            if version in applied:
                stored = applied[version]
                if stored != checksum:
                    print(
                        f"\nFATAL: migration {version} has been modified after "
                        f"it was applied.\n"
                        f"  stored checksum: {stored}\n"
                        f"  file checksum:   {checksum}\n"
                        f"\nNever edit an applied migration. Create a NEW "
                        f"migration file that corrects the problem instead."
                    )
                    return 5
                # Already applied and unchanged
                continue
            pending.append((version, path, checksum))

        if not pending:
            print("All migrations already applied. Nothing to do.")
            return 0

        print(f"Applying {len(pending)} new migration(s):")
        for version, path, checksum in pending:
            _apply_migration(conn, version, path, checksum)

        print(f"\nDone. {len(pending)} migration(s) applied successfully.")
        return 0
    finally:
        conn.close()


def cmd_status() -> int:
    _load_env_file()
    migrations = _discover_migrations()

    conn = _connect()
    try:
        _ensure_migrations_table(conn)
        applied = _load_applied(conn)

        print(f"{'STATUS':10s} {'VERSION':40s} CHECKSUM")
        print("-" * 90)
        for version, path, checksum in migrations:
            if version in applied:
                if applied[version] == checksum:
                    status = "APPLIED"
                else:
                    status = "MODIFIED!"
            else:
                status = "pending"
            print(f"{status:10s} {version:40s} {checksum[:16]}...")
        return 0
    finally:
        conn.close()


def cmd_check() -> int:
    """Verify all applied migrations still match their on-disk checksums."""
    _load_env_file()
    migrations = _discover_migrations()

    conn = _connect()
    try:
        _ensure_migrations_table(conn)
        applied = _load_applied(conn)

        mismatches = []
        for version, path, checksum in migrations:
            if version in applied and applied[version] != checksum:
                mismatches.append((version, applied[version], checksum))

        if mismatches:
            print(f"FATAL: {len(mismatches)} migration(s) have been modified:")
            for version, stored, file_sum in mismatches:
                print(f"  {version}")
                print(f"    stored: {stored}")
                print(f"    file:   {file_sum}")
            return 5

        print(f"All {len(applied)} applied migrations match their on-disk checksums.")
        return 0
    finally:
        conn.close()


def main(argv: list) -> int:
    if len(argv) > 1:
        cmd = argv[1]
        if cmd == "--status":
            return cmd_status()
        if cmd == "--check":
            return cmd_check()
        if cmd in ("--help", "-h"):
            print(__doc__)
            return 0
        print(f"Unknown argument: {cmd}")
        print(__doc__)
        return 1
    return cmd_apply()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
