# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
restore_backup.py — download, decrypt, and restore a backup blob from R2.

Usage:
    # List available backups on R2 (no restore yet)
    python scripts/restore_backup.py --list

    # Download + decrypt a specific backup and show its metadata
    # (doesn't touch the database — safe to run for inspection)
    python scripts/restore_backup.py --inspect backups/2026/04/10/backup-20260410T040012Z.json.gz.enc

    # Full restore: download, decrypt, and INSERT rows back into the DB
    # BY DEFAULT this runs in DRY-RUN mode. Add --apply to actually write.
    python scripts/restore_backup.py --restore backups/2026/04/10/backup-20260410T040012Z.json.gz.enc
    python scripts/restore_backup.py --restore backups/2026/04/10/backup-20260410T040012Z.json.gz.enc --apply

    # Pull the latest backup and restore it (still dry-run by default)
    python scripts/restore_backup.py --latest
    python scripts/restore_backup.py --latest --apply

Environment variables (put in .env):
    SUPABASE_DB_URL         - postgresql://... (Transaction pooler, port 6543)
    R2_ACCOUNT_ID
    R2_ACCESS_KEY_ID
    R2_SECRET_ACCESS_KEY
    R2_BUCKET
    R2_ENDPOINT
    BACKUP_ENCRYPTION_KEY   - 64 hex chars (32 bytes), same key the edge fn uses

Dependencies:
    pip install boto3 cryptography psycopg python-dotenv
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any

try:
    import boto3  # type: ignore
    from botocore.client import Config  # type: ignore
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import psycopg
    from dotenv import load_dotenv
except ImportError as e:
    print(
        f"missing dependency: {e.name}\n"
        "install with: pip install boto3 cryptography psycopg python-dotenv",
        file=sys.stderr,
    )
    sys.exit(2)


# Tables the edge function backs up — restore order matters only if there
# are FK constraints. We have none right now, but this order is safe.
RESTORE_TABLES = ["verified_domains", "abuse_reports", "scans", "audit_log"]


@dataclass
class Config_:
    db_url: str
    r2_account_id: str
    r2_access_key_id: str
    r2_secret_access_key: str
    r2_bucket: str
    r2_endpoint: str
    encryption_key_hex: str

    @classmethod
    def from_env(cls) -> "Config_":
        load_dotenv()
        required = [
            "SUPABASE_DB_URL",
            "R2_ACCOUNT_ID",
            "R2_ACCESS_KEY_ID",
            "R2_SECRET_ACCESS_KEY",
            "R2_BUCKET",
            "R2_ENDPOINT",
            "BACKUP_ENCRYPTION_KEY",
        ]
        missing = [k for k in required if not os.getenv(k)]
        if missing:
            print(f"missing env vars: {', '.join(missing)}", file=sys.stderr)
            sys.exit(2)
        return cls(
            db_url=os.environ["SUPABASE_DB_URL"],
            r2_account_id=os.environ["R2_ACCOUNT_ID"],
            r2_access_key_id=os.environ["R2_ACCESS_KEY_ID"],
            r2_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"],
            r2_bucket=os.environ["R2_BUCKET"],
            r2_endpoint=os.environ["R2_ENDPOINT"],
            encryption_key_hex=os.environ["BACKUP_ENCRYPTION_KEY"],
        )


def make_s3_client(cfg: Config_):
    """Build an S3-compatible client pointed at Cloudflare R2."""
    return boto3.client(
        "s3",
        endpoint_url=cfg.r2_endpoint,
        aws_access_key_id=cfg.r2_access_key_id,
        aws_secret_access_key=cfg.r2_secret_access_key,
        config=Config(signature_version="s3v4"),
        region_name="auto",
    )


def list_backups(cfg: Config_) -> list[dict[str, Any]]:
    """List all backup objects in the R2 bucket, sorted newest first."""
    s3 = make_s3_client(cfg)
    paginator = s3.get_paginator("list_objects_v2")
    objects: list[dict[str, Any]] = []
    for page in paginator.paginate(Bucket=cfg.r2_bucket, Prefix="backups/"):
        for obj in page.get("Contents", []) or []:
            objects.append({
                "key": obj["Key"],
                "size": obj["Size"],
                "last_modified": obj["LastModified"],
            })
    objects.sort(key=lambda o: o["last_modified"], reverse=True)
    return objects


def download_and_decrypt(cfg: Config_, object_key: str) -> dict[str, Any]:
    """
    Download an encrypted backup from R2, decrypt (AES-256-GCM),
    gunzip, and parse the JSON payload.

    The blob layout written by the edge function is:
        [ 12 bytes IV ][ ciphertext + 16-byte GCM tag ]
    """
    s3 = make_s3_client(cfg)
    response = s3.get_object(Bucket=cfg.r2_bucket, Key=object_key)
    encrypted_blob: bytes = response["Body"].read()

    if len(encrypted_blob) < 12 + 16:
        raise ValueError(
            f"blob too small to be valid ({len(encrypted_blob)} bytes)"
        )

    iv = encrypted_blob[:12]
    ciphertext_and_tag = encrypted_blob[12:]

    key_bytes = bytes.fromhex(cfg.encryption_key_hex)
    if len(key_bytes) != 32:
        raise ValueError(
            f"encryption key must be 32 bytes (64 hex chars), got {len(key_bytes)}"
        )

    aesgcm = AESGCM(key_bytes)
    plaintext_gzipped = aesgcm.decrypt(iv, ciphertext_and_tag, None)
    plaintext_json = gzip.decompress(plaintext_gzipped)
    payload: dict[str, Any] = json.loads(plaintext_json.decode("utf-8"))
    return payload


def print_metadata(payload: dict[str, Any], object_key: str | None = None) -> None:
    print()
    if object_key:
        print(f"Object key     : {object_key}")
    print(f"Schema version : {payload.get('schema_version')}")
    print(f"Exported at    : {payload.get('exported_at')}")
    print(f"Trigger source : {payload.get('trigger_source')}")
    print()
    print("Row counts:")
    for table, count in (payload.get("row_counts") or {}).items():
        print(f"  {table:20s} {count:>8d}")
    print()


def restore_rows(
    cfg: Config_,
    payload: dict[str, Any],
    apply_changes: bool,
) -> None:
    """
    Insert rows back into the database. Uses ON CONFLICT DO NOTHING on
    the primary key so re-running a restore is idempotent.

    NOTE: audit_log has a CHECK constraint on `event` — if we ever add
    new event types without backfilling old backups, the restore of old
    rows will still succeed because their old event values are already
    in the CHECK set when the backup was taken.
    """
    tables = payload.get("tables") or {}
    mode = "APPLY" if apply_changes else "DRY-RUN"
    print(f"=== Restoring [{mode}] ===\n")

    with psycopg.connect(cfg.db_url) as conn:
        for table in RESTORE_TABLES:
            rows = tables.get(table) or []
            if not rows:
                print(f"  {table:20s} 0 rows  (skip)")
                continue

            columns = list(rows[0].keys())
            placeholders = ", ".join(["%s"] * len(columns))
            column_list = ", ".join(f'"{c}"' for c in columns)
            sql = (
                f'INSERT INTO "{table}" ({column_list}) '
                f"VALUES ({placeholders}) "
                f"ON CONFLICT DO NOTHING"
            )

            if not apply_changes:
                print(f"  {table:20s} {len(rows)} rows  (would insert)")
                continue

            with conn.cursor() as cur:
                inserted = 0
                for row in rows:
                    values = [_prepare_value(row[c]) for c in columns]
                    cur.execute(sql, values)
                    inserted += cur.rowcount
                conn.commit()
            print(f"  {table:20s} {len(rows)} rows  ({inserted} inserted, {len(rows) - inserted} skipped)")

    print()
    if apply_changes:
        print("Restore complete. Review the DB to confirm state.")
    else:
        print("DRY-RUN complete. Re-run with --apply to actually insert.")


def _prepare_value(v: Any) -> Any:
    """
    psycopg handles most types automatically, but JSON-derived dicts/lists
    need to be passed through json.dumps for jsonb columns.
    """
    if isinstance(v, (dict, list)):
        return json.dumps(v)
    return v


# ──────────────────────────────────────────────────────────────────────────
# CLI entrypoint
# ──────────────────────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(description="Restore a Supabase backup from R2")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="list all backups on R2")
    group.add_argument("--inspect", metavar="KEY", help="download + decrypt + print metadata (no DB writes)")
    group.add_argument("--restore", metavar="KEY", help="restore a specific backup (dry-run unless --apply)")
    group.add_argument("--latest", action="store_true", help="restore the most recent backup")
    parser.add_argument("--apply", action="store_true", help="actually write to the DB (default is dry-run)")
    args = parser.parse_args()

    cfg = Config_.from_env()

    if args.list:
        objects = list_backups(cfg)
        if not objects:
            print("(no backups found)")
            return 0
        print(f"{'SIZE':>10}  {'LAST MODIFIED':<32}  KEY")
        for obj in objects:
            ts = obj["last_modified"].strftime("%Y-%m-%d %H:%M:%S %Z")
            print(f"{obj['size']:>10}  {ts:<32}  {obj['key']}")
        return 0

    if args.inspect:
        payload = download_and_decrypt(cfg, args.inspect)
        print_metadata(payload, args.inspect)
        return 0

    object_key = args.restore
    if args.latest:
        objects = list_backups(cfg)
        if not objects:
            print("no backups found to restore", file=sys.stderr)
            return 1
        object_key = objects[0]["key"]
        print(f"Latest backup: {object_key}")

    payload = download_and_decrypt(cfg, object_key)
    print_metadata(payload, object_key)
    restore_rows(cfg, payload, apply_changes=args.apply)
    return 0


if __name__ == "__main__":
    sys.exit(main())
