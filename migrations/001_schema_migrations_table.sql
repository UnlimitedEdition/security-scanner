-- ============================================================================
-- Migration 001 — schema_migrations tracking table
-- ============================================================================
-- This is always the first migration. It creates the table that the
-- migration runner uses to track which migrations have already been
-- applied, so we can safely re-run `migrate.py` and skip completed work.
--
-- Never edit this file after it's been applied. If you need to change
-- something about how migrations work, add a NEW migration file.
-- ============================================================================

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,           -- filename without .sql, e.g. "001_schema_migrations_table"
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    checksum    TEXT NOT NULL,              -- sha256 of the file content at apply time
    runtime_ms  INTEGER                     -- how long the migration took, for diagnostics
);

COMMENT ON TABLE schema_migrations IS
    'Tracks applied database migrations. Managed by migration_runner.py. Never UPDATE or DELETE rows manually.';
