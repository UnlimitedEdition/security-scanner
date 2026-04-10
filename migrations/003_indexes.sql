-- ============================================================================
-- Migration 003 — indexes on core tables
-- ============================================================================
-- Indexes are created AFTER the tables (separate migration) so schema
-- changes to the tables themselves stay clean and reviewable, and so
-- adding a new index later is a new migration file instead of an edit.
--
-- All indexes use IF NOT EXISTS for idempotency — the migration runner
-- is safe to re-run on a partially-applied state.
-- ============================================================================


-- ──────────────────────────────────────────────────────────────────────────
-- scans
-- ──────────────────────────────────────────────────────────────────────────
-- Lookups: "show me my recent scans" and "scan history for domain X"
CREATE INDEX IF NOT EXISTS idx_scans_ip_hash_created
    ON scans (ip_hash, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_scans_domain_created
    ON scans (domain, created_at DESC);

-- For polling active scan status
CREATE INDEX IF NOT EXISTS idx_scans_status
    ON scans (status)
    WHERE status IN ('queued','running');


-- ──────────────────────────────────────────────────────────────────────────
-- verification_tokens
-- ──────────────────────────────────────────────────────────────────────────
-- Cleanup job needs to find expired tokens
CREATE INDEX IF NOT EXISTS idx_verify_tokens_expires
    ON verification_tokens (expires_at)
    WHERE status = 'pending';

-- Lookup when user submits a verify check
CREATE INDEX IF NOT EXISTS idx_verify_tokens_domain_status
    ON verification_tokens (domain, status);


-- ──────────────────────────────────────────────────────────────────────────
-- verified_domains
-- ──────────────────────────────────────────────────────────────────────────
-- Hot path: "is this (domain, ip_hash) currently verified"
-- UNIQUE (domain, ip_hash) on the table already provides this, but we
-- also want expiry-aware lookups
CREATE INDEX IF NOT EXISTS idx_verified_domains_lookup
    ON verified_domains (domain, ip_hash, expires_at DESC);

-- Cleanup: find expired grants
CREATE INDEX IF NOT EXISTS idx_verified_domains_expires
    ON verified_domains (expires_at);


-- ──────────────────────────────────────────────────────────────────────────
-- audit_log — these are the critical forensic indexes
-- ──────────────────────────────────────────────────────────────────────────
-- "Who scanned this domain?"
CREATE INDEX IF NOT EXISTS idx_audit_domain_created
    ON audit_log (domain, created_at DESC)
    WHERE domain IS NOT NULL;

-- "What has this IP been up to?"
CREATE INDEX IF NOT EXISTS idx_audit_ip_hash_created
    ON audit_log (ip_hash, created_at DESC);

-- "Same device across different IPs" (fingerprint correlation)
CREATE INDEX IF NOT EXISTS idx_audit_fingerprint_created
    ON audit_log (fingerprint_hash, created_at DESC)
    WHERE fingerprint_hash IS NOT NULL;

-- Event-type filters for dashboards
CREATE INDEX IF NOT EXISTS idx_audit_event_created
    ON audit_log (event, created_at DESC);

-- Cleanup job: find unflagged rows older than retention window
CREATE INDEX IF NOT EXISTS idx_audit_prune
    ON audit_log (created_at)
    WHERE flagged = FALSE;


-- ──────────────────────────────────────────────────────────────────────────
-- rate_limits
-- ──────────────────────────────────────────────────────────────────────────
-- Cleanup job: find expired windows.
-- NOTE: We cannot put `window_start + interval_from_window_seconds` into an
-- expression index because all Postgres text-to-interval casts and the
-- make_interval() function are marked STABLE, not IMMUTABLE. So we index
-- plain window_start; the prune query still benefits (it scans oldest rows
-- first and re-evaluates the predicate per row — fine for a small hot table).
CREATE INDEX IF NOT EXISTS idx_rate_limits_window_start
    ON rate_limits (window_start);


-- ──────────────────────────────────────────────────────────────────────────
-- abuse_reports
-- ──────────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_abuse_domain
    ON abuse_reports (reported_domain);

CREATE INDEX IF NOT EXISTS idx_abuse_status_created
    ON abuse_reports (status, created_at DESC);
