-- ============================================================================
-- Migration 004 — Row-Level Security policies
-- ============================================================================
-- Supabase exposes tables over PostgREST with two built-in roles:
--   * anon          — what the public anon key sees
--   * authenticated — what a logged-in user sees (we don't use auth yet)
--   * service_role  — bypasses ALL RLS. Backend only.
--
-- Our rule: RLS is enabled on every table with NO policies for anon or
-- authenticated. That is a default-deny — the anon key sees nothing.
-- All application reads/writes go through the FastAPI backend using the
-- service_role key, which bypasses RLS.
--
-- Additionally, audit_log has UPDATE and DELETE revoked even for the
-- service_role. That table is append-only. If you ever need to rewrite
-- history, that's a conscious migration change, not a runtime operation.
-- ============================================================================


-- ──────────────────────────────────────────────────────────────────────────
-- Enable RLS on everything (default deny)
-- ──────────────────────────────────────────────────────────────────────────
ALTER TABLE scans                  ENABLE ROW LEVEL SECURITY;
ALTER TABLE verification_tokens    ENABLE ROW LEVEL SECURITY;
ALTER TABLE verified_domains       ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log              ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits            ENABLE ROW LEVEL SECURITY;
ALTER TABLE abuse_reports          ENABLE ROW LEVEL SECURITY;
ALTER TABLE schema_migrations      ENABLE ROW LEVEL SECURITY;


-- ──────────────────────────────────────────────────────────────────────────
-- Explicit denials for anon — no policies = no access, but we also
-- REVOKE to make the intent unambiguous and independent of RLS behaviour.
-- ──────────────────────────────────────────────────────────────────────────
REVOKE ALL ON scans                FROM anon, authenticated;
REVOKE ALL ON verification_tokens  FROM anon, authenticated;
REVOKE ALL ON verified_domains     FROM anon, authenticated;
REVOKE ALL ON audit_log            FROM anon, authenticated;
REVOKE ALL ON rate_limits          FROM anon, authenticated;
REVOKE ALL ON abuse_reports        FROM anon, authenticated;
REVOKE ALL ON schema_migrations    FROM anon, authenticated;


-- ──────────────────────────────────────────────────────────────────────────
-- audit_log is APPEND ONLY — even the service role cannot UPDATE or DELETE.
-- ──────────────────────────────────────────────────────────────────────────
-- This is enforced at the grant level, not via RLS, because RLS policies
-- can be added/removed at runtime but revokes require a migration.
REVOKE UPDATE, DELETE ON audit_log FROM service_role;

-- Only the prune job (run as a Supabase cron, see migration 005) should
-- be able to delete non-flagged rows past the retention window. Cron jobs
-- in Supabase run with superuser privileges, so they can bypass this.
-- Explicit note for future me:
--
--   To delete rows as part of retention, run the cleanup function defined
--   in migration 005 via cron. Do NOT grant DELETE back to service_role.

COMMENT ON TABLE audit_log IS
    'APPEND ONLY. UPDATE/DELETE revoked from service_role. Managed by pg_cron (see migration 005).';


-- ──────────────────────────────────────────────────────────────────────────
-- schema_migrations is also append-only (migrations never get un-applied
-- without a conscious manual intervention).
-- ──────────────────────────────────────────────────────────────────────────
REVOKE UPDATE, DELETE ON schema_migrations FROM service_role;
