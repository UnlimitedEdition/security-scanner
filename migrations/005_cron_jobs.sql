-- ============================================================================
-- Migration 005 — scheduled maintenance via pg_cron
-- ============================================================================
-- Supabase enables the `pg_cron` extension on all tiers. We use it to:
--
--   1. Expire pending verification tokens that hit their deadline
--   2. Prune unflagged audit_log rows older than 90 days
--   3. Clean up expired verified_domains grants
--   4. Clean up stale rate_limits windows
--
-- These functions run with superuser privileges via pg_cron, so they
-- can bypass the REVOKE DELETE on audit_log that applies to service_role.
-- ============================================================================


-- Make sure the extension is enabled. Supabase projects have it by default
-- but it's safe to request it explicitly.
CREATE EXTENSION IF NOT EXISTS pg_cron;


-- ──────────────────────────────────────────────────────────────────────────
-- Function: expire pending verification tokens
-- ──────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION expire_pending_verification_tokens()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    UPDATE verification_tokens
       SET status = 'expired'
     WHERE status = 'pending'
       AND expires_at < NOW();
END;
$$;


-- ──────────────────────────────────────────────────────────────────────────
-- Function: prune old unflagged audit_log rows (90-day retention)
-- ──────────────────────────────────────────────────────────────────────────
-- Flagged rows (linked to abuse reports or legal holds) are kept forever.
CREATE OR REPLACE FUNCTION prune_old_audit_log()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    DELETE FROM audit_log
     WHERE created_at < NOW() - INTERVAL '90 days'
       AND flagged = FALSE;
END;
$$;


-- ──────────────────────────────────────────────────────────────────────────
-- Function: clean up expired verified_domains
-- ──────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION prune_expired_verified_domains()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    DELETE FROM verified_domains
     WHERE expires_at < NOW();
END;
$$;


-- ──────────────────────────────────────────────────────────────────────────
-- Function: clean up stale rate_limits windows
-- ──────────────────────────────────────────────────────────────────────────
-- A rate limit row is stale when its window has fully elapsed and it
-- hasn't been updated since. We give a 2x buffer before deleting so
-- in-flight windows are never accidentally cleaned.
CREATE OR REPLACE FUNCTION prune_stale_rate_limits()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    DELETE FROM rate_limits
     WHERE window_start + (window_seconds * 2 || ' seconds')::interval < NOW();
END;
$$;


-- ──────────────────────────────────────────────────────────────────────────
-- Schedule the jobs
-- ──────────────────────────────────────────────────────────────────────────
-- cron.schedule(job_name, schedule, sql) — idempotent via unschedule-before-schedule
-- so the migration can be re-run safely.

-- Token expiry — every 5 minutes
SELECT cron.unschedule('expire-verification-tokens')
    WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'expire-verification-tokens');
SELECT cron.schedule(
    'expire-verification-tokens',
    '*/5 * * * *',
    $$SELECT expire_pending_verification_tokens();$$
);

-- Audit prune — once a day at 03:00 UTC
SELECT cron.unschedule('prune-audit-log')
    WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'prune-audit-log');
SELECT cron.schedule(
    'prune-audit-log',
    '0 3 * * *',
    $$SELECT prune_old_audit_log();$$
);

-- Verified domains prune — once a day at 03:05 UTC
SELECT cron.unschedule('prune-verified-domains')
    WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'prune-verified-domains');
SELECT cron.schedule(
    'prune-verified-domains',
    '5 3 * * *',
    $$SELECT prune_expired_verified_domains();$$
);

-- Rate limits prune — every hour
SELECT cron.unschedule('prune-rate-limits')
    WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'prune-rate-limits');
SELECT cron.schedule(
    'prune-rate-limits',
    '0 * * * *',
    $$SELECT prune_stale_rate_limits();$$
);
