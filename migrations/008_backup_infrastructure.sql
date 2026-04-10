-- ============================================================================
-- Migration 008 — backup infrastructure
-- ============================================================================
-- Sets up the offsite backup system:
--
--   1. Enables `pg_net` so the database can call HTTP endpoints
--      (needed so pg_cron can trigger the backup edge function).
--
--   2. Creates `backup_log` — a small audit table that records each
--      backup attempt, its outcome, and the R2 object key. This is how
--      we'll know if backups stop working without needing to poll R2.
--
--   3. Creates `prune_old_backup_log()` so the log doesn't grow forever.
--
--   4. Schedules the daily cron job that calls the `backup` edge function.
--      The webhook auth secret is read from Supabase Vault at call time,
--      never embedded in this file (which lives in git).
--
-- Secrets this migration depends on existing in vault.secrets:
--   - backup_webhook_secret  (set separately via execute_sql, NOT in git)
--
-- Free tier note: pg_net is available on all Supabase tiers. Edge functions
-- have a 500k invocation/month free tier limit — we use 30 (one per day),
-- so we have ~4 orders of magnitude of headroom.
-- ============================================================================


-- ──────────────────────────────────────────────────────────────────────────
-- 1. Enable pg_net extension
-- ──────────────────────────────────────────────────────────────────────────
-- pg_net installs objects into the `net` schema.
CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;


-- ──────────────────────────────────────────────────────────────────────────
-- 2. backup_log — record of every backup attempt
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS backup_log (
    id               BIGSERIAL PRIMARY KEY,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at     TIMESTAMPTZ,

    status           TEXT NOT NULL DEFAULT 'running'
                     CHECK (status IN ('running','success','error')),

    -- Outcome details
    r2_object_key    TEXT,                    -- e.g. "backups/2026/04/10/backup-20260410T040012Z.json.gz.enc"
    bytes_written    BIGINT,                  -- size of encrypted blob on R2
    rows_exported    JSONB,                   -- {"audit_log": 1234, "scans": 567, ...}
    error_message    TEXT,                    -- populated if status = 'error'

    -- Who kicked off the backup
    trigger_source   TEXT NOT NULL            -- 'cron' | 'manual' | 'test'
);

COMMENT ON TABLE backup_log IS
    'Audit trail of backup attempts. Populated by the backup edge function.';

CREATE INDEX IF NOT EXISTS idx_backup_log_started
    ON backup_log (started_at DESC);

CREATE INDEX IF NOT EXISTS idx_backup_log_status
    ON backup_log (status, started_at DESC)
    WHERE status != 'success';  -- partial index: cheap "show me failures"

-- Enable RLS + explicit deny (consistent with other tables)
ALTER TABLE backup_log ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON backup_log FROM anon, authenticated;

CREATE POLICY "deny_all_anon"          ON backup_log FOR ALL TO anon          USING (false) WITH CHECK (false);
CREATE POLICY "deny_all_authenticated" ON backup_log FOR ALL TO authenticated USING (false) WITH CHECK (false);


-- ──────────────────────────────────────────────────────────────────────────
-- 3. Prune function: keep last 180 days of backup_log (6 months)
-- ──────────────────────────────────────────────────────────────────────────
-- We keep successful backup records longer than we keep the actual R2
-- objects (which are pruned by R2 lifecycle rule at 90 days). That way
-- we still have a paper trail even after the blobs themselves are gone.
CREATE OR REPLACE FUNCTION prune_old_backup_log()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    DELETE FROM backup_log
     WHERE started_at < NOW() - INTERVAL '180 days';
END;
$$;


-- ──────────────────────────────────────────────────────────────────────────
-- 4. Schedule daily backup via pg_cron
-- ──────────────────────────────────────────────────────────────────────────
-- The cron job:
--   a) reads the webhook secret from Vault
--   b) calls the `backup` edge function via pg_net
--   c) the edge function does the actual export+encrypt+upload
--
-- We schedule at 04:00 UTC — 1 hour after `prune-audit-log` (03:00), so
-- the backup captures the post-prune state rather than a mix.

-- Unschedule first (idempotent re-runs)
SELECT cron.unschedule('daily-backup')
    WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'daily-backup');

SELECT cron.schedule(
    'daily-backup',
    '0 4 * * *',
    $$
    SELECT net.http_post(
        url := 'https://wmerashfovgaugxpexqo.supabase.co/functions/v1/backup',
        headers := jsonb_build_object(
            'Content-Type', 'application/json',
            'X-Webhook-Secret', (
                SELECT decrypted_secret
                  FROM vault.decrypted_secrets
                 WHERE name = 'backup_webhook_secret'
            )
        ),
        body := jsonb_build_object('trigger', 'cron'),
        timeout_milliseconds := 60000
    );
    $$
);

-- Schedule the backup_log prune alongside the other prunes
SELECT cron.unschedule('prune-backup-log')
    WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'prune-backup-log');
SELECT cron.schedule(
    'prune-backup-log',
    '10 3 * * *',   -- 03:10 UTC, chained after other prunes
    $$SELECT prune_old_backup_log();$$
);
