-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
--
-- ============================================================================
-- Migration 015 — scan_requests prune function + cron schedule
-- ============================================================================
-- The companion to migration 014. Defines:
--
--   1. prune_abandoned_scan_requests()  — DELETEs scan_requests rows that
--      stayed in pending_consent / consent_recorded / verified status for
--      more than 24 hours without progressing to 'executing'.
--
--   2. cron job 'prune-abandoned-scan-requests' — runs the function once
--      per hour.
--
-- The function is SECURITY DEFINER (runs as the function's owner, not the
-- caller) so pg_cron — which executes as superuser — can DELETE without
-- needing service_role grants. This matches the pattern of every other
-- prune_* function in migration 005.
--
-- CRITICAL: SET search_path = public, pg_temp is INLINE in the CREATE
-- FUNCTION statement, not added later in a hardening migration. Migration
-- 005 forgot this and migration 006 had to fix it. Doing both at once
-- avoids the linter flag `function_search_path_mutable` and avoids leaving
-- a window where the function is exploitable.
--
-- TTL rationale (24h):
--   * Long enough that a user who walks away from their laptop and comes
--     back in the morning still has a valid wizard state.
--   * Short enough that a stale row never lives long enough to skew rate
--     limits or fill the table.
--   * Bonus: 24h aligns with `created_date` being a DATE — yesterday's
--     rows are unambiguously eligible for prune regardless of clock skew.
--
-- Cron interval (hourly):
--   * Same cadence as `prune-rate-limits` (migration 005).
--   * Light query: hits the partial index `idx_scan_requests_prune` which
--     only contains rows still in the wizard. Even with thousands of
--     active wizards, it scans a few hundred bytes.
-- ============================================================================


-- ──────────────────────────────────────────────────────────────────────────
-- 1. The prune function
-- ──────────────────────────────────────────────────────────────────────────
-- We delete rows where created_date is at least one day in the past AND the
-- row is still in a wizard-active status. Rows that reached 'executing' or
-- 'completed' are kept indefinitely (the scan_id link gives them ongoing
-- forensic value). 'abandoned' status is reserved for rows the application
-- explicitly marks as cancelled — those are also pruned by this function.
CREATE OR REPLACE FUNCTION public.prune_abandoned_scan_requests()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    DELETE FROM scan_requests
     WHERE created_date < CURRENT_DATE - INTERVAL '1 day'
       AND status IN ('pending_consent', 'consent_recorded', 'verified', 'abandoned');
END;
$$;

COMMENT ON FUNCTION public.prune_abandoned_scan_requests() IS
    'Hourly cron job. DELETEs scan_requests rows older than 24h that never reached executing/completed. Search path is pinned to public, pg_temp to prevent SECURITY DEFINER privilege escalation through schema shadowing.';


-- ──────────────────────────────────────────────────────────────────────────
-- 2. Schedule the cron job
-- ──────────────────────────────────────────────────────────────────────────
-- Idempotent: unschedule first if it already exists, then schedule fresh.
-- This lets the migration be re-run safely (matches the pattern in 005).

SELECT cron.unschedule('prune-abandoned-scan-requests')
    WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'prune-abandoned-scan-requests');

SELECT cron.schedule(
    'prune-abandoned-scan-requests',
    '0 * * * *',                                  -- top of every hour
    $$SELECT prune_abandoned_scan_requests();$$
);
