-- ============================================================================
-- Migration 010 — RPC: flag_audit_rows_for_scan_ids
-- ============================================================================
-- audit_log has UPDATE and DELETE revoked from service_role (see migration
-- 004) because it's append-only by design. That's the right default — we
-- don't want the backend to be able to rewrite forensic history on a whim.
--
-- But there's exactly ONE legitimate UPDATE we need: when a user submits
-- an abuse report that cites specific scan IDs, we want to flag those
-- scans' audit_log rows so they're exempt from the daily 90-day prune
-- job (`prune_old_audit_log()`, see migration 005). Flagged rows become
-- legal evidence and must survive past the normal retention window.
--
-- We solve this by exposing a narrow SECURITY DEFINER function that:
--   - runs as the function's owner (postgres superuser), bypassing the
--     service_role grant restriction
--   - only permits the specific UPDATE we need (set flagged=TRUE)
--   - never sets flagged=FALSE — once flagged, always flagged (that's
--     the whole point of legal hold)
--   - takes an array of scan_ids as input so the caller can't pass
--     arbitrary SQL
--
-- Only service_role can EXECUTE this function. anon/authenticated can't
-- even see it. If the function itself leaks (via SQL injection somewhere
-- in application code), the blast radius is "attacker can flag additional
-- audit rows" — which extends retention, it doesn't hide anything.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.flag_audit_rows_for_scan_ids(p_scan_ids text[])
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    updated_count integer;
BEGIN
    -- Defensive: if the array is NULL or empty, return 0 without touching
    -- the table. plpgsql lets us return early cheaply.
    IF p_scan_ids IS NULL OR array_length(p_scan_ids, 1) IS NULL THEN
        RETURN 0;
    END IF;

    UPDATE audit_log
       SET flagged = TRUE
     WHERE scan_id = ANY(p_scan_ids)
       AND flagged = FALSE;

    GET DIAGNOSTICS updated_count = ROW_COUNT;
    RETURN updated_count;
END;
$$;

-- Lock down EXECUTE — only service_role can call this.
-- anon/authenticated never see it, so they can't flag rows
-- (which would inflate retention and waste space).
REVOKE ALL ON FUNCTION public.flag_audit_rows_for_scan_ids(text[]) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.flag_audit_rows_for_scan_ids(text[]) TO service_role;

COMMENT ON FUNCTION public.flag_audit_rows_for_scan_ids(text[]) IS
    'Flag audit_log rows to exempt them from 90-day pruning. Called when '
    'an abuse report cites specific scans that need legal-evidence retention. '
    'Only service_role can call; audit_log UPDATE is otherwise revoked.';
