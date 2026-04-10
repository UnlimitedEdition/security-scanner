-- ============================================================================
-- Migration 009 — RPC wrapper for reading backup secrets from Vault
-- ============================================================================
-- The `backup` edge function needs to read 7 secrets from Supabase Vault:
--     r2_account_id, r2_access_key_id, r2_secret_access_key,
--     r2_bucket, r2_endpoint,
--     backup_encryption_key, backup_webhook_secret
--
-- Supabase's standard `vault.decrypted_secrets` view requires SELECT on the
-- `vault` schema, which is granted only to `postgres` by default — the
-- `service_role` that edge functions use cannot read it directly.
--
-- Rather than grant `service_role` access to the entire vault schema (which
-- would expose ALL secrets, not just backup ones), we expose a narrow
-- SECURITY DEFINER function that returns ONLY the backup-related secrets
-- as a single jsonb object. service_role gets EXECUTE on this one function
-- and nothing else.
--
-- The secrets themselves are stored in vault.secrets via a one-off
-- execute_sql call at bootstrap time (NOT in this migration — secrets
-- never go in git). If the secrets are missing, the function raises a
-- loud error rather than returning an empty object silently.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.get_backup_secrets()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp, vault
AS $$
DECLARE
    result jsonb;
BEGIN
    SELECT jsonb_object_agg(name, decrypted_secret)
      INTO result
      FROM vault.decrypted_secrets
     WHERE name IN (
         'r2_account_id',
         'r2_access_key_id',
         'r2_secret_access_key',
         'r2_bucket',
         'r2_endpoint',
         'backup_encryption_key',
         'backup_webhook_secret'
     );

    IF result IS NULL OR jsonb_typeof(result) <> 'object' THEN
        RAISE EXCEPTION 'backup secrets not found in vault';
    END IF;

    RETURN result;
END;
$$;

-- Lock down EXECUTE — only service_role can call this.
-- anon/authenticated must never see the secrets, even indirectly.
REVOKE ALL ON FUNCTION public.get_backup_secrets() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.get_backup_secrets() TO service_role;
