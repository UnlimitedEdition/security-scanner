-- ============================================================================
-- Migration 006 — harden search_path on all SECURITY DEFINER functions
-- ============================================================================
-- The functions defined in migration 005 run as SECURITY DEFINER, which
-- means they execute with the privileges of the function's owner (typically
-- postgres superuser) rather than the caller. That's necessary so pg_cron
-- can bypass the audit_log DELETE revoke from service_role.
--
-- But SECURITY DEFINER without an explicit search_path is a known attack
-- vector: an attacker with CREATE privileges on any schema in the resolver
-- path can shadow built-in operators or tables, and the function — running
-- with elevated rights — will use the attacker's objects.
--
-- Fix: pin search_path to `public, pg_temp` on every function. `pg_temp`
-- stays at the end so temporary tables still work, but nothing else from
-- an attacker-controlled schema can shadow our references.
--
-- Reference: https://supabase.com/docs/guides/database/database-linter?lint=0011_function_search_path_mutable
-- ============================================================================

ALTER FUNCTION public.expire_pending_verification_tokens() SET search_path = public, pg_temp;
ALTER FUNCTION public.prune_old_audit_log()               SET search_path = public, pg_temp;
ALTER FUNCTION public.prune_expired_verified_domains()    SET search_path = public, pg_temp;
ALTER FUNCTION public.prune_stale_rate_limits()           SET search_path = public, pg_temp;
