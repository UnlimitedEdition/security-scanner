-- ============================================================================
-- Migration 007 — explicit DENY-ALL policies for anon/authenticated
-- ============================================================================
-- Migration 004 enabled RLS on every table and REVOKEd all grants for the
-- anon/authenticated roles. That's already airtight (no grants = nothing
-- reaches the RLS layer), but Supabase's database linter flags tables with
-- RLS enabled and zero policies as `rls_enabled_no_policy` (INFO).
--
-- To make the default-deny explicit IN the schema — so anyone reading it
-- sees the intent, not just the grant state — we add `USING (false)`
-- policies for each table targeting the anon and authenticated roles.
--
-- service_role is NOT targeted: it bypasses RLS, and that's how the backend
-- gets in.
--
-- Reference: https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy
-- ============================================================================

-- Helper pattern: one policy per table per role. Using FOR ALL covers
-- SELECT, INSERT, UPDATE, DELETE in a single definition.

-- scans
CREATE POLICY "deny_all_anon"          ON scans               FOR ALL TO anon          USING (false) WITH CHECK (false);
CREATE POLICY "deny_all_authenticated" ON scans               FOR ALL TO authenticated USING (false) WITH CHECK (false);

-- verification_tokens
CREATE POLICY "deny_all_anon"          ON verification_tokens FOR ALL TO anon          USING (false) WITH CHECK (false);
CREATE POLICY "deny_all_authenticated" ON verification_tokens FOR ALL TO authenticated USING (false) WITH CHECK (false);

-- verified_domains
CREATE POLICY "deny_all_anon"          ON verified_domains    FOR ALL TO anon          USING (false) WITH CHECK (false);
CREATE POLICY "deny_all_authenticated" ON verified_domains    FOR ALL TO authenticated USING (false) WITH CHECK (false);

-- audit_log
CREATE POLICY "deny_all_anon"          ON audit_log           FOR ALL TO anon          USING (false) WITH CHECK (false);
CREATE POLICY "deny_all_authenticated" ON audit_log           FOR ALL TO authenticated USING (false) WITH CHECK (false);

-- rate_limits
CREATE POLICY "deny_all_anon"          ON rate_limits         FOR ALL TO anon          USING (false) WITH CHECK (false);
CREATE POLICY "deny_all_authenticated" ON rate_limits         FOR ALL TO authenticated USING (false) WITH CHECK (false);

-- abuse_reports
CREATE POLICY "deny_all_anon"          ON abuse_reports       FOR ALL TO anon          USING (false) WITH CHECK (false);
CREATE POLICY "deny_all_authenticated" ON abuse_reports       FOR ALL TO authenticated USING (false) WITH CHECK (false);

-- schema_migrations
CREATE POLICY "deny_all_anon"          ON schema_migrations   FOR ALL TO anon          USING (false) WITH CHECK (false);
CREATE POLICY "deny_all_authenticated" ON schema_migrations   FOR ALL TO authenticated USING (false) WITH CHECK (false);
