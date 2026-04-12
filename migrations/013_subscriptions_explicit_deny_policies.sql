-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
--
-- ============================================================================
-- Migration 013 — explicit DENY-ALL policies for subscription tables
-- ============================================================================
-- Migration 011 created three new tables (subscriptions, lemon_webhook_events,
-- magic_links), enabled RLS on them, and REVOKEd grants from anon and
-- authenticated. That's already airtight (no grants = nothing reaches the RLS
-- layer), but Supabase's database linter flags tables with RLS enabled and
-- zero policies as `rls_enabled_no_policy` (INFO).
--
-- Migration 007 added the same explicit deny policies for the original six
-- tables. This migration is the equivalent cleanup for migration 011 — same
-- pattern, same intent, just for the three subscription-related tables that
-- did not exist when 007 was written.
--
-- Reference: https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy
-- ============================================================================

-- subscriptions
CREATE POLICY "deny_all_anon"          ON subscriptions        FOR ALL TO anon          USING (false) WITH CHECK (false);
CREATE POLICY "deny_all_authenticated" ON subscriptions        FOR ALL TO authenticated USING (false) WITH CHECK (false);

-- lemon_webhook_events
CREATE POLICY "deny_all_anon"          ON lemon_webhook_events FOR ALL TO anon          USING (false) WITH CHECK (false);
CREATE POLICY "deny_all_authenticated" ON lemon_webhook_events FOR ALL TO authenticated USING (false) WITH CHECK (false);

-- magic_links
CREATE POLICY "deny_all_anon"          ON magic_links          FOR ALL TO anon          USING (false) WITH CHECK (false);
CREATE POLICY "deny_all_authenticated" ON magic_links          FOR ALL TO authenticated USING (false) WITH CHECK (false);
