-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
--
-- ============================================================================
-- Migration 014 — scan_requests: gate-before-scan ownership flow
-- ============================================================================
-- Introduces the table that backs the new "Full Scan" wizard. The old design
-- ran every check unconditionally and redacted sensitive findings AFTER the
-- fact, which meant target servers still saw probes for /.env, /wp-admin/,
-- /backup.sql, etc. — even when the requester had no claim to the domain.
--
-- This migration is the data-model half of the fix. The new flow is:
--
--   1. User picks "Full Scan" → POST /scan/request creates a row here with
--      status='pending_consent'.
--
--   2. Frontend opens the consent wizard. Each consent checkbox click hits
--      POST /scan/request/{id}/consent which sets consent_N_given=TRUE.
--      The button "Continue" only enables once all 3 are recorded
--      server-side (frontend state alone is not trusted).
--
--   3. POST /scan/request/{id}/consent/finalize verifies all 3 consents and
--      transitions status='consent_recorded'. Without this transition the
--      wizard cannot proceed to verification.
--
--   4. User picks a verify method (meta / file / dns), gets a token from
--      the existing verification_tokens table, places it on the target
--      site, then runs verification. On success, this row's
--      verify_passed=TRUE and status='verified'.
--
--   5. Final recap screen shows everything the user agreed to. On the final
--      "Run Full Scan" button, POST /scan/request/{id}/execute re-validates
--      everything (all 3 consents + verify_passed + verified_domains lookup),
--      flips status='executing', and starts scanner.scan(mode='full').
--
--   6. When scanner finishes, status='completed' and scan_id holds the FK
--      to the scans table row that holds the actual results.
--
-- Privacy / no-timing-leak design:
--   * created_date is DATE, not TIMESTAMPTZ. We deliberately do NOT store
--     wall-clock times for consent clicks or wizard progress. The forensic
--     trail goes through audit_log (which has TIMESTAMPTZ for compliance),
--     but THIS table only knows what day a request was created. That way,
--     even a full DB exfiltration cannot reveal "user X clicked consent #2
--     at 14:23:11 UTC" — only "user X had a request on 2026-04-12".
--
--   * Consent state is 3 BOOLEAN columns, not a single bitmask, so the
--     CHECK constraints can be readable and so each consent has its own
--     audit_log event for legal evidence. Bitmask saves 6 bytes; clarity
--     wins.
--
-- Cleanup:
--   prune_abandoned_scan_requests() in migration 015 deletes rows that
--   stayed in pending_consent / consent_recorded / verified for more than
--   24 hours without being executed. Runs hourly via pg_cron.
--
-- Backup:
--   scan_requests is intentionally NOT in TABLES_TO_BACKUP (db_export.ts).
--   Same reasoning as verification_tokens: short TTL, ephemeral state,
--   nothing of forensic value. The audit_log entries that THIS table
--   produces ARE backed up — that's where the legal trail lives.
-- ============================================================================


-- ──────────────────────────────────────────────────────────────────────────
-- 1. The table
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_requests (
    id                  TEXT PRIMARY KEY,        -- uuid4[:8], same shape as scans.id

    -- What the user wants to scan
    domain              TEXT NOT NULL,           -- normalized (no scheme, no port, no www.)
    url                 TEXT NOT NULL,           -- exact URL the user typed (for display)

    -- Wizard state machine
    status              TEXT NOT NULL DEFAULT 'pending_consent'
                        CHECK (status IN (
                            'pending_consent',   -- created, no consents yet
                            'consent_recorded',  -- all 3 consents recorded
                            'verified',          -- ownership proven via verify_method
                            'executing',         -- /execute called, scan in progress
                            'completed',         -- scanner finished, scan_id populated
                            'abandoned'          -- pruned by cron after TTL
                        )),

    -- Three independent consent checkboxes the user must explicitly tick.
    -- Each one is its own column so the audit_log event references which
    -- specific consent was given, and so the CHECK constraint at /execute
    -- time stays readable: "all three must be TRUE".
    consent_1_given     BOOLEAN NOT NULL DEFAULT FALSE,  -- "I own this domain or have written authorization"
    consent_2_given     BOOLEAN NOT NULL DEFAULT FALSE,  -- "I understand active probes will be sent"
    consent_3_given     BOOLEAN NOT NULL DEFAULT FALSE,  -- "I consent to 30-day storage of findings tied to my IP hash"

    -- Verification flow (mirrors verification_tokens but cached on the
    -- scan_request itself so /execute doesn't have to JOIN at high frequency)
    verify_method       TEXT CHECK (verify_method IN ('meta','file','dns') OR verify_method IS NULL),
    verify_token        TEXT,                    -- the token string we issued (no FK — verification_tokens has 1h TTL)
    verify_passed       BOOLEAN NOT NULL DEFAULT FALSE,

    -- Final recap confirmation — set to TRUE only by /execute, never by the
    -- frontend directly. Belt-and-suspenders for "user must click POKRENI".
    final_confirmed     BOOLEAN NOT NULL DEFAULT FALSE,

    -- Requester fingerprint (hashed, never raw — same pattern as scans table)
    client_ip_hash      TEXT NOT NULL,
    user_agent_hash     TEXT,

    -- Link to the actual scan once it starts. NULL until /execute runs.
    -- ON DELETE SET NULL: if the scan row is ever deleted, this row keeps
    -- its forensic value (we still know the request happened) but loses
    -- the link.
    scan_id             TEXT REFERENCES scans(id) ON DELETE SET NULL,

    -- DATE, not TIMESTAMPTZ. Deliberate. See header comment.
    created_date        DATE NOT NULL DEFAULT CURRENT_DATE
);

COMMENT ON TABLE scan_requests IS
    'Gate-before-scan ownership flow. One row per Full Scan attempt, tracks the wizard state machine through consent → verification → execution. Uses DATE not TIMESTAMPTZ for created_date to avoid leaking timing of consent clicks.';

COMMENT ON COLUMN scan_requests.created_date IS
    'DATE only — never TIMESTAMPTZ. Privacy-by-design: even a full DB exfiltration cannot reveal what time of day a user clicked consent boxes. The audit_log has timestamps for compliance, this table does not.';

COMMENT ON COLUMN scan_requests.consent_1_given IS
    'User confirmed they own the domain or have written authorization from its owner.';

COMMENT ON COLUMN scan_requests.consent_2_given IS
    'User confirmed they understand active probes will be sent to private files, admin panels, ports, and vulnerability checks.';

COMMENT ON COLUMN scan_requests.consent_3_given IS
    'User consented to 30-day storage of findings tied to their pseudonymized IP hash.';

COMMENT ON COLUMN scan_requests.final_confirmed IS
    'Set to TRUE only by /scan/request/{id}/execute on the final recap screen. Never set by the frontend. Belt-and-suspenders gate so a malicious client cannot skip the recap.';

COMMENT ON COLUMN scan_requests.scan_id IS
    'FK to scans(id), populated once /execute starts the scanner. NULL while the wizard is still in progress. ON DELETE SET NULL preserves the forensic record if the scan row is later pruned.';


-- ──────────────────────────────────────────────────────────────────────────
-- 2. Indexes
-- ──────────────────────────────────────────────────────────────────────────
-- a. Cron prune job needs to find abandoned rows quickly.
--    Partial index keeps the index small — once a row reaches 'completed'
--    or 'abandoned' it's no longer interesting to the prune query.
CREATE INDEX IF NOT EXISTS idx_scan_requests_prune
    ON scan_requests (created_date, status)
    WHERE status IN ('pending_consent','consent_recorded','verified');

-- b. Per-IP rate limiting on /scan/request endpoint — count how many
--    pending requests this IP has open RIGHT NOW so we can refuse to
--    create a 100th one from the same IP.
CREATE INDEX IF NOT EXISTS idx_scan_requests_ip
    ON scan_requests (client_ip_hash, created_date DESC);

-- c. Reverse lookup: given a scan_id, find which scan_request triggered it.
--    Useful for audit ("show me the consent trail for this scan").
--    Partial index because most scan_requests rows won't have a scan_id
--    until they reach 'executing'.
CREATE INDEX IF NOT EXISTS idx_scan_requests_scan_id
    ON scan_requests (scan_id)
    WHERE scan_id IS NOT NULL;


-- ──────────────────────────────────────────────────────────────────────────
-- 3. Row-Level Security
-- ──────────────────────────────────────────────────────────────────────────
-- Same pattern as every other table in this database:
--   * RLS enabled
--   * REVOKE all grants from anon/authenticated (defense in depth)
--   * Explicit deny policies for anon/authenticated (so the linter is happy
--     AND the intent is visible IN the schema, not just in grant state)
--   * service_role bypasses RLS — backend uses service_role, frontend never
--     touches this table directly
--
-- This time we add the explicit deny policies in the SAME migration as the
-- table, instead of in a follow-up cleanup migration like 007 had to do
-- after 002, or like 013 had to do after 011.
-- ──────────────────────────────────────────────────────────────────────────
ALTER TABLE scan_requests ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON scan_requests FROM anon, authenticated;

CREATE POLICY "deny_all_anon"          ON scan_requests FOR ALL TO anon          USING (false) WITH CHECK (false);
CREATE POLICY "deny_all_authenticated" ON scan_requests FOR ALL TO authenticated USING (false) WITH CHECK (false);
