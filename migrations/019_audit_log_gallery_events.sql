-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
--
-- ============================================================================
-- Migration 019 — extend audit_log event vocabulary for V4 gallery flow
-- ============================================================================
-- The V4 public gallery (migration 018) added two new audit events that the
-- API writes when a user publishes or withdraws a scan from the gallery:
--
--   * gallery_publish    — POST /api/public/{scan_id}/publish succeeded
--   * gallery_withdraw   — DELETE /api/public/{scan_id} succeeded
--
-- Without this migration, db.log_audit_event fails with check-constraint
-- violation 23514 every time a publish/withdraw runs. The publish itself
-- still succeeds (the audit write is fire-and-forget), but the forensic
-- trail is missing.
--
-- Postgres does not let us ALTER an existing CHECK constraint in place; we
-- DROP it and recreate it with the expanded value list. The existing 17
-- values from migrations 002 + 016 are preserved verbatim.
-- ============================================================================

ALTER TABLE audit_log
    DROP CONSTRAINT IF EXISTS audit_log_event_check;

ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_event_check
    CHECK (event IN (
        -- Original 12 events from migration 002
        'scan_request',
        'scan_start',
        'scan_complete',
        'scan_error',
        'scan_blocked_ssrf',
        'scan_blocked_rate_limit',
        'scan_truncated_deadline',
        'verify_request',
        'verify_success',
        'verify_failure',
        'abuse_report_submitted',
        'abuse_block_applied',
        -- 5 wizard events from migration 016
        'scan_request_created',
        'consent_set',
        'consent_finalized',
        'scan_request_executed',
        'scan_request_abandoned',
        -- 2 V4 gallery events (this migration)
        'gallery_publish',
        'gallery_withdraw'
    ));
