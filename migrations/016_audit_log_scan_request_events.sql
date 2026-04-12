-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
--
-- ============================================================================
-- Migration 016 — extend audit_log event vocabulary for scan_requests flow
-- ============================================================================
-- The audit_log.event column has a CHECK constraint that lists every event
-- type the application is allowed to write. Migration 002 defined 12 events
-- covering the original flow (scan lifecycle, verification, abuse reports).
--
-- The new gate-before-scan flow (migrations 014, 015) needs four additional
-- event types so the consent → verification → execution wizard leaves a
-- complete forensic trail in audit_log:
--
--   * scan_request_created    — POST /scan/request created a new wizard row
--   * consent_set             — user ticked one of the 3 consent checkboxes
--                                (each click is its own audit row, with
--                                 details.consent_num = 1|2|3)
--   * consent_finalized       — all 3 consents recorded, status flipped to
--                                'consent_recorded'
--   * scan_request_executed   — final POKRENI button pressed, /execute
--                                handed off to scanner.scan(mode='full')
--   * scan_request_abandoned  — user explicitly cancelled the wizard, OR
--                                cron prune deleted a stale row (we log
--                                BEFORE the prune for the latter case)
--
-- Postgres does not let us ALTER an existing CHECK constraint in place; we
-- DROP it and recreate it with the expanded value list. The existing 12
-- values are preserved verbatim.
--
-- Why no DEFAULT or BACKFILL: the audit_log is append-only and we're not
-- changing any existing rows. The new constraint just permits future writes
-- to use the additional values.
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
        -- New events for the gate-before-scan flow (migration 014/015)
        'scan_request_created',
        'consent_set',
        'consent_finalized',
        'scan_request_executed',
        'scan_request_abandoned'
    ));
