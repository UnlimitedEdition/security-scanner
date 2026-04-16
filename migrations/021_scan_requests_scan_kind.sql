-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)

-- Migration 021 — scan_requests.scan_kind: distinguish main vs malware wizards
--
-- The wizard state machine (migration 014) was originally designed for the
-- main 240+ check scanner. The Malware Scanner product (migration 020) now
-- needs the same gate-before-scan flow — 3 consents → ownership verification
-- → 3-second recap countdown — but produces malware_scans rows, not scans.
--
-- Rather than duplicating the entire scan_requests table + six /scan/request
-- wizard endpoints, we add a scan_kind discriminator:
--
--   * 'main'    — existing behavior. /execute creates a scans row and
--                 enqueues the async scanner.
--   * 'malware' — /execute runs malware_scanner.scan_malware(mode='full')
--                 synchronously, writes malware_scans, returns the result
--                 in the same HTTP response (no polling needed).
--
-- Default 'main' keeps every existing row unchanged; the malware wizard
-- explicitly passes scan_kind='malware' at /scan/request creation time.
--
-- ┌────────────────────────────────────────────────────────────────────────┐
-- │ SECURITY — this column is set ONCE at /scan/request creation. It is    │
-- │ never mutated afterwards, so a compromised frontend cannot flip a      │
-- │ 'main' wizard to 'malware' (or vice versa) mid-flow to bypass gates.   │
-- │ /execute reads the original scan_kind value and dispatches accordingly.│
-- └────────────────────────────────────────────────────────────────────────┘

ALTER TABLE scan_requests
    ADD COLUMN IF NOT EXISTS scan_kind TEXT NOT NULL DEFAULT 'main'
        CHECK (scan_kind IN ('main', 'malware'));

COMMENT ON COLUMN scan_requests.scan_kind IS
    'Discriminator: ''main'' runs the 240+ check scanner (async, scans table), ''malware'' runs the 18-check malware scanner (sync, malware_scans table). Set at /scan/request creation, immutable afterwards.';

-- Index not needed — every wizard row goes through a dispatch lookup
-- exactly once (at /execute time) and the table is pruned to <1000 rows
-- by migration 015's cron job. A full scan of a small table is faster
-- than a B-tree hit on a two-value column.
