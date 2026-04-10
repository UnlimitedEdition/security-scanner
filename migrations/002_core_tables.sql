-- ============================================================================
-- Migration 002 — core tables for Function 6
-- ============================================================================
-- Tables:
--   scans                   — scan results (replaces in-memory dict)
--   verification_tokens     — short-lived ownership verification tokens
--   verified_domains        — 30-day cache of verified (domain, ip_hash) pairs
--   audit_log               — append-only forensic trail
--   rate_limits             — persistent rate-limit counters
--   abuse_reports           — user-submitted abuse reports
--
-- All tables follow these rules:
--   * Primary keys use TEXT/UUID, not sequential ints (ids are not guessable)
--   * All timestamps are TIMESTAMPTZ (never naive)
--   * PII is stored as HASH, never raw (ip_hash, ua_hash)
--   * JSONB for flexible fields (scan results, audit details)
--   * NOT NULL wherever possible — prefer loud failure over silent nulls
-- ============================================================================


-- ──────────────────────────────────────────────────────────────────────────
-- scans — one row per scan request
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
    id                    TEXT PRIMARY KEY,       -- uuid4[:8]
    url                   TEXT NOT NULL,           -- what the user asked for
    domain                TEXT NOT NULL,           -- normalized domain for grouping
    status                TEXT NOT NULL CHECK (status IN ('queued','running','completed','error')),
    progress              INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    step                  TEXT,                    -- human-readable current step
    result                JSONB,                   -- full scan result blob once completed
    error                 TEXT,                    -- error message if status = 'error'

    -- Requester fingerprint (all hashed, never raw)
    ip_hash               TEXT NOT NULL,
    ua_hash               TEXT,
    session_id            UUID,                    -- client-side cookie, for correlating repeated visits
    fingerprint_hash      TEXT,                    -- optional canvas/webgl hash from frontend

    -- Consent & verification
    consent_accepted      BOOLEAN NOT NULL DEFAULT FALSE,
    consent_version       TEXT NOT NULL,           -- which ToS text was shown
    verified              BOOLEAN NOT NULL DEFAULT FALSE,
    verification_method   TEXT CHECK (verification_method IN ('meta','file','dns') OR verification_method IS NULL),

    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at          TIMESTAMPTZ
);

COMMENT ON TABLE scans IS
    'One row per scan. Replaces the in-memory scans dict in api.py.';


-- ──────────────────────────────────────────────────────────────────────────
-- verification_tokens — short-lived tokens for ownership proofs
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS verification_tokens (
    token           TEXT PRIMARY KEY,              -- cryptographically random, ~32 bytes hex
    domain          TEXT NOT NULL,
    method          TEXT NOT NULL CHECK (method IN ('meta','file','dns')),
    ip_hash         TEXT NOT NULL,

    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','verified','expired','failed')),
    attempts        INTEGER NOT NULL DEFAULT 0,    -- how many times we tried to verify

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,          -- +1h for pending, +30d for verified
    verified_at     TIMESTAMPTZ
);

COMMENT ON TABLE verification_tokens IS
    'Short-lived tokens. Successful verifications are copied into verified_domains with a longer TTL.';


-- ──────────────────────────────────────────────────────────────────────────
-- verified_domains — 30-day grant: "this ip_hash owns this domain"
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS verified_domains (
    id          BIGSERIAL PRIMARY KEY,
    domain      TEXT NOT NULL,
    ip_hash     TEXT NOT NULL,
    method      TEXT NOT NULL CHECK (method IN ('meta','file','dns')),

    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,              -- typically +30 days

    UNIQUE (domain, ip_hash)
);

COMMENT ON TABLE verified_domains IS
    'Cache of verified (domain, requester) pairs. Lets owners re-scan without re-verifying every time.';


-- ──────────────────────────────────────────────────────────────────────────
-- audit_log — APPEND ONLY forensic trail
-- ──────────────────────────────────────────────────────────────────────────
-- Every user action that touches the scanner gets a row here. Used for:
--   * Responding to abuse reports ("who scanned this domain and when")
--   * Responding to legal requests ("give us all activity from this IP range")
--   * Detecting attack patterns (many scans from same fingerprint_hash across IPs)
--   * Proving good-faith compliance in case of legal challenge
--
-- UPDATE and DELETE are revoked in migration 004 (rls_policies.sql). Rows
-- with flagged=TRUE are preserved past the normal 90-day retention.
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id                BIGSERIAL PRIMARY KEY,
    event             TEXT NOT NULL CHECK (event IN (
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
        'abuse_block_applied'
    )),

    scan_id           TEXT,                        -- nullable: verify events have no scan_id
    domain            TEXT,                        -- nullable

    ip_hash           TEXT NOT NULL,
    ua_hash           TEXT,
    fingerprint_hash  TEXT,
    session_id        UUID,

    details           JSONB NOT NULL DEFAULT '{}',
    flagged           BOOLEAN NOT NULL DEFAULT FALSE,  -- set TRUE to exempt from pruning

    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE audit_log IS
    'Append-only forensic trail. UPDATE and DELETE are revoked by migration 004.';


-- ──────────────────────────────────────────────────────────────────────────
-- rate_limits — persistent replacement for in-memory _rate_store
-- ──────────────────────────────────────────────────────────────────────────
-- Key scheme:
--   "ip:<ip_hash>"          — per-IP scans in rolling window (default 5/30m)
--   "ip_targets:<ip_hash>"  — distinct target domains per IP (default 3/24h)
--   "domain:<domain>"       — per-domain scan count (anti-abuse)
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limits (
    key              TEXT PRIMARY KEY,
    count            INTEGER NOT NULL DEFAULT 1,
    distinct_values  JSONB,                         -- for "ip_targets:*" keys, stores the set of seen domains
    window_start     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    window_seconds   INTEGER NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE rate_limits IS
    'Survives server restart. Replaces in-memory _rate_store in api.py.';


-- ──────────────────────────────────────────────────────────────────────────
-- abuse_reports — submitted by site owners who find their domain in scans
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS abuse_reports (
    id                  BIGSERIAL PRIMARY KEY,
    reported_domain     TEXT NOT NULL,
    reporter_email      TEXT,                      -- optional, hashed? raw for contact-back
    reporter_ip_hash    TEXT NOT NULL,
    description         TEXT,

    status              TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','reviewed','dismissed','confirmed')),
    related_scan_ids    TEXT[],                    -- array of scan IDs the reporter references

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at         TIMESTAMPTZ,
    reviewer_notes      TEXT
);

COMMENT ON TABLE abuse_reports IS
    'Submitted via the /abuse-report endpoint. Triggers flagging of related audit_log rows.';
