-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
--
-- ============================================================================
-- Migration 011 — Paid Pro plan subscriptions (Lemon Squeezy)
-- ============================================================================
-- Introduces three tables that together implement the paid Pro tier:
--
--   1. subscriptions            — one row per paying customer, tied to their
--                                 Lemon Squeezy subscription. Carries the
--                                 license_key we hand out on purchase, the
--                                 plan name, the period window, and the
--                                 cancellation state.
--
--   2. lemon_webhook_events     — append-only log of every webhook Lemon
--                                 Squeezy has sent us. Primary key enforces
--                                 idempotency (Lemon retries on 5xx, we
--                                 must never double-apply an event). Useful
--                                 for debugging "why is this user's status
--                                 wrong" — the full event payload is here.
--
--   3. magic_links              — short-lived tokens for email-based login.
--                                 User types email → we generate a token →
--                                 email the link → user clicks → we
--                                 exchange the token for a session cookie.
--                                 Tokens expire in 15 minutes and are
--                                 single-use.
--
-- Identity model for Pro users:
--   The scanner has no traditional login. A Pro user proves status two ways:
--
--     (a) License key (32-char random) — stored in localStorage on the
--         frontend. Every API call sends X-License-Key header. Backend
--         looks up subscriptions.license_key → status check → allow/deny.
--
--     (b) Email magic link — if user clears browser / switches device,
--         they enter their email on /login, get a magic link, click,
--         backend sets a session cookie, they're in again.
--
-- Both paths resolve to the same subscriptions row keyed by email.
--
-- ============================================================================


-- ──────────────────────────────────────────────────────────────────────────
-- 1. subscriptions — one row per paying Pro customer
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS subscriptions (
    id                      BIGSERIAL PRIMARY KEY,

    -- Identity (what we use to look up this row at runtime)
    email                   TEXT NOT NULL,            -- stored lowercased by the backend
    license_key             TEXT,                     -- populated by license_key_created webhook (nullable — may arrive after subscription_created)

    -- Lemon Squeezy identifiers (all nullable until webhook lands)
    lemon_customer_id       BIGINT NOT NULL,          -- customer across subscriptions
    lemon_subscription_id   BIGINT NOT NULL,          -- this specific subscription
    lemon_order_id          BIGINT,                   -- initial checkout order
    lemon_product_id        BIGINT NOT NULL,          -- which product (Web Security Scanner Pro)
    lemon_variant_id        BIGINT NOT NULL,          -- which variant (monthly / yearly)

    -- Plan state
    plan_name               TEXT NOT NULL
                            CHECK (plan_name IN ('pro_monthly', 'pro_yearly')),

    status                  TEXT NOT NULL
                            CHECK (status IN (
                                'on_trial',       -- trial period, not yet charged
                                'active',         -- paying, renewing
                                'paused',         -- user-initiated pause (Lemon supports)
                                'past_due',       -- payment failed, in dunning
                                'unpaid',         -- dunning exhausted
                                'cancelled',      -- user cancelled, still valid until current_period_end
                                'expired'         -- past current_period_end, no access
                            )),

    -- Period tracking (refreshed on every subscription_updated webhook)
    trial_ends_at           TIMESTAMPTZ,              -- NULL if no trial
    current_period_start    TIMESTAMPTZ NOT NULL,
    current_period_end      TIMESTAMPTZ NOT NULL,     -- access is allowed while NOW() < this
    cancelled_at            TIMESTAMPTZ,              -- when the user hit cancel

    -- Housekeeping
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Uniqueness
    CONSTRAINT subscriptions_email_unique           UNIQUE (email),
    CONSTRAINT subscriptions_license_key_unique     UNIQUE (license_key),
    CONSTRAINT subscriptions_lemon_sub_id_unique    UNIQUE (lemon_subscription_id)
);

COMMENT ON TABLE subscriptions IS
    'Paid Pro plan subscriptions keyed by Lemon Squeezy subscription_id. One row per customer; email is unique so a customer upgrading plans reuses the same row.';

COMMENT ON COLUMN subscriptions.license_key IS
    'License key issued by Lemon Squeezy (format XXXX-XXXX-XXXX-XXXX). Stored in this row by the license_key_created webhook handler, which typically arrives shortly after subscription_created. Nullable until that second event is processed.';

COMMENT ON COLUMN subscriptions.status IS
    'Lemon Squeezy subscription status. See https://docs.lemonsqueezy.com/api/subscriptions — our status column mirrors theirs 1:1.';

COMMENT ON COLUMN subscriptions.current_period_end IS
    'Pro features are allowed while NOW() < current_period_end, regardless of status. Cancelled users keep access until this timestamp, then flip to expired.';


-- Indexes
CREATE INDEX IF NOT EXISTS idx_subscriptions_email
    ON subscriptions (LOWER(email));

CREATE INDEX IF NOT EXISTS idx_subscriptions_license_key
    ON subscriptions (license_key)
    WHERE license_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_subscriptions_lemon_sub_id
    ON subscriptions (lemon_subscription_id);

CREATE INDEX IF NOT EXISTS idx_subscriptions_status_period
    ON subscriptions (status, current_period_end)
    WHERE status IN ('active', 'on_trial', 'cancelled');


-- ──────────────────────────────────────────────────────────────────────────
-- 2. lemon_webhook_events — append-only idempotency log
-- ──────────────────────────────────────────────────────────────────────────
-- Lemon Squeezy retries webhooks up to 3 times on 5xx responses. Without
-- idempotency, a retried "subscription_created" would create duplicate
-- rows. We dedupe by lemon_event_id.
--
-- Also doubles as a debug log: every webhook we ever received, raw payload,
-- what we did with it. When a user says "my sub is wrong" we can replay.
--
-- APPEND ONLY: UPDATE/DELETE revoked from service_role in the grants block
-- below. If you need to prune, add a pg_cron job that runs as superuser,
-- same pattern as audit_log.
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lemon_webhook_events (
    id                  BIGSERIAL PRIMARY KEY,

    -- Lemon's unique event ID (from the X-Event-Name and request ID headers)
    lemon_event_id      TEXT NOT NULL,
    event_name          TEXT NOT NULL,                -- e.g. "subscription_created"

    -- Full payload for replay / debugging
    payload             JSONB NOT NULL,

    -- Processing outcome
    result              TEXT NOT NULL
                        CHECK (result IN (
                            'ok',           -- processed successfully
                            'skipped',      -- dedup hit, event already seen
                            'ignored',      -- event type we don't care about
                            'error'         -- processing threw, will be retried by Lemon
                        )),
    error_message       TEXT,                         -- populated if result='error'

    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT lemon_webhook_events_event_id_unique UNIQUE (lemon_event_id)
);

COMMENT ON TABLE lemon_webhook_events IS
    'Append-only log of every Lemon Squeezy webhook received. Primary dedup via lemon_event_id unique constraint. UPDATE/DELETE revoked from service_role.';


CREATE INDEX IF NOT EXISTS idx_lemon_events_event_name
    ON lemon_webhook_events (event_name);

CREATE INDEX IF NOT EXISTS idx_lemon_events_received_at
    ON lemon_webhook_events (received_at DESC);


-- ──────────────────────────────────────────────────────────────────────────
-- 3. magic_links — short-lived email login tokens
-- ──────────────────────────────────────────────────────────────────────────
-- Flow:
--   1. User on /login enters email.
--   2. Backend generates 64-char random token, inserts row, emails link.
--   3. User clicks link → GET /api/auth/magic/verify?token=xxx
--   4. Backend validates: not expired, not used, matches. Sets cookie.
--   5. Marks used_at = NOW() so the token cannot be replayed.
--
-- Expired tokens are pruned daily by the cleanup job added in a follow-up
-- migration (see migration 012 when it exists). For now, the index on
-- expires_at supports manual pruning.
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS magic_links (
    id              BIGSERIAL PRIMARY KEY,

    email           TEXT NOT NULL,                    -- lowercased by backend
    token           TEXT NOT NULL,                    -- 64-char url-safe random
    ip_hash         TEXT,                             -- requester fingerprint (optional, for abuse detection)

    expires_at      TIMESTAMPTZ NOT NULL,             -- +15 min from created_at
    used_at         TIMESTAMPTZ,                      -- NULL = unused, NOT NULL = consumed

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT magic_links_token_unique UNIQUE (token)
);

COMMENT ON TABLE magic_links IS
    'Short-lived email login tokens (15 min TTL, single-use). Backend validates: NOT used_at AND NOW() < expires_at.';


CREATE INDEX IF NOT EXISTS idx_magic_links_email
    ON magic_links (LOWER(email));

CREATE INDEX IF NOT EXISTS idx_magic_links_expires_at
    ON magic_links (expires_at);

-- Partial index for "pending" lookups (covers the hot path)
CREATE INDEX IF NOT EXISTS idx_magic_links_unused
    ON magic_links (token)
    WHERE used_at IS NULL;


-- ──────────────────────────────────────────────────────────────────────────
-- 4. Row Level Security
-- ──────────────────────────────────────────────────────────────────────────
-- Same pattern as the rest of the project: RLS on, no anon/authenticated
-- policies (default deny), backend uses service_role which bypasses RLS.
-- ──────────────────────────────────────────────────────────────────────────
ALTER TABLE subscriptions         ENABLE ROW LEVEL SECURITY;
ALTER TABLE lemon_webhook_events  ENABLE ROW LEVEL SECURITY;
ALTER TABLE magic_links           ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON subscriptions         FROM anon, authenticated;
REVOKE ALL ON lemon_webhook_events  FROM anon, authenticated;
REVOKE ALL ON magic_links           FROM anon, authenticated;


-- ──────────────────────────────────────────────────────────────────────────
-- 5. Append-only enforcement for lemon_webhook_events
-- ──────────────────────────────────────────────────────────────────────────
-- Webhook events are historical facts — they should never be updated or
-- deleted by the application. If we need to prune, that's a pg_cron job
-- running as superuser (same pattern as audit_log).
-- ──────────────────────────────────────────────────────────────────────────
REVOKE UPDATE, DELETE ON lemon_webhook_events FROM service_role;


-- ──────────────────────────────────────────────────────────────────────────
-- 6. updated_at trigger for subscriptions
-- ──────────────────────────────────────────────────────────────────────────
-- Keeps subscriptions.updated_at fresh on every row modification without
-- the backend having to remember to set it. The function is idempotent
-- (OR REPLACE) in case an earlier migration already defined it.
-- ──────────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql
   SECURITY DEFINER
   SET search_path = public, pg_temp;

DROP TRIGGER IF EXISTS subscriptions_set_updated_at ON subscriptions;
CREATE TRIGGER subscriptions_set_updated_at
    BEFORE UPDATE ON subscriptions
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();
