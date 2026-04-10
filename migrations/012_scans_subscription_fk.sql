-- ============================================================================
-- Migration 012 — link scans to Pro subscriptions
-- ============================================================================
-- Adds a nullable subscription_id foreign key to the scans table so
-- Pro users can retrieve their own scan history through the
-- GET /api/subscription/scans endpoint. Free-tier scans keep
-- subscription_id NULL and are not included in any history query —
-- free users see their result once and that's it.
--
-- Design notes:
--
--   * Nullable: most scans will always be free-tier, and a NOT NULL
--     column would break every existing row. Using IF NOT EXISTS +
--     NULL is the only safe way to add this in production.
--
--   * ON DELETE SET NULL: subscription rows stick around with
--     status='expired' for legal retention (Serbian 10-year tax law),
--     so this cascade rule is defensive rather than expected. If a
--     subscription ever does get deleted, the related scans lose
--     the link but keep their data, which is exactly what we want
--     for a historical audit trail.
--
--   * Partial index: only Pro-initiated scans need to be searchable
--     by subscription_id. A partial index on (subscription_id, created_at)
--     WHERE subscription_id IS NOT NULL keeps the index small and the
--     history query fast (ORDER BY created_at DESC uses the index).
-- ============================================================================


ALTER TABLE public.scans
    ADD COLUMN IF NOT EXISTS subscription_id BIGINT
    REFERENCES public.subscriptions(id) ON DELETE SET NULL;

COMMENT ON COLUMN public.scans.subscription_id IS
    'FK to subscriptions.id for Pro-initiated scans. NULL for free tier scans. Populated by api.py start_scan when the caller presents an active Pro license key.';

CREATE INDEX IF NOT EXISTS idx_scans_subscription_id
    ON public.scans (subscription_id, created_at DESC)
    WHERE subscription_id IS NOT NULL;
