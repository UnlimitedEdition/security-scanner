-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
-- ============================================================================
-- Migration 018 — public scan gallery (V4 opt-in publish)
-- ============================================================================
-- After a scan completes, the person who ran it can opt in to publishing
-- the RESULT SUMMARY on /gallery.html. The principle is
-- "show quality, never dismiss" — no vulnerability specifics are stored
-- or exposed. The public detail page only shows: domain, grade, score,
-- strictness profile, counts per severity, per-category grades, date.
--
-- Key constraints enforced here:
--   * scan_id must reference a completed scans row (FK + subquery trigger)
--   * one public listing per scan (PK on scan_id)
--   * same domain cannot be republished by a different IP within 24h
--     (enforced in db.py, not via SQL — needs rate-limit context)
--   * withdraw is soft-delete: we keep the row for audit, but set
--     withdrawn_at and the listing endpoint filters WHERE withdrawn_at IS NULL
-- ============================================================================

CREATE TABLE IF NOT EXISTS public_scans (
    -- Primary key is the scan_id itself. One scan -> at most one public row.
    scan_id              TEXT PRIMARY KEY
                         REFERENCES scans(id) ON DELETE CASCADE,

    -- Denormalized fields so the gallery listing endpoint can render
    -- without JOIN + JSONB digging through scans.result on every request.
    -- If the underlying scan row is purged by retention cron, these stay
    -- (ON DELETE CASCADE drops the public row too, which is what we want).
    url                  TEXT NOT NULL,
    domain               TEXT NOT NULL,
    score                INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    grade                TEXT NOT NULL CHECK (grade IN ('A','B','C','D','F')),
    strictness           TEXT NOT NULL CHECK (strictness IN ('basic','standard','strict','paranoid')),
    total_checks         INTEGER NOT NULL CHECK (total_checks >= 0),
    failed_checks        INTEGER NOT NULL CHECK (failed_checks >= 0),

    -- Counts per severity (for the donut chart on the detail page).
    -- Stored as JSONB instead of 4 columns so adding severities later
    -- (e.g. INFO count) doesn't require a schema change.
    counts_json          JSONB NOT NULL,

    -- Per-category breakdown shown on the detail page. Shape:
    --   {
    --     "Security":      {"total": 150, "passed": 140, "grade": "A", "score": 95},
    --     "SEO":           {"total": 37,  "passed": 30,  "grade": "B", "score": 81},
    --     "Performance":   {"total": 20,  "passed": 18,  "grade": "A", "score": 90},
    --     "GDPR":          {"total": 7,   "passed": 7,   "grade": "A", "score": 100},
    --     "Accessibility": {"total": 17,  "passed": 15,  "grade": "B", "score": 88}
    --   }
    -- JSONB so adding/renaming categories doesn't need a migration.
    -- Never contains specific check names or failure reasons — the
    -- "show quality, never dismiss" principle is enforced here.
    categories_json      JSONB NOT NULL,

    -- Who published (hashed, never raw). Used to authorize withdraw
    -- from the same device, same as verified_domains.
    publisher_ip_hash    TEXT NOT NULL,
    publisher_fingerprint TEXT,

    published_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Soft-delete: withdrawn rows are kept for audit trail but filtered
    -- out of public listings. Once withdrawn, cannot be unwithdrawn —
    -- the publisher must run a new scan if they want to re-publish.
    withdrawn_at         TIMESTAMPTZ
);

COMMENT ON TABLE public_scans IS
    'Opt-in public gallery rows. One per published scan. V4 feature.';
COMMENT ON COLUMN public_scans.publisher_ip_hash IS
    'SHA-256 of the publishing client IP. Used to authorize withdraw.';
COMMENT ON COLUMN public_scans.withdrawn_at IS
    'Soft-delete marker. Listing endpoint filters WHERE withdrawn_at IS NULL.';


-- ──────────────────────────────────────────────────────────────────────────
-- Indexes
-- ──────────────────────────────────────────────────────────────────────────

-- Primary gallery listing query: newest first, only non-withdrawn.
-- Partial index is much smaller than a full index and still covers the
-- hot path because withdrawn rows are a minority by design.
CREATE INDEX IF NOT EXISTS idx_public_scans_published_desc
    ON public_scans (published_at DESC)
    WHERE withdrawn_at IS NULL;

-- Detail page + "already published?" lookup from the publish endpoint.
CREATE INDEX IF NOT EXISTS idx_public_scans_domain
    ON public_scans (domain)
    WHERE withdrawn_at IS NULL;

-- Rate-limit check: has this IP published anything in the last 24h?
CREATE INDEX IF NOT EXISTS idx_public_scans_publisher_ip
    ON public_scans (publisher_ip_hash, published_at DESC);


-- ──────────────────────────────────────────────────────────────────────────
-- Row-Level Security — mirrors other tables (default deny; service_role
-- bypasses RLS via its own grant, so the FastAPI backend using the
-- service key is unaffected).
-- ──────────────────────────────────────────────────────────────────────────

ALTER TABLE public_scans ENABLE ROW LEVEL SECURITY;

-- Public read: anyone (including anon role) can SELECT non-withdrawn
-- rows. This is the whole point — the gallery is public. We scope the
-- policy to only expose non-withdrawn rows so a client querying directly
-- cannot see soft-deleted history.
DROP POLICY IF EXISTS public_scans_select_public ON public_scans;
CREATE POLICY public_scans_select_public ON public_scans
    FOR SELECT
    TO anon, authenticated
    USING (withdrawn_at IS NULL);

-- Writes go ONLY through the service role (FastAPI). The publish /
-- withdraw endpoints enforce same-IP authorization before calling the
-- DB, so we don't need per-user RLS rules here.
DROP POLICY IF EXISTS public_scans_no_anon_write ON public_scans;
CREATE POLICY public_scans_no_anon_write ON public_scans
    FOR ALL
    TO anon, authenticated
    USING (false) WITH CHECK (false);
