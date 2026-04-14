# Changelog

All notable changes to Web Security Scanner are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning: semantic.

## [4.1.0] — 2026-04-14

### Fixed
- Vercel rewrite destination (`/public-scan.html` → `/public-scan`)
  — cleanUrls was causing 308 redirect that cached as 404 for all
  `/public/<id>` requests
- Public scan page asset paths (`./blog-common.css` → `/blog-common.css`)
  so self-XSS warning, cookie banner, and stylesheet load under rewrite
- Wizard `/execute` now sends `?strictness=` query param — user's
  picker choice was silently overwritten by `DEFAULT_STRICTNESS`
- Scan progress step labels now translated to English when `lang-en`
  is active (backend always emits SR, frontend maps on the fly)
- Scanner false positives: robots.txt User-agent group parser
  (RFC 9309), port 8080 CDN header fingerprint, MX-conditional
  SPF/DMARC severity, privacy-page lookup path expansion
- Abuse report links in `privacy.html` and `terms.html` now point
  to `/abuse-report#form` / `#form-en` instead of the removed
  `index.html#abuse` anchor

### Added
- Migration 019 — extends `audit_log_event_check` to allow
  `gallery_publish` / `gallery_withdraw` events
- `CHANGELOG.md`, `INSTALL.md`, `ARCHITECTURE.md`, `FOR-BUYERS.md`

### Removed
- `CLAUDE.md` and `BLOG-TODO.md` from tracked files (internal
  workflow artifacts; stay local via `.gitignore`)

## [4.0.0] — 2026-04-13

### Added
- V4 public gallery (`/gallery`, `/public/<id>`) — opt-in publication
  of sanitized scan summaries (grade, score, severity counts; no
  vulnerability specifics, no tech fingerprints)
- Migration 018 — `public_scans` table with publisher IP hashing and
  withdraw support
- Strictness picker on wizard (`basic` / `standard` / `strict` /
  `paranoid`) — controls pass/fail thresholds per check
- 5-step wizard flow with gate-before-scan model: consent → token →
  verify → recap → execute

## [3.x] — 2026-03 – 2026-04

- Initial public release on Vercel + HuggingFace Spaces
- 240+ passive + active checks across Security, SEO, Performance,
  GDPR, Accessibility
- SR/EN bilingual UI, blog (26 articles + 4 hubs)
- Pro tier via Lemon Squeezy (license keys, 30-day history, PDF
  export, multi-page scans)

---

Older releases predate the public repo.
