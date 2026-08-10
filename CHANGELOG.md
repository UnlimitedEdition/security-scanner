# Changelog

All notable changes to **Web Security Scanner** are documented here.

Format: [Conventional Commits](https://www.conventionalcommits.org/)
+ [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/).

---

## [4.3.0] — 2026-04-19

### Added

- `feat(malware)`: **Malware Scanner** as a standalone product
  (`/malware`) — 18 checks in two packs. Safe pack: blacklist, iframes,
  JS obfuscation, cryptojacking, drive-by, redirect chain, SEO spam,
  webshell indicators, cookie stealing, external scripts. Full pack:
  blacklist history, content modification, damage report, email
  reputation, index contamination, reputation score, SSL compromise,
  Wayback analysis
- `feat(db)`: migration 020 — `malware_scans` table
- `feat(malware)`: full scan wizard — 3 consents + domain verification
  + countdown
- `feat(malware)`: backend-gated wizard via `scan_requests`
  (`scan_kind='malware'`) — `/scan/request/{id}/execute` re-validates
  all 3 consents + `verify_passed` + `is_domain_verified` server-side,
  so a compromised frontend cannot bypass the gate
- `feat(db)`: migration 021 — `scan_requests.scan_kind`
  (`'main'` | `'malware'`), default `'main'`
- `security(malware)`: fingerprint + IP dual rate limiting — browser
  fingerprint (Canvas + WebGL + navigator, SHA-256) required on every
  wizard/scan request; no fingerprint → 403 (blocks curl), rotated IP
  with same fingerprint → 429 (blocks VPN rotation)
- `feat(malware)`: rate limit countdown timer (1 free scan / 24h)
- `feat(monetization)`: Phase 7 — Malware Pack purchase pipeline:
  Lemon Squeezy webhook (`order_created` + `license_key_created`),
  atomic credit consumption, post-purchase auto-activation via polling,
  masked/unmaskable license key in account panel, rate limit countdown
  timers on `index.html` and `pricing.html`, Pro users bypass all rate
  limits
- `feat(db)`: migration 022 — `subscriptions` widened for the
  `malware_pack` plan
- `feat(license)`: device fingerprint limiting — max 5 devices per
  license key, with device management in the account panel
- `feat(db)`: migration 023 — `license_activations` table
- `feat(affiliate)`: Lemon Squeezy affiliate tracking script on all
  purchase pages + affiliate program links across the site
- `feat(api)`: live scan load indicator — `/health` polled every 5s for
  active/queued scan count
- `feat(content)`: malware content pages (`faq-malware`,
  `faq-malware-recovery`, `blog-security-malware`,
  `blog-security-malware-recovery`), guides in a 3-column grid
  (detection, recovery, FAQ), category overview grid (6 cards —
  security, SEO, performance, a11y, GDPR, extra)
- `feat(blog)`: 6 Vibe Coding blog pages (AI code security, Next.js,
  Vercel, WordPress, first website, vibe coding) + responsive tables
  + footer column
- `feat(blog)`: timeline nav for `blog-features` categories
- `feat(ui)`: vertical 240+ badge + mobile hide-on-scroll for the
  checks button
- `feat(pricing)`: activation polling protection — prevents page reload
  during auto-activation
- `feat(pricing)`: `#activate` anchor for direct scroll to the
  activation section
- `docs`: `LEMON-SQUEEZY-SETUP.md` + per-directory `README.md` for
  `checks/`, `malware_scanner/`, `scripts/`, `supabase/`, `tests/`

### Changed

- `feat(api)`: max concurrent scans raised 3 → 8 (`_MAX_CONCURRENT`)
- `fix(ratelimit)`: backend scan limit 5/30min → 2/120min to match the
  pricing page
- `fix(malware)`: malware credits never expire — 30-day expiration
  removed from `subscription.py`, `db.py` and all UI copy
- `fix(lemon)`: `LEMON_PRODUCT_ID` split into per-product env vars
  (monthly, yearly, malware)
- `feat(content)`: 5 blog/FAQ pages expanded to the full bilingual
  400-800 line standard
- `docs(pricing)`: 14-day refund guarantee on the Pro Monthly card
- `fix(pricing)`: Free tier limits corrected — 2 scans/120min, PDF
  included
- `fix(ui)`: chrome `alert()` / `confirm()` replaced with styled modals
  for device limit and device removal
- `fix(account)`: logged-out users redirect to the activation form
  instead of generic pricing

### Fixed

- `fix(webhook)`: in-memory buffer for the race between
  `license_key_created` and `subscription_created`
- `fix(webhook)`: retroactive license key attach when
  `subscription_created` arrives after `license_key_created`;
  customer portal URL corrected
- `fix(webhook)`: email unique constraint on repeat purchases +
  fallback plan lookup by email for payment events
- `fix(webhook)`: `upsert` replaced with select + insert/update for
  partial unique index compatibility; missing `variant_id` in payment
  events handled
- `fix(malware)`: wizard gate race condition — modal now waits for the
  backend before opening
- `fix(malware)`: wizard execute double-unwrap — `renderScan` was
  receiving an empty result
- `fix(malware)`: drive-by false positive + port verify panel taken
  from `index.html`
- `fix(malware)`: Spamhaus error IPs (`127.255.255.254`) filtered out
  of RBL checks
- `fix(malware)`: URL input accepts bare domains (`gradovi.rs` →
  `https://gradovi.rs`)
- `fix(malware)`: consent field name + cross-link + inline DNS verify
  flow
- `fix(malware)`: standalone verify button + panel removed
- `fix(malware)`: consent checkbox stays `disabled=false` in `finally`
  (matches the `index.html` pattern)
- `fix(license)`: device activations use the Supabase PostgREST client
  instead of direct Postgres
- `fix(license)`: device fingerprint registered on page load when a
  license key is already present
- `fix(malware)`: mobile responsive layout on the new content pages
- `fix(blog)`: sticky header on `blog-features`
- `fix(hf)`: HuggingFace Space YAML frontmatter restored + logo rollout
- `fix(ui)`: homepage reverted to the original malware cross-link
  banner
- `fix(pricing)`: license key placeholder updated to UUID format

---

## [4.2.0] — 2026-04-14

### Added

- `feat(docs)`: complete documentation overhaul — production-grade README,
  ARCHITECTURE, CONTRIBUTING, SECURITY, FOR-DEVELOPERS, FOR-BUSINESS
- `feat(repo)`: GitHub Actions CI workflow (lint, test, security audit)
- `feat(repo)`: issue templates (bug report, feature request, new check)
- `feat(repo)`: pull request template with security checklist
- `feat(docs)`: integration examples for GitHub Actions, GitLab CI,
  Docker Compose
- `feat(configs)`: scanner configuration presets (minimal, standard,
  strict, paranoid)

### Changed

- `docs(readme)`: restructured with badges, feature comparison matrix,
  false positive strategy, CI/CD integration guides
- `docs(architecture)`: expanded with execution flow diagrams, module
  catalog, scoring engine, data model
- `docs(security)`: added threat model table, attack surface diagram,
  supply chain security section
- `docs(contributing)`: added step-by-step check creation guide with
  code templates

---

## [4.1.0] — 2026-04-14

### Fixed

- `fix(vercel)`: rewrite destination (`/public-scan.html` → `/public-scan`)
  — cleanUrls was causing 308 redirect that cached as 404 for all
  `/public/<id>` requests
- `fix(frontend)`: public scan page asset paths (`./blog-common.css` →
  `/blog-common.css`) so self-XSS warning, cookie banner, and stylesheet
  load under rewrite
- `fix(scanner)`: wizard `/execute` now sends `?strictness=` query param
  — user's picker choice was silently overwritten by `DEFAULT_STRICTNESS`
- `fix(frontend)`: scan progress step labels now translated to English
  when `lang-en` is active (backend always emits SR, frontend maps on
  the fly)
- `fix(checks)`: robots.txt User-agent group parser now RFC 9309
  compliant (case-insensitive matching)
- `fix(checks)`: port 8080 CDN header fingerprint — open port behind
  Cloudflare/Fastly/Akamai is the CDN's port, not the origin's
- `fix(checks)`: MX-conditional SPF/DMARC severity — domains without
  mail infrastructure get LOW instead of HIGH
- `fix(checks)`: privacy-page lookup path expansion for GDPR check
- `fix(frontend)`: abuse report links in `privacy.html` and `terms.html`
  now point to `/abuse-report#form` / `#form-en` instead of the removed
  `index.html#abuse` anchor

### Added

- `feat(db)`: migration 019 — extends `audit_log_event_check` to allow
  `gallery_publish` / `gallery_withdraw` events
- `feat(docs)`: `CHANGELOG.md`, `INSTALL.md`, `ARCHITECTURE.md`,
  `FOR-BUYERS.md`

### Removed

- `chore(repo)`: `CLAUDE.md` and `BLOG-TODO.md` from tracked files
  (internal workflow artifacts; stay local via `.gitignore`)

---

## [4.0.0] — 2026-04-13

### Added

- `feat(gallery)`: V4 public gallery (`/gallery`, `/public/<id>`) —
  opt-in publication of sanitized scan summaries (grade, score, severity
  counts; no vulnerability specifics, no tech fingerprints)
- `feat(db)`: migration 018 — `public_scans` table with publisher IP
  hashing and withdraw support
- `feat(scanner)`: strictness picker on wizard (`basic` / `standard` /
  `strict` / `paranoid`) — controls pass/fail thresholds per check
- `feat(wizard)`: 5-step wizard flow with gate-before-scan model:
  consent → token → verify → recap → execute
- `security(scanner)`: gate-before-scan model — `safe` mode (20 passive
  checks, zero private-surface probes) and `full` mode (33 checks,
  requires ownership verification)
- `security(api)`: IP binding on verification tokens — token must be
  verified from same IP that created it
- `security(db)`: 30-day verification cache per (domain, ip_hash) with
  daily cron pruning
- `security(api)`: legacy `/scan` endpoint hardcoded to `mode='safe'`
  regardless of request body

### Breaking Changes

- `BREAKING`: scan results now include `strictness` field in score object
- `BREAKING`: `/scan/request/{id}/execute` requires `?strictness=` query
  parameter (defaults to `standard` if omitted)

---

## [3.5.0] — 2026-04-10

### Added

- `feat(checks)`: WordPress deep-pass check (`wpscan_lite.py`) — plugin
  enumeration, user enumeration, XMLRPC, REST API exposure
- `feat(checks)`: well-known endpoint scanner (`wellknown_check.py`) —
  24 `/.well-known/*` probes per IETF/W3C standards
- `feat(checks)`: JWT token analysis (`jwt_check.py`) — algorithm
  detection, expiry validation, claim analysis
- `feat(checks)`: subdomain takeover detection (`takeover_check.py`) —
  dangling CNAME for 70+ cloud providers
- `feat(scanner)`: bot protection detection with retry logic (Cloudflare,
  Vercel, WAF blocks) + fallback mobile UA

### Fixed

- `fix(checks)`: content-signature file detection — `.env` files
  containing "error" in comments no longer false-negative
- `fix(security)`: SSRF protection extended to IPv4-mapped IPv6 addresses
  (`::ffff:127.0.0.1`)
- `fix(scanner)`: scan deadline enforcement moved to per-check level
  (was per-phase, allowing deadline overrun)

---

## [3.4.0] — 2026-04-06

### Added

- `feat(pro)`: PDF report export — branded A4 reports with severity
  breakdown, top priorities, and remediation guidance
- `feat(pro)`: multi-page scanning — crawl up to 10 same-origin pages
  with per-page findings
- `feat(api)`: `/api/discover` endpoint for two-phase page selection flow
- `feat(db)`: migration 016 — `subscriptions` table for Pro tier

### Changed

- `refactor(scanner)`: target-side rate limit (0.5s between pages) for
  multi-page scans

---

## [3.3.0] — 2026-04-01

### Added

- `feat(checks)`: email security check (`email_security_check.py`) —
  MX TLS, STARTTLS, MTA-STS, DANE, TLS-RPT
- `feat(checks)`: WHOIS analysis (`whois_check.py`) — domain age,
  registrar reputation, privacy protection
- `feat(checks)`: accessibility check (`accessibility_check.py`) — ARIA,
  lang attribute, image alt text

### Fixed

- `fix(scoring)`: diminishing returns cap was applied after bonus
  calculation instead of before, inflating scores by up to 8 points

---

## [3.2.0] — 2026-03-25

### Added

- `feat(risk)`: risk engine — prioritized remediation with composite
  scoring (severity × confidence × exposure × ROI)
- `feat(api)`: abuse report endpoint with legal-hold flagging on cited
  scan audit log rows
- `feat(db)`: migration 012 — `abuse_reports` table, `domain_blocks`

### Security

- `security(api)`: SSRF audit logging — `RequestValidationError` handler
  now logs `scan_blocked_ssrf` events with caller IP

---

## [3.1.0] — 2026-03-18

### Added

- `feat(frontend)`: SR/EN bilingual toggle via `body.lang-en` class
- `feat(blog)`: 26 security articles + 4 hub pages
- `feat(api)`: cookie consent script with granular 3-category banner

### Fixed

- `fix(api)`: HEAD method support for all static file routes (was
  blocking AdSense crawler, Google verification, robots.txt validation)

---

## [3.0.0] — 2026-03-10

### Added

- `feat`: initial public release on Vercel + HuggingFace Spaces
- `feat(scanner)`: 240+ passive + active checks across Security, SEO,
  Performance, GDPR, Accessibility
- `feat(api)`: FastAPI backend with rate limiting, CORS, security headers
- `feat(db)`: Supabase Postgres with RLS, pg_cron, Vault
- `feat(backup)`: daily encrypted backups to Cloudflare R2
- `feat(pro)`: Pro tier via Lemon Squeezy (license keys, 30-day history)

---

*Older releases predate the public repository.*
