# Architecture

High-level system map for Web Security Scanner v4.1.

## Deployment topology

```
                  ┌─────────────────────────────────┐
                  │ User browser                    │
                  │ (security-skener.gradovi.rs)    │
                  └──────────────┬──────────────────┘
                                 │
         ┌───────────────────────┴───────────────────────┐
         │ Vercel Edge (static hosting + CDN)            │
         │ • index.html, gallery.html, public-scan.html  │
         │ • blog-*.html (26 articles + 4 hubs)          │
         │ • privacy.html, terms.html, abuse-report.html │
         │ • Rewrites: /public/:id → /public-scan        │
         └───────────────────────┬───────────────────────┘
                                 │  fetch()
                                 ▼
         ┌───────────────────────────────────────────────┐
         │ HuggingFace Spaces (Docker)                   │
         │ • FastAPI (api.py, 3257 LOC)                  │
         │ • Scanner engine (scanner.py, 853 LOC)        │
         │ • 33 check modules (checks/)                  │
         │ • Python 3.11, async                          │
         └──────┬────────────────────┬──────────┬────────┘
                │                    │          │
                ▼                    ▼          ▼
         ┌──────────┐         ┌──────────┐ ┌──────────┐
         │ Target   │         │ Supabase │ │ Lemon    │
         │ sites    │         │ Postgres │ │ Squeezy  │
         │ (probes) │         │ + Vault  │ │ (Pro)    │
         └──────────┘         └────┬─────┘ └──────────┘
                                   │
                                   ▼
                              ┌──────────┐
                              │ R2       │
                              │ backups  │
                              │ (AES-GCM)│
                              └──────────┘
```

## Core flow: free public scan

1. User enters URL on `index.html`
2. Browser `POST /scan/quick` → FastAPI
3. Rate limit check (sliding window, 5 req / 30 min per IP hash)
4. SSRF filter (blocks private IPs, metadata endpoints, DNS
   rebinding)
5. `scanner.run_passive(url)` dispatches 20 passive modules in
   parallel
6. Results aggregated, grade computed, categories scored
7. Response streamed as SSE progress events
8. `audit_log` row written (fire-and-forget)

**No database row for quick scans.** Results live in the response
and the user's browser localStorage.

## Full scan flow (owner-verified)

1. User opens wizard (`index.html#wizard`)
2. Step 1 — consent: 3 checkboxes, persisted to `scan_requests`
   row with `created_date DATE` (no timestamp, anti-forensics)
3. Step 2 — verify token: `POST /scan/request/:id/verify/token`
   issues a short-lived token; user places it as meta tag / file /
   DNS TXT
4. Step 2 — verify: `POST /scan/request/:id/verify` checks ownership
5. Step 3 — recap + 3-sec anti-reflex delay
6. `POST /scan/request/:id/execute?strictness=...` runs the full
   30-check scan against the verified domain
7. Result persisted in `scans` table; owner can view, share, or
   publish to gallery

## Data model

Key tables (see `migrations/` for schema):

- `scans` — completed scan results (JSONB findings)
- `scan_requests` — wizard state (consent → verify → execute)
- `audit_log` — append-only forensic trail (UPDATE/DELETE revoked
  at DB role level)
- `public_scans` — V4 gallery entries (sanitized summaries, opt-in)
- `subscriptions` — Pro tier license keys from Lemon Squeezy
- `lemon_webhook_events` — idempotent webhook mirror
- `abuse_reports` — owner complaints; links to `domain_blocks`
- `domain_blocks` — domains permanently blocked from scanning
- `ip_rate_limits` — sliding-window rate counter

All PII (email, IP, fingerprint) is stored as `sha256(value || SERVER_SALT)` — never raw.

## Check modules

33 files in `checks/`. Each exposes a `run(url, ctx) → list[Finding]`
function. Scanner dispatches them via `asyncio.gather`. Representative
modules:

| Module | Scope |
|---|---|
| `ssl_check` | Certificate chain, expiry, cipher strength, OCSP |
| `dns_check` | SPF, DMARC, DKIM, CAA, DNSSEC, MX-conditional |
| `headers_check` | HSTS, CSP, X-Frame, Referrer, Permissions |
| `files_check` | 430 sensitive-file probes (`.env`, `.git/`, dumps) |
| `ports_check` | 203 dangerous-port probes with CDN fingerprinting |
| `gdpr_check` | Privacy policy, cookie consent, tracker census |
| `seo_check` | Meta, headings, canonical, sitemap, robots |
| `performance_check` | Response time, page weight, compression |
| `accessibility_check` | ARIA, lang attr, contrast hints |
| `email_security_check` | MX TLS, STARTTLS, MTA-STS, DANE, TLS-RPT |
| `vuln_check` | Known-vulnerable endpoint patterns |
| `admin_check` | Admin panel exposure (`/admin`, `/wp-admin/`) |
| `wellknown_check` | 24 `/.well-known/*` probes |

## Frontend

Single-page vanilla HTML + JS, no framework. `blog-common.js`
injects shared header, footer, cookie banner, self-XSS warning.
SR/EN toggle via `body.lang-en` class + `data-sr` / `data-en`
attributes.

## Security posture

- **SSRF**: every outbound request passes through `security_utils.py`
  (blocks private IPs, link-local, DNS rebinding, metadata endpoints)
- **PII**: SHA-256 hashed with server salt before DB write
- **Audit log**: append-only, UPDATE/DELETE revoked at DB role level
- **Backups**: daily encrypted (AES-256-GCM) to Cloudflare R2, keys
  in Supabase Vault
- **Rate limiting**: sliding window per IP hash, 5 scans / 30 min
- **CORS**: strict origin allowlist on backend
- **CSP**: `default-src 'self'`, narrow allowlist for Google Ads,
  Cloudflare Insights, Vercel Live

## Observability

- Backend logs → HF Spaces log stream (retained 7 days)
- `audit_log` table for forensic queries
- UptimeRobot pings `/health` every 5 min
- GA4 + AdSense on frontend (cookie-gated)

See `SECURITY.md` for threat model and disclosure policy.
