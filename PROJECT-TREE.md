# Web Security Scanner — Project Tree

> **Generisano:** 2026-04-10
> **Svrha:** Kompletna mapa projekta za code review / agent analysis.
> **Git HEAD:** `efbc526` (Phase 7.16 — cache-bust version marker)
> **Live deploys:**
> - Frontend: https://security-scanner-ruddy.vercel.app
> - Backend API: https://unlimitededition-web-security-scanner.hf.space
> - DB: Supabase project `wmerashfovgaugxpexqo`

---

## Ukupno

| Kategorija | Broj fajlova | Ukupno linija |
|---|---|---|
| Python (backend) | 28 | ~7,500 |
| HTML (frontend + blog) | 36 | ~15,000 |
| CSS | 1 standalone + inline u HTML-u | ~274 standalone |
| JavaScript | 1 standalone + inline u HTML-u | ~441 standalone |
| SQL (migrations) | 10 | ~820 |
| TypeScript (Supabase Edge Function) | 4 | ~622 |
| Markdown docs | 6 | ~3,400 |
| Config (Dockerfile, vercel.json, fly.toml, .gitignore, itd.) | ~8 | — |

---

## 📁 Directory Tree

```
security-scanner/
│
├── 📄 BACKEND — Python (FastAPI + scanner core)
│   ├── api.py                       1062 lines — FastAPI app, routes, middleware, endpoints
│   ├── scanner.py                    494 lines — Scan orchestrator, deadline, check runner
│   ├── db.py                         731 lines — Supabase wrapper + PII hashing + lifecycle helpers
│   ├── security_utils.py             283 lines — SSRF protection (safe_get/safe_head/safe_post)
│   ├── verification.py               375 lines — Function 6 ownership verification (meta/file/dns)
│   ├── risk_engine.py                188 lines — Score -> grade -> top-5 priorities + fix difficulty
│   ├── migration_runner.py           264 lines — SQL migration applier with checksum enforcement
│   ├── requirements.txt               11 lines — Python deps (fastapi, uvicorn, supabase, psycopg)
│   └── Dockerfile                     14 lines — Python 3.11-slim + uvicorn :7860
│
├── 📁 checks/                       Check modules (one per scan category)
│   ├── __init__.py                    0 lines — empty package marker
│   ├── accessibility_check.py       245 lines — WCAG a11y checks (alt text, ARIA, labels, tabindex)
│   ├── admin_check.py                233 lines — Admin panel discovery
│   ├── api_check.py                  245 lines — API security (GraphQL intro, Swagger, CORS, auth)
│   ├── cms_check.py                  170 lines — CMS fingerprint (WP, Joomla, jQuery, mixed content)
│   ├── cookies_check.py              111 lines — HttpOnly, Secure, SameSite cookie flags
│   ├── cors_check.py                 118 lines — CORS policy (wildcard, credentials, reflected)
│   ├── crawler.py                    129 lines — Page crawler (same-origin, SSRF-guarded)
│   ├── ct_check.py                    86 lines — Certificate Transparency logs
│   ├── dependency_check.py           293 lines — Outdated JS libs (jQuery, bootstrap, react)
│   ├── disclosure_check.py           123 lines — Server version, powered-by, debug, WP version leaks
│   ├── dns_check.py                  304 lines — SPF, DMARC, DNSSEC, nameserver checks
│   ├── email_security_check.py      163 lines — Email-related DNS hardening
│   ├── extras_check.py               208 lines — security.txt, CAA records, SRI
│   ├── files_check.py                354 lines — Exposed files (.env, .git, .bak, .sql, wp-config)
│   ├── gdpr_check.py                 307 lines — Cookie consent, privacy, trackers, forms HTTPS
│   ├── headers_check.py              161 lines — HSTS, CSP, X-Frame, X-Content, Referrer, Permissions
│   ├── js_check.py                   340 lines — Inline JS, unsafe sinks, localStorage leaks
│   ├── observatory_check.py          139 lines — Mozilla Observatory integration
│   ├── performance_check.py          355 lines — TTFB, page size, compression, cache, images
│   ├── ports_check.py                131 lines — Dangerous open ports (mongo, redis, rdp)
│   ├── redirect_check.py             116 lines — Redirect chain analysis
│   ├── robots_check.py               129 lines — robots.txt + sitemap validation
│   ├── seo_check.py                  447 lines — SEO (title, meta, OG, Twitter, schema)
│   ├── ssl_check.py                  170 lines — SSL/TLS version, cipher, cert expiry
│   ├── subdomain_check.py            140 lines — Subdomain discovery via CT logs
│   ├── tech_stack_check.py           153 lines — Framework detection (Django, Rails, Laravel)
│   ├── vuln_check.py                 348 lines — Passive vuln scan (SQLi, XSS, CSRF, dir listing)
│   └── whois_check.py                220 lines — WHOIS + domain age + registrar info
│
├── 📁 migrations/                   Supabase PostgreSQL schema history
│   ├── README.md                      92 lines — Migration rules & workflow
│   ├── 001_schema_migrations_table.sql          20 lines — Tracker table
│   ├── 002_core_tables.sql                     181 lines — 6 core tables
│   ├── 003_indexes.sql                         103 lines — Hot-path indexes
│   ├── 004_rls_policies.sql                     68 lines — RLS enabled, default deny
│   ├── 005_cron_jobs.sql                       128 lines — pg_cron scheduled cleanup
│   ├── 006_function_search_path_hardening.sql   24 lines — SET search_path on SECURITY DEFINER fns
│   ├── 007_explicit_deny_policies.sql           48 lines — USING (false) for anon/authenticated
│   ├── 008_backup_infrastructure.sql           135 lines — pg_net + backup_log + daily-backup cron
│   ├── 009_backup_secrets_rpc.sql               58 lines — get_backup_secrets() RPC
│   └── 010_flag_audit_rows_rpc.sql              63 lines — flag_audit_rows_for_scan_ids() RPC
│
├── 📁 supabase/functions/backup/    Supabase Edge Function (TypeScript / Deno)
│   ├── index.ts                      207 lines — Main handler: verify webhook, export, encrypt, upload
│   ├── db_export.ts                  137 lines — SELECT critical tables, build JSON payload
│   ├── crypto.ts                     104 lines — AES-256-GCM encrypt + gzip via Web Crypto API
│   └── r2_upload.ts                  174 lines — AWS SigV4 signing + PUT to Cloudflare R2
│
├── 📁 scripts/                      Developer-side tooling
│   ├── restore_backup.py             288 lines — CLI to download/decrypt/restore R2 backup
│   └── dr_drill_bootstrap.sql        892 lines — Concatenated migrations 001-010 for DR drill
│
├── 📄 FRONTEND — HTML pages (static, no build step)
│   ├── index.html                    2145 lines — Main scanner UI + consent + verify + scan logic
│   ├── blog-common.js                 441 lines — Shared header/footer/timeline/lang toggle + STOP banner
│   ├── blog-common.css                274 lines — Shared styles for blog layout
│   │
│   ├── 🔒 Legal / Policy Pages
│   │   ├── privacy.html               268 lines — Privacy Policy (SR + EN, Phase 1-3 accurate)
│   │   ├── terms.html                 194 lines — Terms of Service (SR + EN)
│   │   └── abuse-report.html          431 lines — Abuse report form + FAQ + process (SR + EN)
│   │
│   ├── 📰 Blog — Security articles
│   │   ├── blog-security.html           339 lines — Security overview + hub
│   │   ├── blog-security-ssl.html       725 lines — SSL/TLS guide
│   │   ├── blog-security-headers.html   724 lines — HTTP security headers
│   │   ├── blog-security-xss.html       586 lines — XSS guide
│   │   ├── blog-security-sql.html       855 lines — SQL injection
│   │   ├── blog-security-csrf.html      574 lines — CSRF
│   │   ├── blog-security-dns.html       521 lines — DNS security
│   │   ├── blog-security-ports.html     614 lines — Port scanning
│   │   └── blog-security-api.html       670 lines — API security
│   │
│   ├── 📰 Blog — SEO articles
│   │   ├── blog-seo.html                343 lines — SEO overview
│   │   ├── blog-seo-meta.html           528 lines — Meta tags
│   │   ├── blog-seo-schema.html         585 lines — Schema.org
│   │   ├── blog-seo-sitemap.html        521 lines — Sitemap.xml
│   │   ├── blog-seo-local.html          480 lines — Local SEO
│   │   ├── blog-seo-opengraph.html      447 lines — Open Graph
│   │   ├── blog-seo-headings.html       451 lines — H1-H6 hierarchy
│   │   └── blog-seo-mobile.html         429 lines — Mobile SEO
│   │
│   ├── 📰 Blog — Performance articles
│   │   ├── blog-performance.html        267 lines — Performance overview
│   │   ├── blog-perf-cwv.html           540 lines — Core Web Vitals
│   │   ├── blog-perf-images.html        434 lines — Image optimization
│   │   ├── blog-perf-cache.html         462 lines — HTTP caching
│   │   ├── blog-perf-compression.html   470 lines — Gzip + Brotli
│   │   ├── blog-perf-cdn.html           367 lines — CDN
│   │   └── blog-perf-lazy.html          442 lines — Lazy loading
│   │
│   ├── 📰 Blog — GDPR articles
│   │   ├── blog-gdpr.html               242 lines — GDPR overview
│   │   ├── blog-gdpr-cookies.html       417 lines — Cookie consent
│   │   ├── blog-gdpr-policy.html        377 lines — Privacy policy template
│   │   ├── blog-gdpr-trackers.html      325 lines — Third-party trackers
│   │   ├── blog-gdpr-rights.html        373 lines — User rights (linked from legal footer row)
│   │   └── blog-gdpr-fines.html         315 lines — GDPR fines overview
│   │
│   └── blog-features.html               128 lines — Features / product landing page
│
├── 📄 WEB CRAWLER META FILES
│   ├── robots.txt                       3 lines
│   ├── sitemap.xml                    208 lines (auto-generated sitemap of all pages)
│   ├── ads.txt                          1 line — AdSense publisher identification
│   ├── .well-known/security.txt         3 lines — Security contact
│   ├── google739403949172c6ee.html      Search Console verification file
│   └── google6b954a0930cdbbcc.html      Search Console verification file
│
├── 📄 DOCUMENTATION
│   ├── README.md                       29 lines — Project summary + quick start
│   ├── SECURITY.md                    156 lines — Public security policy (vulnerability reporting)
│   ├── PRIRUCNIK.md                  1644 lines — Operator handbook (SR) — 14 sections
│   ├── BLOG-TODO.md                   371 lines — Content roadmap for blog articles
│   ├── CLAUDE.md                       32 lines — Claude Code project config (SR + rules)
│   └── migrations/README.md            92 lines — Migration workflow & naming rules
│
├── 📄 DEPLOY CONFIG
│   ├── Dockerfile                      14 lines — HF Space container (Python 3.11 + uvicorn)
│   ├── vercel.json                     21 lines — Vercel static host + CSP headers
│   ├── fly.toml                        27 lines — Fly.io deploy config (alternative)
│   ├── start.sh                        12 lines — Linux launcher (uvicorn)
│   ├── start.bat                       46 lines — Windows dev launcher
│   └── .mcp.json                        7 lines — Claude MCP server config (Supabase)
│
├── 📄 ENV / GITIGNORE
│   ├── .env.example                   114 lines — Template with all env vars documented
│   ├── .env                               —    — GITIGNORED, real values (SERVICE_KEY, DB_URL, salt)
│   └── .gitignore                     101 lines — Paranoid secrets blocklist
│
└── 📄 BRANDING
    ├── logo.svg                        11 lines — Shield logo
    └── logo.png                        —        — PNG version
```

---

## 🔑 Backend module purpose map

### `api.py` (1062 lines) — FastAPI application root
- **Imports:** `fastapi`, `scanner`, `db`, `verification`, `security_utils`
- **Middleware:** `GZipMiddleware`, `CORSMiddleware`, `SecurityHeadersMiddleware` (custom CSP)
- **Routes:**
  - `GET /` + `/index.html`, `/privacy.html`, `/terms.html`, `/abuse-report.html`, `/blog-*.html`, `/blog-common.{css,js}`, `/ads.txt`, `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt` — all `[GET, HEAD]` for crawler compat
  - `POST /scan` — start scan with consent_accepted + rate limit + SSRF guard + domain block check
  - `GET /scan/{scan_id}` — poll scan state, with redaction gate for unverified users
  - `POST /verify/request` — generate ownership verification token
  - `POST /verify/check` — validate ownership proof (meta/file/dns)
  - `POST /abuse-report` — submit abuse report (domain, email, description, scan_ids)
  - `GET /health` — health check + db reachability
- **State:** in-memory `scans` dict as cache (DB is authoritative), `_scan_queue`, `_rate_store` backstop
- **Constants:** `MAX_VERIFY_ATTEMPTS=5`, `REDACTED_CHECK_PREFIXES`, `SENSITIVE_CHECK_PREFIXES`

### `scanner.py` (494 lines) — Scan orchestrator
- Runs all 23+ check modules in sequence
- Hard 180s deadline via `SCAN_DEADLINE_SECONDS`
- `run_check()` wrapper handles per-check exceptions
- Bot protection detection (Cloudflare, DataDome, Perimeter)
- SSL verify ALWAYS on (security scanner cannot skip cert validation)
- Progress callback for real-time UI updates

### `db.py` (731 lines) — Supabase wrapper
- **PII hashing:** `hash_pii()`, `hash_ip()`, `hash_ua()` with server-side salt
- **Scan lifecycle:** `create_scan`, `update_scan_progress`, `mark_scan_running/completed/error`, `get_scan_from_db`
- **Rate limiting:** `check_rate_limit()` (fixed-window counter in rate_limits table)
- **Audit:** `log_audit_event()` with 12 valid event types
- **Verification:** `create_verification_token`, `get_verification_token`, `mark_token_verified`, `upsert_verified_domain`, `is_domain_verified`
- **Abuse:** `create_abuse_report`, `flag_audit_rows_for_scans` (via RPC), `is_domain_blocked`
- **Graceful degradation:** everything wrapped in `_safe_db_call()` — DB outage logs warning but doesn't crash scans

### `security_utils.py` (283 lines) — SSRF protection
- `is_safe_target(url)` — resolves DNS, blocks localhost, link-local (169.254.169.254 = AWS metadata), private ranges, IPv6 ULA, broadcast
- `assert_safe_target(url)` — raises `UnsafeTargetError` if blocked
- `safe_get(session, url, ...)` / `safe_head` / `safe_post` — re-validates on every redirect hop
- Blocklist: `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`, `192.168.x`, `10.x`, `172.16-31.x`, `169.254.x`, `fc00::/7`

### `verification.py` (375 lines) — Function 6 ownership verification
- `normalize_domain()` — strips scheme/port/www, validates with regex
- `verify_via_meta()` — fetches homepage, regex-matches `<meta name="scanner-verify" content="...">`
- `verify_via_file()` — GETs `/.well-known/scanner-verify.txt`, expects first line == token
- `verify_via_dns()` — DNS TXT lookup on `_scanner-verify.<domain>` via 1.1.1.1/8.8.8.8/9.9.9.9
- `build_instructions()` — returns user-facing steps + code snippets in SR

### `risk_engine.py` (188 lines) — Score + priorities
- `SEVERITY_WEIGHT` (CRITICAL=10, HIGH=5, MEDIUM=3, LOW=1)
- `FIX_DIFFICULTY` per check_id (easy/medium/hard)
- `calculate_risk_score()` — weight × confidence × exposure
- `get_top_priorities()` — top 5 by risk score
- `CATEGORY_DEFAULT_DIFFICULTY` — prefix-based fallback for unknown check IDs

### `checks/*.py` (23 modules, ~4,300 lines total) — Individual scan implementations
Each module exports a `check_*()` function that takes `(url, session, response, base_domain)` and returns a list of finding dicts with standardized schema:
```
{
    "id": "file_env",           // unique check ID, prefix-based
    "category": "Files",
    "severity": "CRITICAL",
    "passed": False,
    "title": "...",
    "title_en": "...",
    "description": "...",
    "description_en": "...",
    "recommendation": "...",
    "recommendation_en": "...",
}
```

---

## 🗄️ Database schema (Supabase PostgreSQL)

### Tables (7 application + 1 backup log + 1 migrations)
| Table | Rows store | Retention | Special |
|---|---|---|---|
| `schema_migrations` | Applied migrations with checksums | Forever | UPDATE/DELETE revoked from service_role |
| `scans` | URL, domain, result JSONB, ip_hash, ua_hash, consent | Manual cleanup | RLS default-deny |
| `verification_tokens` | Pending challenges | 1h | Auto-expired by pg_cron |
| `verified_domains` | Successful (domain, ip_hash) grants | 30 days | UNIQUE (domain, ip_hash) |
| `audit_log` | All events | 90 days (unflagged) | APPEND-ONLY (UPDATE/DELETE revoked) |
| `rate_limits` | Fixed-window counters | Rolling window | Key = `ip:<hash>` or `domain:<d>` |
| `abuse_reports` | User complaints | Forever | Operator-managed lifecycle |
| `backup_log` | Daily backup audit | 180 days | Populated by edge function |

### RPC functions (SECURITY DEFINER)
- `get_backup_secrets()` — returns all 7 backup secrets from vault.decrypted_secrets (service_role only)
- `flag_audit_rows_for_scan_ids(text[])` — flags audit rows to exempt from pruning (bypasses audit_log REVOKE)
- `expire_pending_verification_tokens()` — scheduled cleanup
- `prune_old_audit_log()` — 90-day retention (flagged rows skipped)
- `prune_expired_verified_domains()` — 30-day retention
- `prune_stale_rate_limits()` — rolling window cleanup
- `prune_old_backup_log()` — 180-day retention

### pg_cron jobs (6 scheduled)
```
expire-verification-tokens  */5 * * * *   # every 5 min
prune-rate-limits           0 * * * *     # every hour
prune-audit-log             0 3 * * *     # daily 03:00 UTC
prune-verified-domains      5 3 * * *     # daily 03:05 UTC
prune-backup-log            10 3 * * *    # daily 03:10 UTC
daily-backup                0 4 * * *     # daily 04:00 UTC (triggers edge fn)
```

---

## ☁️ Deployment topology

```
┌─────────────────┐                       ┌──────────────────────────┐
│  End user       │                       │  Cloudflare R2           │
│  browser        │                       │  (encrypted backups)     │
└────────┬────────┘                       └──────────▲───────────────┘
         │                                           │
         │ HTTPS                          AWS SigV4  │
         │                                           │
         ▼                                           │
┌─────────────────┐   POST /scan       ┌──────────────────────────┐
│  Vercel static  │──────────────────▶│  HF Space Docker          │
│  frontend       │                    │  Python 3.11 + FastAPI    │
│  (index.html +  │  /verify/* /abuse  │                            │
│   blog-*.html)  │                    │  api.py → scanner.py →    │
└─────────────────┘                    │  23× checks/*.py           │
                                        │                            │
                                        │  db.py (Supabase client)   │
                                        └─────────┬──────────────────┘
                                                  │ HTTPS
                                                  ▼
                                        ┌──────────────────────────┐
                                        │  Supabase PostgreSQL     │
                                        │  (EU region)             │
                                        │                          │
                                        │  8 tables + Vault        │
                                        │  pg_cron + Edge Function │
                                        └──────────────────────────┘
                                                  │
                                                  │ daily 04:00 UTC
                                                  ▼
                                        ┌──────────────────────────┐
                                        │  Backup Edge Function    │
                                        │  (Deno / TypeScript)     │
                                        │                          │
                                        │  Export → gzip →         │
                                        │  AES-256-GCM → R2 upload │
                                        └──────────────────────────┘
```

---

## 🔐 Security posture summary

| Control | Implementation |
|---|---|
| **SSRF** | `security_utils.py` blocks private/local/metadata ranges, re-validates on every redirect hop |
| **Rate limiting** | DB-backed (rate_limits table) + in-memory backstop (5 scans / 30 min / IP) |
| **PII protection** | SHA-256 hash with server-side salt, raw IP/UA never in DB (GDPR Art. 4(5) pseudonymization) |
| **Audit trail** | Append-only `audit_log`, UPDATE/DELETE revoked from service_role, 90-day retention + legal hold flagging |
| **Row-Level Security** | Enabled on every table, default deny, service_role only |
| **Consent capture** | Every scan records `consent_accepted` + `consent_version` |
| **Encrypted backups** | Daily AES-256-GCM to Cloudflare R2 (offsite provider), 90-day retention |
| **Disaster recovery** | Tested restore via `scripts/restore_backup.py` against isolated staging (2026-04-10 drill passed) |
| **Ownership verification** | Meta tag / file / DNS TXT, 30-day grant per (domain, ip_hash) |
| **Abuse channel** | `/abuse-report` endpoint + dedicated `abuse-report.html` page |
| **Domain blocklist** | Confirmed reports → `is_domain_blocked()` → 403 on `/scan` |
| **CSP** | Wildcard for Google ad stack (*.g.doubleclick.net, *.googlesyndication.com, *.adtrafficquality.google), strict elsewhere |
| **HSTS** | 1 year max-age, includeSubDomains |
| **Self-XSS warning** | Bilingual STOP banner in devtools console (blog-common.js) |
| **Informed consent** | Consent checkbox links to terms.html + privacy.html |
| **Secret management** | Vault (Supabase) + HF Space Secrets + local .env (gitignored) |

---

## 📝 Notable files explained

### `CLAUDE.md` (32 lines)
Claude Code project configuration. Defines workflow rules (in Serbian), auto-plugin triggers, and git conventions.

### `PRIRUCNIK.md` (1644 lines)
Operator handbook in Serbian. Written as a "things to do when something breaks" reference, not a tutorial. Covers:
- §1-3: Architecture + what's stored + what's NOT stored
- §4: PII hashing rationale + GDPR posture
- §5: Three legal defense scenarios (angry email, police request, GDPR erasure)
- §6: Daily/weekly health check SQL
- §7: SQL cookbook (14 common queries)
- §8: Secret rotation with blast-radius matrix
- §9: "Never touch these"
- §10: Contact escalation
- §11: Ownership verification workflow
- §12: Abuse report triage playbook + reply templates
- §13: Deploy + live monitoring procedures
- §14: DR drill procedure + measured baseline (20 min)

### `SECURITY.md` (156 lines)
Public-facing security policy for vulnerability reporting. Lists in-scope/out-of-scope, commitment to audit trail, encryption, RLS, PII hashing.

### `.env.example` (114 lines)
Every env var the backend consumes, with threat model + rotation rules documented inline.

### `vercel.json` (21 lines)
Static deploy with CSP headers (via Vercel headers config, not FastAPI middleware — Vercel serves the HTML directly).

### `Dockerfile` (14 lines)
Minimal HF Space deploy target. Python 3.11-slim → pip install → copy → uvicorn.

### `scripts/dr_drill_bootstrap.sql` (892 lines)
Auto-generated concatenation of migrations 001-010, for single-paste application to a fresh Supabase project during DR drills.

### `scripts/restore_backup.py` (288 lines)
CLI tool: `--list`, `--inspect KEY`, `--latest`, `--apply`. Downloads from R2, decrypts AES-256-GCM, gunzips, INSERTs back via `psycopg` + `ON CONFLICT DO NOTHING` (idempotent).

---

## 🧪 What has been tested

| Test | Date | Result |
|---|---|---|
| SSRF protection | Phase 0 commit | ✅ redirect hops, link-local, private ranges all blocked |
| DB integration smoke test (Mode A: no env) | Phase 1 | ✅ graceful degradation, scanner still works |
| DB integration smoke test (Mode B: real Supabase) | Phase 1 | ✅ scans row + audit_log populated with hashed PII |
| Function 6 verification endpoint tests | Phase 2 | ✅ 8/8 endpoint tests (happy + error paths) |
| Meta regex parser unit test | Phase 2 | ✅ 7/7 (quotes, case, reversed attrs) |
| File body parser unit test | Phase 2 | ✅ 6/6 (whitespace, newlines) |
| Redaction logic test | Phase 2.7 | ✅ 5 sensitive redacted, 4 hardening intact |
| Abuse report endpoint tests | Phase 3 | ✅ 6/6 (happy + validation errors) |
| Domain block flow | Phase 3 | ✅ 403 on confirmed abuse domain |
| Backup pipeline (create → R2 upload) | Phase 0 | ✅ 3 backups on R2, all authenticated |
| DR drill — restore 29 audit_log rows to staging | Phase 6 (2026-04-10) | ✅ row counts match, content spot-checked |
| HF Space live production smoke | Phase 5 | ✅ /health reachable, POST /scan succeeds, full audit trail |
| Vercel live production | Phase 5 | ✅ all static files serve with correct CSP |

## 🚫 What has NOT been tested (honest disclosure)

- Full penetration test by third party
- Formal code audit
- Automated dependency vulnerability scan (`pip audit`, `bandit`, `safety`)
- Fuzzing of input parsers
- Load testing / DoS resilience
- Race condition analysis on concurrent scan submissions
- Browser compatibility matrix (Safari, Edge, older Chrome)
- Mobile UI responsive testing
- Accessibility audit (WAVE, axe)

---

## 🔄 Current git state

```
Branch: master
Remote: space (HF) + origin (GitHub)
HEAD: efbc526  Cache-bust blog-common.js + add visible version marker
```

Last ~21 commits (this session):
```
efbc526  Cache-bust blog-common.js + add visible version marker
5a1fbcc  Add self-XSS console warning (bilingual STOP banner)
34e7d84  api.py: add HEAD support to all static-file routes
583b840  consent checkbox: link to Terms + Privacy for GDPR informed consent
29928f3  abuse-report.html: fix 4 Serbian typos in FAQ section
dcfa638  Move abuse reporting to dedicated page + final CSP fix
cd4817b  CSP: use wildcards for Google ad stack + allow sodar2.js
ea0d923  Fix AdSense push() timing + expand CSP for ad telemetry
162ff68  Rewrite privacy.html to match Phase 1-3 reality
82f2fc2  Footer: separate legal links from blog content + fix data-sr bug
0830bf2  Phase 7 — Frontend polish + dev-context string cleanup
0fed487  Phase 6 — DR drill completed + PRIRUCNIK §14
b1adb2b  Fix Phase 2 redaction — gate by check_id prefix
c867fb8  Add PRIRUCNIK §13 — deploy + live monitoring playbook
30b43d8  Add /abuse-report endpoint + confirmed-report domain blocking
f61ac78  Add Function 6 — ownership verification + scan result gating
d81cb45  Wire db.py into api.py + add operator handbook (PRIRUCNIK.md)
f23dc3f  Clean up risk_engine fix-difficulty lookup + drop dead code
e0701ed  Add Supabase schema, RLS, cron jobs, and offsite backup pipeline
5d12d5e  Add Supabase DB layer foundation + secrets-aware .gitignore
af96240  Harden scanner against SSRF + enforce scan deadline
```

---

*End of project tree.*
