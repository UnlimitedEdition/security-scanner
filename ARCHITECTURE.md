# Architecture

> **Version:** 4.1 · **Last updated:** 2026-04-14 · **Status:** Production

This document describes the system architecture of Web Security Scanner.
It is intended for contributors, security auditors, and potential acquirers.

---

## Table of Contents

- [Deployment Topology](#deployment-topology)
- [Scanning Engine](#scanning-engine)
- [Gate-Before-Scan Model](#gate-before-scan-model)
- [Check Module System](#check-module-system)
- [Scoring Engine](#scoring-engine)
- [Risk Engine](#risk-engine)
- [Data Model](#data-model)
- [Security Architecture](#security-architecture)
- [Frontend Architecture](#frontend-architecture)
- [Observability](#observability)
- [Performance Characteristics](#performance-characteristics)

---

## Deployment Topology

```
                                ┌─────────────────────────────────────┐
                                │         User Browser / CI           │
                                │    (security-skener.gradovi.rs)     │
                                └──────────────────┬──────────────────┘
                                                   │ HTTPS
                   ┌───────────────────────────────┴───────────────────────────────┐
                   │                    Vercel Edge (CDN)                          │
                   │  • index.html (scanner SPA, ~3800 LOC inline)                │
                   │  • gallery.html, public-scan.html                            │
                   │  • blog-*.html (26 articles + 4 hub pages)                   │
                   │  • privacy.html, terms.html, abuse-report.html               │
                   │  • Rewrites: /public/:id → /public-scan                      │
                   │  • cookie-consent.js, blog-common.{css,js}                   │
                   └───────────────────────────────┬───────────────────────────────┘
                                                   │ fetch() / SSE
                   ┌───────────────────────────────┴───────────────────────────────┐
                   │                HuggingFace Spaces (Docker)                    │
                   │                                                               │
                   │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
                   │  │   FastAPI    │  │   Scanner    │  │    Check Modules     │ │
                   │  │   api.py     │──│  scanner.py  │──│    checks/*.py       │ │
                   │  │  (3257 LOC)  │  │  (854 LOC)   │  │    (33 modules)      │ │
                   │  └──────┬──────┘  └──────┬───────┘  └──────────────────────┘ │
                   │         │                │                                    │
                   │  ┌──────┴──────┐  ┌──────┴───────┐  ┌──────────────────────┐ │
                   │  │  Security   │  │    Risk      │  │   PDF Report         │ │
                   │  │   Utils     │  │   Engine     │  │   Generator          │ │
                   │  │  (SSRF)     │  │              │  │   (fpdf2)            │ │
                   │  └─────────────┘  └──────────────┘  └──────────────────────┘ │
                   └─────────┬────────────────┬────────────────┬───────────────────┘
                             │                │                │
                    ┌────────┴──────┐  ┌──────┴─────┐  ┌──────┴──────┐
                    │  Target       │  │  Supabase   │  │  Lemon      │
                    │  Websites     │  │  Postgres   │  │  Squeezy    │
                    │  (probes)     │  │  + Vault    │  │  (Pro plan) │
                    └───────────────┘  │  + pg_cron  │  └─────────────┘
                                       └──────┬──────┘
                                              │
                                       ┌──────┴──────┐
                                       │ Cloudflare  │
                                       │ R2 Backups  │
                                       │ (AES-256-GCM)│
                                       └─────────────┘
```

---

## Scanning Engine

The scanning engine (`scanner.py`) orchestrates all 33 check modules through
a deadline-aware, fault-tolerant execution pipeline.

### Execution flow

```
URL input
    │
    ▼
┌──────────────────┐
│ URL normalization │  Strip protocol, resolve redirects
└────────┬─────────┘
         ▼
┌──────────────────┐
│ SSRF validation  │  Block private IPs, metadata endpoints, DNS rebinding
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Initial fetch    │  GET target with browser-mimicking headers
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Bot detection    │  Detect Cloudflare, Vercel checkpoints, WAF blocks
│ + retry logic    │  Retry with mobile UA, retry with minimal headers
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Crawler (opt.)   │  Discover additional pages (Pro: up to 10)
└────────┬─────────┘
         ▼
┌──────────────────────────────────────────────────┐
│              Check Dispatch Loop                  │
│                                                   │
│  For each check module:                           │
│    1. Check scan deadline (180s hard cap)          │
│    2. Check mode gate (safe / full / redacted)     │
│    3. Execute check with exception isolation       │
│    4. Append results to findings list              │
│                                                   │
│  Crash isolation: a failure in one check           │
│  never stops the remaining checks.                 │
└────────┬─────────────────────────────────────────┘
         ▼
┌──────────────────┐
│ Score computation │  Profile-driven weighted penalties
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Risk engine      │  Top-5 prioritized recommendations
└────────┬─────────┘
         ▼
┌──────────────────┐
│ Result assembly  │  JSON response + DB persistence + audit log
└──────────────────┘
```

### Deadline enforcement

Every scan has a hard 180-second wall-clock deadline. A malicious target
could otherwise keep the scanner busy indefinitely by responding slowly.
When the deadline is exceeded:

1. Remaining checks are skipped (not queued)
2. A truncation notice is added to the errors list
3. The audit log records the truncation event
4. Results from checks that did complete are still returned

### Concurrency model

The scanner uses a thread-per-scan model with a configurable cap
(`_MAX_CONCURRENT = 3`). Scans beyond the cap are queued in-memory.
Each scan runs in its own thread with its own `requests.Session`.

```
Request → Queue → Thread Pool (3 slots) → Check pipeline → DB write
                     │
                     └── progress_callback → SSE to frontend
```

---

## Gate-Before-Scan Model

Introduced in v4.0, the gate-before-scan model separates checks into
three tiers based on what they probe:

### Tier classification

| Tier | Gate | Behavior | Count |
|------|------|----------|-------|
| **safe** | None — always runs | No probes against private surface. Uses only public information: DNS records, TLS cert, HTTP headers from normal GET, HTML body analysis. | 20 |
| **redacted** | None — always runs | Runs in both modes, but the check internally redacts sensitive values (server versions, JWT contents, API key names) when `mode='safe'`. | 3 |
| **full** | Ownership verification required | Touches private attack surface: probes `/.env`, `/wp-admin/`, port scans, GraphQL introspection, subdomain enumeration. | 10 |

### Verification flow (full-mode gate)

```
User                    Frontend              Backend              Target
  │                        │                     │                    │
  │  Click "Full Scan"     │                     │                    │
  │───────────────────────>│                     │                    │
  │                        │  POST /scan/request │                    │
  │                        │────────────────────>│                    │
  │                        │  ← scan_request_id  │                    │
  │                        │<───────────────────│                    │
  │                        │                     │                    │
  │  ☑ Consent 1           │                     │                    │
  │  ☑ Consent 2           │  POST /verify/token │                    │
  │  ☑ Consent 3           │────────────────────>│                    │
  │                        │  ← token            │                    │
  │                        │<───────────────────│                    │
  │                        │                     │                    │
  │  Place token on site   │                     │                    │
  │─────────────────────────────────────────────────────────────────>│
  │                        │                     │                    │
  │                        │  POST /verify       │                    │
  │                        │────────────────────>│  GET /.well-known/ │
  │                        │                     │───────────────────>│
  │                        │                     │  ← token found ✓   │
  │                        │  ← verified         │<──────────────────│
  │                        │<───────────────────│                    │
  │                        │                     │                    │
  │  [3-sec anti-reflex]   │                     │                    │
  │                        │  POST /execute      │                    │
  │                        │────────────────────>│  Full scan         │
  │                        │                     │───────────────────>│
```

### Anti-automation defenses (10 layers)

1. Legacy `/scan` endpoint hardcoded to `mode='safe'`
2. 7 server-side precondition checks on `/execute`
3. 6-condition atomic `WHERE` clause on database state transition
4. IP binding on verification tokens (must verify from same IP)
5. Consent checkboxes recorded server-side with version tracking
6. 3-second anti-reflex delay on recap screen
7. Verification token expires after use
8. 30-day verification cache per (domain, ip_hash)
9. Rate limiting per IP (5 scans / 30 min)
10. Distinct-target-count tracking to catch recon patterns

---

## Check Module System

Each check module in `checks/` follows a standard interface:

```python
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Module: <check_name>
Category: <Security|GDPR|SEO|Performance|Accessibility>
Tier: <safe|redacted|full>
"""

def run(target, context, **kwargs) -> List[Dict[str, Any]]:
    """
    Execute the check and return findings.
    
    Each finding is a dict with:
      - id: str              — unique check identifier (e.g., "ssl_cert_expired")
      - category: str        — grouping category
      - severity: str        — CRITICAL | HIGH | MEDIUM | LOW | INFO
      - passed: bool         — True if the check passed (no issue found)
      - title: str           — human-readable title (Serbian)
      - title_en: str        — human-readable title (English)
      - description: str     — explanation (Serbian)
      - description_en: str  — explanation (English)
      - recommendation: str  — fix guidance (Serbian)
      - recommendation_en: str — fix guidance (English)
    """
    results = []
    # ... check logic ...
    return results
```

### Module catalog (33 modules)

| Module | Category | Tier | Checks |
|--------|----------|------|--------|
| `ssl_check.py` | SSL/TLS | safe | Certificate, TLS version, cipher, HSTS preload |
| `headers_check.py` | Security Headers | safe | HSTS, CSP, XFO, XCTO, RP, PP, COOP |
| `dns_check.py` | DNS Security | safe | SPF, DMARC, DKIM, CAA, DNSSEC |
| `files_check.py` | Sensitive Files | full | 430+ file path probes |
| `disclosure_check.py` | Info Disclosure | redacted | Server headers, tech fingerprints |
| `cookies_check.py` | Cookie Security | safe | Secure, HttpOnly, SameSite |
| `redirect_check.py` | Redirects | safe | HTTP→HTTPS, chain validation |
| `cms_check.py` | CMS Detection | safe | WordPress, Joomla, Drupal, etc. |
| `wpscan_lite.py` | WordPress | full | Plugins, users, XMLRPC, REST API |
| `admin_check.py` | Admin Exposure | full | 50+ admin panel paths |
| `robots_check.py` | Robots/Sitemap | safe | RFC 9309 parser, disclosure |
| `ports_check.py` | Port Scanning | full | 203 ports, CDN fingerprinting |
| `cors_check.py` | CORS | full | Wildcard, credentials, null origin |
| `extras_check.py` | Extras | safe | security.txt, CAA, SRI |
| `wellknown_check.py` | Well-Known | safe | 24 IETF/W3C endpoints |
| `vuln_check.py` | Vulnerabilities | full | SQL leaks, dir listing, CSRF, debug |
| `js_check.py` | JavaScript | redacted | Libraries, API keys, SRI, handlers |
| `jwt_check.py` | JWT | redacted | Algorithm, expiry, claims |
| `api_check.py` | API Security | full | GraphQL, Swagger, routes |
| `dependency_check.py` | Dependencies | full | Frontend library CVEs |
| `seo_check.py` | SEO | safe | Meta, headings, OG, canonical |
| `performance_check.py` | Performance | safe | Weight, compression, caching |
| `gdpr_check.py` | GDPR | safe | Privacy policy, consent, trackers |
| `accessibility_check.py` | Accessibility | safe | ARIA, lang, alt, contrast |
| `whois_check.py` | WHOIS | safe | Age, registrar, privacy |
| `tech_stack_check.py` | Tech Stack | safe | Framework detection |
| `email_security_check.py` | Email | safe | MX TLS, MTA-STS, DANE |
| `observatory_check.py` | Observatory | safe | Mozilla Observatory grade |
| `ct_check.py` | CT Logs | safe | Certificate Transparency |
| `subdomain_check.py` | Subdomains | full | Enumeration, CT mining |
| `takeover_check.py` | Takeover | full | Dangling CNAME, 70+ providers |
| `crawler.py` | Crawler | safe | Same-origin link discovery |

---

## Scoring Engine

The scoring engine uses a profile-driven weighted penalty system:

```
Score = max(5, min(100, 100 - Σ(penalties) + Σ(bonuses)))
```

### Penalty calculation

For each failed check:
- Severity weight × count (with optional diminishing returns cap)
- Excluded categories are skipped entirely

### Bonus calculation

For each passed INFO-severity check:
- Fixed bonus per check, capped at profile maximum

### Grade mapping

Score maps to grade (A–F) via profile-specific thresholds.
The `standard` profile is V3-compatible and acts as the regression
gate — changing its thresholds requires a paired test update in
`tests/test_strictness.py`.

---

## Risk Engine

The risk engine (`risk_engine.py`) provides prioritized remediation
guidance by combining three factors:

```
Priority Score = Severity Weight × Confidence × Exposure × ROI Boost
```

| Factor | Description |
|--------|-------------|
| **Severity Weight** | CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1, INFO=0 |
| **Confidence** | 1.0 for confirmed findings, 0.6 for "potential"/"possible" |
| **Exposure** | How publicly visible the issue is (1.0 for SSL, 0.7 for DNS) |
| **ROI Boost** | Easy fixes get 1.3×, hard fixes get 0.7× (maximize impact per effort) |

The `get_top_priorities()` function returns the top-N findings sorted
by this composite score, with bilingual fix guidance and difficulty
estimates.

---

## Data Model

### Core tables

| Table | Purpose | Retention |
|-------|---------|-----------|
| `scans` | Completed scan results (JSONB findings) | Indefinite |
| `scan_requests` | Wizard state machine (consent → verify → execute) | 30 days |
| `audit_log` | Append-only forensic trail (UPDATE/DELETE revoked) | 90 days |
| `public_scans` | Gallery entries (sanitized summaries, opt-in) | Until withdrawal |
| `verified_domains` | Ownership verification cache | 30 days |
| `subscriptions` | Pro tier license keys (Lemon Squeezy) | Active subscription |
| `lemon_webhook_events` | Idempotent webhook mirror | 180 days |
| `abuse_reports` | Owner complaints, linked to `domain_blocks` | Indefinite |
| `domain_blocks` | Domains permanently blocked from scanning | Indefinite |
| `ip_rate_limits` | Sliding-window rate counter | Auto-pruned |

### PII handling

All PII passes through `SHA-256(value || SERVER_SALT)` before database writes.
The salt is stored in environment variables, never in git. Even a complete
database leak reveals no usable IP addresses, emails, or user agents.

### Migration system

Migrations in `migrations/` are applied via `migration_runner.py` on
startup. Each migration is idempotent and tested against a clean schema.
Vault secrets are loaded via `execute_sql` outside the migration flow —
migrations reference secret *names*, never values.

---

## Security Architecture

### SSRF protection (`security_utils.py`)

Every outbound request passes through `safe_get()`, which:

1. Validates the URL scheme (http/https only)
2. Checks hostname against forbidden lists (localhost, .local, .internal)
3. Resolves DNS and validates every resolved IP against private ranges
4. Follows redirects manually, re-validating each hop
5. Caps redirect chains at 5 hops

```
safe_get() validation pipeline:
  URL → scheme check → hostname check → DNS resolve →
  IP range check (IPv4 + IPv6 + IPv4-mapped IPv6) →
  request → redirect? → re-validate new URL → ...
```

### Blocked address ranges

- IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8,
  169.254.0.0/16 (AWS metadata), 100.64.0.0/10 (CGNAT), plus
  TEST-NET, multicast, reserved
- IPv6: ::1, fc00::/7 (ULA), fe80::/10 (link-local), ::ffff:0:0/96
  (IPv4-mapped, unwrapped and rechecked), 2001:db8::/32

### Rate limiting

Dual enforcement:
1. **Database-backed** (primary): sliding window in `ip_rate_limits`
2. **In-memory** (fallback): `defaultdict(list)` with TTL, active when DB
   is unreachable

Both must agree to allow a request — a DB outage cannot disable rate limiting.

---

## Frontend Architecture

Single-page vanilla HTML + JS (no framework). Key components:

- `index.html` — scanner SPA with wizard, progress, results
- `blog-common.js` — injected header, footer, cookie banner, self-XSS warning
- `cookie-consent.js` — GDPR-compliant granular consent (essential/analytics/advertising)
- `blog-common.css` — shared blog styling

Language toggle: `body.lang-en` class + `data-sr`/`data-en` attributes
on every translatable element.

---

## Observability

| Signal | Destination | Retention |
|--------|-------------|-----------|
| Backend logs | HF Spaces log stream | 7 days |
| Audit log | `audit_log` table | 90 days |
| Uptime monitoring | UptimeRobot → `/health` | Continuous |
| Frontend analytics | GA4 (cookie-gated) | Standard |
| Backup status | `backup_log` table | 180 days |

---

## Performance Characteristics

| Component | Latency | Notes |
|-----------|---------|-------|
| SSL check | 2–5s | TCP + TLS handshake + HSTS preload API |
| DNS checks | 1–3s | Multiple record types |
| File probes | 5–15s | 430 paths, 2s timeout each, batched |
| Port scan | 5–20s | 203 ports, short timeouts, CDN fingerprint |
| Complete scan | 45–90s | All 33 modules, deadline at 180s |
| Multi-page scan | +5s/page | 0.5s rate limit between pages |
| PDF generation | 2–5s | Pure Python (fpdf2), no external deps |

See `SECURITY.md` for the full threat model and `CONTRIBUTING.md` for
development setup.
