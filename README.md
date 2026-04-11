---
title: Web Security Scanner
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
short_description: Passive website security analysis - 110+ checks
---

# 🛡️ Web Security Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Content License: CC BY-NC 4.0](https://img.shields.io/badge/Content-CC%20BY--NC%204.0-lightgrey.svg)](LICENSE-CONTENT)
[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-async-009688.svg)](https://fastapi.tiangolo.com/)

Passive security analysis for websites — **110+ checks**, no site modification, GDPR-compliant.

Live: https://security-scanner-ruddy.vercel.app

## What it checks

- **TLS / Certificates** — validity, expiry, chain, cipher strength
- **HTTP security headers** — HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **DNS security** — SPF, DKIM, DMARC, CAA, DNSSEC
- **Sensitive file exposure** — `.env`, `.git/`, backup dumps, phpMyAdmin, `wp-config.php`
- **Cookie security** — Secure, HttpOnly, SameSite flags
- **Open dangerous ports** — MySQL, Redis, MongoDB, Elasticsearch, Memcached
- **CORS policy** — wildcard origins, credential leaks
- **CMS / technology detection** — WordPress, Joomla, Drupal, Shopify, etc.
- **robots.txt / sitemap.xml** — information disclosure patterns
- **Admin panel exposure** — common paths, default credentials hints
- **JavaScript analysis** — inline handlers, outdated libraries, SRI
- **API endpoint discovery** — leaked routes, Swagger/OpenAPI exposure
- **GDPR signals** — privacy policy presence, cookie consent, tracker census
- **SEO/performance** — meta tags, heading structure, page weight

See `PRIRUCNIK.md` (Serbian) for the full operator handbook and
`checks/` directory for the individual check implementations.

## Free vs Pro

The scanner is free-first. Every check in the catalog above runs on
the free tier with no account needed — enter a URL and scan. A paid
**Pro** plan is available for users who want more:

- **Unlimited scans** (no 5 scans / 30 min rate limit)
- **Multi-page scanning** — pick up to 10 same-origin pages from the
  crawler's discovered set and run the page-level check subset on
  each, with findings tagged per URL
- **PDF report export** — branded A4 reports you can hand to a client
  or print for compliance review (requires ownership verification)
- **30-day scan history** in the `/account` dashboard
- **Stateless license key auth** — no passwords, no email verification,
  no magic link flow. The key is issued at purchase by Lemon Squeezy
  (our Merchant of Record) and activated via `/pricing`. See
  `pricing.html` and `account.html` for the user-facing flow.

Pricing, FAQ, and the refund policy live at
[`/pricing`](https://security-scanner-ruddy.vercel.app/pricing).

## Tech stack

- **Backend:** Python 3.11 + FastAPI (async), deployed as Docker on
  HuggingFace Spaces
- **Frontend:** Vanilla HTML/CSS/JS, deployed on Vercel
- **Database:** Supabase Postgres with RLS, pg_cron, Vault, daily
  encrypted backups to Cloudflare R2
- **Payments:** Lemon Squeezy (Merchant of Record) for Pro plan
  subscriptions — we store license keys in `subscriptions` and
  mirror Lemon webhook state in `lemon_webhook_events`
- **PDF reports:** `fpdf2` (pure Python, no system deps)
- **Libraries:** `dnspython`, `requests`, `certifi`, `psycopg`,
  `cryptography`, `fpdf2`

## Security posture

This scanner is itself designed to be secure:

- **SSRF protection** on every outbound request (blocks localhost,
  metadata endpoints, private networks, DNS rebinding)
- **PII hashed, never stored raw** (SHA-256 + server salt)
- **Append-only audit log** (UPDATE/DELETE revoked at DB level)
- **Ownership verification** required for attack-useful findings
- **Daily encrypted backups** (AES-256-GCM) with quarterly DR drills

Full details in `SECURITY.md`.

## Contributing

See `CONTRIBUTING.md` for local setup, PR guidelines, and areas where
help is welcome. New contributors are welcome — especially for passive
checks, i18n, and blog articles.

## Reporting vulnerabilities

**Do not open public issues for security bugs.** Use GitHub Security
Advisories instead:
https://github.com/UnlimitedEdition/security-scanner/security/advisories/new

See `SECURITY.md` for the full disclosure policy.

## License

This project uses a **dual licensing** model:

- **Source code** — MIT License → see [`LICENSE`](LICENSE)
  Applies to all Python, SQL, TypeScript, JavaScript, CSS, and config
  files. You may use, modify, and redistribute the code freely,
  including for commercial purposes, as long as the MIT notice is
  preserved.

- **Editorial content** — Creative Commons Attribution-NonCommercial
  4.0 International → see [`LICENSE-CONTENT`](LICENSE-CONTENT)
  Applies to blog articles, the operator handbook (`PRIRUCNIK.md`),
  privacy policy, terms of service, and other user-facing prose. You
  may share and adapt the content with attribution, but not for
  commercial purposes. If you have a commercial use case you believe
  is reasonable, contact the maintainer.

The project name "Web Security Scanner" and its shield logo are
trademarks of Toske-Programer and are NOT covered by either license.
Forks should use their own branding.

## Code of Conduct

See `CODE_OF_CONDUCT.md`. Short version: focus on the work, be patient
with newcomers, report problems privately via Security Advisories.

## Contributors

See `AUTHORS` for the full credits list.
