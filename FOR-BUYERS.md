# For potential buyers

This document is for anyone evaluating the acquisition of
**Web Security Scanner** as an asset. It consolidates the material
a due-diligence process typically asks for, in one place.

Contact the maintainer (see `AUTHORS`) before initiating any formal
offer.

## What's being sold

The asset bundle includes:

- **Source code**: this GitHub repository (MIT-licensed code, except
  the trademarked name/logo — see License section)
- **Editorial content**: 26 blog articles + 4 hub pages, privacy
  policy, terms of service, operator handbook (`PRIRUCNIK.md`). These
  are CC BY-NC 4.0; transfer of commercial rights is **negotiable**.
- **Deployment infrastructure** (transferable upon agreement):
  - Domain `security-skener.gradovi.rs` (hosted on Cloudflare)
  - HuggingFace Space `Unlimitededition/web-security-scanner`
  - Supabase project (database + Vault + pg_cron + backups)
  - Vercel project
  - Lemon Squeezy store (Pro tier)
  - Cloudflare R2 bucket (encrypted backup archive)
- **Optional** (separate negotiation):
  - Email subscriber list
  - Active Pro customer subscriptions
  - Social accounts

## Financials

Not published here. Request under NDA.

Anonymized metrics available on request:
- Monthly unique scans (free tier)
- Active Pro subscriber count and MRR
- AdSense revenue (free tier)
- Hosting costs (HF Spaces Pro + Vercel + Supabase + R2)

## Technical due diligence checklist

| Area | Status | Evidence |
|---|---|---|
| Source available | ✅ | Public GitHub repo |
| Architecture docs | ✅ | `ARCHITECTURE.md` |
| Install / deploy | ✅ | `INSTALL.md` |
| Changelog | ✅ | `CHANGELOG.md` |
| Security policy | ✅ | `SECURITY.md` |
| Code of conduct | ✅ | `CODE_OF_CONDUCT.md` |
| Contribution guide | ✅ | `CONTRIBUTING.md` |
| SBOM | 🟡 | `requirements.txt` — run `pip-audit` for CVE |
| Automated tests | 🟡 | 3 test files in `tests/` — coverage partial |
| DR drill evidence | 🟡 | Manual restore tested; logs on request |
| Penetration test report | ❌ | Not commissioned yet |
| Load test report | ❌ | Not published; request under NDA |

## Legal due diligence checklist

| Area | Status |
|---|---|
| MIT source license | ✅ (`LICENSE`) |
| CC BY-NC 4.0 content license | ✅ (`CONTENT-LICENSE.md`) |
| Dual-license scope | ✅ (`LICENSE-NOTES.md`) |
| Trademark status ("Web Security Scanner") | 🟡 Unregistered; claim is use-based only |
| GDPR DPIA | ❌ Not formally documented |
| Records of Processing Activities | 🟡 Implicit in `privacy.html`; not a standalone doc |
| Privacy policy (user-facing) | ✅ (`privacy.html`) |
| Terms of service | ✅ (`terms.html`) |
| Abuse report process | ✅ (`abuse-report.html`, 72h SLA) |
| Transfer agreement template | ❌ Buyer's counsel to draft |

## Compliance posture

- **GDPR**: Article 6(1)(f) legitimate interest basis for audit log;
  Article 12 data subject rights honored via email-to-contact
  channel; 90-day audit retention with flag-for-legal exception
- **Serbian ZZPL**: transparency notice, right to object, right to
  erasure; gaps in data-breach procedure documentation (see
  `project_zzpl_compliance` in maintainer notes)
- **Cookie consent**: granular (necessary / analytics / ads),
  withdrawal mechanism, no pre-ticked boxes
- **AdSense policy**: AFC / AFS compliant (no scanner data used for
  targeting)

## What the buyer inherits vs. must handle

| Item | Transfer method |
|---|---|
| Code copyright | Assignment on signing |
| Content copyright | Separate CC BY-NC transfer (negotiable) |
| Domain | DNS + registrar transfer (~48h) |
| HF Space | Transfer via HF admin panel |
| Supabase project | Owner change or export + reimport |
| Lemon Squeezy store | Cannot transfer; buyer creates new store + migrates subscribers |
| Pro customers | Opt-in migration with 30-day grace |
| Subscriber list | Double opt-in renewal required under GDPR |
| Trademark | Maintainer assigns "Web Security Scanner" name + shield logo usage rights |

## Known risks / open items

- **No formal pentest** — buyer should commission one before
  production migration
- **Single maintainer bus factor** — contributor bench is thin
- **Third-party dependencies**: ~15 Python packages; `fpdf2`,
  `dnspython`, `requests`, `cryptography`, `psycopg` are the
  load-bearing ones
- **Platform risk**: HF Spaces and Vercel can change pricing; code
  is portable to any Docker host + any static host
- **Regulatory risk**: passive scanning is legal in EU / US / RS;
  buyer should re-verify for their jurisdiction
- **V4 gallery (public opt-in summaries)**: stores no vulnerability
  specifics, but buyer should review `public_scans` schema against
  their jurisdiction's data localization rules

## Post-sale transition

Offered as part of a 30-day transition engagement (negotiable):
- Deployment walkthrough on buyer's infrastructure
- Knowledge transfer sessions (architecture, check modules, wizard
  flow, Pro tier)
- 72h response on inherited open issues for the transition period
- Handover of ops runbook and incident history

## Next steps for a buyer

1. Read `README.md`, `ARCHITECTURE.md`, `SECURITY.md`
2. Clone, run `INSTALL.md`, verify a scan works end-to-end
3. Request NDA + financial package
4. Commission an independent security review
5. Agree on asset bundle scope + transition period
6. Draft transfer agreement (buyer's counsel)
7. Close + announce

Contact via GitHub Security Advisory or the email in
`security-skener.gradovi.rs` footer.
