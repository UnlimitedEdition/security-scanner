# Security Policy

> A security scanner that can't secure itself is a contradiction.
> This document describes how we protect the scanner, its users, and what
> to do if you find a vulnerability.

---

## Table of Contents

- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Threat Model](#threat-model)
- [Security Architecture](#security-architecture)
- [Data Handling & Privacy](#data-handling--privacy)
- [Gate-Before-Scan Model](#gate-before-scan-model)
- [Access Control](#access-control)
- [Backup & Disaster Recovery](#backup--disaster-recovery)
- [Supply Chain Security](#supply-chain-security)
- [Scope](#scope)

---

## Reporting a Vulnerability

If you discover a security issue in the scanner itself, please report it
privately. **Do not open a public GitHub issue** and **do not post it to
the HuggingFace Space community tab** — both are public and would expose
the bug to attackers before a fix ships.

### Preferred channel

👉 **GitHub Security Advisories (private):**
https://github.com/UnlimitedEdition/security-scanner/security/advisories/new

This channel is private between you and the maintainers, supports embargo
coordination, and issues a CVE if warranted.

### Response timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | **72 hours** |
| Initial assessment | 5 business days |
| Fix development | 14 days (critical), 30 days (high) |
| Public disclosure | After fix is deployed |

### What to include in your report

- **Affected component** — file, endpoint, or check module
- **Reproduction steps** — minimal proof-of-concept preferred
- **Impact assessment** — what an attacker gains (data access, code execution, DoS)
- **Suggested fix** — if you have one
- **Your preferred credit name** — we credit responsible reporters in release notes (unless you prefer anonymity)

### Bug bounty

We don't currently offer monetary rewards, but we credit reporters in
the `CHANGELOG.md` and `AUTHORS` file, and provide early access to
pre-release versions.

---

## Threat Model

### Assets we protect

| Asset | Sensitivity | Protection |
|-------|------------|------------|
| Scan results | Medium | Per-scan isolation, no cross-tenant access |
| User PII (IP, email, UA) | High | SHA-256 hashed with server salt, never stored raw |
| Database credentials | Critical | Environment variables, never in git |
| Backup encryption key | Critical | Supabase Vault + operator password manager |
| Pro license keys | Medium | Stored hashed, validated via Lemon Squeezy API |
| Target website data | Low | Transient in memory, not persisted beyond findings |

### Threat actors

| Actor | Goal | Mitigations |
|-------|------|-------------|
| **Malicious target** | Exploit SSRF to reach internal services | SSRF guard on every redirect hop, DNS rebinding check |
| **Reconnaissance attacker** | Use scanner as proxy for recon | Ownership verification gate, rate limits, distinct-target tracking |
| **Data exfiltrator** | Extract PII from database | PII hashing, RLS, append-only audit log |
| **Credential thief** | Steal API keys or DB credentials | No secrets in git, Vault for runtime secrets |
| **DoS attacker** | Overwhelm scanner or target | Scan deadline (180s), rate limit (5/30min), concurrent scan cap (3) |
| **Supply chain attacker** | Compromise via dependencies | Pinned deps, Dependabot, pip-audit |

### Attack surface

```
                          ┌─────────────────────────┐
                          │   Public Internet        │
                          └────────────┬────────────┘
                                       │
              ┌────────────────────────┴────────────────────────┐
              │                  Attack Surface                  │
              │                                                  │
              │  POST /scan         ← rate limited, SSRF guard  │
              │  POST /scan/request ← consent + verification    │
              │  POST /abuse-report ← rate limited               │
              │  GET  /health       ← no auth, returns "ok"      │
              │  GET  /api/gallery  ← public read-only           │
              │                                                  │
              │  All other endpoints: auth or intent-gated       │
              └──────────────────────────────────────────────────┘
```

---

## Security Architecture

### Code-level protections

#### SSRF protection (`security_utils.py`)

Every outbound HTTP request flows through `safe_get()`, which:

1. **Scheme validation** — only `http://` and `https://` allowed
2. **Hostname blocklist** — `localhost`, `.local`, `.internal`, `.corp`, etc.
3. **DNS resolution** — resolves hostname, checks ALL returned IPs
4. **IP range validation** — blocks private, loopback, link-local
   (169.254.x.x / AWS metadata), CGNAT, multicast, reserved
5. **IPv4-mapped IPv6 unwrapping** — `::ffff:127.0.0.1` is caught
6. **Redirect following** — each hop re-validated (blocks `302 → localhost`)
7. **Redirect cap** — max 5 hops to prevent redirect loops

```python
# NEVER do this:
response = requests.get(url)            # ❌ No SSRF protection

# ALWAYS do this:
from security_utils import safe_get
response = safe_get(session, url)       # ✅ Every hop validated
```

#### SSL verification

SSL certificate validation is **always on**. We do not disable cert
verification as a fallback or convenience measure. If SSL fails, the
scan reports it as a finding — it does not bypass it.

#### Scan deadline

Every scan has a hard 180-second wall-clock cap (`SCAN_DEADLINE_SECONDS`).
A malicious target that responds slowly on each check cannot keep the
scanner busy indefinitely. When the deadline fires, remaining checks are
skipped and a truncation notice is recorded.

#### Content-signature verification

Sensitive file detection (`.env`, `.git/config`) validates response
bodies for expected content patterns, not just HTTP status codes. This
prevents false positives from custom 404 pages returning `200 OK` and
false negatives from `.env` files containing the word "error" in comments.

#### Input validation

- URL format validation via Pydantic with regex + SSRF check
- Strictness profile whitelist validation
- Abuse report field length limits (4000 chars description, 320 email)
- Scan ID format validation (`^[a-f0-9]{8}$`)

---

## Data Handling & Privacy

### PII lifecycle

```
User request
    │
    ▼
┌──────────────────┐
│ Extract PII      │  IP, User-Agent, email (if provided)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ SHA-256 + salt   │  PII_HASH_SALT from environment
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Store hash only  │  Original value discarded immediately
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ 90-day retention │  Auto-pruned via pg_cron
└──────────────────┘
```

### Database security

| Control | Implementation |
|---------|---------------|
| **Row-Level Security** | Enabled on every table, default deny |
| **Append-only audit log** | `UPDATE`/`DELETE` revoked at DB role level |
| **Encryption at rest** | AES-256, enforced by Supabase |
| **TLS in transit** | TLS 1.2+, enforced by Supabase for all connections |
| **Credential isolation** | Service key in env vars, application key for frontend |

### No external data transmission

- **No telemetry.** The scanner does not phone home.
- **No third-party scan APIs.** All analysis happens locally.
- **No data sharing.** Scan results are not sent to analytics services.
- **Frontend analytics** (GA4, AdSense) are cookie-gated and run only
  after explicit user consent. They have zero access to scan data.

---

## Gate-Before-Scan Model

Introduced in v4.0 (2026-04-12) to prevent scanner abuse for unauthorized
reconnaissance.

### Two modes

| Mode | Trigger | Checks | Probes private surface? |
|------|---------|--------|------------------------|
| `safe` | Default, no verification | 20 passive + 3 redacted | **No** — zero requests to `/.env`, `/wp-admin/`, ports, etc. |
| `full` | After ownership verification | All 33 checks | Yes — sensitive files, ports, admin panels, subdomains |

### Verification methods

1. **Meta tag** — place `<meta name="security-scanner-verify" content="TOKEN">` in `<head>`
2. **File upload** — place `TOKEN` in `/.well-known/security-scanner-verify.txt`
3. **DNS TXT record** — add `TXT security-scanner-verify=TOKEN` to the domain

### Anti-automation defenses (10 layers)

1. Legacy `/scan` hardcoded to `mode='safe'`
2. 7 server-side precondition checks on `/execute`
3. 6-condition atomic `WHERE` clause on DB state transition
4. IP binding on verification tokens
5. Server-side consent logging with version tracking
6. 3-second anti-reflex delay on recap screen
7. One-time-use verification tokens
8. 30-day verification cache per (domain, ip_hash)
9. Rate limiting per IP hash
10. Distinct-target-count tracking per IP

### Consent privacy

The wizard uses `created_date DATE` (no timestamp component) for consent
records. Even a complete database leak cannot reveal what time of day the
user clicked which checkbox.

---

## Access Control

### Rate limiting

**Dual enforcement:**

1. **Database-backed** (primary): sliding window counter in `ip_rate_limits`
2. **In-memory** (fallback): `defaultdict(list)` with TTL

Both must agree — a database outage cannot disable rate limiting.

**Limits:**
- 5 scans per 30 minutes per IP hash (configurable via env)
- Applies to both `/scan` and `/abuse-report` endpoints

### CORS policy

Backend enforces a strict origin allowlist. `Access-Control-Allow-Origin`
is not set to `*` in production — only authorized frontend origins are
permitted.

### Content Security Policy

```
default-src 'self';
script-src 'self' 'unsafe-inline' [Google Ads stack];
style-src 'self' 'unsafe-inline' fonts.googleapis.com;
font-src fonts.gstatic.com;
img-src 'self' data: https:;
connect-src 'self' [API endpoints] [Google Ads stack];
frame-src [Google Ads stack];
frame-ancestors 'self' huggingface.co *.hf.space;
```

Advertising stack uses wildcard subdomains (`*.googlesyndication.com`,
`*.g.doubleclick.net`) because Google's ad delivery infrastructure uses
dynamic subdomains.

---

## Backup & Disaster Recovery

### Backup architecture

```
pg_cron (daily 04:00 UTC)
    │
    ▼
Supabase Edge Function (/supabase/functions/backup)
    │
    ├── Dump critical tables as JSON
    ├── gzip compress
    ├── Encrypt with AES-256-GCM (random 12-byte IV per blob)
    │
    ▼
Cloudflare R2 bucket (security-scanner-backups)
    │
    Object key: backups/YYYY/MM/DD/backup-YYYYMMDDTHHMMSSZ.json.gz.enc
```

### What gets backed up

| Table | Purpose | Backed up? |
|-------|---------|-----------|
| `audit_log` | Forensic trail | ✅ |
| `abuse_reports` | User complaints | ✅ |
| `scans` | Scan history | ✅ |
| `verified_domains` | Verification cache | ✅ |
| `verification_tokens` | Ephemeral | ❌ |
| `scan_requests` | Ephemeral wizard state | ❌ |
| `rate_limits` | Regenerable | ❌ |

### Security controls

| Control | Implementation |
|---------|---------------|
| **Encryption key** | 256-bit, stored in Supabase Vault + operator password manager |
| **R2 credentials** | Supabase Vault only, loaded at runtime via `SECURITY DEFINER` RPC |
| **R2 token scope** | Write-only to single bucket — leaked token cannot read backups |
| **Webhook auth** | Shared secret in `X-Webhook-Secret` header |
| **No key material in git** | Migrations reference secret names, never values |

### Monitoring

```sql
-- Last 7 days of backup attempts
SELECT started_at, status, bytes_written, rows_exported
  FROM backup_log
 WHERE started_at > NOW() - INTERVAL '7 days'
 ORDER BY started_at DESC;

-- Alert: any failures in last 2 days
SELECT COUNT(*) AS failures FROM backup_log
 WHERE status = 'error' AND started_at > NOW() - INTERVAL '2 days';
```

### Restore procedure

```bash
pip install boto3 cryptography psycopg python-dotenv

# List available backups
python scripts/restore_backup.py --list

# Inspect without touching DB
python scripts/restore_backup.py --inspect backups/2026/04/10/backup-20260410T040012Z.json.gz.enc

# Dry-run restore
python scripts/restore_backup.py --latest

# Apply restore (idempotent via ON CONFLICT DO NOTHING)
python scripts/restore_backup.py --latest --apply
```

### DR drill schedule

At least **quarterly**, run a restore against a disposable Supabase project
or local Postgres instance. A backup that has never been tested is not a backup.

---

## Supply Chain Security

### Dependency management

- **Pinned versions** in `requirements.txt` for reproducible builds
- **Dependabot** configured for weekly Python, Docker, and GitHub Actions updates
- **Major version bumps** get individual PRs for manual review
- **pip-audit** recommended before releases

### Minimal dependency surface

The scanner uses 10 direct dependencies:

| Package | Purpose | Risk profile |
|---------|---------|-------------|
| `fastapi` | Web framework | Well-maintained, large community |
| `uvicorn` | ASGI server | Part of FastAPI ecosystem |
| `requests` | HTTP client | Most-used Python package |
| `dnspython` | DNS queries | Mature, security-focused |
| `pydantic` | Input validation | Type-safe, well-audited |
| `beautifulsoup4` | HTML parsing | Mature, stable API |
| `certifi` | CA certificates | Mozilla-backed |
| `supabase` | Database client | Official SDK |
| `psycopg` | PostgreSQL driver | C-extension, well-audited |
| `fpdf2` | PDF generation | Pure Python, no system deps |

No dependency requires native compilation beyond `psycopg[binary]`,
which uses the standard libpq.

---

## Scope

### In-scope for security reports

- FastAPI backend (`api.py`, `scanner.py`, `security_utils.py`)
- All check modules (`checks/*.py`)
- Frontend (`index.html`, blog pages)
- Database schema and migrations
- SSRF / auth / crypto / data handling bugs
- Rate limit bypass
- Ownership verification bypass

### Out-of-scope

- Findings on third-party websites (report to the site owner)
- DoS via legitimate scanning traffic (use rate limit path)
- Issues in upstream dependencies (report to the dependency maintainer)
- Social engineering attacks against maintainers
- Physical attacks against hosting infrastructure

---

## License

- **Source code** — [MIT License](LICENSE)
- **Editorial content** — [CC BY-NC 4.0](CONTENT-LICENSE.md)
