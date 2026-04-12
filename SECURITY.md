# Security Policy

## Our own security commitments

A security scanner that leaks its own secrets is a contradiction. This
project takes the following measures to protect itself and its users:

### Code-level
- **No hardcoded secrets.** All credentials, API keys, and salts live in
  environment variables (see `.env.example`).
- **SSRF protection** on every outbound request — see `security_utils.py`.
  The scanner cannot be tricked into probing localhost, cloud metadata
  endpoints, or private networks, even via redirect.
- **SSL verification mandatory.** We do not disable cert validation as a
  fallback. If SSL fails, the scan reports it.
- **Scan deadline.** Every scan has a hard 180-second wall-clock cap to
  prevent malicious targets from monopolizing the scanner.
- **Content-signature file detection** — we no longer false-negative real
  `.env` files that contain the word "error" in a comment.

### Data handling
- **PII is hashed, never stored raw.** IPs and User-Agents pass through
  SHA-256 with a server-side salt before hitting the database.
- **Row-Level Security** on every database table. Default deny. Only the
  backend service role can read the audit log.
- **Audit log is append-only.** `UPDATE` and `DELETE` are revoked for
  that table at the database level — not even the backend can rewrite
  history.
- **90-day retention** on audit logs, pruned automatically via pg_cron.
- **Encryption at rest** — enforced by Supabase (AES-256).
- **TLS 1.2+** — enforced by Supabase for all connections.
- **Offsite encrypted backups, daily.** See "Backup & restore" below.

### Gate-before-scan model (2026-04-12)
- **Two scan modes** enforced server-side: `safe` (20 passive checks,
  zero probes against private infrastructure) and `full` (additional
  10 active checks — sensitive files, admin panels, ports, etc.).
- **Full scan requires a 5-step wizard:** three explicit consent
  checkboxes (each server-logged), ownership verification (meta tag /
  file / DNS TXT), and a recap screen with anti-reflex delay.
- **IP binding on verification tokens** — the token must be verified
  from the same IP that created it. Prevents token interception attacks.
- **30-day verification cache** per (domain, ip_hash) in
  `verified_domains` table with daily cron pruning.
- **Legacy `/scan` endpoint** is hardcoded to `mode='safe'` regardless
  of request body — full mode can ONLY be triggered through the wizard.

### Access control
- **Ownership verification** required before running active probes.
  Without verification, the target server never sees requests for
  `/.env`, `/wp-admin/`, port scans, or anything resembling recon.
- **Rate limits** per IP and per distinct-target-count to catch
  reconnaissance patterns.
- **Script/automation resistance** — 10 layered defenses prevent
  automated full-scan abuse: hardcoded safe mode on `/scan`, 7
  server-side precondition checks + 6-condition atomic WHERE in
  the database on `/execute`, IP binding on verification tokens,
  and server-side consent validation. See PRIRUCNIK.md §16 for
  the complete attack scenario analysis.
- **Consent checkbox** required for every scan, versioned and logged.
- **GDPR cookie consent** — granular 3-category banner (essential /
  analytics / advertising) on all pages. AdSense does not load until
  the user explicitly accepts advertising cookies.

## Backup & restore

Supabase free tier has no automated backups, so we run our own: a daily
`pg_cron` job triggers a Supabase Edge Function (`supabase/functions/backup`)
which dumps critical tables as JSON, gzips them, encrypts with AES-256-GCM,
and uploads to Cloudflare R2 via an IAM-scoped write-only token.

### What gets backed up
- `audit_log` — forensic trail
- `abuse_reports` — user complaints
- `scans` — scan history
- `verified_domains` — verification cache

Not backed up (ephemeral or regenerable): `verification_tokens`,
`scan_requests`, `rate_limits`, `schema_migrations`, `backup_log`
itself.

### Where
- **Destination:** Cloudflare R2 bucket `security-scanner-backups`
- **Object key format:** `backups/YYYY/MM/DD/backup-YYYYMMDDTHHMMSSZ.json.gz.enc`
- **Schedule:** daily at 04:00 UTC (see `cron.job` where `jobname = 'daily-backup'`)
- **Retention:** 90 days of blobs (R2 lifecycle rule), 180 days of `backup_log` metadata

### Security model
- **Encryption key** is 256 bits, generated once, stored in Supabase Vault
  and in the operator's password manager. Without the key, no backup can
  be read — AES-256-GCM with a random 12-byte IV per blob is authenticated
  encryption, so tampering is also detectable.
- **R2 credentials** are stored only in Supabase Vault. The edge function
  reads them at call time via a `SECURITY DEFINER` RPC (`get_backup_secrets`)
  that is granted only to `service_role`.
- **Webhook auth.** The pg_cron → edge function call carries a
  shared secret (`X-Webhook-Secret` header). The edge function rejects
  any request without the matching secret with HTTP 401.
- **R2 token scope.** The R2 API token has write access **only** to the
  `security-scanner-backups` bucket — not to other buckets, not to the
  Cloudflare account. If it leaks, blast radius is "fill this one bucket".
- **No key material in git.** Vault secrets are loaded via `execute_sql`
  outside the migration flow; migrations in git reference secret *names*,
  never values.

### Monitoring
Every backup attempt writes a row to `public.backup_log` with status
(`running`/`success`/`error`), the R2 object key, byte count, row counts,
and any error message. To check health:

```sql
-- Last 7 days of backup attempts
SELECT started_at, status, bytes_written, rows_exported
  FROM backup_log
 WHERE started_at > NOW() - INTERVAL '7 days'
 ORDER BY started_at DESC;

-- Alert query: any failures in last 2 days
SELECT COUNT(*) FROM backup_log
 WHERE status = 'error' AND started_at > NOW() - INTERVAL '2 days';
```

### Restore procedure

Restore is done from a developer machine via `scripts/restore_backup.py`.
Fill the `R2_*` and `BACKUP_ENCRYPTION_KEY` variables in your local `.env`
(get them from the operator's password manager), install dependencies, and
run:

```bash
pip install boto3 cryptography psycopg python-dotenv

# 1. See what backups exist
python scripts/restore_backup.py --list

# 2. Inspect a specific backup without touching the DB
python scripts/restore_backup.py --inspect backups/2026/04/10/backup-20260410T040012Z.json.gz.enc

# 3. Dry-run the restore (reports what WOULD happen, doesn't write)
python scripts/restore_backup.py --latest

# 4. Actually restore (requires --apply, idempotent via ON CONFLICT DO NOTHING)
python scripts/restore_backup.py --latest --apply
```

The script uses `ON CONFLICT DO NOTHING` on primary keys, so running a
restore against a non-empty database will only fill in missing rows — it
will not overwrite existing ones. Re-running the same restore is a no-op.

### Disaster recovery drill
At least quarterly, run the restore against a disposable second Supabase
project (or a local Postgres) to verify the full chain actually works.
A backup that has never been tested is not a backup.


## Reporting a vulnerability in THIS scanner

If you discover a security issue in the scanner itself, please report it
privately. Do **not** open a public GitHub issue, and do **not** post it
to the HuggingFace Space community tab — both are public and would
expose the bug to attackers before a fix ships.

- **Preferred — GitHub Security Advisories (private):**
  https://github.com/UnlimitedEdition/security-scanner/security/advisories/new
  This channel is private between you and the maintainers, supports
  embargo coordination, and issues a CVE if warranted.
- **Response time:** We aim to acknowledge reports within 72 hours.
- **Credit:** We will credit responsible reporters in release notes
  (unless you prefer anonymity).

### What to include
- Affected file / endpoint / check name
- Reproduction steps (minimal POC preferred)
- Impact assessment (what an attacker gains)
- Your suggested fix, if any

## Scope

In-scope:
- The FastAPI backend (`api.py`, `scanner.py`, all `checks/*.py`)
- The frontend (`index.html`, blog pages)
- The database schema and migrations
- SSRF / auth / crypto / data handling bugs

Out-of-scope:
- Findings on third-party sites that the scanner reports (those belong
  to the site owner)
- DoS against our own infrastructure via legitimate scanning traffic
  (use the rate limit path instead)
- Issues in third-party dependencies (report to upstream)

## License

- **Source code** — MIT License, see [LICENSE](LICENSE)
- **Editorial content** (blog articles, PRIRUCNIK, privacy/terms prose) —
  CC BY-NC 4.0, see [CONTENT-LICENSE.md](CONTENT-LICENSE.md)
