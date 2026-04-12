# Migrations

Every schema change in this project **must** be a migration file. No
direct DDL via the Supabase dashboard. No manual `CREATE TABLE` in
Python code. Every change goes through a versioned SQL file, gets
committed to git, and is applied via the migration runner.

## Why

1. **Reproducibility** — any environment (local, staging, production)
   can be rebuilt from these files alone.
2. **Audit trail** — schema history lives in git, alongside the code
   that depends on it.
3. **Rollback is possible** — not automatic, but you can always read
   backwards through the files to understand what changed.
4. **Team safety** — if someone else ever contributes, they can see
   exactly what database shape the code expects.

## Naming

```
NNN_short_description.sql
```

- `NNN` is a three-digit zero-padded sequence starting at 001.
- `short_description` uses snake_case.
- Examples:
  - `001_schema_migrations_table.sql`
  - `012_add_user_email_to_scans.sql`
  - `023_backfill_old_ip_hashes.sql`

**Never skip a number.** Never reuse a number. Never rename a file
after it's been applied anywhere.

## Rules

1. **Never edit a migration file once it has been applied to any
   environment.** The migration runner tracks file checksums and will
   refuse to proceed if a previously-applied migration has changed.
   If you need to fix a bug in an earlier migration, write a NEW
   migration that corrects it.

2. **Migrations must be idempotent where possible.** Use
   `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`,
   `DO $$ BEGIN ... EXCEPTION WHEN duplicate_object THEN NULL; END $$`
   for policy creation, etc. This lets the runner safely re-run
   a partially-completed migration after an error.

3. **Each migration is a single transaction.** The runner wraps the
   whole file in `BEGIN; ... COMMIT;`, so either everything applies
   or nothing does. Do NOT put `BEGIN` / `COMMIT` statements inside
   the file yourself — you'll break transaction nesting.

4. **Document destructive changes.** Any `DROP`, `DELETE`, or `ALTER`
   that removes data must have a comment explaining what is lost
   and why it's safe. The reviewer (future you) will thank you.

5. **Keep migrations small.** Prefer five small, focused migrations
   over one sprawling one. Smaller files are easier to review,
   easier to roll back mentally, and fail in smaller ways.

## Running migrations

Local development:
```bash
python migration_runner.py
```

The runner:
1. Connects using `SUPABASE_DB_URL` from `.env`
2. Creates `schema_migrations` table if it doesn't exist
3. Computes SHA-256 of every `.sql` file in this directory
4. Skips any migration whose version is already in `schema_migrations`
   **and** whose checksum matches
5. **Aborts loudly** if a previously-applied migration has changed
   on disk (checksum mismatch)
6. Applies each new migration in a single transaction
7. Records the version, checksum, and runtime in `schema_migrations`

## Current files

| File | Purpose |
|------|---------|
| `001_schema_migrations_table.sql` | Bootstrap — tracking table for the runner itself |
| `002_core_tables.sql` | Scans, verification, audit log, rate limits, abuse reports |
| `003_indexes.sql` | Query performance indexes on all core tables |
| `004_rls_policies.sql` | Row-Level Security: default deny, append-only audit log |
| `005_cron_jobs.sql` | Scheduled cleanup: token expiry, audit prune, verified_domains prune |
| `006_function_search_path_hardening.sql` | Pin `search_path` on all SECURITY DEFINER functions |
| `007_explicit_deny_policies.sql` | Explicit `USING (false)` policies for anon/authenticated on every table |
| `008_backup_infrastructure.sql` | pg_net extension + `backup_log` table + daily-backup cron |
| `009_backup_secrets_rpc.sql` | `get_backup_secrets()` RPC so the edge function can read Vault |
| `010_flag_audit_rows_rpc.sql` | `flag_audit_rows_for_scan_ids()` RPC for abuse legal holds |
| `011_subscriptions.sql` | Pro plan tables: `subscriptions`, `lemon_webhook_events`, `magic_links` |
| `012_scans_subscription_fk.sql` | Add `subscription_id` FK to `scans` table |
| `013_subscriptions_explicit_deny_policies.sql` | Explicit deny RLS for Pro tables (fixes 3 security INFO lints) |
| `014_scan_requests_table.sql` | `scan_requests` table for gate-before-scan wizard (DATE, not TIMESTAMPTZ) |
| `015_scan_requests_cron.sql` | `prune_abandoned_scan_requests()` cron (hourly, 24h TTL) |
| `016_audit_log_scan_request_events.sql` | Extend audit_log CHECK constraint with 5 wizard events |
