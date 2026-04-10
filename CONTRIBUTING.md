# Contributing to Web Security Scanner

Thanks for your interest in improving the scanner. This document covers
the practical stuff: how the repo is laid out, how to run it locally,
and what a good PR looks like.

## Quick orientation

- **Backend:** Python 3.11 + FastAPI (`api.py`, `scanner.py`, `checks/`)
- **Frontend:** Static HTML (`index.html`, `blog-*.html`) served via
  Vercel
- **Database:** Supabase Postgres with RLS, pg_cron, Vault
- **Deploy targets:** HuggingFace Space (backend Docker) + Vercel
  (frontend)
- **Docs:** `PRIRUCNIK.md` (operator handbook, Serbian) is the primary
  source of truth for day-to-day operations

See `PROJECT-TREE.md` for the full file map.

## Running locally

```bash
# 1. Clone
git clone https://github.com/UnlimitedEdition/security-scanner.git
cd security-scanner

# 2. Python environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Fill in SUPABASE_URL, SUPABASE_SERVICE_KEY, PII_HASH_SALT, etc.

# 4. Run the API
uvicorn api:app --reload --port 7860

# 5. Open the frontend
# The static site can be opened directly, or served via any HTTP server:
python -m http.server 8000
# Then visit http://localhost:8000
```

You do NOT need a full Supabase project to develop most checks — the
scanner logic in `checks/*.py` can be exercised via unit-style scripts
without a live database.

## Licensing of contributions

By submitting a pull request, you agree that:

- Your **code changes** will be released under the project's MIT
  License (see `LICENSE`).
- Your **editorial content changes** (blog articles, handbook prose,
  privacy/terms copy) will be released under CC BY-NC 4.0 (see
  `LICENSE-CONTENT`).
- You have the right to submit the work (either it is your own, or you
  have permission from the original author).

We do not require a formal CLA. The license grant in this paragraph is
sufficient.

## What makes a good pull request

### Scope
- **One concern per PR.** A PR that fixes an SSRF bug AND adds a new
  check AND refactors the logger is three PRs, not one. Split it.
- **Keep diffs minimal.** Don't reformat unrelated files. Don't rename
  variables outside the changed scope. Don't add docstrings to
  functions you didn't touch.

### Code style
- Python: follow the existing style in `scanner.py` and `checks/`.
  Type hints where they help, `async` for I/O, explicit error handling
  at system boundaries only.
- No hardcoded secrets, ever. If you need a new credential, add it to
  `.env.example` with a placeholder and document it in the PR.
- SSRF protection: every new outbound HTTP call must go through the
  helpers in `security_utils.py`. Do not bypass them.

### Tests
- If you add a new check in `checks/`, include at least one test case
  that exercises the check against a known-vulnerable and known-clean
  fixture.
- If you fix a bug, add a regression test that fails on the old code
  and passes on the new code.

### Commit messages
- First line: imperative, under 72 characters. `Add CORS wildcard
  detection` not `Added CORS wildcard detection` and not `Adding...`.
- Body: explain the *why*, not the *what*. The diff already shows what
  changed. The commit message should say why the old behavior was
  wrong or insufficient.
- Reference issues with `#123` when relevant.

### Security-sensitive changes
- Changes to SSRF, auth, crypto, rate limiting, or database RLS
  policies need extra review. Mark the PR title with `[security]` and
  expect at least one round of discussion before merge.
- Do NOT submit security fixes as public PRs if the bug is still
  exploitable in production. Instead, report via Security Advisories
  first (see `SECURITY.md`).

## Reporting bugs (non-security)

Open a GitHub issue with:

1. What you expected to happen
2. What actually happened
3. Minimal reproduction (URL scanned, exact command, or PRI output)
4. Environment (OS, Python version, local vs deployed)

## Reporting security bugs

**Do not open a public issue.** Use Security Advisories instead:
https://github.com/UnlimitedEdition/security-scanner/security/advisories/new

See `SECURITY.md` for the full policy.

## Areas where help is especially welcome

- **New passive checks** in `checks/` — see existing checks for the
  pattern
- **i18n** — the frontend currently supports Serbian and English, new
  language translations are welcome
- **Blog articles** on security topics (CC BY-NC 4.0 licensed)
- **Docs improvements** to `PRIRUCNIK.md` and inline code comments
- **Test fixtures** — every new fixture makes regression testing
  cheaper

## Areas where PRs are unlikely to be accepted

- Active/intrusive checks (anything that sends payloads designed to
  trigger vulnerabilities). The scanner is passive by design.
- Dependency bumps without a reason. Use `pip-audit` output or a CVE
  reference as the reason.
- Rewrites in another language or framework.
- Removal of the consent gate, rate limits, or ownership verification
  in the name of "convenience".

## Questions

If something in this document is unclear, open an issue with the label
`docs` and the maintainers will clarify and update the file.

Thanks again for contributing.
