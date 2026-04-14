# Contributing to Web Security Scanner

Thanks for your interest in improving the scanner. Whether you're fixing
a typo, adding a new security check, or writing a blog article — your
contribution makes the web a safer place.

This document covers everything you need to get started.

---

## Table of Contents

- [Quick Orientation](#quick-orientation)
- [Development Setup](#development-setup)
- [Adding a New Security Check](#adding-a-new-security-check)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Commit Message Convention](#commit-message-convention)
- [Testing](#testing)
- [Security-Sensitive Changes](#security-sensitive-changes)
- [Licensing of Contributions](#licensing-of-contributions)
- [Where Help Is Welcome](#where-help-is-welcome)
- [Where PRs Are Unlikely to Be Accepted](#where-prs-are-unlikely-to-be-accepted)

---

## Quick Orientation

### Repository layout

```
security-scanner/
├── api.py                 # FastAPI backend (3257 LOC) — routes, auth, queue
├── scanner.py             # Scan orchestrator — deadline, dispatch, scoring
├── risk_engine.py         # Prioritized remediation engine
├── security_utils.py      # SSRF protection, safe HTTP wrappers
├── db.py                  # Database layer (Supabase Postgres)
├── verification.py        # Ownership verification (meta/file/DNS)
├── subscription.py        # Pro tier (Lemon Squeezy webhooks)
├── pdf_report.py          # PDF report generator (fpdf2)
├── migration_runner.py    # DB migration system
│
├── checks/                # 33 security check modules
│   ├── __init__.py
│   ├── ssl_check.py       # TLS/certificate analysis
│   ├── headers_check.py   # HTTP security headers
│   ├── dns_check.py       # SPF, DMARC, DKIM, CAA, DNSSEC
│   ├── files_check.py     # 430+ sensitive file probes
│   ├── ports_check.py     # 203 dangerous port probes
│   ├── vuln_check.py      # Vulnerability pattern detection
│   ├── js_check.py        # JavaScript security analysis
│   ├── jwt_check.py       # JWT token analysis
│   ├── ...                # See ARCHITECTURE.md for full catalog
│   └── crawler.py         # Same-origin page discovery
│
├── tests/                 # Test suite
│   ├── test_strictness.py # Scoring regression tests
│   ├── test_public_gallery.py
│   └── bench_strictness.py
│
├── migrations/            # SQL migrations (idempotent)
├── scripts/               # Operational scripts (backup restore)
│
├── .github/               # GitHub config
│   ├── workflows/         # CI/CD pipelines
│   ├── ISSUE_TEMPLATE/    # Bug report & feature request templates
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── FUNDING.yml
│   └── dependabot.yml
│
├── docs/                  # Extended documentation
├── examples/              # Integration examples
├── configs/               # Scanner configuration presets
│
├── index.html             # Scanner SPA frontend
├── blog-*.html            # 26 blog articles + 4 hubs
├── Dockerfile             # Docker deployment
├── requirements.txt       # Python dependencies
├── vercel.json            # Vercel deployment config
└── fly.toml               # Fly.io deployment config (alternative)
```

### Tech stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11 + FastAPI (async) |
| Frontend | Vanilla HTML/CSS/JS |
| Database | Supabase Postgres + RLS + pg_cron + Vault |
| Payments | Lemon Squeezy (Merchant of Record) |
| PDF export | fpdf2 (pure Python) |
| Deploy (backend) | Docker on HuggingFace Spaces |
| Deploy (frontend) | Vercel Edge |
| Backups | AES-256-GCM → Cloudflare R2 |

---

## Development Setup

### Prerequisites

- Python 3.11+
- Git
- (Optional) Docker for container testing
- (Optional) Supabase project for full DB integration

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/UnlimitedEdition/security-scanner.git
cd security-scanner

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate    # macOS/Linux
# .venv\Scripts\activate     # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment (optional for check development)
cp .env.example .env
# Fill in SUPABASE_URL, SUPABASE_SERVICE_KEY, PII_HASH_SALT, etc.
# Most check modules work WITHOUT a database connection.

# 5. Start the API server
uvicorn api:app --reload --port 7860

# 6. (Optional) Serve the frontend separately
python -m http.server 8000
# Visit http://localhost:8000
```

### DB-free development

You do **NOT** need a Supabase project to develop or test check modules.
The scanner engine can run standalone — the API layer detects when the
database is unconfigured and operates in stateless mode (results are
returned directly, not persisted).

```python
# Quick test of a single check module:
from checks import ssl_check
results = ssl_check.run("example.com")
for r in results:
    print(f"[{r['severity']}] {r['title_en']}: {'PASS' if r['passed'] else 'FAIL'}")
```

---

## Adding a New Security Check

This is the most common contribution type. Follow these steps to add a
production-quality check module:

### 1. Create the module file

```bash
# Choose a descriptive name following the <domain>_check.py convention
touch checks/your_check.py
```

### 2. Implement the standard interface

```python
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
<Check Name> Security Check
Category: <Security|DNS Security|Cookie Security|...>
Tier: <safe|redacted|full>

<Brief description of what this check detects and why it matters.>
"""
from typing import List, Dict, Any


def run(target: str, *args, **kwargs) -> List[Dict[str, Any]]:
    """
    Execute the check against the target.

    Args:
        target: Domain name, URL, or response data depending on check type.
        *args, **kwargs: Context data (session, headers, body, mode).

    Returns:
        List of finding dicts, each containing:
          - id: str           — unique identifier (e.g., "your_check_name")
          - category: str     — human-readable category
          - severity: str     — CRITICAL | HIGH | MEDIUM | LOW | INFO
          - passed: bool      — True if no issue found
          - title: str        — finding title (Serbian)
          - title_en: str     — finding title (English)
          - description: str  — explanation (Serbian)
          - description_en: str — explanation (English)
          - recommendation: str — remediation guide (Serbian)
          - recommendation_en: str — remediation guide (English)
    """
    results = []

    # Your check logic here...
    # IMPORTANT: All outbound HTTP requests MUST use safe_get() from
    # security_utils.py — never raw requests.get() or session.get().

    results.append({
        "id": "your_check_passed",
        "category": "Your Category",
        "severity": "INFO",
        "passed": True,
        "title": "Provera uspešna",
        "title_en": "Check passed",
        "description": "Opis na srpskom.",
        "description_en": "English description.",
        "recommendation": "",
        "recommendation_en": "",
    })

    return results
```

### 3. Register in the scanner

Add your check to `scanner.py` in two places:

```python
# 1. Import at the top
from checks import your_check

# 2. Add to the check dispatch sequence (choose the right tier)
run_check("Your check description...", 55, "YourCheck",
          lambda: your_check.run(base_url, session), kind="safe")
#                                                    ^^^^^^^^^^^^
# kind="safe"     → runs always (passive, public data only)
# kind="full"     → runs only with verified ownership
# kind="redacted" → runs always, but redacts values in safe mode
```

### 4. Add to risk engine (optional)

If your check IDs have a common prefix, add it to `CATEGORY_DEFAULT_DIFFICULTY`
in `risk_engine.py`:

```python
CATEGORY_DEFAULT_DIFFICULTY = {
    ...
    "your_":  "easy",   # or "medium" or "hard"
}
```

### 5. Write tests

```python
# tests/test_your_check.py
from checks import your_check

def test_your_check_clean():
    """Test against a known-clean target."""
    results = your_check.run("example.com")
    assert all(r["passed"] for r in results)

def test_your_check_vulnerable():
    """Test against a known-vulnerable fixture."""
    results = your_check.run("vulnerable-fixture.test")
    assert any(not r["passed"] for r in results)
```

### 6. Checklist before submitting

- [ ] Module has the `SPDX-License-Identifier: MIT` header
- [ ] Module has both Serbian and English strings
- [ ] All outbound HTTP calls use `safe_get()` / `safe_head()` / `safe_post()`
- [ ] Exception handling: crashes are caught, never propagate to scanner
- [ ] Finding IDs are unique and follow the `category_detail` pattern
- [ ] Severity levels follow the project's severity guidelines
- [ ] At least one test case included
- [ ] ARCHITECTURE.md updated with the new module

---

## Pull Request Guidelines

### Scope

- **One concern per PR.** A PR that fixes an SSRF bug AND adds a new
  check AND refactors the logger is three PRs. Split them.
- **Keep diffs minimal.** Don't reformat unrelated files. Don't rename
  variables outside the changed scope.

### Code style

- Follow the existing style in `scanner.py` and `checks/`.
- Type hints where they help readability.
- `async` for I/O operations.
- Explicit error handling at system boundaries only.
- **No hardcoded secrets, ever.** Add new credentials to `.env.example`
  with a placeholder.
- **SSRF protection:** every new outbound HTTP call must use helpers from
  `security_utils.py`. Direct `requests.get()` calls will be rejected.

### PR template

When opening a PR, include:

```markdown
## What this PR does

Brief description of the change.

## Why

Explain the motivation — what was broken or missing.

## How to test

1. Step-by-step reproduction
2. Expected outcome

## Checklist

- [ ] Tests pass locally
- [ ] New code has SPDX license header
- [ ] No secrets committed
- [ ] SSRF protection on all outbound requests
- [ ] Bilingual strings (SR + EN)
```

---

## Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | New feature or check |
| `fix` | Bug fix |
| `security` | Security-related fix |
| `docs` | Documentation changes |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or fixing tests |
| `perf` | Performance improvement |
| `deps` | Dependency updates |
| `ci` | CI/CD pipeline changes |
| `chore` | Build process, tooling, or config |

### Examples

```
feat(checks): add WebSocket security check

Detects unencrypted WebSocket connections (ws://) and missing
authentication on WebSocket endpoints. Covers 3 new finding IDs:
ws_unencrypted, ws_no_auth, ws_open_proxy.

Closes #142
```

```
fix(scanner): prevent false positive on robots.txt User-agent groups

RFC 9309 requires case-insensitive matching of User-agent values.
The parser was doing exact string comparison, causing legitimate
wildcard rules to be flagged as information disclosure.

Regression test: tests/test_robots_rfc9309.py
```

---

## Testing

### Running the test suite

```bash
# All tests
python -m pytest tests/ -v

# Specific test file
python -m pytest tests/test_strictness.py -v

# With coverage
python -m pytest tests/ --cov=checks --cov=scanner --cov-report=term-missing
```

### Regression gate

The `test_strictness.py` suite is the regression gate for the scoring
engine. If you change `STRICTNESS_PROFILES` or `compute_score()` in
`scanner.py`, the tests will fail. This is intentional — update the
test expectations and document the change in your commit message.

### Test fixtures

If your test requires a specific server response, add a fixture in
`tests/fixtures/`. Mock the HTTP layer rather than making live requests
in tests.

---

## Security-Sensitive Changes

Changes to the following areas require extra scrutiny:

- `security_utils.py` (SSRF protection)
- `verification.py` (ownership verification)
- `api.py` (authentication, rate limiting)
- `db.py` (RLS policies, PII handling)
- `migration_runner.py` (schema changes)
- Any check that sends probes to target servers (kind="full")

### Process for security changes

1. **Mark the PR title** with `[security]` prefix
2. **Expect at least one round of discussion** before merge
3. **Do NOT submit public PRs** if the bug is still exploitable in
   production. Report via [Security Advisories](https://github.com/UnlimitedEdition/security-scanner/security/advisories/new) first.

---

## Licensing of Contributions

By submitting a pull request, you agree that:

- Your **code changes** will be released under the project's
  [MIT License](LICENSE).
- Your **editorial content changes** (blog articles, handbook prose,
  privacy/terms copy) will be released under
  [CC BY-NC 4.0](CONTENT-LICENSE.md).
- You have the right to submit the work (either it is your own, or you
  have permission from the original author).

We do not require a formal CLA. The license grant in this paragraph is
sufficient.

---

## Where Help Is Welcome

High-impact contributions that we actively seek:

| Area | Impact | Difficulty |
|------|--------|-----------|
| **New passive checks** | High | Medium |
| **i18n translations** | High | Easy |
| **Test fixtures** | High | Easy |
| **Blog articles** (CC BY-NC 4.0) | Medium | Easy |
| **Documentation improvements** | Medium | Easy |
| **Performance optimizations** | Medium | Hard |
| **CLI interface** | High | Medium |
| **Docker Compose recipes** | Medium | Easy |

---

## Where PRs Are Unlikely to Be Accepted

- **Active/intrusive checks** — anything that sends exploit payloads.
  The scanner is passive by design.
- **Dependency bumps without reason** — use `pip-audit` output or a CVE
  reference as justification.
- **Rewrites in another language** — the codebase is Python, and that's
  intentional.
- **Removal of security gates** — consent, rate limits, ownership
  verification, or cookie consent exist for legal and ethical reasons.
- **Pre-consent tracking** — loading analytics or advertising scripts
  before user consent violates GDPR and project policy.

---

## Reporting Bugs (Non-Security)

Open a [GitHub issue](https://github.com/UnlimitedEdition/security-scanner/issues/new) with:

1. What you expected to happen
2. What actually happened
3. Minimal reproduction (URL scanned, exact command, or output)
4. Environment (OS, Python version, local vs deployed)

## Reporting Security Bugs

**Do not open a public issue.** Use Security Advisories:

👉 https://github.com/UnlimitedEdition/security-scanner/security/advisories/new

See [SECURITY.md](SECURITY.md) for the full policy.

---

## Questions

If something in this guide is unclear, open an issue with the `docs`
label and we'll clarify and update the file.

Thanks for contributing to web security. 🔒
