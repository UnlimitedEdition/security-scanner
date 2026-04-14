<!--
  SPDX-License-Identifier: CC-BY-NC-4.0
  Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
-->

# Check Writing Guide

> Step-by-step guide to adding a new security check to Web Security Scanner.

This guide walks through the entire process of implementing a production-quality
check module — from concept to merge-ready PR.

---

## Prerequisites

- Python 3.11+
- Familiarity with the scanner's architecture ([ARCHITECTURE.md](../ARCHITECTURE.md))
- Local development environment set up ([CONTRIBUTING.md](../CONTRIBUTING.md))

---

## Step 1: Define the Check

Before writing code, answer these questions:

| Question | Example answer |
|----------|---------------|
| What security issue does this detect? | Unencrypted WebSocket connections |
| Why does it matter? | Data transmitted in cleartext can be intercepted |
| What is the detection signal? | `ws://` URLs in HTML/JavaScript source |
| What is the expected false positive rate? | Very low — `ws://` is unambiguous |
| Is this passive or active? | Passive (reads HTML body) and active (probes endpoints) |
| What tier? | Mixed: body analysis is `safe`, endpoint probing is `full` |

## Step 2: Choose the Check Tier

| Tier | When to use | Example |
|------|------------|---------|
| `safe` | Check uses only public information: DNS, TLS cert, HTTP headers, HTML body from normal GET | `ssl_check`, `headers_check`, `seo_check` |
| `redacted` | Check runs always but hides sensitive details in safe mode | `disclosure_check`, `js_check`, `jwt_check` |
| `full` | Check sends probes to non-public endpoints or scans ports | `files_check`, `ports_check`, `admin_check` |

## Step 3: Create the Module

```bash
touch checks/your_check.py
```

### Template

```python
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
<Your Check Name>
Category: <Category Name>
Tier: <safe|redacted|full>

<One or two sentences describing what this check detects and why it matters.>
"""
from typing import List, Dict, Any

# If making outbound HTTP requests:
from security_utils import safe_get


def run(target, *args, **kwargs) -> List[Dict[str, Any]]:
    results = []

    # Your check logic here

    return results
```

### Critical rules

1. **SSRF:** All HTTP requests MUST use `safe_get()`, `safe_head()`, or `safe_post()`
2. **Crash isolation:** Wrap risky operations in try/except — don't let exceptions propagate
3. **Timeout:** Use short timeouts (5-10s) on HTTP requests
4. **Bilingual:** Include both Serbian and English strings
5. **Finding IDs:** Use unique, descriptive IDs: `category_detail` (e.g., `ws_unencrypted`)

## Step 4: Write the Findings

Each finding must include all required fields:

```python
{
    "id": "ws_unencrypted",           # Unique — used by risk engine & dedup
    "category": "API Security",        # Grouping for UI
    "severity": "HIGH",                # CRITICAL|HIGH|MEDIUM|LOW|INFO
    "passed": False,                   # False = issue found, True = check passed
    "title": "Srpski naslov",          # Serbian title
    "title_en": "English title",       # English title
    "description": "Srpski opis.",     # Serbian explanation
    "description_en": "English desc.", # English explanation
    "recommendation": "Preporuka SR.", # Serbian fix guidance
    "recommendation_en": "Fix EN.",    # English fix guidance
}
```

## Step 5: Register in scanner.py

```python
# 1. Add import
from checks import your_check

# 2. Add to check sequence
run_check("Checking your thing...", 55, "YourCheck",
          lambda: your_check.run(base_url, session), kind="full")
```

**Position matters:** Group your check near related checks. The progress
percentage (55 in the example) should fit logically between surrounding checks.

## Step 6: Add to Risk Engine

In `risk_engine.py`:

```python
# Specific check IDs (optional but recommended)
FIX_DIFFICULTY = {
    ...
    "ws_unencrypted": "easy",
    "ws_endpoint_exposed": "medium",
}

# Prefix fallback (always add this)
CATEGORY_DEFAULT_DIFFICULTY = {
    ...
    "ws_": "medium",
}
```

## Step 7: Write Tests

```python
# tests/test_your_check.py

def test_clean_target():
    """Check returns empty or all-passed for clean targets."""
    results = your_check.run("https://example.com", ...)
    for r in results:
        assert r["passed"]

def test_vulnerable_target():
    """Check detects the issue when present."""
    results = your_check.run(vulnerable_fixture, ...)
    assert any(not r["passed"] for r in results)
    assert any(r["id"] == "your_finding_id" for r in results)

def test_required_fields():
    """All findings have the required schema."""
    results = your_check.run(...)
    required = {"id", "category", "severity", "passed",
                "title", "title_en", "description", "description_en",
                "recommendation", "recommendation_en"}
    for r in results:
        assert required.issubset(r.keys()), f"Missing fields in {r['id']}"
```

## Step 8: Update Documentation

- [ ] Add module to the table in [ARCHITECTURE.md](../ARCHITECTURE.md)
- [ ] Update the check count in [README.md](../README.md) if it changed
- [ ] Add to the changelog entry you'll include in your PR

## Step 9: Self-Review Checklist

Before submitting your PR:

- [ ] `SPDX-License-Identifier: MIT` header present
- [ ] Both SR and EN strings for all findings
- [ ] All HTTP requests use `safe_get()` / `safe_head()` / `safe_post()`
- [ ] Exception handling — no unhandled crashes
- [ ] Finding IDs are unique across all modules
- [ ] Severity follows the [severity guidelines](../FOR-DEVELOPERS.md#severity-guidelines)
- [ ] At least one test case
- [ ] Registered in `scanner.py` with correct tier
- [ ] Added to `risk_engine.py` difficulty mapping
- [ ] Documentation updated

## Step 10: Submit the PR

Use the PR template and check all applicable boxes. Security-related
checks should be tagged `[security]` in the PR title.

---

## Common Patterns

### Pattern: Check with HTTP probing

```python
endpoints = ["/api/v1/debug", "/api/graphql"]
for ep in endpoints:
    try:
        resp = safe_get(session, f"{base_url}{ep}", timeout=5)
        if resp.status_code == 200 and indicator_in(resp.text):
            results.append(make_finding(...))
            break  # One finding per category is enough
    except Exception:
        continue  # Silently skip — don't crash the scan
```

### Pattern: Mode-aware redaction

```python
def run(data, ..., mode="safe"):
    if mode == "safe":
        # Emit summary only — don't reveal specific values
        results.append({
            "description_en": "Server version header detected.",
        })
    else:
        # Full mode — reveal the actual value
        results.append({
            "description_en": f"Server version: {server_header}",
        })
```

### Pattern: Content validation (avoid false positives)

```python
# Don't just check status code:
if resp.status_code == 200:
    body = resp.text
    # Validate the response is actually the file we're looking for
    if "DB_HOST" in body and "DB_PASSWORD" in body:
        results.append(make_env_finding())
    # else: probably a custom 404 page → skip
```

---

*This guide is licensed under CC BY-NC 4.0.*
