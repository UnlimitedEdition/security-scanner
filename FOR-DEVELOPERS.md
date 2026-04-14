# For Developers — Extending Web Security Scanner

> **Audience:** Developers who want to add custom security checks,
> integrate the scanner into their toolchain, or build on top of the engine.

---

## Table of Contents

- [Architecture at a Glance](#architecture-at-a-glance)
- [Writing a Custom Check Module](#writing-a-custom-check-module)
- [Check Module API Reference](#check-module-api-reference)
- [Severity Guidelines](#severity-guidelines)
- [The Risk Engine](#the-risk-engine)
- [Using the Scanner as a Library](#using-the-scanner-as-a-library)
- [REST API Reference](#rest-api-reference)
- [Extending the Scoring Engine](#extending-the-scoring-engine)
- [Adding a New Strictness Profile](#adding-a-new-strictness-profile)
- [Database Integration](#database-integration)
- [Header Comment Templates](#header-comment-templates)

---

## Architecture at a Glance

```
┌──────────────┐     ┌──────────────┐     ┌──────────────────────┐
│   api.py     │────>│  scanner.py  │────>│   checks/*.py        │
│  (FastAPI)   │     │ (orchestrator)│     │   (33 modules)       │
└──────────────┘     └──────┬───────┘     └──────────────────────┘
                            │
                     ┌──────┴───────┐
                     │ risk_engine  │
                     │   .py        │
                     └──────────────┘
```

1. **api.py** receives scan requests, manages the queue, handles auth
2. **scanner.py** orchestrates checks with deadline enforcement
3. **checks/*.py** each implement a single security concern
4. **risk_engine.py** generates prioritized remediation advice

---

## Writing a Custom Check Module

### Step 1: Create the file

```bash
touch checks/websocket_check.py
```

### Step 2: Implement the standard interface

```python
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
WebSocket Security Check
Category: API Security
Tier: full (requires ownership verification)

Detects insecure WebSocket connections and common misconfigurations:
- Unencrypted WebSocket (ws:// instead of wss://)
- Missing authentication on WebSocket endpoints
- Cross-origin WebSocket hijacking
"""
from typing import List, Dict, Any
from security_utils import safe_get


def run(
    base_url: str,
    response_body: str,
    session,
    **kwargs,
) -> List[Dict[str, Any]]:
    """
    Scan for WebSocket security issues.

    Args:
        base_url: Target website base URL (https://example.com)
        response_body: HTML body of the homepage
        session: requests.Session with scanner headers

    Returns:
        List of finding dicts
    """
    results = []

    # --- Check 1: Detect unencrypted WebSocket URLs in source ---
    if "ws://" in response_body and "wss://" not in response_body:
        results.append({
            "id": "ws_unencrypted",
            "category": "API Security",
            "severity": "HIGH",
            "passed": False,
            "title": "Nešifrovan WebSocket (ws://)",
            "title_en": "Unencrypted WebSocket connection (ws://)",
            "description": (
                "Kod sadrži ws:// URL bez wss:// alternative. "
                "WebSocket komunikacija nije šifrovana."
            ),
            "description_en": (
                "Source code contains ws:// URL without wss:// alternative. "
                "WebSocket communication is unencrypted."
            ),
            "recommendation": "Koristite wss:// za sve WebSocket konekcije.",
            "recommendation_en": "Use wss:// for all WebSocket connections.",
        })
    elif "wss://" in response_body:
        results.append({
            "id": "ws_encrypted",
            "category": "API Security",
            "severity": "INFO",
            "passed": True,
            "title": "WebSocket koristi šifrovanu konekciju (wss://)",
            "title_en": "WebSocket uses encrypted connection (wss://)",
            "description": "WebSocket komunikacija je šifrovana.",
            "description_en": "WebSocket communication is encrypted.",
            "recommendation": "",
            "recommendation_en": "",
        })

    # --- Check 2: Probe for common WebSocket endpoints ---
    ws_endpoints = ["/ws", "/websocket", "/socket.io/", "/sockjs/"]
    for endpoint in ws_endpoints:
        try:
            resp = safe_get(session, f"{base_url}{endpoint}", timeout=5)
            # WebSocket upgrade endpoints typically return 400 or 426
            # when accessed via HTTP GET (not a WS upgrade request)
            if resp.status_code in (101, 200, 400, 426):
                results.append({
                    "id": "ws_endpoint_exposed",
                    "category": "API Security",
                    "severity": "MEDIUM",
                    "passed": False,
                    "title": f"WebSocket endpoint dostupan: {endpoint}",
                    "title_en": f"WebSocket endpoint accessible: {endpoint}",
                    "description": (
                        f"Endpoint {endpoint} odgovara na HTTP zahteve. "
                        "Proverite da li zahteva autentifikaciju."
                    ),
                    "description_en": (
                        f"Endpoint {endpoint} responds to HTTP requests. "
                        "Verify it requires authentication."
                    ),
                    "recommendation": (
                        "Zaštitite WebSocket endpointe autentifikacijom "
                        "i validacijom Origin headera."
                    ),
                    "recommendation_en": (
                        "Protect WebSocket endpoints with authentication "
                        "and Origin header validation."
                    ),
                })
                break  # One finding is enough
        except Exception:
            continue

    return results
```

### Step 3: Register in the scanner

In `scanner.py`, add:

```python
# At the top with other imports
from checks import websocket_check

# In the check dispatch sequence (choose appropriate position and tier)
run_check("Proveravam WebSocket bezbednost...", 66, "WebSocket",
          lambda: websocket_check.run(base_url, response_body, session),
          kind="full")  # 'full' because it probes endpoints
```

### Step 4: Add to the risk engine

In `risk_engine.py`, add the prefix to `CATEGORY_DEFAULT_DIFFICULTY`:

```python
CATEGORY_DEFAULT_DIFFICULTY = {
    ...
    "ws_":  "medium",
}
```

### Step 5: Write tests

```python
# tests/test_websocket_check.py
from checks import websocket_check

def test_no_websocket():
    """Site without WebSocket should return empty results."""
    results = websocket_check.run(
        "https://example.com",
        "<html><body>Hello</body></html>",
        None,
    )
    assert len(results) == 0

def test_unencrypted_websocket():
    """Site with ws:// should be flagged."""
    body = '<script>var ws = new WebSocket("ws://example.com/chat");</script>'
    results = websocket_check.run("https://example.com", body, None)
    failed = [r for r in results if not r["passed"]]
    assert any(r["id"] == "ws_unencrypted" for r in failed)

def test_encrypted_websocket():
    """Site with wss:// should pass."""
    body = '<script>var ws = new WebSocket("wss://example.com/chat");</script>'
    results = websocket_check.run("https://example.com", body, None)
    assert any(r["id"] == "ws_encrypted" and r["passed"] for r in results)
```

---

## Check Module API Reference

### Finding dict schema

Every finding returned by a check module must include these fields:

```python
{
    "id": str,                # Unique identifier: "category_detail"
    "category": str,          # Human-readable category name
    "severity": str,          # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    "passed": bool,           # True if check passed (no issue found)
    "title": str,             # Finding title (Serbian)
    "title_en": str,          # Finding title (English)
    "description": str,       # Explanation (Serbian)
    "description_en": str,    # Explanation (English)
    "recommendation": str,    # Remediation guidance (Serbian)
    "recommendation_en": str, # Remediation guidance (English)
}
```

### Optional fields

```python
{
    "page_url": str,          # For multi-page scans: which page this finding is from
    "details": dict,          # Additional structured data (versions, CVEs, etc.)
}
```

### Check function signatures

Different check types receive different arguments. Match the existing
pattern for your check category:

```python
# Domain-level checks (SSL, DNS, WHOIS, email)
def run(hostname: str) -> List[Dict[str, Any]]: ...

# Header-level checks (headers, cookies)
def run(headers: dict, is_https: bool = True) -> List[Dict[str, Any]]: ...

# Content-level checks (SEO, GDPR, accessibility)
def run(url: str, body: str, headers: dict, session) -> List[Dict[str, Any]]: ...

# Probe-level checks (files, admin, ports, vuln)
def run(base_url: str, session) -> List[Dict[str, Any]]: ...

# Mode-aware checks (disclosure, JS, JWT)
def run(data, ..., mode: str = "safe") -> List[Dict[str, Any]]: ...
```

---

## Severity Guidelines

Use these guidelines consistently across all check modules:

| Severity | When to use | Examples |
|----------|------------|---------|
| **CRITICAL** | Immediate, exploitable risk. Data breach likely without fix. | Expired SSL cert, exposed `.env` file, open database port |
| **HIGH** | Significant risk. Exploitable with moderate effort. | Missing HSTS, weak TLS cipher, exposed admin panel |
| **MEDIUM** | Moderate risk. Requires specific conditions to exploit. | Missing CSP, CORS misconfiguration, outdated library |
| **LOW** | Minor risk or best-practice violation. | Missing Referrer-Policy, no HSTS preload, info disclosure |
| **INFO** | Informational finding. Passed check or neutral observation. | Valid SSL cert, detected CMS, domain age |

### Severity escalation

Multiple related LOW/MEDIUM findings can indicate a pattern that
justifies escalation. Example: a server leaking its version through
three different channels (Server header, X-Powered-By, error page)
is worse than any single leak.

---

## The Risk Engine

The risk engine (`risk_engine.py`) computes a composite priority score:

```
Priority = Severity × Confidence × Exposure × ROI_Boost
```

| Factor | Values | Purpose |
|--------|--------|---------|
| Severity | CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1 | Base weight |
| Confidence | 1.0 (confirmed), 0.6 (potential) | Reduce noise |
| Exposure | 0.7–1.0 based on category | Prioritize public-facing issues |
| ROI Boost | easy=1.3×, medium=1.0×, hard=0.7× | Maximize impact per effort |

To add fix difficulty for a new check, add entries to `FIX_DIFFICULTY`:

```python
FIX_DIFFICULTY = {
    ...
    "ws_unencrypted": "easy",        # Just change ws:// to wss://
    "ws_endpoint_exposed": "medium", # Requires auth implementation
}
```

---

## Using the Scanner as a Library

You can use the scanner engine directly from Python without the API layer:

```python
import scanner

# Basic scan
result = scanner.scan("https://example.com")

print(f"Grade: {result['score']['grade']}")
print(f"Score: {result['score']['score']}/100")
print(f"Total checks: {result['total_checks']}")
print(f"Failed: {result['failed_checks']}")

# With strictness profile
result = scanner.scan("https://example.com", strictness="paranoid")

# With progress callback
def on_progress(step, pct):
    print(f"[{pct}%] {step}")

result = scanner.scan("https://example.com", progress_callback=on_progress)

# Multi-page scan
result = scanner.scan("https://example.com", max_pages=5)

# Score computation only
from scanner import compute_score
score = compute_score(findings_list, strictness="strict")
```

---

## REST API Reference

### POST /scan

Start a quick public scan (safe mode only).

**Request:**
```json
{
    "url": "https://example.com",
    "consent_accepted": true,
    "strictness": "standard"
}
```

**Response:**
```json
{
    "scan_id": "a1b2c3d4",
    "status": "queued",
    "position": 0
}
```

### GET /scan/{scan_id}

Poll scan progress.

**Response (running):**
```json
{
    "status": "running",
    "progress": 45,
    "step": "Checking security headers..."
}
```

**Response (completed):**
```json
{
    "status": "completed",
    "result": {
        "url": "https://example.com",
        "domain": "example.com",
        "score": {"score": 82, "grade": "B", "grade_color": "#84cc16"},
        "results": [...],
        "errors": [],
        "total_checks": 240,
        "failed_checks": 12
    }
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{"status": "ok"}
```

---

## Extending the Scoring Engine

### Adding a new strictness profile

In `scanner.py`, add to `STRICTNESS_PROFILES`:

```python
STRICTNESS_PROFILES["custom"] = {
    "weights": {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 10, "LOW": 5},
    "diminishing": False,
    "diminishing_caps": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    "bonus_per_info": 1,
    "bonus_cap": 5,
    "excluded_categories": [],
    "grade_thresholds": {"A": 98, "B": 90, "C": 75, "D": 55},
}
```

⚠️ **Important:** If you change the `"standard"` profile, you MUST update
the regression tests in `tests/test_strictness.py`. The standard profile
is the V3-compatibility gate.

---

## Database Integration

### Required environment variables

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=eyJ...
PII_HASH_SALT=your-random-salt-at-least-32-chars
```

### Running without a database

The scanner operates in stateless mode when `SUPABASE_URL` is unset:
- Scan results are returned directly (not persisted)
- Rate limiting falls back to in-memory counters
- Audit logging is disabled
- Pro features are unavailable

This mode is ideal for development, testing, and CI/CD integration.

---

## Header Comment Templates

### Python files

```python
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
"""
Module: <module_name>
<Brief description of what this module does.>
"""
```

### JavaScript files

```javascript
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
//
// <module_name> — <brief description>
```

### Configuration files (YAML, TOML, INI)

```yaml
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
#
# <config_name> — <brief description>
```

### SQL migration files

```sql
-- SPDX-License-Identifier: MIT
-- Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
--
-- Migration: <NNN> — <description>
-- Applied by: migration_runner.py
```

### HTML files (editorial content — CC BY-NC 4.0)

```html
<!--
  SPDX-License-Identifier: CC-BY-NC-4.0
  Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
  
  This file is editorial content licensed under Creative Commons
  Attribution-NonCommercial 4.0 International. See CONTENT-LICENSE.md.
-->
```

---

## Further Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) — system design, data flow, execution model
- [CONTRIBUTING.md](CONTRIBUTING.md) — PR guidelines, commit conventions, testing
- [SECURITY.md](SECURITY.md) — threat model, SSRF protection, data handling
- [FOR-BUSINESS.md](FOR-BUSINESS.md) — enterprise deployment and SaaS roadmap
