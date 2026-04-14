<!--
  SPDX-License-Identifier: CC-BY-NC-4.0
  Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
-->

# False Positive Handling Strategy

> **Last updated:** 2026-04-14 · **Version:** 4.1

False positives are the silent killer of security tools. When a scanner
repeatedly flags non-issues, teams learn to ignore it — and then they
miss the real vulnerability buried in the noise.

This document describes how Web Security Scanner minimizes false positives
across its 240+ check catalog.

---

## Design Principles

### 1. Multi-signal correlation

Never flag on a single indicator. Correlate multiple signals before
raising severity:

```
Single signal:        Server: Apache/2.4.41       → LOW (informational)
Correlated signals:   Server: Apache/2.4.41
                    + X-Powered-By: PHP/7.2.34
                    + /phpinfo.php returns 200    → CRITICAL (exploitable)
```

### 2. Context-aware severity

The same finding has different severity depending on context:

| Finding | Without MX records | With MX records |
|---------|-------------------|-----------------|
| Missing SPF | LOW | HIGH |
| Missing DMARC | LOW | HIGH |
| Missing DKIM | INFO | MEDIUM |

### 3. Validate, don't just detect

When checking for sensitive files, don't just look for HTTP 200:

```python
# ❌ Bad: triggers on custom 404 pages returning 200
if response.status_code == 200:
    flag_as_vulnerable()

# ✅ Good: validate content signature
if response.status_code == 200:
    content = response.text
    if looks_like_env_file(content):  # Check for KEY=VALUE patterns
        flag_as_vulnerable()
```

### 4. Fail open, not false positive

When uncertain, emit INFO/LOW instead of HIGH/CRITICAL:

```python
# When we can't determine if the finding is real
results.append({
    "severity": "LOW",         # Not HIGH — we're not sure
    "title": "Potential ...",   # "Potential" signals uncertainty
})
```

---

## Category-Specific Strategies

### Bot Protection Detection

**Problem:** WAF/CDN challenge pages (Cloudflare, Vercel, DataDome)
return HTML that doesn't represent the real site. Running SEO, GDPR,
or performance checks against a challenge page produces nonsense failures.

**Solution:** Before content-dependent checks, the scanner:

1. Checks for known challenge signatures (15+ patterns)
2. Validates HTML structure (`<html>`, `<head>`, `<body>`, `<title>`)
3. Checks response size and meta tag presence
4. If blocked, retries with mobile User-Agent
5. If still blocked, retries with minimal headers
6. If all retries fail, skips content-dependent checks and flags transparently

```python
# Known challenge signatures
challenge_signs = [
    "vercel security checkpoint",
    "checking your browser",
    "just a moment",
    "cf-challenge",
    "__cf_chl",
    "challenge-platform",
    # ... 15+ patterns
]
```

### CDN Fingerprinting for Port Scans

**Problem:** Cloudflare, Fastly, and Akamai proxy HTTP traffic on
ports 80, 443, 8080, and 8443. An "open" port 8080 behind a CDN is
the CDN's port, not the origin server's.

**Solution:** The port scanner fingerprints CDN presence via response
headers (`cf-ray`, `x-served-by`, `x-cache`) and adjusts findings:

- CDN-proxied port: INFO (expected behavior)
- Non-CDN open port: severity based on service type

### Content-Signature File Detection

**Problem:** Custom 404 pages that return `200 OK` cause false positives
for every file check. `.env` files with comments containing the word
"error" were false-negatively excluded by naive pattern matching.

**Solution:** File checks validate expected content patterns:

| File | Expected pattern |
|------|-----------------|
| `.env` | Lines matching `^[A-Z_]+=` |
| `.git/config` | `[core]` section in INI format |
| `wp-config.php` | `DB_NAME`, `DB_USER`, `DB_PASSWORD` defines |
| `phpinfo()` | `PHP Version`, `Build Date`, `Configuration File` |

### Robots.txt RFC Compliance

**Problem:** The scanner was parsing `User-agent` values with exact
string matching, but RFC 9309 requires case-insensitive comparison.
Legitimate wildcard rules (`User-agent: *`) were being flagged as
information disclosure when a site also had specific bot rules.

**Solution:** RFC 9309-compliant parser with case-insensitive matching
and proper group separation.

### MX-Conditional DNS Severity

**Problem:** Domains without mail infrastructure don't need SPF/DMARC
records. Flagging them as HIGH severity is a false positive.

**Solution:** Check for MX records first. If the domain has no MX:
- SPF missing: LOW instead of HIGH
- DMARC missing: LOW instead of HIGH
- DKIM: skip entirely

---

## Metrics & Monitoring

### False positive rate tracking

We track false positive reports through:

1. **GitHub Issues** tagged `false-positive`
2. **Abuse reports** citing incorrect findings
3. **Regression tests** — every confirmed false positive gets a test fixture

### Acceptable rate

Our target false positive rate:

| Severity | Target FP rate | Current estimate |
|----------|---------------|-----------------|
| CRITICAL | < 0.1% | ~0.05% |
| HIGH | < 1% | ~0.5% |
| MEDIUM | < 3% | ~2% |
| LOW | < 5% | ~3% |

### Reporting false positives

If you encounter a false positive:

1. Open a [GitHub Issue](https://github.com/UnlimitedEdition/security-scanner/issues/new?template=bug_report.md)
2. Include the target URL (if you own it), the check ID, and why you
   believe it's a false positive
3. We'll investigate and add a regression test if confirmed

---

*This document is licensed under CC BY-NC 4.0.*
