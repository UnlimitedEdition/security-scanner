<!--
  SPDX-License-Identifier: CC-BY-NC-4.0
  Copyright (c) 2026 Toske-Programer (Web Security Scanner contributors)
-->

# Threat Model

> **Last updated:** 2026-04-14 · **Version:** 4.1

This document provides a structured threat analysis for Web Security Scanner.
It covers the assets we protect, threat actors, attack vectors, and the
mitigations in place.

---

## 1. Asset Inventory

| Asset | Classification | Location | Protection |
|-------|---------------|----------|------------|
| User scan results | Confidential | Supabase `scans` table | RLS, per-scan isolation |
| PII (IP, email, UA) | Sensitive | Supabase (hashed) | SHA-256 + server salt |
| Database credentials | Secret | Environment variables | Never in git, rotated quarterly |
| Backup encryption key | Secret | Supabase Vault + password manager | AES-256-GCM, split knowledge |
| Pro license keys | Confidential | Supabase `subscriptions` | Hashed at rest |
| Target website data | Transient | In-memory during scan | Discarded after findings extracted |
| Source code | Public | GitHub | MIT license, signed commits |
| Audit log | Legal | Supabase `audit_log` | Append-only, UPDATE/DELETE revoked |

## 2. Threat Actor Profiles

### 2.1 Malicious Target Operator

**Goal:** Exploit the scanner's outbound requests to reach internal services.

**Attack vectors:**
- HTTP redirect to `http://127.0.0.1:6379` (Redis)
- DNS rebinding: hostname resolves to public IP on first lookup, private IP on second
- Response with `Location: http://169.254.169.254/latest/meta-data/` (AWS metadata)

**Mitigations:**
- `safe_get()` re-validates every redirect hop
- DNS resolution checked against private ranges before every request
- IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) are unwrapped and rechecked
- Redirect chain capped at 5 hops
- Only `http://` and `https://` schemes allowed

### 2.2 Reconnaissance Attacker

**Goal:** Use the scanner as a proxy to scan targets they don't own.

**Attack vectors:**
- Submit many different target domains to enumerate infrastructure
- Use quick scan for passive reconnaissance of competitors
- Automate full scans to bypass ownership verification

**Mitigations:**
- Rate limiting: 5 scans per 30 minutes per IP hash
- Distinct-target-count tracking per IP
- Full scans require ownership verification (meta tag / file / DNS TXT)
- 10 anti-automation layers on the verification flow
- IP binding on verification tokens

### 2.3 Data Exfiltrator

**Goal:** Extract PII or scan results from the database.

**Attack vectors:**
- SQL injection via scan URL input
- Direct database access via leaked credentials
- API endpoint enumeration for unauthenticated data access

**Mitigations:**
- Input validation via Pydantic (URL regex + SSRF check)
- All PII hashed with server salt before storage
- Row-Level Security on all tables (default deny)
- No direct database URLs exposed in API responses
- Credentials in environment variables, never in git

### 2.4 Denial of Service

**Goal:** Overwhelm the scanner or use it to DoS target sites.

**Attack vectors:**
- Submit slow-responding targets to exhaust scan slots
- Submit many scans to fill the queue
- Use port scanning against targets to generate traffic

**Mitigations:**
- 180-second hard deadline per scan
- 3 concurrent scan limit (configurable)
- Rate limiting (5 per 30 min per IP)
- Target-side rate limit (0.5s between multi-page probes)
- Queue system with position tracking

### 2.5 Supply Chain Attacker

**Goal:** Compromise the scanner via a malicious dependency.

**Attack vectors:**
- Typosquatting on PyPI
- Compromised upstream package (dependency confusion)
- Malicious PR introducing a backdoor

**Mitigations:**
- Pinned dependency versions in `requirements.txt`
- Dependabot for automated update monitoring
- pip-audit in CI for vulnerability scanning
- Minimal dependency surface (10 direct deps)
- Code review required for all PRs

## 3. Attack Tree

```
Compromise Scanner
├── SSRF (use scanner to reach internal services)
│   ├── Direct private IP in URL           → blocked by is_safe_target()
│   ├── Redirect to private IP             → blocked by safe_get() per-hop check
│   ├── DNS rebinding                      → blocked by pre-request DNS resolution
│   └── IPv4-mapped IPv6                   → blocked by IPv6 unwrap + recheck
│
├── Abuse (use scanner for unauthorized scanning)
│   ├── Automated full scans               → blocked by 10 anti-automation layers
│   ├── Mass reconnaissance                → blocked by rate limits + target tracking
│   └── Bypass ownership verification      → blocked by IP binding + one-time tokens
│
├── Data theft
│   ├── SQL injection                      → blocked by Pydantic validation
│   ├── Credential leak                    → blocked by env vars, no secrets in git
│   └── Unauthenticated API access         → blocked by RLS + endpoint design
│
├── Denial of service
│   ├── Slow target exhaustion             → blocked by 180s deadline
│   ├── Queue flooding                     → blocked by rate limits
│   └── Target-side DoS via scanner        → blocked by 0.5s rate limit, passive approach
│
└── Supply chain
    ├── Malicious dependency               → blocked by pinned versions + pip-audit
    └── Malicious PR                       → blocked by code review requirement
```

## 4. Residual Risks

| Risk | Likelihood | Impact | Status |
|------|-----------|--------|--------|
| Zero-day in `requests` library | Low | High | Monitored via Dependabot |
| DNS rebinding with very short TTL | Very Low | Medium | Mitigated (pre-request resolution) |
| Timing side-channel on rate limiter | Low | Low | Accepted |
| Single-maintainer bus factor | Medium | Medium | Documented in FOR-BUYERS.md |
| HF Spaces platform incident | Low | High | Portable to any Docker host |

## 5. Review Schedule

This threat model is reviewed:
- **Quarterly** as part of the DR drill
- **After any security incident**
- **After major architectural changes** (e.g., new scan mode, new data store)

---

*This document is licensed under CC BY-NC 4.0. See [CONTENT-LICENSE.md](../CONTENT-LICENSE.md).*
