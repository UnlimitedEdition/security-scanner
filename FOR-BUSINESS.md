# For Business — Enterprise Deployment & Commercial Use

> **Audience:** CTOs, engineering managers, DevSecOps leads, and security
> consultants evaluating Web Security Scanner for organizational use.

---

## Table of Contents

- [Why Organizations Choose This Tool](#why-organizations-choose-this-tool)
- [Deployment Options](#deployment-options)
- [Enterprise Use Cases](#enterprise-use-cases)
- [Compliance & Regulatory Alignment](#compliance--regulatory-alignment)
- [Integration Patterns](#integration-patterns)
- [Security Posture of the Scanner Itself](#security-posture-of-the-scanner-itself)
- [Performance & Scaling](#performance--scaling)
- [SaaS Roadmap](#saas-roadmap)
- [Licensing for Commercial Use](#licensing-for-commercial-use)
- [Support & SLA](#support--sla)
- [Acquisition Due Diligence](#acquisition-due-diligence)

---

## Why Organizations Choose This Tool

### Problem

Most security scanning tools force a tradeoff:

| Tool type | Pros | Cons |
|-----------|------|------|
| **Active scanners** (ZAP, Nuclei, Burp) | Thorough, finds real vulnerabilities | Triggers WAF alerts, can break staging, requires expertise |
| **Header checkers** (SecurityHeaders, Observatory) | Safe, fast | Only checks HTTP headers (~10 signals) |
| **Enterprise DAST** (Checkmarx, Qualys, Rapid7) | Comprehensive | $50K+/year, complex setup, vendor lock-in |

### Solution

Web Security Scanner provides **240+ checks with zero risk to production**:

- **Passive-first approach** — mimics a normal browser visit
- **Ownership-gated active checks** — file enumeration, port scanning only after proving domain ownership
- **Self-hosted option** — complete data residency control
- **CI/CD native** — integrates into existing pipelines with one YAML block
- **MIT licensed** — no vendor lock-in, no license fees for the core engine

---

## Deployment Options

### Option 1: SaaS (Hosted)

Use the scanner at [security-skener.gradovi.rs](https://security-skener.gradovi.rs).

| Feature | Free tier | Pro tier |
|---------|-----------|----------|
| Quick scan (20 checks) | ✅ Unlimited | ✅ Unlimited |
| Full scan (33 checks) | ✅ With verification | ✅ With verification |
| Rate limit | 5 scans / 30 min | Unlimited |
| Multi-page scanning | 1 page | Up to 10 pages |
| PDF report export | ❌ | ✅ |
| Scan history | ❌ | 30 days |
| Price | Free | See [pricing](https://security-skener.gradovi.rs/pricing) |

### Option 2: Self-hosted (Docker)

Full control over data residency, scanning frequency, and customization.

```bash
# Quick start
git clone https://github.com/UnlimitedEdition/security-scanner.git
cd security-scanner
docker build -t security-scanner .
docker run -p 7860:7860 \
  -e PII_HASH_SALT="$(openssl rand -hex 32)" \
  security-scanner
```

### Option 3: Self-hosted with database

For scan history, audit logging, and Pro features:

```yaml
# docker-compose.yml
version: "3.8"
services:
  scanner:
    build: .
    ports:
      - "7860:7860"
    environment:
      - SUPABASE_URL=${SUPABASE_URL}
      - SUPABASE_SERVICE_KEY=${SUPABASE_SERVICE_KEY}
      - PII_HASH_SALT=${PII_HASH_SALT}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7860/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Option 4: Air-gapped / on-premises

The scanner engine runs entirely offline. The only external network
calls are to the target domains being scanned. No telemetry, no
phoning home, no licensing servers to contact.

Requirements:
- Python 3.11+ or Docker
- Network access to target domains
- (Optional) PostgreSQL 14+ for persistence

---

## Enterprise Use Cases

### 1. Pre-deployment security gate

Block production deploys that drop below a security grade threshold:

```yaml
# GitHub Actions example
- name: Security scan
  run: |
    GRADE=$(curl -s -X POST http://scanner:7860/scan \
      -d '{"url":"${{ env.STAGING_URL }}"}' | jq -r '.result.score.grade')
    if [[ "$GRADE" =~ ^(D|F)$ ]]; then
      echo "::error::Security grade $GRADE is below deployment threshold"
      exit 1
    fi
```

### 2. Portfolio monitoring

Scan all company web properties on a schedule:

```python
# scripts/portfolio_scan.py
import requests
import json
from datetime import datetime

DOMAINS = [
    "corporate-site.com",
    "app.product.com",
    "docs.product.com",
    "status.product.com",
]

results = []
for domain in DOMAINS:
    resp = requests.post("http://scanner:7860/scan",
        json={"url": f"https://{domain}", "consent_accepted": True})
    data = resp.json()
    results.append({
        "domain": domain,
        "grade": data["result"]["score"]["grade"],
        "score": data["result"]["score"]["score"],
        "critical": data["result"]["score"]["counts"].get("critical", 0),
        "scanned_at": datetime.utcnow().isoformat(),
    })

# Export for dashboard
with open("security_report.json", "w") as f:
    json.dump(results, f, indent=2)
```

### 3. Client-facing security reports

Security consultants generate PDF reports for client engagements:

1. Run a full scan with ownership verification
2. Export the PDF report (Pro feature)
3. Deliver the branded A4 report with severity breakdown, top priorities,
   and remediation guidance

### 4. Compliance evidence

Use scan results as evidence for:
- **SOC 2 Type II** — continuous monitoring control
- **ISO 27001** — A.12.6 "Technical vulnerability management"
- **PCI DSS** — Requirement 6.6 "Addressing web application threats"
- **GDPR Article 32** — "Security of processing" (demonstrate regular assessment)

### 5. Third-party risk assessment

Evaluate the security posture of vendors, partners, and acquisition targets
without requiring their cooperation or credentials. The quick scan (safe mode)
is indistinguishable from a normal browser visit.

---

## Compliance & Regulatory Alignment

### GDPR

| Requirement | Scanner's approach |
|-------------|-------------------|
| Legal basis (Art. 6) | Legitimate interest for audit log; consent for scanning |
| Data minimization (Art. 5) | PII hashed immediately, raw values never stored |
| Storage limitation (Art. 5) | 90-day auto-prune via pg_cron |
| Right to erasure (Art. 17) | Hash-based storage makes identification infeasible |
| Data breach notification (Art. 33) | Append-only audit log provides forensic trail |
| Privacy by design (Art. 25) | SHA-256 hashing at ingestion, RLS on all tables |

### Privacy-first architecture

- **No external data transmission** — scan data never leaves your infrastructure
- **No telemetry** — the scanner doesn't phone home
- **Cookie consent** — granular 3-category banner (essential/analytics/advertising)
- **PII impossible to reverse** — SHA-256 with server-side salt

---

## Integration Patterns

### REST API

The scanner exposes a simple REST API:

```
POST /scan                    → Start a scan
GET  /scan/{id}               → Poll scan status/results
GET  /health                  → Health check
POST /scan/request            → Start ownership verification wizard
POST /scan/request/{id}/verify → Verify ownership
POST /scan/request/{id}/execute → Run full scan
```

### Webhook / callback

Not yet implemented natively, but achievable with a polling wrapper:

```python
# Poll until complete, then POST results to your webhook
import time, requests

scan = requests.post("http://scanner:7860/scan",
    json={"url": "https://example.com"}).json()

while True:
    status = requests.get(f"http://scanner:7860/scan/{scan['scan_id']}").json()
    if status["status"] in ("completed", "error"):
        requests.post("https://your-webhook.com/security-results",
            json=status)
        break
    time.sleep(5)
```

### Prometheus metrics (roadmap)

Planned for a future release:

```
# HELP security_scanner_scans_total Total scans completed
# TYPE security_scanner_scans_total counter
security_scanner_scans_total{grade="A"} 1234
security_scanner_scans_total{grade="B"} 567
```

---

## Security Posture of the Scanner Itself

The scanner practices what it preaches:

| Control | Implementation |
|---------|---------------|
| **SSRF protection** | Every outbound request validated, every redirect hop rechecked |
| **PII hashing** | SHA-256 with server salt at ingestion |
| **Append-only audit** | UPDATE/DELETE revoked at DB level |
| **Encrypted backups** | AES-256-GCM, daily to Cloudflare R2 |
| **Row-Level Security** | Default deny on all tables |
| **Rate limiting** | Dual enforcement (DB + in-memory fallback) |
| **Dependency pinning** | Exact versions in requirements.txt |
| **Automated updates** | Dependabot for Python, Docker, GitHub Actions |
| **No secrets in git** | All credentials via environment variables |

Full details: [SECURITY.md](SECURITY.md)

---

## Performance & Scaling

### Single instance

| Metric | Value |
|--------|-------|
| Scan time | 45–90 seconds |
| Concurrent scans | 3 (configurable) |
| Memory per scan | ~50 MB |
| CPU per scan | ~0.3 vCPU |
| Network per scan | ~2 MB egress |

### Scaling horizontally

The scanner is stateless when run without a database. To scale:

1. Deploy multiple Docker instances behind a load balancer
2. Point all instances at the same Supabase project (or PostgreSQL)
3. Rate limiting, audit log, and scan persistence are handled by the shared DB

```
                    ┌──────────────┐
                    │ Load Balancer│
                    └──────┬───────┘
               ┌───────────┼───────────┐
               │           │           │
        ┌──────┴──┐ ┌──────┴──┐ ┌──────┴──┐
        │Scanner 1│ │Scanner 2│ │Scanner 3│
        └────┬────┘ └────┬────┘ └────┬────┘
             │           │           │
             └───────────┼───────────┘
                         │
                  ┌──────┴──────┐
                  │  PostgreSQL │
                  └─────────────┘
```

### Estimated throughput (3 instances, 3 concurrent each)

| Load | Scans/hour | Notes |
|------|-----------|-------|
| Light | ~120 | Average scan time 90s |
| Heavy | ~360 | Average scan time 30s (bot protection → skip content checks) |

---

## SaaS Roadmap

The scanner is designed with a clear path from open-source tool to
managed service:

### Current state (v4.x)

- ✅ Self-hosted MIT-licensed core engine
- ✅ Hosted SaaS with Pro tier
- ✅ PDF reports, multi-page scanning
- ✅ REST API for programmatic access

### Planned (v5.x)

- 🔲 **Team workspaces** — shared scan history, role-based access
- 🔲 **Scheduled scans** — cron-based recurring monitoring
- 🔲 **Webhook callbacks** — push results to Slack, PagerDuty, Jira
- 🔲 **Dashboard** — portfolio view with trend charts
- 🔲 **Prometheus metrics** — integrate with existing observability
- 🔲 **CLI tool** — `pip install security-scanner && security-scanner scan example.com`
- 🔲 **Custom check marketplace** — community-contributed check modules

### Planned (v6.x)

- 🔲 **Multi-tenant SaaS** — isolated workspaces per organization
- 🔲 **SSO / SAML** — enterprise identity integration
- 🔲 **Compliance templates** — SOC 2, ISO 27001, PCI DSS mapping
- 🔲 **API key authentication** — for CI/CD integration without cookies
- 🔲 **Scan comparison** — diff between two scans of the same target

---

## Licensing for Commercial Use

### Source code (MIT License)

You may use, modify, and redistribute the code freely — including for
commercial purposes — as long as the MIT notice is preserved. This means:

- ✅ Self-host for internal security scanning
- ✅ Integrate into your product or platform
- ✅ Modify and extend with proprietary checks
- ✅ Sell services built on the scanner
- ✅ Fork and operate as a competing SaaS

### Editorial content (CC BY-NC 4.0)

Blog articles, the operator handbook, privacy policy, and terms of service
are licensed under Creative Commons Attribution-NonCommercial 4.0. This means:

- ✅ Share and adapt with attribution
- ❌ Commercial use without permission
- 📧 Contact the maintainer for commercial content licensing

### Trademark

The name "**Web Security Scanner**" and the shield logo are trademarks
of Toske-Programer and are NOT covered by either license. Forks and
derivative products must use their own branding.

---

## Support & SLA

### Community support (free)

- GitHub Issues for bug reports
- GitHub Discussions for questions
- Security Advisories for vulnerability reports

### Enterprise support (planned)

- 📧 Priority email support
- ⏱️ 4-hour response SLA for critical issues
- 🔒 Private security advisory channel
- 📞 Annual architecture review call

Contact the maintainer via GitHub Security Advisory or the email in
the [footer](https://security-skener.gradovi.rs) to discuss enterprise
arrangements.

---

## Acquisition Due Diligence

For parties evaluating acquisition of the project as an asset, see
[FOR-BUYERS.md](FOR-BUYERS.md) which covers:

- Asset bundle (code, content, infrastructure, customers)
- Technical due diligence checklist
- Legal due diligence checklist
- Compliance posture
- Known risks and open items
- Post-sale transition plan

---

## Further Reading

- [README.md](README.md) — project overview, quick start, feature comparison
- [ARCHITECTURE.md](ARCHITECTURE.md) — system design and data flow
- [FOR-DEVELOPERS.md](FOR-DEVELOPERS.md) — extending the scanner
- [SECURITY.md](SECURITY.md) — threat model and security controls
- [FOR-BUYERS.md](FOR-BUYERS.md) — acquisition due diligence
