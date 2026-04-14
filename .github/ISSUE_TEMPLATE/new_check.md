---
name: 🔍 New Security Check
about: Propose a new security check module
title: "[check] "
labels: ["new-check", "triage"]
assignees: []

---

## Check Overview

- **Name:** [e.g., "WebSocket Security Check"]
- **Module:** [e.g., `checks/websocket_check.py`]
- **Category:** [Security / DNS / Cookies / API / GDPR / SEO / Performance / Accessibility]
- **Tier:** [safe / redacted / full]

## What It Detects

Describe the security issue(s) this check would detect. Be specific:

1. [Detection 1] — [severity: CRITICAL/HIGH/MEDIUM/LOW]
2. [Detection 2] — [severity]
3. ...

## Why It Matters

- What is the real-world risk?
- How common is this misconfiguration?
- What attacks does it enable?

## Detection Logic

How would the check work? Describe the signals:

```
1. Fetch [endpoint/header/DNS record]
2. Parse [response]
3. Check for [pattern/absence/value]
4. If [condition], emit finding with severity [X]
```

## False Positive Considerations

- How might this check produce false positives?
- What mitigation strategies would you use?
- Are there known edge cases?

## Passive or Active?

- [ ] **Passive** — uses only publicly available information (DNS, headers, HTML body)
- [ ] **Active** — probes specific endpoints or sends non-standard requests

> If active, this check MUST be classified as `kind="full"` and will
> only run after ownership verification.

## References

- [Include links to relevant RFCs, OWASP pages, CVEs, or blog posts]

## I Would Like To

- [ ] **Implement this myself** — I'll submit a PR following CONTRIBUTING.md
- [ ] **Someone else implement this** — I'm proposing the idea only
