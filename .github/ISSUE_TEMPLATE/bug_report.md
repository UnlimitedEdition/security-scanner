---
name: 🐛 Bug Report
about: Report a bug in the scanner (false positive, crash, incorrect result)
title: "[bug] "
labels: ["bug", "triage"]
assignees: []

---

## Description

A clear and concise description of the bug.

## Steps to Reproduce

1. Go to '...'
2. Enter URL '...'
3. Select strictness profile '...'
4. See error

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include the error message or incorrect finding.

## Environment

- **Scanner version:** [e.g., v4.1.0 or commit hash]
- **Deployment:** [hosted / self-hosted Docker / self-hosted source]
- **Python version:** [e.g., 3.11.7]
- **OS:** [e.g., Ubuntu 22.04, macOS 14, Windows 11]
- **Browser:** [e.g., Chrome 124, Firefox 125] (if frontend bug)

## Scan Details (if applicable)

- **Target URL:** (only if it's a public site you own or control)
- **Scan mode:** safe / full
- **Strictness:** basic / standard / strict / paranoid
- **Check module:** [e.g., ssl_check, dns_check, files_check]

## Screenshots / Logs

If applicable, add screenshots or paste relevant log output.

```
Paste logs here
```

## Additional Context

Any other context about the problem — e.g., was this a regression
from a previous version, does it only happen with certain targets, etc.
