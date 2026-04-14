# Scanner Configuration Presets

This directory contains YAML configuration presets for the scanner's
strictness profiles. They document the scoring parameters used by each
profile in a human-readable format.

> **Note:** These files are **reference documentation**, not runtime
> configuration. The actual profiles are defined in `scanner.py` →
> `STRICTNESS_PROFILES`. If you want to add a custom profile, add it
> to that dict and create a matching YAML here for documentation.

## Available Profiles

| Profile | File | Use Case | Grade A Threshold |
|---------|------|----------|-------------------|
| **Minimal** | [minimal.yml](minimal.yml) | CI/CD speed runs | ≥ 85 |
| **Standard** | [standard.yml](standard.yml) | General assessment (default) | ≥ 90 |
| **Strict** | [strict.yml](strict.yml) | Production hardening | ≥ 95 |
| **Paranoid** | [paranoid.yml](paranoid.yml) | Critical infrastructure | = 100 |

## Choosing a Profile

- **Individual developers / side projects** → `minimal` or `standard`
- **Startups / SaaS products** → `standard`
- **Enterprise / regulated industries** → `strict`
- **Banking / defense / critical infra** → `paranoid`

## API Usage

```json
POST /scan
{
    "url": "https://example.com",
    "strictness": "strict"
}
```

See [ARCHITECTURE.md](../ARCHITECTURE.md) for scoring engine details.
