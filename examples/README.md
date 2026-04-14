# Examples

This directory contains ready-to-use integration examples:

| File | Description |
|------|-------------|
| [github-actions-security-gate.yml](github-actions-security-gate.yml) | GitHub Actions workflow that blocks deploys below a security grade threshold |
| [portfolio_scan.py](portfolio_scan.py) | Python script to scan multiple domains and generate a portfolio report |
| [docker-compose.yml](docker-compose.yml) | Self-contained Docker Compose deployment with PostgreSQL |

## Quick Start

### GitHub Actions

Copy `github-actions-security-gate.yml` to your project's `.github/workflows/` directory and set the `SCAN_TARGET_URL` secret.

### Portfolio Scanner

```bash
pip install requests tabulate
python portfolio_scan.py --domains my-domains.txt --threshold B
```

### Docker Compose

```bash
cd examples
docker compose up -d
# Open http://localhost:7860
```

## Need a different integration?

See [FOR-DEVELOPERS.md](../FOR-DEVELOPERS.md) for the REST API reference and [FOR-BUSINESS.md](../FOR-BUSINESS.md) for enterprise deployment patterns.
