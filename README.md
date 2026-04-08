---
title: Web Security Scanner
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
short_description: Passive website security analysis - 60+ checks
---

# 🛡️ Web Security Scanner

Passive security analysis for websites — 60+ checks, no site modification.

## What it checks
- SSL/TLS certificate validity and configuration
- HTTP Security Headers (HSTS, CSP, X-Frame-Options...)
- DNS Security (SPF, DMARC, CAA)
- Sensitive file exposure (.env, .git, phpMyAdmin...)
- Cookie security flags
- Open dangerous ports (MySQL, Redis, MongoDB...)
- CORS policy
- CMS/Technology detection
- robots.txt analysis
- Admin panel exposure

## Tech Stack
- Python 3.11 + FastAPI
- dnspython, requests, certifi
