# Security Profile — Web Security Scanner
> Poslednji audit: 2026-04-18
> Ocena: B+ (82/100)

## Tech Stack
- Backend: Python 3.11 + FastAPI (async)
- Frontend: Vanilla HTML/JS (single page)
- Database: Supabase (Postgres) + ORM (nema raw SQL)
- Deploy: Vercel (frontend) + HF Spaces Docker (backend)
- Payment: Lemon Squeezy (webhook HMAC)

## Attack Surface
- 29 API endpointa u api.py
- User input: URL (scan target), fingerprint, license key, abuse report
- External API calls: URLhaus, OpenPhish, Wayback, crt.sh, DNS RBL
- Verification: meta tag, file, DNS TXT (3 metode)
- Payment webhook: /webhooks/lemon (HMAC verified)

## Poznate Dobre Prakse (ne menjaj)
- SSRF zastita: multi-layer, DNS rebinding defense, svaki redirect hop proveren (security_utils.py)
- PII hashing: SHA-256 + server salt pre upisa u bazu (db.py)
- Rate limiting: DB-backed + in-memory fallback + dual-key IP+fingerprint
- Webhook: HMAC-SHA256 constant-time comparison (subscription.py)
- Verification tokens: 128-bit entropy, IP-bound, 5 pokusaja max, 1h TTL
- Input validacija: Pydantic modeli, URL regex, domain normalizacija
- Error handling: poruke skracene na 200 char, nema stack trace-ova
- PDF generacija: in-memory, nema file I/O, Unicode sanitized (pdf_report.py)
- Migration runner: parameterized queries, checksum validacija

## Otvoreni Problemi (za resavanje)

### KRITICNO
1. [ ] Dockerfile radi kao root — dodaj USER appuser
2. [ ] CORS wildcard allow_origins=["*"] — ogranici na frontend origin
3. [ ] Ad-blocker throttle time.sleep(8.0) — zameni sa async ili ukloni

### VISOKO
4. [ ] CSP unsafe-inline u script-src i style-src — prebaci na nonce/hash
5. [ ] Fingerprint format validacija — dodaj regex (hex, 32-128 chars)

### SREDNJE
6. [ ] Punycode/IDN normalizacija u SSRF proveri — security_utils.py:158
7. [ ] Dockerfile bind 0.0.0.0 — koristi 127.0.0.1 u produkciji
8. [ ] Wayback API rate limiter — dodaj request queue

### NISKO
9. [ ] License key u Authorization: Bearer umesto custom header
10. [ ] Hardcoded Python path u start.bat
11. [ ] Token prefix u audit logu (8 hex chars)

## Prethodni Auditi
- 2026-04-18: Prvi audit. Ocena B+ (82/100). 3 kriticna, 2 visoka, 3 srednja, 3 niska nalaza.
