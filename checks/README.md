# checks/ — Security & Quality Check Modules

33 nezavisna check modula koje `scanner.py` poziva za analizu web sajtova.

## Kako radi

`scanner.py` importuje svaki check modul i poziva njegovu glavnu funkciju sa HTTP response podacima. Svaki check vraca listu nalaza (findings) sa severity, title, recommendation.

## Lista check-ova

| Modul | Sta proverava |
|-------|--------------|
| ssl_check | Sertifikat, istek, TLS verzija, cipher |
| headers_check | 11 security header-a (CSP, HSTS, X-Frame...) |
| seo_check | Meta tagovi, headings, sitemap, OG |
| gdpr_check | Cookie consent, privacy policy, data collection |
| dns_check | DNS konfiguracija, DNSSEC |
| ports_check | Otvoreni portovi |
| cors_check | CORS podesavanja |
| cookies_check | Cookie flags (Secure, HttpOnly, SameSite) |
| performance_check | Page speed, resource size |
| accessibility_check | a11y standardi |
| admin_check | Exposed admin paneli |
| api_check | API endpoint bezbednost |
| cms_check | CMS detekcija i verzije |
| ct_check | Certificate Transparency |
| dependency_check | Frontend zavisnosti |
| disclosure_check | Information disclosure |
| email_security_check | SPF, DKIM, DMARC |
| extras_check | Dodatne provere |
| files_check | Exposed fajlovi (.git, .env...) |
| js_check | JavaScript bezbednost |
| jwt_check | JWT konfiguracija |
| observatory_check | Mozilla Observatory |
| redirect_check | Redirect chain analiza |
| robots_check | robots.txt analiza |
| subdomain_check | Subdomain enumeration |
| takeover_check | Subdomain takeover |
| tech_stack_check | Tehnologije detekcija |
| vuln_check | Poznate ranjivosti |
| wellknown_check | .well-known endpointi |
| whois_check | WHOIS informacije |
| wpscan_lite_check | WordPress bezbednost |
| crawler | Link discovery za multi-page scan |

## Kako dodati novi check

1. Kreiraj `novi_check.py` u ovom folderu
2. Funkcija mora da primi HTTP response podatke i vrati listu nalaza
3. Svaki nalaz mora imati: `id`, `title`, `severity`, `passed`, `recommendation`
4. Importuj i registruj u `scanner.py`
5. Dodaj test u `tests/`

## Konvencije

- Imenovanje: `ime_check.py` (snake_case + _check suffix)
- Licenca: MIT header na vrhu svakog fajla
- Svaki check je nezavisan — pad jednog ne utice na ostale
