# ROADMAP — Web Security Scanner

Živi dokument za praćenje unapređenja skenera. Svaki red stavke sadrži
prioritet, procenu truda, pravni rizik i konkretne fajlove. Dok novi
moduli ne budu spremni, sva filozofija ostaje: **pasivno skeniranje,
dostojanstvena komunikacija, prevencija kao ogledalo — ne kao strah**.

## Legenda

**Status**: ✅ Done · 🔄 In progress · 📋 Planned · 💭 Research / filozofsko · 🚫 Deferred

**Effort**: **S** (1 fajl, < 200 linija, 1 sesija) · **M** (2-3 fajla, DB/API izmene, 1-2 sesije) · **L** (migracije, UI, više sesija) · **XL** (nova arhitektura)

**Pravni rizik**: None · Low · Medium · High

---

## ✅ Završeno

### Subdomain Takeover Detection
- **Fajlovi**: `checks/takeover_check.py` (novo), `scanner.py` (registracija)
- **Commit**: `af6ff94`
- **Pokriva**: 51 subdomen × 22 SaaS servisa (GitHub Pages, Heroku, S3, CloudFront, Azure, Shopify, Fastly, Tumblr, Surge, Bitbucket, Ghost, Zendesk, Unbounce, Pantheon, Readme.io, Netlify, Webflow, Kinsta, Strikingly, Helpjuice, Tilda, Intercom)
- **Detekcija**: two-gate (CNAME match → HTTP fingerprint verify) za 0 false positives na legitimnim CNAME-ima

### Git Deep Walker (bivša #8)
- **Fajl**: `checks/files_check.py` (extend)
- **Commit**: `0a1bbee`
- **Pokriva**: 6 internih .git fajlova (HEAD, index, logs/HEAD, refs/heads/main, refs/heads/master, packed-refs), svaki sa path-aware content validacijom
- **Threshold**: 2+ pogodaka → jedan agregirani CRITICAL nalaz `git_deep_dumpable` (napadač može pokrenuti `git-dumper` i rekonstruisati ceo repo)
- **Dedup**: `refs/heads/main` + `refs/heads/master` računaju se kao jedan hit — default branch sam ne može da prebaci threshold
- **SPA guard**: text putanje odbijaju body koji počinje sa `<!doctype html` ili `<html`

### Prošireni Dangerous Ports (bivša #1)
- **Fajl**: `checks/ports_check.py` (extend)
- **Commit**: `941fef2`
- **Pokriva**: 10 → 25 portova, podeljeno u 4 kategorije:
  - Distribuirane baze: Cassandra 9042, CouchDB 5984, RethinkDB 28015, Couchbase 8091
  - Message brokeri i coordination: RabbitMQ 15672, Kafka 9092, Zookeeper 2181
  - Container orchestration: Docker daemon 2375/2376, Kubelet 10250, etcd 2379
  - Search i big data: Solr 8983, Hadoop NameNode 50070, Spark master 7077, Spark UI 4040
- **Severity breakdown**: 12 CRITICAL, 10 HIGH, 2 MEDIUM, 1 LOW
- **Tri RCE-trigger porta označena CRITICAL**: Docker daemon 2375 (trivijalni RCE), Kubelet 10250 (node RCE), etcd 2379 (cluster takeover)
- `max_workers` bumped 10 → 15 da wall-time ostane ~6s za 25 portova

### CSP Strict Analyzer (bivša #2)
- **Fajl**: `checks/headers_check.py` (extend)
- **Commit**: `dced3eb`
- **Pokriva**: 8 provera kvaliteta postojećeg CSP-a:
  - `script-src` (sa fallback na `default-src`): `'unsafe-inline'` HIGH, `'unsafe-eval'` HIGH, wildcard `*` CRITICAL, `data:` URI HIGH
  - Nedostajuće direktive: `object-src` (ako `default-src` nije `'none'`) MEDIUM, `base-uri` LOW, `frame-ancestors` LOW, `form-action` LOW
- **Format**: jedan agregirani `hdr_csp_weak` nalaz sa listom svih slabosti, severity = max pojedinačne slabosti
- **Fallback semantika**: `script-src` nasleđuje `default-src`; `base-uri`/`frame-ancestors`/`form-action` ne nasleđuju (po CSP spec-u)
- 10/10 unit testova: strict policy, individualne slabosti, fallback, empty CSP, all-wrong slučaj

### JWT Exposure & Weakness Check (bivša #11)
- **Fajl**: `checks/jwt_check.py` (novo), `scanner.py` (registracija single-page + multi-page)
- **Commit**: `6791825`
- **Pokriva**: pasivnu detekciju JWT-ova u 3 izvora (response body, response headers, session cookies) i 4 klase slabosti:
  - `alg: none` → CRITICAL (trivijalna falsifikacija — token bez potpisa)
  - `HS256/HS384/HS512` sa slabim secretom → CRITICAL (offline dictionary attack nad curated listom od ~55 javno poznatih weak secrets)
  - Missing `exp` claim → LOW ("token traje zauvek")
  - `exp` > 1 godina u budućnost → LOW
- **Offline dictionary attack**: HMAC računanje in-process nad već primljenim bajtovima, 100 pokušaja za 0.3ms — nula mrežnog saobraćaja ka meti, tehnički HMAC verify a ne cracking
- **Dedup**: 5 tokena sa istom slabošću → 1 agregirani nalaz (ne 5)
- **Masking**: tokeni su skraćeni na prvih 24 char-a u izveštaju da ne bi zapisivali pune kredencijale
- 13/13 unit testova: sva 4 tipa slabosti, HS384 varijanta, empty string secret, Authorization header detekcija, dedup, false positive rejection, mixed-issue aggregation, timing bound

---

## 📋 Next up — Easy wins (S, None/Low legal)

Male izmene, visoka vrednost. Redosled je okviran — biraj šta ti je najvažnije.

### 3. DMARC policy parser
- **Fajl**: `checks/dns_check.py` ili `checks/email_security_check.py` (extend)
- **Effort**: S · **Legal**: None · **Impact**: MEDIUM
- **Obuhvat**: ne samo "ima DMARC", parsiraj `p=none/quarantine/reject`, `pct=`, `rua=`, `sp=`, flaguj `p=none` kao slab
- **Zašto**: 80% srpskih `.rs` domena ima `p=none` (monitoring only) — to je DMARC samo na papiru.

### 4. Modern email security (MTA-STS, TLS-RPT, BIMI, DANE)
- **Fajl**: `checks/email_security_check.py` (extend)
- **Effort**: S · **Legal**: None · **Impact**: MEDIUM
- **Obuhvat**: probe `/.well-known/mta-sts.txt`, DNS TLS-RPT record, BIMI DNS record, DANE TLSA records
- **Zašto**: moderni email security stack, niko u Srbiji ne proverava.

### 5. Cookie prefix enforcement
- **Fajl**: `checks/cookies_check.py` (extend)
- **Effort**: S · **Legal**: None · **Impact**: LOW
- **Obuhvat**: flaguj `session`/`auth` kolačiće koji ne koriste `__Host-` ili `__Secure-` prefikse

### 6. `.well-known` endpoint enumerator
- **Fajl**: novo `checks/wellknown_check.py`
- **Effort**: S · **Legal**: None · **Impact**: LOW-MEDIUM
- **Obuhvat**: `security.txt` (već imaš), `change-password`, `assetlinks.json`, `apple-app-site-association`, `openid-configuration`, `openpgpkey`, `host-meta`, `webfinger`, `nodeinfo`

### 7. HSTS preload list check
- **Fajl**: `checks/ssl_check.py` ili `checks/headers_check.py` (extend)
- **Effort**: S · **Legal**: None · **Impact**: LOW
- **Obuhvat**: proveri da li je domen u Chromium HSTS preload listi (cache-ovana statička lista)

### 9. DS_Store / IDE / backup leak check
- **Fajl**: `checks/files_check.py` (extend)
- **Effort**: S · **Legal**: None · **Impact**: MEDIUM
- **Obuhvat**: `/.DS_Store`, `/.idea/workspace.xml`, `/.vscode/settings.json`, `/Thumbs.db`, `/desktop.ini`, `/.env.local`, `/.env.backup`, `/.env.production`, `/backup.sql`, `/dump.sql`, `/users.csv`, `/site.zip`

### 10. Source map deep parser
- **Fajl**: `checks/js_check.py` (extend)
- **Effort**: S-M · **Legal**: None · **Impact**: MEDIUM
- **Obuhvat**: kada `.map` detektovan, fetch, parse `sources` array, flaguj leaked interne path-ove koji sadrže `/home/`, `C:\Users\`, imena programera, secret-like substringove

### 12. Crossdomain / clientaccesspolicy check
- **Fajl**: `checks/files_check.py` (extend)
- **Effort**: S · **Legal**: None · **Impact**: MEDIUM
- **Obuhvat**: `/crossdomain.xml` i `/clientaccesspolicy.xml` — ako postoje i imaju `*`, flaguj (Flash/Silverlight legacy, i dalje eksploatabilan na nekim sajtovima)

---

## 📋 Medium effort (M, None/Low legal)

### 13. crt.sh deep subdomain enumeration
- **Fajl**: novo `checks/ct_subdomains.py` ili extend `takeover_check.py`
- **Effort**: M · **Legal**: None (crt.sh je javan)
- **Impact**: **HIGH**
- **Obuhvat**: upit `https://crt.sh/?q=%.domain.com&output=json`, ekstraktuj sve istorijske subdomene iz izdatih sertifikata, spusti ih na `takeover_check.run()`. Rate-limit handling obavezan.
- **Zašto**: statična lista od 51 subdomena hvata uobičajene; crt.sh hvata zaboravljene (`old-staging-2019`, `backup-db-migration`, itd.) — pravi biseri za takeover.

### 14. WPScan-lite
- **Fajl**: `checks/cms_check.py` (extend) ili novo `checks/wpscan_lite.py`
- **Effort**: M · **Legal**: Low · **Impact**: **CRITICAL**
- **Obuhvat**: enumeracija plugin-a preko `/wp-content/plugins/*/readme.txt`, match protiv lokalnog CVE feed-a, user enum preko `/?author=1..10`, `xmlrpc.php` exposure, `wp-json/wp/v2/users` enum
- **Zašto**: WordPress je 40%+ srpskih sajtova. Jedan ranjiv plugin = potpuna kompromitacija. Ovo je najveći single-module ROI.

### 15. Banner grabbing na otvorenim portovima
- **Fajl**: `checks/ports_check.py` (extend)
- **Effort**: M · **Legal**: Low (single read, no exploitation)
- **Impact**: MEDIUM
- **Obuhvat**: na detektovanim otvorenim portovima pročitaj prvih 1KB (SSH banner, HTTP Server header, Redis `INFO`, SMTP greeting), match protiv lokalnog vuln DB

### 16. DNS zone transfer (AXFR) attempt
- **Fajl**: `checks/dns_check.py` (extend)
- **Effort**: S-M · **Legal**: Low (standardni DNS protokol)
- **Impact**: **CRITICAL** kada prolazi (retko ali kad da, tarik)
- **Obuhvat**: za svaki NS server, probaj AXFR. Ako uspe, flag CRITICAL + lista prvih N zapisa (anonimizovano u UI)

### 17. Nuclei templates runner (safe subset)
- **Fajl**: novo `checks/nuclei_check.py` + Docker binary
- **Effort**: M-L · **Legal**: Medium (zavisi od izbora template-a)
- **Impact**: **HIGH** (hiljade battle-tested provera besplatno)
- **Obuhvat**: bundle nuclei binary u Docker image, kurirana lista template-a sa tagovima `exposure,misconfig,cve,panel,token-spray`. Strogo isključi bilo šta sa tagom `intrusive`, `dos`, `fuzz`, `sqli`, `rce`.

---

## 💭 Hard / Philosophical (L / XL effort)

### 18. Prevention Receipts Database
- **Fajlovi**: `migrations/NNN_scan_history.sql`, `db.py` (extend), `api.py` (extend), `index.html` (extend)
- **Effort**: L · **Legal**: **Medium** — treba privacy policy update i GDPR retention policy
- **Impact**: Strateški — ovo je šta čini Mythos narativ realnim ("rekao sam ti pre 90 dana")
- **Obuhvat**:
  - Nova `scan_history` tabela: `domain`, `scanned_at`, `score`, `findings_snapshot` (JSONB), `scan_id`
  - Post-scan hook automatski upisuje snapshot
  - Public `/history/:domain` endpoint sa timeline prikazom
  - UI: "Ova nedelja vs pre 30/90/180 dana" diff
  - Retention: agregirani score-ovi zauvek, detaljni findings 1 god, posle toga auto-anonimizacija
  - Privacy policy: eksplicitna sekcija o istorijskim snapshot-ima, opt-out forma
- **Gate**: ne kreći bez privacy policy update-a

### 19. Continuous Monitoring (diff mode)
- **Fajlovi**: novi worker (cron), `db.py`, notification sistem (email/webhook)
- **Effort**: L · **Legal**: Low (samo za consented domene)
- **Impact**: **HIGH** — ovo je kako prodaješ recurring subscription
- **Obuhvat**: korisnik dodaje domen na "monitor list", weekly rescan, diff protiv poslednjeg, notifikacija ako se pojavi novi CRITICAL/HIGH

### 20. AI Business Logic Anomaly Detection — Mythos core
- **Fajlovi**: novo `mythos/` paket, Claude API integracija, prompt caching
- **Effort**: XL · **Legal**: Medium (podaci idu do LLM provider-a)
- **Impact**: Ovde se "Mythos pronalazi ono što iskusan developer nije predvideo" stvarno dešava
- **Obuhvat**:
  - Pipe scan findings + site structure + CMS kontekst u Claude API
  - Prompt kaže: "identifikuj suspicious obrasce koje rule engine ne bi uhvatio"
  - Cache-uj po domain+version ključu agresivno (prompt caching)
  - Izbegni claim "100 grešaka"; ciljaj "3 kontekstualne pretnje sa exploit chain objašnjenjem"
- **Filozofija**: ne broj nalaza, već **kvalitet insight-a**

### 21. Correlation Engine preko Scan DB
- **Fajl**: `mythos/correlation.py`, cron jobs
- **Effort**: L · **Legal**: Low
- **Impact**: HIGH (zahteva #18 prvo)
- **Obuhvat**: preko svih skenova u bazi, pronađi pattern-e tipa "90% sajtova sa WP 6.2 + plugin X imaju CVE Y"; prikaži po-scan: "tvoj profil se poklapa sa high-risk klasterom"

---

## 🚫 Deferred — legal review obavezan pre početka

### Active payload injection (SQLi, XSS, SSTI, RCE)
- **Risk**: **HIGH** — samo na eksplicitno autorizovanim domenima
- **Gate**: zahtevaj upload potpisanog pentest ugovora pre aktivacije. Odvojeni "Pro Active" tier, ne default scan.

### Authenticated scanning
- **Risk**: **HIGH** — kredencijali u bazi, rizik od impersonacije
- **Gate**: zahteva dedicated UI, credential vault, striktna access control

### Automatizovan cold outreach na pronađene ranjivosti
- **Risk**: **HIGH** — GDPR, zakon o neželjenim komercijalnim komunikacijama
- **Gate**: pravno mišljenje + NCERT registracija + opt-in flow + coordinated disclosure template

---

## Decision log

- **2026-04-11** — Roadmap startovan. Završen subdomain takeover check kao prvi dodatak.
- **2026-04-11** — Filozofija zaključana: passive-only, "ogledalo ne strah", dostojanstvena komunikacija, legitimnost pre outreach-a.
- **2026-04-11** — Prevention Receipts DB (#18) označen kao prerekvizit za Mythos korelaciju (#21) i Continuous Monitoring (#19).
- **2026-04-12** — Završene tri easy-win stavke u jednoj sesiji: #8 Git deep walker (`0a1bbee`), #1 Prošireni dangerous ports 10→25 (`941fef2`), #2 CSP strict analyzer (`dced3eb`). Go-to-market kontekst potvrđen: B2B outreach kroz hosting kuće, nikakav direktan kontakt sa vlasnicima sajtova.
- **2026-04-12** — Sledeći planirani redosled po korisniku: #11 JWT exposure check, potom #14 WPScan-lite, pa ostale S/M stavke u pasivnim granicama. Izvan ROADMAP-a: potrebna nova `user-rights.html` legal stranica jer trenutni footer linkovi "Prava korisnika" vode na generic GDPR blog umesto na dedicated legal fajl.
- **2026-04-12** — Završeno #11 JWT exposure & weakness check (`6791825`). Offline dictionary attack prihvaćen kao pasivna tehnika jer nema mreže — HMAC računanje nad već primljenim bajtovima je tehnički verifikacija a ne cracking. Push na space je odložen dok i #14 ne bude gotov, da se HF Space ne rebildje dva puta u kratkom roku.

---

## Kako koristiti ovaj fajl

1. Kad želiš da kreneš novu stavku, reci broj (npr. "idemo na #8") ili ime
2. Stavka se obradi po redosledu: plan → implementacija → test → commit → push → update ROADMAP.md status
3. Novi nalazi koje otkriješ tokom rada dodaj u odgovarajuću sekciju sa istim formatom
4. Stavka prelazi u ✅ sekciju tek posle uspešnog commit-a sa hash-om
