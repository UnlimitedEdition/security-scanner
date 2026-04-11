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

---

## 📋 Next up — Easy wins (S, None/Low legal)

Male izmene, visoka vrednost. Redosled je okviran — biraj šta ti je najvažnije.

### 1. Prošireni "dangerous ports" spisak
- **Fajl**: `checks/ports_check.py` (extend)
- **Effort**: S · **Legal**: None · **Impact**: HIGH
- **Dodaci**: 11211 (Memcached), 9042 (Cassandra), 5984 (CouchDB), 28015 (RethinkDB), 15672 (RabbitMQ), 9092 (Kafka), 2181 (Zookeeper), 2375/2376 (Docker daemon), 10250 (Kubelet), 2379 (etcd), 8091 (Couchbase), 8983 (Solr), 50070 (Hadoop), 7077 (Spark), 4040 (Spark UI)
- **Zašto**: trenutno hvataš klasične baze (MySQL/PG/Mongo/Redis), ali moderne stack-ove propuštaš. Exposed Memcached je čest u .rs prostoru.

### 2. CSP strict analyzer
- **Fajl**: `checks/headers_check.py` (extend) ili novo `checks/csp_check.py`
- **Effort**: S · **Legal**: None · **Impact**: MEDIUM
- **Obuhvat**: parse postojeći CSP header, flaguj `unsafe-inline`, `unsafe-eval`, `*`, `data:` u `script-src`, nedostajuće `object-src`, `frame-ancestors`, `base-uri`, `form-action`
- **Zašto**: trenutno samo proveravaš "da li postoji CSP", ne njegov kvalitet. Većina CSP-ova u praksi je "postoji ali bezvredan".

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

### 8. Git deep directory walker
- **Fajl**: `checks/files_check.py` (extend)
- **Effort**: S · **Legal**: Low · **Impact**: **CRITICAL**
- **Obuhvat**: pored `/.git/config`, probe `/.git/HEAD`, `/.git/logs/HEAD`, `/.git/refs/heads/main`, `/.git/index`, `/.git/packed-refs` — ako 2+ vraćaju 200, flaguj "full repo dumpable"
- **Zašto**: `.git/config` sam nije dovoljan za potpun leak; ova provera pokazuje da li napadač može da `git-dumper`-om rekonstruiše ceo repo.

### 9. DS_Store / IDE / backup leak check
- **Fajl**: `checks/files_check.py` (extend)
- **Effort**: S · **Legal**: None · **Impact**: MEDIUM
- **Obuhvat**: `/.DS_Store`, `/.idea/workspace.xml`, `/.vscode/settings.json`, `/Thumbs.db`, `/desktop.ini`, `/.env.local`, `/.env.backup`, `/.env.production`, `/backup.sql`, `/dump.sql`, `/users.csv`, `/site.zip`

### 10. Source map deep parser
- **Fajl**: `checks/js_check.py` (extend)
- **Effort**: S-M · **Legal**: None · **Impact**: MEDIUM
- **Obuhvat**: kada `.map` detektovan, fetch, parse `sources` array, flaguj leaked interne path-ove koji sadrže `/home/`, `C:\Users\`, imena programera, secret-like substringove

### 11. JWT exposure & weakness check
- **Fajl**: novo `checks/jwt_check.py`
- **Effort**: S-M · **Legal**: None (pasivno — samo gleda JWT koji su već vidljivi u response)
- **Impact**: **HIGH** (alg:none = instant auth bypass)
- **Obuhvat**: detektuj JWT pattern u response body/headers/cookies, base64-decode header, flaguj `alg:none`, `alg:HS256` sa sumnjivo kratkim secret-om (probaj common words offline), `exp` previše dugo, missing `kid`

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

---

## Kako koristiti ovaj fajl

1. Kad želiš da kreneš novu stavku, reci broj (npr. "idemo na #8") ili ime
2. Stavka se obradi po redosledu: plan → implementacija → test → commit → push → update ROADMAP.md status
3. Novi nalazi koje otkriješ tokom rada dodaj u odgovarajuću sekciju sa istim formatom
4. Stavka prelazi u ✅ sekciju tek posle uspešnog commit-a sa hash-om
