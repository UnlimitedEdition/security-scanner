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

### Gate-before-scan model (architectural rewrite, 2026-04-12)
- **Fajlovi**: `migrations/013-016`, `db.py`, `scanner.py`, `checks/disclosure_check.py`, `checks/jwt_check.py`, `checks/js_check.py`, `api.py`, `index.html`, `privacy.html`, `terms.html`
- **Commit**: TBD
- **Problem koji rešava**: stari skener je pokretao SVIH 30 check-ova bezuslovno pa filtrirao osetljive nalaze TEK na display layer-u (`_redact_result()`). To znači da je target server PRIMIO probe-ove za `/.env`, `/wp-admin/`, `/backup.sql`, port scan, GraphQL introspection itd. čak i od neverifikovanih korisnika. Filter je bio prekasan — osetljivi podaci su već postojali u memoriji backenda i u bazi.
- **Novi model**: dva moda skeniranja sa **gate-om PRE skena**, ne filterom POSLE.
  - **`mode='safe'` (default)**: 17 SAFE check-ova + 3 SAFE+REDACTED (disclosure/js/jwt) koji rade ali sumarno bez tačnih vrednosti. Zero probe-ova ka privatnoj infrastrukturi. Nikad ne dira `/.env`, admin panele, vuln scan, port scan.
  - **`mode='full'` (samo posle wizard-a)**: dodatnih 10 FULL check-ova (files, admin, vuln, ports, api, cors, dependency, subdomain, takeover, wpscan).
- **Wizard flow** (`POST /scan/request` → `/consent` × 3 → `/consent/finalize` → `/verify` → `/execute`): 3 odvojene saglasnosti server-side, svaki klik audit-loguje, finalna recap strana sa 3-sekundnim anti-reflex delay-om pre `POKRENI`.
- **Privacy by design**: `scan_requests` tabela koristi `created_date DATE` (NE `TIMESTAMPTZ`), API response-i nikad ne vraćaju vreme klika. Cak ni kompletan leak baze ne moze da otkrije kada je korisnik kliknuo consent.
- **Defansivne mere u DB**: SVE state machine tranzicije su atomicne UPDATE-ove sa WHERE clausama koji re-validiraju izvorni state. `mark_scan_request_executed` ima 6-uslovni WHERE (status, sva 3 consent-a, verify_passed) tako da malicious frontend ne moze da preskoci ni jedan korak.
- **Backward compat**: legacy `/scan` endpoint je hardkodovan na `mode='safe'` cak i ako frontend salje `mode:'full'` u body. Stari frontend dobija default ponasanje bez izmena.
- **Test trail**: 17 curl test-ova + 16 Playwright browser test-ova prosli pre push-a, security advisori 0 lints na produkciji posle migracija.

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

### DS_Store / IDE / backup leak check (bivša #9)
- **Fajl**: `checks/files_check.py` (extend)
- **Commit**: `e6d466a`
- **Pokriva**: 10 novih osetljivih fajlova podeljenih u 3 kategorije (SENSITIVE_FILES sa 11 → 21 entry-ja, CONTENT_SIGNATURES sa 11 → 21 signatures):
  - **IDE/OS metadata** (MEDIUM/LOW): `.idea/workspace.xml` (JetBrains), `.vscode/settings.json` (VS Code), `Thumbs.db` (Windows binary magic), `desktop.ini` (Windows INI)
  - **Environment variants** (CRITICAL): `.env.local`, `.env.backup`, `.env.production` — istih signature kao postojeći `.env`
  - **Backups/eksporti** (CRITICAL): `dump.sql` (isto sig kao `backup.sql`), `users.csv` (CSV header pattern sa reject_html guard-om), `site.zip` (ZIP magic isti kao `backup.zip`)
- Svaki entry ima specifican content signature — SPA catch-all 200 OK responses se odbijaju
- 9/9 signature unit testova: thumbs.db binary magic, desktop.ini INI headers, VSCode JSON keys, idea XML, env substrings, users.csv CSV header, site.zip ZIP magic, dump.sql SQL markers, SPA rejection

### Crossdomain / clientaccesspolicy check (bivša #12)
- **Fajl**: `checks/files_check.py` (extend)
- **Commit**: `5e03404`
- **Pokriva**: 2 nova entry-ja — `/crossdomain.xml` (Flash policy) i `/clientaccesspolicy.xml` (Silverlight policy), oba MEDIUM severity
- **Signatures**: `<cross-domain-policy>` / `<allow-access-from>` za Flash, `<access-policy>` / `<cross-domain-access>` / `<allow-from>` za Silverlight
- Silverlight je deprecated od 2021, Flash od 2020 — postojanje ovih fajlova na modernim sajtovima je skoro uvek konfiguracijska greska ili zaboravljen legacy
- SENSITIVE_FILES: 21 → 23, CONTENT_SIGNATURES: 21 → 23

### Source Map Deep Parser (bivša #10)
- **Fajl**: `checks/js_check.py` (extend — 2 nova helpera + integracija u _check_source_maps)
- **Commit**: `ebcd754`
- **Pokriva**: kada se detektuje pristupačan `.map` fajl, sada se i **fetch-uje** i parsira JSON, i `sources` array se analizira za 5 klasa leak patterna:
  - `/home/<user>/` → MEDIUM (Linux/macOS developer path)
  - `/Users/<user>/` → MEDIUM (macOS developer path)
  - `C:\Users\<user>\` ili `C:/Users/` → MEDIUM (Windows developer path)
  - `/root/` → HIGH (build kao root, ceo sistem kompromitovan pri incidentu)
  - `/var/www/` → LOW (build layout leak)
- **Novi nalaz**: `js_source_map_leaks` (severity = max detektovanih leak patterna), odvojen od postojećeg `js_source_maps` MEDIUM-a
- **Bezbednosno**: bomb guard (2 MB max), dedup po label klasi, SSRF-guarded preko `safe_get`
- 5/5 leak pattern testova + edge case testovi (size bomb, non-JSON, empty, missing sources array)

### .well-known Endpoint Enumerator (bivša #6)
- **Fajl**: `checks/wellknown_check.py` (novo, 205 linija), `scanner.py` (registracija na pct=55 posle extras_check)
- **Commit**: `29b60f6`
- **Pokriva**: 8 IETF/W3C registered .well-known endpoint-a (security.txt vec pokriven u extras_check):
  - `/change-password` (RFC 8615) — prihvata 200/302 redirect
  - `/assetlinks.json` — Android App Links (JSON validation)
  - `/apple-app-site-association` — iOS Universal Links (JSON validation)
  - `/openid-configuration` — OIDC discovery document (JSON validation)
  - `/host-meta` — XRD metadata
  - `/webfinger` — social discovery
  - `/nodeinfo` — ActivityPub/Fediverse server info (JSON validation)
  - `/openpgpkey/hu/policy` — OpenPGP Web Key Directory
- **Svi nalazi su INFO pozitivni** — missing endpoint-i se ne flaguju jer većina sajtova legitimno ne koristi većinu ovih. Vrednost je u surfacing onoga sto JESTE izloženo
- **Validacija**: JSON endpoint-i moraju parse-ovati kao dict/list; text endpoint-i imaju SPA HTML guard — oba odbijaju catch-all 200 OK shell-ove

### Modern Email Security (bivša #4)
- **Fajl**: `checks/email_security_check.py` (extend)
- **Commit**: `dc1b951`
- **Pokriva**: 3 nove email-security provere + 1 fix postojeće:
  - **MTA-STS full verify** (MEDIUM if policy missing) — proverava i DNS record i HTTP policy fajl na `https://mta-sts.<domain>/.well-known/mta-sts.txt`. DNS record sam nije dovoljan; postojeća provera je ranije flagovala "pozitivno" i za domene sa samo DNS-om bez policy-ja
  - **TLS-RPT** — `_smtp._tls.<domain>` TXT record sa `v=TLSRPTv1`, INFO pozitivan nalaz
  - **DANE TLSA** — `_25._tcp.<primary_mx>` TLSA records, INFO pozitivan nalaz (resistant na CA kompromitaciju preko DNSSEC)
  - **MTA-STS missing policy** — novi MEDIUM fail finding kada DNS record postoji ali policy fajl nije dostupan ili malformiran
- Live verifikovano: gmail.com pravilno detektovan MTA-STS (DNS + policy) i TLS-RPT

### DMARC Deep Parser (bivša #3)
- **Fajl**: `checks/dns_check.py` (extend — 3 nova helpera, replacement inline logike)
- **Commit**: `fb35b90`
- **Pokriva**: 4 nove klase slabosti u postojećem DMARC record-u (pored postojeće `p=none` provere):
  - `p=none` → MEDIUM (monitoring only, ne blokira spoofing)
  - `p=` missing → HIGH (record postoji ali policy nedefinisana)
  - `pct<100` (sa p=quarantine/reject) → LOW (parcijalni enforcement)
  - Missing `rua` tag → LOW (nema aggregate report-a, slepilo za efikasnost)
  - `sp=none` → LOW (subdomeni nezaštićeni iako main domen jeste)
- **Format**: jedan agregirani `dns_dmarc_weak` nalaz sa listom svih slabosti, severity = max pojedinačne
- **Zašto je bitno po ROADMAP-u**: "80% srpskih .rs domena ima p=none (monitoring only) — to je DMARC samo na papiru". Sada osim p=none hvata i parcijalni pct, slepe politike bez rua, i subdomain fallback
- 8/8 unit testova: parser, strict policy (0 issues), p=none, pct=50, missing rua, sp=none, kombinovane slabosti, finding builder

### HSTS Preload List Check (bivša #7)
- **Fajl**: `checks/ssl_check.py` (extend)
- **Commit**: `a6365cb`
- **Pokriva**: lookup domena u Chromium HSTS preload listi kroz hstspreload.org API v2 — lightweight HTTP GET (read-only, unauthenticated)
- **Tri stanja**:
  - `preloaded` → INFO pozitivni nalaz "domen je u preload listi, first-visit je automatski zaštićen od SSL stripping"
  - `pending` → INFO pozitivni nalaz "submitted, čeka sledeći Chrome release"
  - `unknown` → LOW negativni nalaz sa uputstvima za submission na hstspreload.org
- **Fail-open**: ako API nije dostupan (network error, timeout, nepoznat status string) → vraća None i check se tiho preskače — ne želimo false "not preloaded" findings kad ne možemo da verifikujemo
- Live API test potvrđen: github.com → preloaded (bulk: True), google.com → unknown (pokriveno kroz parent TLD, ne direktno)

### Cookie Prefix Enforcement (bivša #5)
- **Fajl**: `checks/cookies_check.py` (extend)
- **Commit**: `d6e1470`
- **Pokriva**: detekcija session/auth kolačića koji ne koriste `__Host-` ili `__Secure-` prefiks (LOW severity, samo na HTTPS)
- **Selektivnost**: pattern match na imenu kolačića (session, sess, sid, auth, token, login, user, jwt, access, refresh, connect.sid, phpsessid, asp.net_sessionid) — non-session kolačići (analytics, consent, theme) se **ne** flaguju da se izbegne spam
- **HTTPS-only gate**: prefiks enforcement se primjenjuje samo kad je konekcija HTTPS — HTTP sajtovi dobiju druga upozorenja (no-Secure) pa prefiks postaje besmisleni
- 6/6 unit testova: session bez prefiksa, __Host- prihvaćen, __Secure- prihvaćen, analytics preskočeno, HTTP ignorisan, razni session nazivi (JSESSIONID, PHPSESSID, auth_token, jwt_refresh)

### WPScan-lite (bivša #14)
- **Fajl**: `checks/wpscan_lite.py` (novo, 585 linija), `scanner.py` (registracija single-page samo — domain-level check, ne ide u multi-page pass)
- **Commit**: `c8a4110`
- **Pokriva**: 4 WordPress-specifične površine, sve pasivne HTTP GET (nula POST-ova, nula login pokušaja, nula eksploatacije):
  - **Plugin enumeration** — paralelno (5 workers) probe `/wp-content/plugins/<slug>/readme.txt` za 20 najpopularnijih pluginova, parse `Stable tag:` za verziju, SPA guard preko `=== Plugin Name ===` marker-a, agregirani LOW nalaz sa listom svih detektovanih
  - **CVE matching** — curated `KNOWN_VULN_PLUGINS` dict sa 3 konzervativna well-documented CVE-a: Contact Form 7 ≤5.3.1 (CVE-2020-35489, unrestricted file upload, HIGH), Slider Revolution ≤4.2 (CVE-2014-9735, arbitrary file download, CRITICAL), UpdraftPlus ≤1.22.2 (CVE-2022-23337, backup disclosure, HIGH)
  - **User enumeration** — oba metoda kombinovana u jedan MEDIUM nalaz: `/wp-json/wp/v2/users` JSON parse + `/?author=1..3` 3xx Location header extraction
  - **xmlrpc.php** — GET (ne POST) za default WP response "XML-RPC server accepts POST requests only", MEDIUM nalaz za attack surface
- **Early exit**: `_is_wordpress(body)` gate pre bilo kog zahteva — non-WP sajtovi dobiju 0ms i 0 HTTP zahteva
- **Zašto samo single-page**: plugin lista, REST users, xmlrpc su svi domain-level, isti rezultat bez obzira koja stranica se probuje — ne vredi 10× ponavljanja za 10 Pro stranica
- 20 pluginova u listi, 3 CVE-a u dict-u, worst-case ~25 HTTP zahteva (20 plugin + 1 REST + 3 author + 1 xmlrpc)
- 6/6 unit testova + 1 end-to-end integration test sa mock responses: verifikovano 5 tipova nalaza sa tačnim severity nivoima

---

## 📋 Next up — Easy wins (S, None/Low legal)

Male izmene, visoka vrednost. Redosled je okviran — biraj šta ti je najvažnije.

---

## 📋 Medium effort (M, None/Low legal)

### 13. crt.sh deep subdomain enumeration
- **Fajl**: novo `checks/ct_subdomains.py` ili extend `takeover_check.py`
- **Effort**: M · **Legal**: None (crt.sh je javan)
- **Impact**: **HIGH**
- **Obuhvat**: upit `https://crt.sh/?q=%.domain.com&output=json`, ekstraktuj sve istorijske subdomene iz izdatih sertifikata, spusti ih na `takeover_check.run()`. Rate-limit handling obavezan.
- **Zašto**: statična lista od 51 subdomena hvata uobičajene; crt.sh hvata zaboravljene (`old-staging-2019`, `backup-db-migration`, itd.) — pravi biseri za takeover. **Stateless** — samo čita javnu CT bazu, ni jedan zahtev ne ide ka meti.

---

## 🔴 Permanent skip — trajno odbačeno (2026-04-12)

Sve stavke ispod ovog bloka su **eksplicitno odbačene** zbog hard red line-a o zero user data retention / stateless-by-design arhitekturi (vidi decision log 2026-04-12). Ne otvarati ponovo za diskusiju — trajno deferred bez obzira na tehničku vrednost.

### ~~15. Banner grabbing na otvorenim portovima~~ — SKIP
- **Razlog**: korisnik može da dozivi kao agresivno iako je tehnički pasivno (SSH/SMTP banneri su "autovaljni", ali Redis `INFO` šalje komandu). Rizik percepcije > vrednost.

### ~~16. DNS zone transfer (AXFR) attempt~~ — SKIP
- **Razlog**: pravno čist (standardni DNS protokol) ali se filozofski oseća kao napad — "zašto skener traži moju celu DNS zonu?". U 99% slučajeva ne prolazi ionako.

### ~~17. Nuclei templates runner~~ — SKIP
- **Razlog**: Nuclei je **klasifikovan kao vulnerability scanner** u većini jurisdikcija i reputacijski hosting kuće ga dožive kao hakerski alat bez obzira na "safe subset" tagove. Reputation cost > benefit.

### ~~18. Prevention Receipts Database~~ — SKIP
- **Razlog**: skladišti tuđu vulnerability info u persistentnoj bazi. Ako baza ikad procuri, korisnik je pravno izložen (GDPR) iako servis daje besplatno. Nedopustiv storage risk.

### ~~19. Continuous Monitoring (diff mode)~~ — SKIP
- **Razlog**: zahteva čuvanje scan baseline-a za diff, ista klasa storage rizika kao #18. Čak i opt-in ne smanjuje data breach risk — data je i dalje na serveru.

### ~~20. AI Business Logic / Mythos core~~ — SKIP
- **Razlog**: šalje scan findings do Anthropic Claude API-ja. Treća strana = treća površina za breach. Korisnik ne može garantovati šta Anthropic radi sa prosleđenim podacima na dugi rok, ne može kontrolisati njihove logove.

### ~~21. Correlation Engine preko Scan DB~~ — SKIP
- **Razlog**: zahteva #18 historijsku bazu, automatski pada sa #18.

**Šta ovo znači:** Scanner ostaje **stateless by design** — svaki scan je efemeran, rezultat ide direktno korisniku, nista ne ostaje na serveru. To je jaci B2B argument prema hosting kucama: "ne čuvamo ono što ne možemo da izgubimo". Monetizacija ide kroz stateless modele (više provera po scan-u, bolji izveštaji), ne kroz storage feature-a.

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
- **2026-04-12** — Završeno #14 WPScan-lite (`c8a4110`). Najveći single-module ROI po originalnoj proceni — pokriva 40%+ srpskih sajtova koji koriste WordPress. CVE dict drži se konzervativno (samo 3 entry-ja) jer je listanje netačnih CVE-ova gore od listanja nijednog. WPScan ide samo u single-page pass jer su sve 4 površine domain-level (plugin lista, REST users, xmlrpc su identični nezavisno od stranice). Non-WP sajtovi imaju nula dodatnih zahteva preko `_is_wordpress()` early-exit gate-a.
- **2026-04-12** — **Zakljucana crvena linija: ZERO USER DATA RETENTION.** Skener ne sme (a) skladistiti scan rezultate u persistentnu bazu, (b) transmitovati scan podatke trecima (Claude API, bilo koji LLM/eksterni sistem), (c) pokretati provere koje korisnik moze da dozivi kao agresivno. Razlog: servis je FREE — korisnik ne moze da nosi pravnu odgovornost za data breach na besplatnom alatu koji skenira tudje sajtove. Trajno deferred (ne samo "posle pripreme"): **#18 Prevention Receipts DB**, **#19 Continuous Monitoring** (zahteva storage baseline-a za diff), **#20 Mythos AI core** (salje scan podatke trecoj strani), **#21 Correlation Engine** (zahteva #18), **#15 Banner grabbing** (cak i SSH banner korisnik moze pogresno da protumaci), **#16 AXFR zone transfer** (pasivno ali "oseca se" agresivno), **#17 Nuclei templates** (reputacijski rizik — hosting kuce ga dozivljavaju kao hakerski alat bez obzira na subset tagove). Novi arhitektonski princip: **stateless by design**. Jaci B2B argument prema hosting kucama: "ne cuvamo ono sto ne mozemo da izgubimo".

---

## Kako koristiti ovaj fajl

1. Kad želiš da kreneš novu stavku, reci broj (npr. "idemo na #8") ili ime
2. Stavka se obradi po redosledu: plan → implementacija → test → commit → push → update ROADMAP.md status
3. Novi nalazi koje otkriješ tokom rada dodaj u odgovarajuću sekciju sa istim formatom
4. Stavka prelazi u ✅ sekciju tek posle uspešnog commit-a sa hash-om
