# PRIRUČNIK OPERATORA — Web Security Scanner

> **Za koga je ovaj dokument:** za tebe (operatera / vlasnika sistema) i za
> svakoga ko u budućnosti bude preuzeo operativnu brigu o ovom scanner-u.
> Ovo NIJE javna dokumentacija — `SECURITY.md` je za korisnike i istraživače
> sigurnosti. Ovaj priručnik je za onoga ko gasi požare.
>
> **Jezik:** namerno na srpskom. Kad ti se "nešto dešava", trebaš jasan
> tekst bez mentalnog prevođenja.

---

## 🚨 AKO TI SE SAD NEŠTO DEŠAVA — skoči direktno

| Situacija | Idi na sekciju |
|---|---|
| Neko mi šalje pretnju "skenirali ste me bez dozvole" | **§5.1** |
| Policija / sud / advokat traži podatke | **§5.2** |
| Korisnik traži "obrišite moje podatke" (GDPR) | **§5.3** |
| Scanner je prestao da radi | **§6.3** |
| Backup nije napravljen 2+ dana | **§6.1** |
| Mislim da je `SUPABASE_SERVICE_KEY` procureo | **§8** |

**Ako ne znaš na koju sekciju da odeš** — pročitaj §1 i §5. Sve ostalo je
referenca koju čitaš kad ti zatreba.

---

## 1. Arhitektura u 1 minutu

Scanner ima **3 glavna dela**:

```
┌──────────────┐    HTTPS    ┌───────────────┐    Postgres    ┌──────────────┐
│  Frontend    │────────────▶│  FastAPI      │───────────────▶│  Supabase    │
│  (HTML+JS)   │             │  (HF Spaces)  │                │  Postgres    │
│  Vercel      │             │  api.py       │                │  + Vault     │
└──────────────┘             └───────────────┘                └──────┬───────┘
                                     │                               │
                                     │                               │ pg_cron
                                     │                               │ svaki dan
                                     ▼                               ▼
                             ┌───────────────┐                 ┌──────────────┐
                             │  scanner.py   │                 │  Backup Edge │
                             │  + 23 check-a │                 │  Function    │
                             └───────────────┘                 └──────┬───────┘
                                                                       │
                                                                       ▼
                                                               ┌──────────────┐
                                                               │ Cloudflare R2│
                                                               │ (enkriptovan │
                                                               │  AES-256-GCM)│
                                                               └──────────────┘
```

**Kljucno da zapamtiš:**

- **Korisnik je uvek na korisničkoj strani** — šalje HTTP POST na
  `/scan` sa URL-om. Backend skenira i vraća rezultat.
- **Svaki scan se upisuje u bazu** kao red u tabeli `scans` + 3+ reda u
  `audit_log`. Ovo je **append-only** — ništa se ne briše osim po
  automatskom pruning-u posle 90 dana.
- **PII (IP adresa, User-Agent) se hashuje** pre nego što ikad dođe
  do baze. Raw vrednosti nikad nisu zapisane nigde.
- **Svaki dan u 04:00 UTC** pg_cron u bazi automatski pokreće edge
  funkciju koja povlači kritične tabele, gzipuje, enkriptuje, i šalje
  u Cloudflare R2 kao offsite backup.
- **Ako se nešto desi i treba da restore-uješ** — skripta
  `scripts/restore_backup.py` radi ceo posao sa jednim komandom.

---

## 2. ŠTA TAČNO ČUVAMO U BAZI

Ovo je kompletna lista polja po tabelama. Ako ti neko kaže "zahtevamo
kompletnu informaciju o mom korisniku", ovo je maksimum što postoji.

### Tabela `scans` — jedan red po svakom scan-u

| Kolona | Primer vrednosti | Šta znači |
|---|---|---|
| `id` | `29235cd6` | Random 8-char ID, ne može se pogoditi |
| `url` | `https://example.com` | **Originalni URL koji je korisnik uneo** |
| `domain` | `example.com` | Normalizovan domen (`www.` uklonjen) |
| `status` | `completed` | queued / running / completed / error |
| `progress` | `100` | 0–100 |
| `step` | `Proveravam email bezbednost...` | Poslednji korak |
| `result` | `{...}` JSONB | **CELI SKEN REZULTAT — 79 findings, score, grade** |
| `error` | `NULL` ili poruka | Ako je crash-ovao |
| `ip_hash` | `1810d49b...` | SHA-256 hash IP adrese (ne može se reverse) |
| `ua_hash` | `90312fc8...` | SHA-256 hash User-Agent-a |
| `session_id` | `uuid...` ili NULL | Frontend browser session (ako je pružen) |
| `fingerprint_hash` | `text...` ili NULL | Canvas/WebGL fingerprint iz frontend-a |
| `consent_accepted` | `true` | **Da li je označio pristanak checkbox** |
| `consent_version` | `2026-04-10-v1` | **Koju verziju ToS teksta je video** |
| `verified` | `false` | Da li je dokazao vlasništvo domena |
| `verification_method` | `NULL` | meta / file / dns (ako je verifikovao) |
| `created_at` | `2026-04-10 10:37:04+00` | Kad je počeo |
| `completed_at` | `2026-04-10 10:38:16+00` | Kad je završio |

### Tabela `audit_log` — forenzički trag

**Ovo je najvažnija tabela za legal defense.** Append-only — ni service_role
ne može da UPDATE ili DELETE (video migration 004).

Svaki scan kreira **najmanje 3 reda**:
1. `scan_request` — čim POST /scan stigne
2. `scan_start` — kad scanner.py krene
3. `scan_complete` — sa score-om i brojem findings

Plus opcioni:
- `scan_blocked_rate_limit` — rate limit ga je odbio
- `scan_blocked_ssrf` — pokušao je localhost/privatnu IP
- `scan_truncated_deadline` — 180s timeout
- `scan_error` — crash
- `verify_request` / `verify_success` / `verify_failure` — ownership checks
- `abuse_report_submitted` — neko prijavio
- `abuse_block_applied` — mi blokirali domen

| Kolona | Šta znači |
|---|---|
| `id` | BIGSERIAL |
| `event` | event tip iz liste iznad (CHECK constraint) |
| `scan_id` | veza ka `scans.id` (NULL za neke evente) |
| `domain` | domen koji je u pitanju |
| `ip_hash` | SHA-256 hash requester-ovog IP-ja |
| `ua_hash` | SHA-256 hash User-Agent-a |
| `fingerprint_hash` | opcioni browser fingerprint |
| `session_id` | opcioni browser session |
| `details` | JSONB sa slobodnim kontekstom (URL, greške, score...) |
| `flagged` | `true` = ne brisati pri 90-dnevnom pruning-u |
| `created_at` | timestamp |

### Ostale tabele

| Tabela | Čuva | Retention |
|---|---|---|
| `verification_tokens` | kratkotrajni token + dokaz vlasništva | 1h pending, pa expire |
| `verified_domains` | "ovaj ip_hash je dokazao vlasništvo domena X" | 30 dana |
| `rate_limits` | brojači po IP-ju i po domenu | čisti se kad prođe window |
| `abuse_reports` | prijave zloupotrebe | zauvek (dok ručno ne obrišeš) |
| `backup_log` | audit backup pokušaja | 180 dana |
| `schema_migrations` | history schema promena | zauvek |

---

## 3. ŠTA SE **NE** ČUVA

- ❌ **Raw IP adrese** — samo SHA-256 hash sa server-side salt-om
- ❌ **Raw User-Agent stringovi** — samo hash
- ❌ **HTTP body-ji** koje korisnik pošalje — samo URL
- ❌ **Lozinke, keys, tokens** korisnika — scanner nema access to tome
- ❌ **HTML sadržaj skeniranih sajtova** — samo metadata (headers, score)
- ❌ **Kontent koji korisnik vidi u rezultatu** (delimićno — dok ne
  implementiramo verification, rezultat se čuva cio; posle verification,
  verified=false scans će čuvati samo counts, ne URLs)
- ❌ **Email adrese korisnika** — nemamo login sistem
- ❌ **Bilo šta što pravi korisničku identitet tržljivim** bez salt-a

---

## 4. ZAŠTO HASHUJEMO IP-JEVE (i zašto je to DOBRO za tebe)

### Problem koji rešavamo

GDPR, DSA, CCPA i slični propisi tretiraju IP adresu kao **personal data**.
To znači da ako je čuvaš raw:
- Moraš imati pravnu osnovu (consent / legitimate interest)
- Moraš je obrisati kad korisnik traži
- Moraš da se štitiš od data breach-a (i da prijaviš breach u 72h)
- Možeš biti tužen za skladištenje PII-ja

Ako je **ne čuvaš uopšte**:
- Ne možeš da se braniš kad neko tvrdi zloupotrebu
- Ne možeš da odgovoriš na zahtev policije
- Ne možeš da blokiraš ponovljenog abuser-a

### Naše rešenje: pseudonimizacija

Koristimo formulu:
```
ip_hash = SHA-256(ip_adresa + ":" + PII_HASH_SALT)
```

Gde je `PII_HASH_SALT` 64-hex random string koji:
- Postoji SAMO u `.env` fajlu / HF Space Secrets
- **Nikad ne ide u bazu**
- Nikad ne ide u git, u frontend, u log fajlove
- Svi hashovi su deterministički — isti IP daje isti hash

### Posledice za tebe

✅ **Ako bazu hakuju:** napadač dobija hash stringove bez ključa.
   SHA-256 sa salt-om se ne može brute-force-ovati. IPv4 prostor je
   "samo" 4 milijarde IP adresa ali bez salt-a napadač ne zna formulu.
   
✅ **Ako te policija pita "dokaži šta je ova IP radila":** izračunaš hash
   od njihove IP i query-uješ `audit_log`. **Možeš da odgovoriš.**
   
✅ **Ako korisnik kaže "obrišite moj IP":** formalno je već obrisan
   (pseudonimizovan). Možeš da mu pokažeš da baza sadrži samo hash,
   koji se po GDPR-u smatra značajno manjim rizikom.
   
✅ **GDPR Art. 11:** ako ne možeš da identifikuješ osobu, ne moraš da
   ispunjavaš sve obaveze (prava pristupa, brisanja, itd). Pseudonimizovan
   hash + salt koji ti nikad ne daješ znači da **ne možeš sam enumerisati
   sve njihove scanove bez da ti oni kažu svoj IP** — što tebe amnestira
   od velikog dela GDPR tereta.

❌ **Šta ne možeš:** da daš listu "svi IP-jevi koji su ikad koristili
   scanner". Ovo je **dobro** — nema legitimnog razloga da to uradiš, i
   sprečava te da postaneš izvor privacy leak-a.

---

## 5. TRI GLAVNA SCENARIJA — kako se pravdamo

### §5.1 Neko mi šalje ljuti mejl: "Skenirali ste moj sajt bez dozvole"

**Korak 1: SMIRI SE.** Pročitaj mejl celog. Izvadi ove informacije:
- Koji domen tvrdi da je skeniran? (npr. `mycompany.com`)
- Kada? (približan datum ako je naveo)
- Šta tvrdi da je "dokaz" (log zapis, email sa subject-om, itd)

**Korak 2: Proveri `audit_log`.** Kroz Supabase Dashboard → SQL Editor:

```sql
SELECT id, event, scan_id, ip_hash, created_at, details
  FROM audit_log
 WHERE domain = 'mycompany.com'
 ORDER BY created_at DESC
 LIMIT 50;
```

Ako nema rezultata → skeniranje nikad nije ni pokrenuto protiv tog
domena preko **tvog** scanner-a. To znači ili se vara, ili je neko drugi.
Odgovori uljudno: "Proverio sam naš audit log za poslednjih 90 dana i
nema skeniranja tog domena. Možete li poslati identifikator zahteva
ili tačan vremenski pečat?"

Ako IMA rezultata → pogledaj `consent_accepted` za te scan-ove:
```sql
SELECT s.id, s.url, s.consent_accepted, s.consent_version,
       s.created_at, a.details
  FROM scans s
  JOIN audit_log a ON a.scan_id = s.id
 WHERE s.domain = 'mycompany.com'
   AND a.event = 'scan_request';
```

Ako je `consent_accepted = true` → odgovori:
> Poštovani, pregledao sam naš audit sistem za vaš domen. Skeniranje je
> inicirao korisnik dana X u Y sati, nakon što je eksplicitno prihvatio
> uslove korišćenja verzija `2026-04-10-v1`. Skeniranje je **pasivno**
> (samo javno dostupne HTTP informacije, nikakvo exploitovanje). Ako
> želite da onemogućimo buduće skeniranje vašeg domena, molim vas da
> popunite formular za abuse report na [link].

Ako je `consent_accepted = false` → imaš legitimnu zabrinutost. Razmisli
da li da implementiraš strožu proveru consenta. Za sad, odgovori uljudno
i dodaj njihov domen na block listu preko abuse_reports tabele.

**Korak 3: Dokumentuj razmenu.** Sačuvaj mejl lokalno. Ako se pretvori
u legal matter, ovo je tvoj trail.

### §5.2 Policija / sud / regulator traži podatke

**Nikad ne panikuj. Uvek traži pismeni zahtev.** Email od
"policija@gmail.com" nije validan zahtev. Pravni zahtev dolazi:
- Preko službenog email-a (`@policija.rs`, `@mup.gov.rs`, `@sud.gov.rs`)
- Sa brojem predmeta
- Sa identifikovanim službenim licem
- Obično na papirnom nalogu ili preko ePošte

**Najčešći tipovi zahteva i šta treba da uradiš:**

#### Tip 1: "Dokaži šta je ova IP adresa radila na vašem sistemu"

Oni ti daju IP (recimo `5.6.7.8`). Ti računaš hash i queryuješ:

```sql
-- U Supabase SQL Editoru — OVO TRAJE 0.5 SEKUNDI
WITH target AS (
    SELECT encode(
        sha256(('5.6.7.8:' || '<tvoj_PII_HASH_SALT>')::bytea),
        'hex'
    ) AS h
)
SELECT al.created_at, al.event, al.scan_id, al.domain, al.details
  FROM audit_log al, target
 WHERE al.ip_hash = target.h
 ORDER BY al.created_at;
```

**Kako da dobiješ `PII_HASH_SALT`:** iz HF Space Secrets dashboard-a ili
iz tvog lokalnog `.env` fajla. **Ovo ne ide u query direktno** —
koristi SQL parameter ili privremeni PostgreSQL session setting.

Rezultat pošalješ kao PDF ili Excel. Dodaj napomenu:
> "Napomena: scanner čuva IP adrese u SHA-256 hash formi. Ova pretraga
> je izvršena transformacijom zadate IP adrese u hash vrednost
> korišćenjem servisnog salt-a i pretragom podudarnih audit zapisa."

#### Tip 2: "Dajte nam sve scan-ove nekog domena"

```sql
SELECT s.id, s.url, s.status, s.created_at, s.completed_at,
       s.consent_accepted, s.consent_version, s.ip_hash
  FROM scans s
 WHERE s.domain = 'target-domen.rs'
 ORDER BY s.created_at;
```

Eksportuj kao CSV. Nemoj slati `result` JSONB polje osim ako eksplicitno
traže — to su rezultati skeniranja, nisu pod zahtevom.

#### Tip 3: "Dajte nam pristup bazi"

**NE.** Na to odgovaraš: "Imajte na umu da je ovaj sistem host-ovan na
Supabase (EU) uz standardne GDPR zaštite. Pristup bazi se ne daje bez
sudskog naloga. Molim vas da dostavite specifičan upit (npr. IP adresa,
domen, vremenski period) i odgovoriću na konkretno pitanje."

### §5.3 Korisnik traži GDPR brisanje / pristup

GDPR daje korisniku pravo da traži:
- **Art. 15** — šta imaš o njemu
- **Art. 16** — ispravka podataka
- **Art. 17** — pravo na brisanje ("right to be forgotten")
- **Art. 20** — data portability (export)

**Problem:** bez da ti kaže svoj IP, ne možeš da identifikuješ njegove
zapise. To je očekivano i legalno OK pod GDPR Art. 11.

**Šta da odgovoriš:**

> Poštovani, hvala vam na zahtevu. Naš sistem ne skladišti korisnička
> imena, email adrese, ni direktne identifikatore. IP adrese se čuvaju
> u SHA-256 hash formi sa servisnim salt-om, što po GDPR Art. 4(5)
> kvalifikuje kao pseudonimizacija.
>
> Da bi smo mogli da identifikujemo vaše zapise, molim vas da nam:
> 1. Navedete IP adresu koju ste koristili u trenutku skeniranja
> 2. Navedete približno vreme (dan i sat)
>
> Uz ove podatke možemo da lociramo i obrišemo vaše zapise iz tabele
> `scans`, kao i da vas izuzmemo iz tabele `audit_log` dodavanjem
> "flagged" markera (napomena: audit_log je namerno append-only za
> forenzičke potrebe; markiranje znači da zapis više neće biti korišćen
> u operativnoj statistici ali ostaje kao zakonski zahtevan trag).
>
> Rok za odgovor: 30 dana od prijema zahteva (GDPR Art. 12).

Kad dobiješ IP:
```sql
-- Brisanje iz scans (nije append-only)
DELETE FROM scans
 WHERE ip_hash = encode(sha256(('X.X.X.X:' || '<salt>')::bytea), 'hex');

-- audit_log: ne brišemo, markiramo "flagged" da izuzmemo iz default queries
UPDATE audit_log
   SET flagged = TRUE
 WHERE ip_hash = encode(sha256(('X.X.X.X:' || '<salt>')::bytea), 'hex');
```

**Napomena:** audit_log namerno ostaje čak i nakon "brisanja" jer je
forenzički trag koji imaš pravo da čuvaš pod "legitimate interest"
(GDPR Art. 6(1)(f)) — dokumentovanje sigurnosnog incidenta. U praksi,
posle 90 dana se ionako automatski briše nezaflagovan redovima.

---

## 6. DNEVNO / NEDELJNO PROVERAVANJE ZDRAVLJA

Ovo su pitanja koja treba da postavljaš sistemu **redovno** — ne da
čekaš da se nešto slomi. Pokreni u SQL Editor-u na Supabase dashboard-u.

### §6.1 Da li backup radi?

```sql
-- Poslednji backup — očekujem status='success' i <26h star
SELECT id, started_at, completed_at, status, bytes_written,
       rows_exported, trigger_source, error_message
  FROM backup_log
 ORDER BY id DESC LIMIT 5;
```

**Šta tražiš:**
- ✅ `status = 'success'` na poslednjem redu
- ✅ `started_at` ne stariji od 26 sati (cron je 04:00 UTC svaki dan)
- ✅ `bytes_written > 0`
- ✅ `rows_exported` ima brojeve za sve 4 tabele

**Crvene zastave:**
- 🚩 `status = 'error'` → pogledaj `error_message`
- 🚩 Poslednji backup stariji od 2 dana → cron ne radi, proveri §6.2
- 🚩 `bytes_written` pao dramatično (10x manji od prethodnog) → tabele
  se prazne bez razloga (ili je prune_audit_log pokupio previše)

### §6.2 Da li cron jobovi rade?

```sql
SELECT jobname, schedule, active,
       (SELECT start_time FROM cron.job_run_details jrd
         WHERE jrd.jobid = j.jobid ORDER BY start_time DESC LIMIT 1) AS last_run,
       (SELECT status FROM cron.job_run_details jrd
         WHERE jrd.jobid = j.jobid ORDER BY start_time DESC LIMIT 1) AS last_status
  FROM cron.job j
 ORDER BY jobname;
```

**Treba da vidiš 6 aktivnih job-ova:**
```
daily-backup                0 4 * * *
expire-verification-tokens  */5 * * * *
prune-audit-log             0 3 * * *
prune-backup-log            10 3 * * *
prune-rate-limits           0 * * * *
prune-verified-domains      5 3 * * *
```

Ako `active = false` negde → neko ga je unschedule-ovao. Razlog se vidi
u `cron.job_run_details.status` — ako je `failed`, query-uj
`return_message` tamo za detalj.

### §6.3 Da li ima neuobičajenih grešaka?

```sql
-- Failed scanovi u poslednjih 7 dana
SELECT DATE(created_at) AS dan, COUNT(*) AS failed_scans
  FROM audit_log
 WHERE event = 'scan_error'
   AND created_at > NOW() - INTERVAL '7 days'
 GROUP BY dan
 ORDER BY dan DESC;

-- Rate limit-blokirani zahtevi u poslednjih 24h
SELECT COUNT(*) AS blocked_count,
       COUNT(DISTINCT ip_hash) AS unique_ips
  FROM audit_log
 WHERE event = 'scan_blocked_rate_limit'
   AND created_at > NOW() - INTERVAL '24 hours';

-- SSRF pokušaji u poslednjih 7 dana (pokazuje abuse patterns)
SELECT COUNT(*) AS ssrf_attempts,
       COUNT(DISTINCT ip_hash) AS attackers
  FROM audit_log
 WHERE event = 'scan_blocked_ssrf'
   AND created_at > NOW() - INTERVAL '7 days';
```

**Normalno:** ~0-10 failed_scans po danu (zavisi od network-a),
~0-50 rate_limit blokada po danu, ~0-5 SSRF pokušaja po sedmici.

**Alarm:** ako SSRF pokušaji skoče na 100+/dan — imaš targeted attack.
Razmotri dodavanje firewall pravila iznad scanner-a.

### §6.4 Najaktivniji skenirani domeni

```sql
SELECT domain, COUNT(*) AS scan_count, MAX(created_at) AS last_scan
  FROM scans
 WHERE created_at > NOW() - INTERVAL '30 days'
 GROUP BY domain
 ORDER BY scan_count DESC
 LIMIT 20;
```

Ovo ti daje sliku šta korisnici skeniraju. Ako iznenada jedan domen
dobija 1000 scanova → verovatno neko ga targetuje, razmotri da ga
dodaš u abuse_reports i auto-block-uješ.

---

## 7. KORISNE SQL KOMANDE — COPY-PASTE KUVAR

Sve ove možeš da pokreneš u **Supabase Dashboard → SQL Editor**.

### Koliko scanova dnevno
```sql
SELECT DATE(created_at) AS dan, COUNT(*) AS scanova,
       COUNT(DISTINCT ip_hash) AS razlicitih_korisnika,
       COUNT(DISTINCT domain) AS razlicitih_domena
  FROM scans
 WHERE created_at > NOW() - INTERVAL '14 days'
 GROUP BY dan
 ORDER BY dan DESC;
```

### Najčešći findings u poslednjih 7 dana
```sql
SELECT finding->>'check_id' AS check_id,
       finding->>'severity' AS severity,
       COUNT(*) AS pronalazaka
  FROM scans s,
       jsonb_array_elements(s.result->'results') AS finding
 WHERE s.created_at > NOW() - INTERVAL '7 days'
   AND s.status = 'completed'
 GROUP BY check_id, severity
 ORDER BY pronalazaka DESC
 LIMIT 30;
```

### Scanovi koji su pukli u deadline (180s timeout)
```sql
SELECT scan_id, domain, created_at, details
  FROM audit_log
 WHERE event = 'scan_truncated_deadline'
 ORDER BY created_at DESC
 LIMIT 20;
```

### Korisnik koji skenira stalno isti domen (sumnja na abuse)
```sql
SELECT ip_hash, domain, COUNT(*) AS puta, MIN(created_at) AS od, MAX(created_at) AS do_
  FROM scans
 WHERE created_at > NOW() - INTERVAL '7 days'
 GROUP BY ip_hash, domain
HAVING COUNT(*) > 10
 ORDER BY puta DESC;
```

### Ukupno veličina baze
```sql
SELECT pg_size_pretty(pg_database_size(current_database())) AS db_size;

SELECT schemaname, tablename,
       pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) AS velicina
  FROM pg_tables
 WHERE schemaname = 'public'
 ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC;
```

### Ko ima koji grade
```sql
SELECT result->'score'->>'grade' AS grade,
       COUNT(*) AS broj_scanova,
       ROUND(AVG((result->'score'->>'score')::int)) AS avg_score
  FROM scans
 WHERE status = 'completed'
   AND result IS NOT NULL
 GROUP BY grade
 ORDER BY avg_score DESC;
```

### Manual trigger backup-a (hitno, pre nego što nešto radikalno dirneš)
```sql
SELECT net.http_post(
    url := 'https://wmerashfovgaugxpexqo.supabase.co/functions/v1/backup',
    headers := jsonb_build_object(
        'Content-Type', 'application/json',
        'X-Webhook-Secret', (
            SELECT decrypted_secret FROM vault.decrypted_secrets
             WHERE name = 'backup_webhook_secret'
        )
    ),
    body := jsonb_build_object('trigger', 'manual-emergency'),
    timeout_milliseconds := 60000
);
-- Sačekaj 30s, pa:
SELECT * FROM backup_log ORDER BY id DESC LIMIT 1;
```

---

## 8. ROTACIJA TAJNI — KADA I KAKO

Sve tajne ovog sistema, sortirano po važnosti:

| Tajna | Gde živi | Ako procuri → šta može | Kako rotirati |
|---|---|---|---|
| `BACKUP_ENCRYPTION_KEY` | password manager, Vault | **FATAL:** dešifruje svaki backup | Ne možeš bez re-enkriptovanja svih postojećih backup-ova. Videće se niže. |
| `SUPABASE_SERVICE_KEY` | `.env`, HF Space Secret | Potpuna kontrola baze (čitanje + pisanje + brisanje osim audit_log UPDATE/DELETE) | Dashboard → Settings → API → "Reset service_role secret" |
| `PII_HASH_SALT` | `.env`, HF Space Secret | Može da računa validne hashove za postojeće IP-jeve (ako zna salt + IP, pogodi hash) | **NE ROTIRAJ** osim u krajnjoj nuždi — gubiš sve stare korelacije |
| DB password (u SUPABASE_DB_URL) | `.env`, HF Space Secret | Direktan Postgres pristup | Dashboard → Settings → Database → Reset password |
| `R2_SECRET_ACCESS_KEY` | Vault, `.env` (za restore skripte) | Pisanje u backup bucket — može upload-ovati smeće | R2 Dashboard → Manage R2 API Tokens → Roll |
| `backup_webhook_secret` | Vault | Može da pozove backup edge funkciju — DoS na backup sistem | SQL: `UPDATE vault.secrets SET secret = encode(gen_random_bytes(32),'hex') WHERE name = 'backup_webhook_secret'` |

### Kad MORAM da rotiram

- ✅ Poznato curenje (pronašao si ključ u git-u, u Slack-u, u tuđem mejlu)
- ✅ Bivši kolega je imao pristup — rotiraj sve što je mogao da vidi
- ✅ Sumnjivo ponašanje u audit_log (neočekivani service_role pozivi)
- ✅ Svakih 12 meseci kao higijena (osim `PII_HASH_SALT`)

### Kako da rotiram `BACKUP_ENCRYPTION_KEY` (najteže)

Ovo je najkomplikovanije jer stari backup-i postaju nečitljivi sa novim ključem.

**Ispravan postupak:**
1. Generiši novi ključ: `python -c "import secrets; print(secrets.token_hex(32))"`
2. **Čuvaj STARI ključ** dok ne prođu svi backup retention rokovi (90 dana)
3. Ažuriraj Vault sa novim ključem:
   ```sql
   UPDATE vault.secrets SET secret = 'nov_hex_ovde'
    WHERE name = 'backup_encryption_key';
   ```
4. Od sutra svi novi backup-i koriste novi ključ
5. Stari backup-i i dalje mogu da se dešifruju sa starim ključem — čuvaj ga u password manager-u posebno sa oznakom "stari backup key, potreban do <datum>"
6. Posle 90 dana, kad su svi stari backup-i istrošeni, možeš da zaboraviš stari ključ

**NIKAD ne rotiraj backup key ako nisi siguran gde su svi stari.**
Ako izgubiš stari ključ prerano → svi backup-i pre rotacije su mrtvi.

---

## 9. ŠTA NIKAD NE DIRAJ

Ako vidiš ove stvari i zamisliš "hajde da ovo očistim" — **NE**.

### 🚫 `audit_log` tabela — UPDATE i DELETE
Namerno su revoked za service_role. Ako probaš da uradiš DELETE, dobićeš
error. **Tako i treba.** Audit trail je tvoja legalna zaštita, ne tech debt.

### 🚫 `schema_migrations` tabela
Ista priča kao audit_log. Migration runner zavisi od toga da su zapisi
tačni. Ako manuelno UPDATE-uješ version ili checksum, sledeći migration
run će se zbuniti i možda ponovo primeniti stari migration.

### 🚫 `migrations/001-009.sql` fajlovi
Pošto su već primenjeni u produkciji, menjanje sadržaja NIKAD. Ako hoćeš
da ispraviš nešto iz stare migracije, kreiraj NOVU migraciju `010_...`.
Migration runner proverava SHA-256 checksum i odbija da nastavi ako se
stari fajl promenio.

### 🚫 `PII_HASH_SALT` rotiranje
Opisano u §8. Rotiranje razbija sve istorijske korelacije.

### 🚫 Cron jobove ne brisati iz `cron.job`
Ako trebaš da promeniš raspored, idi kroz migraciju sa
`cron.unschedule()` pa `cron.schedule()`. Ne brisati direktno jer
funkcija još postoji i tvoj dashboard će pokazivati "where's my job".

### 🚫 Supabase Vault `vault.secrets` ručno brisanje
Prvo ažuriraj mesto koje čita secret (edge funkcija, cron job) da ima
fallback, pa tek onda brisati. Inače backup edge funkcija postaje 500.

### 🚫 HF Spaces git push koji zamenjuje Supabase kredencijale
Kad deploy-uješ, postavi env vars **u HF Space Secrets dashboard-u**, ne
u `.env` commit-ovano u git. `.env` je gitignored, ali ako ga ikad
slučajno commit-uješ, secret je javan.

---

## 10. KONTAKT I ESKALACIJA

### Ako se nešto gori i treba ti pomoć

Ovaj priručnik je tvoj prvi stepenik. Ako je incident izvan njega:

1. **SMIRI SE.** Većina stvari se može popraviti dokle god ne praviš
   ishitrene poteze. "Ne znam" nije panika — panika je "imam tačno 5
   minuta da ovo rešim".

2. **Napravi manuelni backup pre bilo čega destruktivnog.** Vidi §7
   "Manual trigger backup-a". Ovo ti daje recovery point ako razbiješ
   nešto u sledećih 10 minuta.

3. **Snimi sve što vidiš.** Screenshot-uj dashboard-e, kopiraj SQL
   output-e, sačuvaj email-ove. Legal incident ti može trajati mesecima,
   proces počinje sad.

4. **Ako je legal matter:** kontaktiraj advokata pre nego što odgovoriš.
   Prvi email koji pošalješ policiji je dokaz, ne draft. Nemoj da žuriš.

### Ključni URL-ovi

- **Supabase Dashboard:** https://supabase.com/dashboard/project/wmerashfovgaugxpexqo
  - Settings → API (keys + URLs)
  - Settings → Database (connection strings)
  - SQL Editor (za sve queries u ovom priručniku)
  - Edge Functions → backup (logs, invocation history)
  - Database → Tables (vizuelni pregled)
  - Database → Migrations (lista applied migracija)

- **Cloudflare R2 Dashboard:** https://dash.cloudflare.com/?to=/:account/r2/default/buckets/security-scanner-backups
  - Objects (lista backup blob-ova)
  - Settings → Object lifecycle rules (retention config)
  - Metrics (storage usage, req count)

- **HuggingFace Space (produkcija backend-a):** https://huggingface.co/spaces/Unlimitededition/web-security-scanner/settings
  - Variables and secrets (env vars idu ovde, ne u `.env`)
  - Logs

- **Vercel (frontend):** https://vercel.com/dashboard
  - Environment Variables
  - Deployments (rollback history)

### Dokumenti koje trebaš da znaš da postoje

| Fajl | Šta sadrži | Kad ga otvaraš |
|---|---|---|
| `PRIRUCNIK.md` (ovaj) | Operator handbook | Kad nešto gori |
| `SECURITY.md` | Public security policy, backup architecture | Kad neko pita "imate li bug bounty" |
| `CLAUDE.md` | Pravila rada sa Claude Code agentom | Kad editujem kod kroz Claude |
| `.env.example` | Template svih env vars (bez vrednosti) | Kad setup-uješ na novoj mašini |
| `.env` | Realne vrednosti (gitignored) | **NIKAD ne commit-ovati** |
| `migrations/README.md` | Pravila za DB migracije | Kad menjaš schemu |
| `migrations/001-009.sql` | Sve schema promene, u redosledu | Za rollback / audit |
| `supabase/functions/backup/` | Edge funkcija za dnevni backup | Kad backup puca |
| `scripts/restore_backup.py` | Tool za vraćanje iz backup-a | Kad se baza sfrka |

### Poslednji savet

**Ovaj sistem je složen, ali namerno projektovan da se može operisati
bez da mu razumeš svaki detalj.** Većina operativnih zadataka se svodi
na "pokreni ovaj SQL" i "pročitaj ovaj log". Ne pokušavaj da "popraviš"
nešto što ne razumeš — pitaj, guglaj, ili sačekaj. Scanner neće umreti
ako ga ne diraš nekoliko sati.

Najgora stvar koju možeš da uradiš je **destruktivna akcija u panici**
(drop tabele, reset kredencijala bez zapisa starih vrednosti, force push
na produkciju). Uvek prvo **pravi backup, dokumentuj trenutno stanje**,
pa onda intervenisši.

Ako ti ovaj dokument ne daje odgovor — dodaj pitanje na dno ovog fajla
kao TODO i pitaj sledeći put kad radiš sa Claude-om. Priručnik je živ
dokument, trebao bi da raste kako se sistem menja.

---

*Poslednja verzija: 2026-04-10, po završetku Faze 1 (DB integracija).*
*Sledeća revizija: kad završimo Fazu 2 (ownership verification) — dodaće
sekciju o `verify_*` event-ima i `verified_domains` tabeli.*

