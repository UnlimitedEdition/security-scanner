# PRIRUCNIK V4 — Strictness Mode Rollout

> **Status:** PLAN / ROADMAP za V4 verziju Web Security Scanner-a.
> **Trenutna verzija u produkciji:** V3 (Standard mode samo).
> **Cilj V4:** Dodati **4 dugmeta za izbor kriterijuma procene** pre skeniranja.
> **Jezik:** srpski (operativni nivo).
> **Status dokumenta:** DRAFT — odobrava operater pre pocetka rada.

---

## §1 Zasto V4 postoji

### §1.1 Problem koji V4 resava

Trenutni scanner (V3) koristi **jedan, fiksan, blag kriterijum** procene:
- `CRITICAL` = -20, `HIGH` = -10, `MEDIUM` = -5, `LOW` = -2
- Diminishing returns (prvih nekoliko greski boli, ostale ne)
- Bonus +2 po `INFO` check-u (do +20)
- SEO, GDPR, Accessibility, Performance se **NE racunaju** u security score

**Posledica:** sajt kao `hardenize.com` (profesionalni security auditor)
dobija **100/A** iako ima **23 failed check-a od 66**. To je preblago.

### §1.2 Sta V4 donosi

**4 dugmeta pre skeniranja** — korisnik bira nivo strogosti:

| Dugme | Za koga | Kljucna ideja |
|-------|---------|---------------|
| 🟢 **BASIC** | Blogeri, pocetnici | Samo CRITICAL/HIGH se broji, ostalo info |
| 🟡 **STANDARD** | Mali biznisi (trenutno V3 ponasanje) | Default, kompatibilno sa V3 |
| 🔴 **STRICT** | Security profesionalci | Sve kategorije se racunaju, nema bonus-a |
| ⚫ **PARANOID** | Banke, gov, compliance | Sve + Accessibility + Performance, 100 ili nista |

---

## §2 Kriterijumi procene — detaljna matrica

### §2.1 Kazne po severity nivoima

| Parametar | Basic | Standard | Strict | Paranoid |
|-----------|-------|----------|--------|----------|
| CRITICAL | -15 | -20 | -25 | -35 |
| HIGH | -6 | -10 | -15 | -20 |
| MEDIUM | -2 | -5 | -8 | -12 |
| LOW | -0.5 | -2 | -4 | -7 |
| Diminishing cap | Da | Da | **Ne** | **Ne** |
| Bonus INFO pass | +3 | +2 | +1 | **0** |

### §2.2 Kategorije koje se racunaju u score

| Kategorija | Basic | Standard | Strict | Paranoid |
|------------|:-----:|:--------:|:------:|:--------:|
| Security Headers | ✅ | ✅ | ✅ | ✅ |
| DNS Security | ✅ | ✅ | ✅ | ✅ |
| SSL/TLS | ✅ | ✅ | ✅ | ✅ |
| Best Practices | ✅ | ✅ | ✅ | ✅ |
| SEO | ❌ | ❌ | ✅ | ✅ |
| GDPR | ❌ | ❌ | ✅ | ✅ |
| Accessibility | ❌ | ❌ | ❌ | ✅ |
| Performance | ❌ | ❌ | ❌ | ✅ |

### §2.3 Pragovi za ocenu (grade)

| Grade | Basic | Standard | Strict | Paranoid |
|-------|-------|----------|--------|----------|
| A | ≥85 | ≥90 | ≥95 | **=100** |
| B | ≥70 | ≥75 | ≥85 | ≥90 |
| C | ≥55 | ≥60 | ≥70 | ≥80 |
| D | ≥35 | ≥40 | ≥50 | ≥65 |
| F | <35 | <40 | <50 | <65 |

### §2.4 Benchmark test: kako V4 ocenjuje poznate sajtove

| Sajt | Basic | Standard | Strict | Paranoid |
|------|-------|----------|--------|----------|
| hardenize.com | ~95 A | ~100 A | ~62 D | ~38 F |
| nas sajt (security-skener) | 100 A | 100 A | ~92 A | ~85 B |
| google.com (ocekivano) | 100 A | 100 A | ~88 B | ~70 C |

*Napomena: vrednosti su procena; stvarne ce se meriti po implementaciji.*

---

## §3 UI / UX dizajn

### §3.1 Gde ide selektor

**Lokacija:** iznad URL input-a na glavnoj stranici (`index.html`).
**Tip kontrole:** segmented button group (ne dropdown).
**Mobilna verzija:** 2×2 grid, na desktopu 1×4.

### §3.2 Vizuelni layout (desktop)

```
┌────────────────────────────────────────────────────────────┐
│  Izaberi nivo procene:                                     │
│  ┌──────────┬────────────┬──────────┬────────────┐         │
│  │🟢 BASIC  │🟡 STANDARD │🔴 STRICT │⚫ PARANOID │         │
│  │ blogeri  │  default   │  profi   │ compliance │         │
│  └──────────┴────────────┴──────────┴────────────┘         │
│                                                            │
│  URL: [________________________________]  [Skeniraj]       │
└────────────────────────────────────────────────────────────┘
```

### §3.3 Ponasanje

- **Default:** STANDARD (zuta) — kompatibilnost sa V3
- **Pamti izbor:** `localStorage.scannerStrictness`
- **Tooltip:** hover prikazuje punu matricu (§2.1-§2.3)
- **Badge u rezultatu:** "Skenirano sa: STRICT mode" — krupno, prvo sto korisnik vidi
- **Print report:** nivo strogosti stampan u PDF izvestaju

### §3.4 Boje dugmica

| Mode | Boja ON | Boja OFF |
|------|---------|----------|
| Basic | `#22c55e` (zeleno) | `#1a1d2e` (tamno) |
| Standard | `#eab308` (zuto) | `#1a1d2e` |
| Strict | `#ef4444` (crveno) | `#1a1d2e` |
| Paranoid | `#18181b` (crno) sa `#fff` tekstom | `#1a1d2e` |

---

## §4 Tehnicki plan

### §4.1 Fajlovi koji se menjaju

| Fajl | Izmena | Estimacija |
|------|--------|------------|
| `scanner.py` | `compute_score()` dobija `strictness` parametar | 45 min |
| `scanner.py` | `STRICTNESS_PROFILES` konstanta | 15 min |
| `api.py` | `/scan` endpoint prihvata `strictness` query param | 30 min |
| `api.py` | Validacija (whitelist: basic/standard/strict/paranoid) | 15 min |
| `index.html` | Segmented button UI | 45 min |
| `index.html` | JS za slanje strictness u API request | 30 min |
| `index.html` | Badge "Skenirano sa: X mode" u rezultatu | 20 min |
| `blog-strictness-modes.html` | Novi edukativni clanak | 90 min |
| `PRIRUCNIK.md` | Dodati §V4 paragraf za operatera | 15 min |
| `sitemap.xml` | Dodati novi blog post URL | 5 min |

**Ukupno estimirano:** ~5h 20min

### §4.2 `scanner.py` izmene — pseudokod

```python
STRICTNESS_PROFILES = {
    "basic": {
        "weights": {"CRITICAL": 15, "HIGH": 6, "MEDIUM": 2, "LOW": 0.5},
        "diminishing": True,
        "bonus_per_info": 3,
        "bonus_cap": 25,
        "excluded_categories": ["SEO", "GDPR", "Accessibility", "Performance"],
        "grade_thresholds": {"A": 85, "B": 70, "C": 55, "D": 35},
    },
    "standard": {  # default, V3 compatible
        "weights": {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2},
        "diminishing": True,
        "bonus_per_info": 2,
        "bonus_cap": 20,
        "excluded_categories": ["SEO", "GDPR", "Accessibility", "Performance"],
        "grade_thresholds": {"A": 90, "B": 75, "C": 60, "D": 40},
    },
    "strict": {
        "weights": {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 4},
        "diminishing": False,
        "bonus_per_info": 1,
        "bonus_cap": 10,
        "excluded_categories": ["Accessibility", "Performance"],
        "grade_thresholds": {"A": 95, "B": 85, "C": 70, "D": 50},
    },
    "paranoid": {
        "weights": {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 12, "LOW": 7},
        "diminishing": False,
        "bonus_per_info": 0,
        "bonus_cap": 0,
        "excluded_categories": [],  # sve se racuna
        "grade_thresholds": {"A": 100, "B": 90, "C": 80, "D": 65},
    },
}

def compute_score(results, strictness="standard"):
    profile = STRICTNESS_PROFILES[strictness]
    # ... primeni profile umesto fiksnih konstanti
```

### §4.3 `api.py` — endpoint izmena

```python
@app.get("/scan")
async def scan_endpoint(
    url: str,
    strictness: str = "standard",  # novi parametar
    ...
):
    if strictness not in STRICTNESS_PROFILES:
        raise HTTPException(400, "Invalid strictness level")
    # proslediti strictness u scanner.scan() → compute_score()
```

### §4.4 Frontend — minimalni JS

```javascript
let selectedStrictness = localStorage.getItem('scannerStrictness') || 'standard';

document.querySelectorAll('.strictness-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    selectedStrictness = btn.dataset.mode;
    localStorage.setItem('scannerStrictness', selectedStrictness);
    updateStrictnessUI();
  });
});

function runScan(url) {
  fetch(`${API}/scan?url=${url}&strictness=${selectedStrictness}`)
    .then(r => r.json())
    .then(renderResults);
}
```

---

## §5 Test plan

### §5.1 Unit testovi (`tests/test_strictness.py`)

```
- test_basic_mode_ignores_low_severity
- test_standard_mode_matches_v3_output
- test_strict_mode_includes_seo
- test_paranoid_requires_100_for_grade_a
- test_invalid_strictness_raises_error
- test_default_is_standard
```

### §5.2 Manuelni testovi (benchmark sajtovi)

Pre merge-a — skenirati ova 4 sajta na sva 4 nivoa i zabeleziti score:
1. `security-skener.gradovi.rs` (nas sajt)
2. `hardenize.com`
3. `securityheaders.com`
4. `google.com`

Rezultati ulaze u §2.4 kao real-world benchmark.

#### Rezultati (2026-04-13, `tests/bench_strictness.py`)

Metoda: jedan pravi sken po sajtu + `compute_score()` replayed kroz sva
4 profila na istom `all_results` skupu. Matematicki identicno sa 4
zasebna skena, bez 4× mrezne varijanse i bez CDN cache jitter-a.

| Sajt | Basic | Standard | Strict | Paranoid |
|------|:-----:|:--------:|:------:|:--------:|
| `gradovi.rs`          | 100 A | **95 A** | 5 F | 5 F |
| `hardenize.com`       | 100 A | 100 A    | 5 F | 5 F |
| `securityheaders.com` | 100 A | **93 A** | 5 F | 5 F |
| `google.com`          | 100 A | **90 A** | 5 F | 5 F |

Counts CRIT/HIGH/MED/LOW po profilu (failures):

| Sajt | Basic | Standard | Strict | Paranoid |
|------|:-----:|:--------:|:------:|:--------:|
| `gradovi.rs`          | 0/1/1/5 | 0/1/1/5 | 0/4/7/8  | 0/4/7/8  |
| `hardenize.com`       | 0/0/2/8 | 0/0/2/8 | 0/0/9/10 | 0/0/11/12 |
| `securityheaders.com` | 0/2/1/1 | 0/2/1/1 | 0/3/7/5  | 0/3/7/7  |
| `google.com`          | 0/1/2/7 | 0/1/2/7 | 0/3/7/11 | 0/3/7/13 |

Kljucne opservacije (dobar sadrzaj za blog post):

1. **Standard = V3 parity OK** — sva 4 sajta dobijaju iste vrednosti kao
   pre V4. Regression gate cist.
2. **Basic = marketing-friendly** — 100/A za svakoga na benchmark setu.
   Korisno za prezentaciju klijentu ali nije dovoljno strogo za
   kompliance proveru.
3. **Strict vs Paranoid razlika se krije** — svi benchmark sajtovi
   padaju na floor=5 jer HIGH×15 + MEDIUM×8 + LOW×4 vrlo brzo premasi
   100 penalty. Razlika se vidi tek u **counts** (paranoid dodaje
   Accessibility + Performance failure-e: hardenize +2 MED +2 LOW,
   google +2 LOW).
4. **Cak i hardenize.com / securityheaders.com dobijaju F u Paranoid
   modu** — jak marketing ugao: *"Nijedan sajt nije savrsen. Mozete
   li da prodjete Paranoid?"*

Benchmark raw JSON: `tests/benchmark_results.json` (zadnji sken tj.
`google.com` iz ove runde — skripta overwrites svaki put).

### §5.3 Regression test

- **Kritican uslov:** Standard mode mora dati **identican** score kao V3.
- Ako postoji razlika → bug, blokira merge.

---

## §6 Monetizacija (opciono, za kasnije)

### §6.1 Predlog paketa

| Tier | Dostupni nivoi | Cena |
|------|----------------|------|
| **Anonimni** (free) | Basic, Standard | 0€ / 2 skena / 2h |
| **Registrovan** (free) | Basic, Standard, Strict | 0€ / 10 skena / 24h |
| **Pro** | sva 4 nivoa + export | 5€ / mesec |
| **Compliance** | Pro + Paranoid dubinski + audit log | 25€ / mesec |

### §6.2 Argumenti za paid tier

- **Strict/Paranoid** su ozbiljan security asset — korisnici ih koriste za sopstvene compliance provere
- Banke, gov agencije, hosting kuce ce platiti jer im je jeftinije od spoljnih auditora
- Free tier i dalje ostaje punopravan alat (Basic + Standard pokrivaju 80% slucajeva)

---

## §7 Marketing hooks (za blog + landing)

### §7.1 Headline ideje

- *"Mozes li da prodjes Paranoid mode?"*
- *"Hardenize.com dobija 100/A u blagom modu — 38/F u Paranoid modu. A tvoj sajt?"*
- *"Jedini skener u regionu sa 4 nivoa strogosti"*

### §7.2 Edukativni clanak (`blog-strictness-modes.html`)

Strukture od ~350 linija, SR+EN, sa:
- Objasnjenje sta svaki nivo broji
- Real-world benchmark (hardenize vs tvoj sajt tabela)
- Kada koristiti koji nivo (use case lista)
- Tehnicki detalji scoring formule
- FAQ: "Zasto Paranoid daje F mom sajtu?"

---

## §8 Redosled implementacije

### §8.1 Korak-po-korak (operator vodi)

1. ✅ **Plan** — ovaj dokument (§1-§7)
2. ⏳ **Backend** — `scanner.py` + `api.py` (§4.2, §4.3)
3. ⏳ **Backend testovi** — `test_strictness.py` (§5.1)
4. ⏳ **Regression check** — Standard mode = V3 (§5.3)
5. ⏳ **Frontend UI** — segmented buttons (§3)
6. ⏳ **Frontend JS** — API integracija (§4.4)
7. ⏳ **Benchmark skeniranja** — 4 sajta × 4 nivoa (§5.2)
8. ⏳ **Rezultate upisati** u §2.4 i u blog post
9. ⏳ **Blog post** — `blog-strictness-modes.html` (§7.2)
10. ⏳ **Sitemap update** + SEO meta
11. ⏳ **Manualni smoke test** produkcija (staging URL)
12. ⏳ **Deploy** — Vercel + HF Space
13. ⏳ **Marketing poduhvat** — post na LinkedIn/X + screenshot hardenize benchmark-a

### §8.2 Gates (sta blokira napredak)

- Korak 4 mora da prodje (regression) — inace kvarimo postojeci V3 produkcijski ponasanje
- Korak 7 mora da se uradi pre 9 — blog post MORA imati stvarne benchmark brojeve
- Korak 11 mora da prodje — bez smoke testa nema deploy-a

---

## §9 Rollback plan

### §9.1 Ako nesto pukne u produkciji

1. **Vercel rollback** — jedan klik u dashboard-u, vraca prethodni frontend
2. **HF Space rollback** — `git revert <sha>` + `git push space master:main --force`
3. **Default fallback** — ako `strictness` parametar nedostaje u requestu, koristi `"standard"` → V4 je backward-compatible sa V3 klijentima

### §9.2 Monitoring posle deploy-a

- Proveriti UptimeRobot prvih 24h
- Supabase logove za bilo kakve greske u `/scan` endpoint-u
- Manualni sken sopstvenog sajta u sva 4 moda — svaki dan prvih 3 dana

---

## §10 Definicija gotovosti (Definition of Done)

V4 je **gotova i spremna za marketing** kada:

- [ ] Svi unit testovi prolaze (§5.1)
- [ ] Regression test: Standard = V3 (§5.3)
- [ ] 4 benchmark sajta skenirana i rezultati upisani u §2.4
- [ ] Blog post `blog-strictness-modes.html` objavljen
- [ ] Sitemap azuriran, SEO meta kompletna (SR+EN)
- [ ] PRIRUCNIK.md dopunjen §V4 sekcijom za operatera
- [ ] Produkcijski smoke test prosao na sva 4 nivoa
- [ ] UptimeRobot 24h cisto posle deploy-a
- [ ] VERSION.md azuriran na 4.0.0
- [ ] README.md azuriran (kratak spomen feature-a + link na blog post)

---

## §11 Napomene za operatera

- **Ne menjaj Standard mode ponasanje** — to je ugovor sa postojecim korisnicima.
- **Paranoid mode namerno daje nisku ocenu** — to je funkcionalnost, ne bug.
  Ne popustaj pragove ako korisnici zale. Objasni im razliku izmedju nivoa.
- **Blog post mora biti edukativan, ne prodajni** — korisnik mora da razume
  **zasto** isti sajt moze dobiti 100 u jednom i 40 u drugom modu.
- **Benchmark hardenize.com je zakonit marketing** — pasivni sken javnog sajta je legalan,
  rezultati su objektivni, nisu fitnah.

---

## §12 Lekcije iz hardenize-ovog skena naseg sajta

Hardenize je skenirao `security-skener.gradovi.rs` i prijavio fail-ove. Njihova
analiza je otkrila **dizajnerske greske u njihovom skeneru** koje mi ne smemo
ponoviti u V4.

### §12.1 Lazni fail-ovi koje V4 mora da izbegne

#### A) Deprecated testovi — NE testirati vise
Hardenize jos uvek testira `X-XSS-Protection` header. Ovaj header je:
- **Deprecated od 2020** — Chrome ga je uklonio, Firefox nikad nije podrzao
- Mozilla, Google, OWASP preporucuju da se **NE salje**
- Moderan standard je CSP (Content Security Policy)

**Pravilo za V4:** ako je security mehanizam oficijelno deprecated, ne testiramo ga.
Ako je bio test u V3, markiramo ga kao **`INFO`** ili ga brisemo.

Nas trenutni scanner vec **ne testira** `X-XSS-Protection` — to je ispravno.
Ne dodajemo taj test ni u Strict ni u Paranoid.

#### B) N/A (nije primenljivo) — mora biti odvojena kategorija
Hardenize je prijavio fail za:
- SMTP / SPF / DMARC / MTA-STS / DANE

Ali `security-skener.gradovi.rs` **ne prima email** (nema MX zapis). Prijavljivanje
fail-ova za nepostojecu funkcionalnost je netacno.

**Pravilo za V4:** skener mora da razlikuje **3 stanja:**
1. `passed` — test prosao
2. `failed` — test pao, treba popravka
3. **`not_applicable`** — test nije primenljiv (feature ne postoji na targetu)

`not_applicable` **NE ulazi u score racunicu** ni u jednom modu (ni u Paranoid).

Primeri `not_applicable` stanja:
- SPF/DMARC/MTA-STS kada domen nema MX zapis
- Cookie consent kada sajt ne salje cookies
- CSP frame-ancestors kada sajt nije frameable po svojoj prirodi

#### C) Tehnicki nemoguce provere — drugacija klasifikacija
SRI (Subresource Integrity) je best practice za self-hosted CDN resurse.
Ali za:
- **Google Fonts** (dynamic CSS, zvanicno ne podrzavaju SRI)
- **Google AdSense** (dinamicki skriptovi)
- **Vercel live** (dev-only skripta)

SRI je **tehnicki nemoguc** jer su skripte dinamicke.

**Pravilo za V4:** SRI test mora da razlikuje:
- ✅ **SRI dodat** — passed
- ❌ **SRI nedostaje na self-hosted resursu** — failed
- ⚠️ **SRI nije moguc (Google/dinamicki resurs)** — `not_applicable` sa napomenom

Ovo se detektuje po domenu resursa: whitelist poznatih servisa koji ne podrzavaju SRI.

### §12.2 Realni fail-ovi koje Paranoid mora da trazi

Hardenize je prijavio 3 legitimne oblasti gde i nas sopstveni sajt **treba poboljsanje**:

| Fail | Realan? | Paranoid mora da trazi? |
|------|---------|-------------------------|
| HSTS Preload | ✅ Da | ✅ Da |
| DNSSEC | ✅ Da | ✅ Da |
| CAA DNS record | ✅ Da | ✅ Da |

**Pravilo za V4 Paranoid mode:** ova 3 moraju biti **`HIGH` severity** (ne LOW/MEDIUM).
Ozbiljan security asset mora imati sve tri.

### §12.3 Pre-V4 pripremne akcije (self-dogfood)

Pre nego sto pocnemo da gadjamo Paranoid mode na druge sajtove, **nas sopstveni
sajt mora da prodje Paranoid-ove uslove:**

1. ⏳ **Dodaj `preload` direktivu** u HSTS header (`vercel.json`)
   ```json
   "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"
   ```
2. ⏳ **Aktiviraj DNSSEC** u Cloudflare dashboard → DNS → Settings → DNSSEC → Enable
   - Kopiraj DS record iz CF
   - Paste u registrar za `gradovi.rs`
3. ⏳ **Dodaj CAA DNS zapis** u Cloudflare DNS:
   ```
   Type: CAA  |  Name: @  |  Tag: issue  |  Value: "letsencrypt.org"
   ```
4. ⏳ **Submituj na hstspreload.org** — zahteva da koraci 1-3 budu zavrseni
   (max-age ≥ 1 godina + preload flag + HTTPS redirect)

**Zasto pre V4:** kad pustimo marketing hook *"Hardenize dobija F u Paranoid-u, a tvoj sajt?"*,
**nas sajt mora biti ciste savesti** i proci sopstveni Paranoid test. Inace je
kontradikcija i guilty-by-association.

### §12.4 Tehnicka implikacija za scanner.py

Polje `status` u rezultatu check-a menja se iz binarnog (`passed: bool`) u tri stanja:

```python
# staro (V3)
{"category": "...", "severity": "HIGH", "passed": False}

# novo (V4)
{"category": "...", "severity": "HIGH", "status": "not_applicable",
 "reason": "Target has no MX record — email security checks skipped"}
```

**Backward kompatibilnost:** `passed` polje ostaje u outputu (derivirano iz `status`)
da se ne razbije frontend koji jos gleda `passed`.

```python
# u API response transformaciji:
result["passed"] = (result["status"] == "passed")
```

`compute_score()` filtrira `not_applicable` iz racunice u SVAKOM modu.

---

## §13 Azurirane obaveze (dopuna §10 Definition of Done)

Pored postojecih 10 stavki, V4 nije gotova bez:

- [ ] Uveden `status` enum: `passed | failed | not_applicable` (§12.1-B)
- [ ] SRI test ima whitelist Google/dinamickih resursa (§12.1-C)
- [ ] Email security testovi proveravaju MX zapis pre trcanja (§12.1-B)
- [ ] Paranoid mode oznacava HSTS Preload + DNSSEC + CAA kao `HIGH` (§12.2)
- [ ] Nas sopstveni sajt prolazi Paranoid mode test (§12.3)
  - HSTS `preload` aktivan
  - DNSSEC aktivan
  - CAA zapis postavljen
  - hstspreload.org submitovan (ili bar pending)

---

**Verzija dokumenta:** V4-DRAFT-2 (dopunjen hardenize analizom)
**Autor plana:** Claude Code (Opus 4.6) + operater
**Datum:** 2026-04-13
**Sledeci pregled:** posle koraka 4 (regression test)

**Istorija izmena:**
- V4-DRAFT-1 (2026-04-13) — inicijalni plan sa 4 strictness nivoa
- V4-DRAFT-2 (2026-04-13) — dopuna §12-§13: lekcije iz hardenize skena, N/A stanje,
  deprecated test handling, pre-V4 self-dogfood akcije
