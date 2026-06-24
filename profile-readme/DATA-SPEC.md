# 🗂️ DATA-SPEC — koji podaci idu u registry i kako ih vadimo

> Dva dela:
> **A)** Popunjena data karta ovog projekta (`security-scanner`) — etalon/primer.
> **B)** Spec po poljima: ŠTA tražimo i GDE/KAKO to vadimo za bilo koji drugi repo.

---

## DEO A — `security-scanner` (popunjeno, etalon)

| Polje | Vrednost |
|-------|----------|
| **repo (owner/name)** | `UnlimitedEdition/security-scanner` |
| **url** | https://github.com/UnlimitedEdition/security-scanner |
| **opis (1 rečenica)** | Pasivni web security skener — 240+ provera (TLS, headers, DNS, GDPR, SEO, perf), bez exploit payload-a |
| **stack (1–3)** | Python · FastAPI *(+ Supabase, Docker)* |
| **⭐ zvezdice** | 4 |
| **status** | 🟢 Aktivno |
| **verzija** | v4.2.0 |
| **licenca** | MIT |
| **live / demo** | https://security-skener.gradovi.rs/ |
| **topics** | security, security-scanner, web-security, fastapi, python, gdpr, passive-scanning, supabase, vercel, huggingface-spaces |
| **primarni jezik (GitHub)** | HTML *(obmanjujuće — vidi napomenu u Delu B)* |
| **stvarni jezici (po fajlovima)** | py(74), html(56), md(40), sql(24), yml(10) |
| **poslednja aktivnost** | 2026-06-02 |

### → Registry red (ono što se upisuje u README):
```
| [security-scanner](https://github.com/UnlimitedEdition/security-scanner) | Pasivni web security skener — 240+ provera (TLS, headers, DNS, GDPR, SEO, perf) | Python · FastAPI | 4 | 🟢 Aktivno · v4.2.0 |
```

---

## DEO B — Spec po poljima (za SVAKI drugi repo)

Za svaki repo, agent popunjava istih 5 kolona registry-ja (+ pomoćna polja po želji).
Za svako polje dat je **izvor**, **kako se vadi**, i **fallback redosled**.

### 1. `repo` i `url` — OBAVEZNO
- **Izvor:** sam repo.
- **Kako:** `git remote get-url origin` → izvuci `owner/name`; url = `https://github.com/<owner>/<name>`.
- **Fallback:** GitHub API `gh repo view --json nameWithOwner,url`.

### 2. `opis` (1 rečenica) — OBAVEZNO
- **Izvor (redosled):**
  1. GitHub „About"/description: `gh repo view <repo> --json description -q .description`
  2. Prvi pasus / podnaslov u `README.md` (h1 subtitle).
  3. `package.json` → `.description`.
- **Pravilo:** skratiti na 1 jasnu rečenicu, bez markdown-a, bez tačke na kraju ako kvari tabelu.

### 3. `stack` (1–3 tehnologije) — OBAVEZNO
- **Izvor (kombinuj):**
  - **Manifest fajl** (najpouzdaniji): `requirements.txt`/`pyproject.toml` (Python),
    `package.json` `dependencies` (JS/TS), `go.mod`, `Cargo.toml`, `composer.json`.
  - **Framework badge-ovi** u README (npr. FastAPI, Next.js, Astro).
  - **Konfiguracije** u repo-u: `Dockerfile`→Docker, `vercel.json`→Vercel, `supabase/`→Supabase,
    `next.config.*`→Next.js, `astro.config.*`→Astro.
- **⚠️ NE oslanjaj se na „primarni jezik" sa GitHub-a** — linguist broji bajtove, pa npr.
  ovaj repo prijavljuje **HTML** iako je backend **Python/FastAPI**. Uzmi jezik/okvir
  koji opisuje ŠTA projekat radi, ne najveći fajl.
- **Format:** `Glavni · Okvir` (npr. `TypeScript · Next.js`, `Python · FastAPI`).

### 4. `⭐ zvezdice`
- **Izvor:** GitHub API. `gh repo view <repo> --json stargazerCount -q .stargazerCount`.
- **Fallback:** ostavi prazno ako nije dostupno (ne izmišljaj broj).

### 5. `status` (emoji) — OBAVEZNO
- **Izvor:** datum poslednjeg commit-a + `archived` flag.
- **Kako:**
  - `gh repo view <repo> --json isArchived -q .isArchived` → ako `true` → **⚪ Arhivirano**.
  - inače po poslednjem commit-u `git log -1 --format=%cd --date=short`:
    - ≤ 90 dana → **🟢 Aktivno**
    - 90–365 dana → **🟡 Održavanje**
  - ako je repo očigledno proba/POC (nema README/licence, malo commit-ova) → **🔵 Eksperiment**.

### 6. `verzija` (dodaje se uz status ako postoji)
- **Izvor (fallback redosled):**
  1. **Git tag:** `git describe --tags --abbrev=0` (najpouzdanije).
  2. **CHANGELOG.md:** prvi `## [x.y.z]` red. *(ovde npr. daje `4.2.0` jer nema tagova)*
  3. **VERSION/VERSION.md** fajl.
  4. **package.json** → `.version`.
- **Format:** `v<broj>` (npr. `v4.2.0`). Ako nigde nema verzije → izostavi.

### 7. (pomoćno) `licenca`
- **Izvor:** `gh repo view <repo> --json licenseInfo -q .licenseInfo.spdxId` ili `LICENSE` fajl (prva linija).

### 8. (pomoćno) `live / demo`
- **Izvor:** GitHub „homepage" polje (`gh repo view <repo> --json homepageUrl -q .homepageUrl`)
  ili „Live"/„Demo" badge/link u README.

### 9. (pomoćno) `topics`
- **Izvor:** `gh repo view <repo> --json repositoryTopics`.

---

## 🧪 Brzi izvlakač (jedan blok — pokreni u repo-u, daje sve)
```bash
REPO="$(git remote get-url origin | sed -E 's#.*github.com[:/]##; s/\.git$//')"
echo "repo   : $REPO"
echo "url    : https://github.com/$REPO"
gh repo view "$REPO" --json description,stargazerCount,isArchived,licenseInfo,homepageUrl,repositoryTopics \
  -q '"opis   : \(.description)\n⭐      : \(.stargazerCount)\narhiv  : \(.isArchived)\nlicenca: \(.licenseInfo.spdxId // "—")\nlive   : \(.homepageUrl // "—")"' 2>/dev/null
echo "stack  : $(ls requirements.txt pyproject.toml package.json go.mod Cargo.toml composer.json 2>/dev/null | head -1) (+ Dockerfile/vercel.json/supabase ako postoje)"
echo "verzija: $(git describe --tags --abbrev=0 2>/dev/null || grep -m1 -oE '\[[0-9]+\.[0-9]+\.[0-9]+\]' CHANGELOG.md 2>/dev/null | tr -d '[]' || echo '—')"
echo "zadnji : $(git log -1 --format=%cd --date=short)"
```
> Rezultat ovog bloka agent mapira u 5 kolona registry-ja po pravilima iznad, pa upiše
> red prateći **protokol upisa iz `PROFILE-REPO-BRIEF.md` (sekcija 4)**.

---

## ✅ Minimalni skup (mora) vs. prošireni (lepo imati)
- **Mora (5 kolona):** repo+url · opis · stack · ⭐ · status(+verzija)
- **Lepo imati:** licenca · live/demo · topics — koristi ako ćeš proširivati tabelu kasnije.
- **Nikad ne izmišljaj** vrednost (npr. broj zvezdica ili verziju) — ako nema izvora, ostavi prazno.
