# Claude for Open Source — Profesionalni Application Kit
### Kandidat: Milan Tošić (@UnlimitedEdition) · Projekat: Web Security Scanner

> 🔗 Prijava: https://claude.com/contact-sales/claude-for-oss
> 📄 Uslovi: https://www.anthropic.com/claude-for-oss-terms
> ⏰ Rok: **30. jun 2026.**

---

## ⚠️ Najpre — iskreno o šansama

Glavni prag programa je **5.000+ GitHub zvezdica** ili **1M+ NPM/mesec**. Tvoj najjači
repo ima **4 zvezdice**, tako da **standardni Maintainer Track ne prolazi**.

Jedini put je **Ecosystem Impact Track** („održavaš nešto od čega ekosistem zavisi") —
to je subjektivna procena recenzenta. Šanse su male, ali:
- Prijava je **besplatna** i ne košta te ništa osim 15 minuta.
- Projekat je **realno kvalitetan** (MIT, 240+ provera, CI, dokumentacija, live demo) —
  što je tačno ono što jača „impact" priču.
- **Sigurnosni domen** je relevantan Anthropic-u.

**Pravilo broj 1:** Nikad ne naduvavaj brojke (zvezdice/preuzimanja). Uslovi izričito
kažu da je to razlog za **diskvalifikaciju**. Igramo na kvalitet i iskrenost, ne na blef.

---

## ✅ KORAK 1 — Pripremi GitHub profil i repo PRE prijave (1–2 sata)

Recenzent prvo otvara tvoj GitHub. Mora da deluje profesionalno i živo.

### Na repo-u `security-scanner`:
- [ ] **Description** (About sekcija): `Passive web security scanner — 240+ checks, zero payloads, privacy-first. Python/FastAPI.`
- [ ] **Topics** (tagovi): `security`, `security-scanner`, `appsec`, `devsecops`, `python`, `fastapi`, `web-security`, `tls`, `gdpr`, `ci-cd`
- [ ] **Website** polje: postavi live demo URL (`https://security-skener.gradovi.rs`)
- [ ] Napravi bar **1 GitHub Release** sa tagom (npr. `v4.0`) i changelog-om — program ceni „releases" kao znak aktivnosti.
- [ ] Proveri da je **CI badge zelen** (Actions prolaze).
- [ ] Otvori 2–3 **realna Issue-a** (roadmap stavke) da repo deluje aktivno i otvoreno za doprinose.
- [ ] **Pin-uj** repo na profilu.

### Na profilu (@UnlimitedEdition):
- [ ] Dodaj **profilni README** (`UnlimitedEdition/UnlimitedEdition` repo) sa kratkim bio i listom projekata.
- [ ] Bio: `Indie developer & maintainer of open-source web security tooling.`
- [ ] Dodaj sliku/avatar ako ga nema.

> Cilj: kad recenzent otvori profil, da vidi ozbiljnog maintainer-a, ne napušten nalog.

---

## ✅ KORAK 2 — Popuni formu (copy-paste, engleski)

Forma na `claude.com/contact-sales/claude-for-oss` traži osnovna polja (ime, email,
GitHub, opis). Koristi ovaj tekst — **iskren, konkretan, bez naduvavanja**.

### Polje: Name
```
Milan Tošić
```

### Polje: Email
```
mtosic0450@gmail.com
```

### Polje: GitHub profile / username
```
https://github.com/UnlimitedEdition
```

### Polje: Project repository / URL
```
https://github.com/UnlimitedEdition/security-scanner
```
(Live demo: https://security-skener.gradovi.rs)

### Polje: Your role
```
Sole maintainer and author
```

### Polje: Project description / Why you qualify  (GLAVNO POLJE)
> Ako je kratko polje, koristi „Kratka verzija". Ako je veliki textarea, „Duga verzija".

**Kratka verzija (2–3 rečenice):**
```
I'm the sole maintainer of Web Security Scanner, an MIT-licensed passive web
security tool (Python/FastAPI) that runs 240+ checks across TLS, HTTP headers,
DNS, cookies, GDPR and more — without sending a single exploit payload. It ships
with a gated active-scan model requiring cryptographic ownership verification, full
SSRF protection on every redirect hop, Docker/CI integration, and a live hosted
instance. I maintain it actively (releases, CI, extensive docs) and want Claude Max
to accelerate the security-check engine and reduce false positives.
```

**Duga verzija (ako ima prostora):**
```
Project: Web Security Scanner (https://github.com/UnlimitedEdition/security-scanner)
License: MIT (code) + CC BY-NC 4.0 (docs)
Role: Sole maintainer and author

What it is:
A privacy-first, passive web security scanner that performs 240+ checks covering
TLS/SSL, HTTP security headers, DNS, cookies, JavaScript, APIs, CMS detection,
GDPR compliance, SEO and performance — all without sending exploit payloads, so it
never trips WAFs or violates scope. It bridges the gap between shallow header
checkers (Mozilla Observatory, SecurityHeaders) and aggressive active scanners
(Nuclei, ZAP).

Why it matters to the ecosystem:
- Gate-before-scan architecture: the most sensitive checks (file enumeration, port
  scanning, subdomain-takeover detection) only run after cryptographic ownership
  verification — a safety model most scanners lack.
- SSRF protection validated on every redirect hop.
- Multi-signal correlation to suppress false positives.
- Ships as Docker image, CI/CD one-liner, and a hosted live instance.
- Fully documented: ARCHITECTURE.md, CONTRIBUTING.md, SECURITY.md, ROADMAP.md.

Maintenance signal:
Active development with regular commits, CI on every push, dependency automation
via Dependabot, and tagged releases. I am the primary maintainer and review every
change.

How Claude Max would help:
I would use Claude Max 20x to expand and harden the check engine, design new passive
detection heuristics, reduce false positives, and improve the security
documentation that website owners and DevSecOps teams rely on. As a solo maintainer,
this directly multiplies how much safety tooling I can ship to the community.

Note on metrics:
This is an emerging project with modest stars today, but it is genuine, MIT-licensed,
actively maintained open-source security infrastructure. I'm applying under the
ecosystem-impact consideration rather than the star/download threshold, and I'd be
glad to share usage or deployment details on request.
```

---

## ✅ KORAK 3 — Pošalji i sačekaj

- Pregled je **rolling** (kako stižu prijave). Nema fiksnog roka za odgovor.
- Odobrenje stiže **email-om sa linkom za aktivaciju** (važi do 30. jun 2026.).
- Ako te odobre → klikneš link → Claude Max 20x se aktivira na nalogu na 6 meseci.

---

## 🎯 Saveti za maksimalne šanse

1. **Iskrenost pobeđuje.** Recenzent vidi 4 zvezdice svejedno — bolje da ti sam kažeš
   „emerging project" nego da pokušaš da prikriješ. Naduvane metrike = automatska diskvalifikacija.
2. **Kvalitet repo-a je tvoj najjači adut.** MIT licenca, čista dokumentacija, CI,
   sigurnosni fokus — sve to radi u tvoju korist. Zato je KORAK 1 obavezan pre prijave.
3. **Sigurnosni ugao.** Naglašavaj „passive, no payloads, SSRF-safe, ownership-gated" —
   to je tehnički ozbiljno i pokazuje da znaš materiju.
4. **Ne spamuj.** Pošalji jednu kvalitetnu prijavu, ne više.
5. **Plan B paralelno:** radi na realnoj popularnosti projekta (Show HN, Reddit
   r/netsec, dev.to članci, Hugging Face Space) — ako skupiš zvezdice, sledeći put
   ideš pravim Maintainer Track-om.

---

## 📋 Checklist pre slanja
- [ ] Repo description + topics + website postavljeni
- [ ] Bar 1 GitHub Release napravljen
- [ ] CI zelen, repo deluje aktivno
- [ ] Profilni README dodat
- [ ] Forma popunjena tekstom iznad
- [ ] Email tačan: mtosic0450@gmail.com
- [ ] Poslato pre 30. jun 2026.

---

### Izvori
- [Claude for Open Source — zvanična stranica](https://claude.com/contact-sales/claude-for-oss)
- [Uslovi programa](https://www.anthropic.com/claude-for-oss-terms)
- [Simon Willison — pregled](https://simonwillison.net/2026/Feb/27/claude-max-oss-six-months/)
- [Daniel Avila — kako se prijaviti (Medium)](https://medium.com/@dan.avila7/i-got-selected-for-claude-for-open-source-program-heres-how-you-can-apply-too-1024da17ef31)
