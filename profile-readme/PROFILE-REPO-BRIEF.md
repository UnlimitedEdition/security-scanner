# 📋 KOMPLETAN BRIEF — Profilni repo `UnlimitedEdition/UnlimitedEdition`

> **Za koga:** agent koji se pokreće UNUTAR repo-a `UnlimitedEdition/UnlimitedEdition`.
> **Cilj:** postaviti i održavati **živi profilni README** koji agenti iz svih ostalih
> repo-a kontinuirano dopunjavaju — bez ikada „zatvorene" finalne verzije.
>
> Nalepi ovaj ceo dokument agentu kao zadatak.

---

## 1. KONTEKST

- Ovo je „magični" profilni repo (isto ime kao GitHub username) — njegov `README.md`
  se prikazuje na vrhu profila https://github.com/UnlimitedEdition.
- Vlasnik: **Milan Tošić** (@UnlimitedEdition), indie dev za open-source web security /
  GDPR alat. Flagship projekat: `security-scanner` (240+ pasivnih provera).
- Repo ima ~35 projekata. Svaki od njih će pokretati agenta koji upisuje SVOJ red
  u registry tabelu ovog README-a.

---

## 2. APSOLUTNA PRAVILA (važe za SVE agente, uvek)

1. **Dokument je ŽIV — nikad se ne zatvara.** Ne pisati „v1.0 final", „complete",
   „closed". Ne stavljati datum „poslednje izmene" koji implicira kraj.
2. **Piše se SAMO unutar označenih zona** (`<!-- PROJECTS:START -->` … `END`,
   `<!-- TECH:START -->` … `END`). Van zona se ništa ne dira.
3. **Jedan repo = jedan red.** Agent dodaje/ažurira isključivo red svog repo-a.
4. **Nikad ne brisati ni menjati tuđi red** — ni pri rešavanju merge konflikta.
5. **Idempotentno:** ponovljeno pokretanje samo osvežava postojeći red, ne duplira.
6. **Alfabetski** poredak redova po imenu repo-a.

---

## 3. ŠTA AGENT U OVOM REPOU (PROFILNOM) TREBA DA URADI — sada, jednom

### Korak A — Napiši `README.md`
Upiši TAČNO sadržaj iz **sekcije 6** ovog brief-a u `README.md` u korenu repo-a.
(Ako README već postoji sa nekim tekstom, zameni ga ovim scaffold-om — ovo je osnova.)

### Korak B — Dodaj `CONTRIBUTING-REGISTRY.md`
Upiši sadržaj iz **sekcije 7** (kratka pravila + prompt za repo-agente), da svako ko
dođe u ovaj repo zna kako se dopunjava registry.

### Korak C — Commit & push na default granu
```bash
git add README.md CONTRIBUTING-REGISTRY.md
git commit -m "chore(profile): bootstrap living profile README + registry rules"
for i in 1 2 3 4 5; do
  git pull --rebase origin HEAD && git push origin HEAD && break
  sleep $((2**i))
done
```

### Korak D (opciono, preporučeno) — Auto-update
Ako želiš da se redovi osvežavaju automatski, dodaj workflow iz **sekcije 8**.

---

## 4. KAKO SE PIŠE U OVAJ REPO — protokol upisa (za sve agente)

Ovo je srce sistema. Svaki agent (iz ovog ili iz drugog repo-a) prati isti protokol
kada dira registry:

1. **Uzmi najnovije stanje** (jer više agenata gađa isti fajl):
   ```bash
   git clone https://github.com/UnlimitedEdition/UnlimitedEdition.git   # ili git pull --rebase ako već imaš klon
   cd UnlimitedEdition
   ```
2. **Nađi zonu** između `<!-- PROJECTS:START -->` i `<!-- PROJECTS:END -->`.
3. **Sastavi svoj red** (5 kolona, tačan format):
   ```
   | [<ime-repo>](<url>) | <šta radi, 1 rečenica> | <stack 1-3> | <⭐ broj ili prazno> | <emoji> <status> |
   ```
   - Status emoji: 🟢 Aktivno · 🟡 Održavanje · 🔵 Eksperiment · ⚪ Arhivirano
   - Verziju dodati ako postoji (npr. `🟢 Aktivno · v1.2.0`).
4. **Upiši red idempotentno:**
   - Ako red sa `[<ime-repo>](...)` već postoji → zameni ga novim.
   - Ako ne postoji → ubaci ga tako da redovi ostanu alfabetski sortirani.
   - Zaglavlje tabele (`| Projekat | ... |`) i separator (`| --- |`) NE dirati.
5. **Commit + push sa zaštitom od trke:**
   ```bash
   git add README.md
   git commit -m "chore(profile): update <ime-repo> entry"
   for i in 1 2 3 4 5; do
     git pull --rebase origin HEAD && git push origin HEAD && break
     sleep $((2**i))
   done
   ```
6. **Konflikt = zadrži OBA reda.** Ako rebase prijavi konflikt na tabeli, spoji tako
   što zadržiš tuđe redove netaknute + svoj ažuriran red, pa `git rebase --continue`.
   Nikad ne rešavaj konflikt brisanjem tuđeg reda.

**Zašto ovako:** marker-zone + idempotentni red + `pull --rebase`/retry petlja
omogućavaju da desetine agenata paralelno dopunjavaju isti fajl bez gubljenja podataka.

---

## 5. VERIFIKACIJA (svaki agent na kraju proverava)

- [ ] Tabela ima zaglavlje + separator + sve ranije redove + svoj (ažuriran) red.
- [ ] Markeri `PROJECTS:START/END` i `TECH:START/END` i dalje postoje.
- [ ] Nema duplikata reda za isti repo.
- [ ] Nema reči „final / complete / closed" niti obrisanih tuđih redova.
- [ ] Push prošao (ili je odrađen rebase + ponovni push).

---

## 6. SADRŽAJ ZA `README.md` (upiši verbatim)

```markdown
<!--
  PROFILNI README — ŽIVI DOKUMENT. Nema finalnu verziju.
  Agenti iz svakog repo-a dopunjavaju REGISTRY tabelu ispod — svaki agent
  dodaje/ažurira SAMO svoj red (idempotentno), ne briše tuđe.
  Piše se isključivo unutar <!-- ...:START --> / <!-- ...:END --> zona.
-->

<h1 align="center">Milan Tošić 👋</h1>

<p align="center">
  <strong>Indie developer &amp; maintainer of open-source web tooling</strong><br/>
  Security · GDPR/ZZPL compliance · developer utilities
</p>

<p align="center">
  <a href="https://github.com/UnlimitedEdition"><img src="https://img.shields.io/badge/GitHub-UnlimitedEdition-181717?logo=github" alt="GitHub"/></a>
  <img src="https://komarev.com/ghpvc/?username=UnlimitedEdition&label=Profile%20views&color=0e75b6&style=flat" alt="views"/>
</p>

---

### 🧭 O meni
- 🛡️ Gradim [**Web Security Scanner**](https://github.com/UnlimitedEdition/security-scanner) — pasivna analiza bezbednosti veb sajtova, 240+ provera, bez exploit payload-a.
- 🌍 Srbija · sigurnosni i GDPR/ZZPL alat.
- 📫 Kontakt: kontakt@gradovi.rs
- 🤝 Otvoren za saradnju na open-source security/devtool projektima.

---

## 🚀 Projekti

<!--
  PROJECTS:START
  PRAVILA: dodaj/ažuriraj TAČNO JEDAN red (za svoj repo). Ne briši tuđe.
  Alfabetski po imenu repo-a. Idempotentno. Format = 5 kolona ispod.
-->
| Projekat | Šta radi | Stack | ⭐ | Status |
|----------|----------|-------|----|--------|
| [security-scanner](https://github.com/UnlimitedEdition/security-scanner) | Pasivni web security skener — 240+ provera (TLS, headers, DNS, GDPR, SEO, perf) | Python · FastAPI | 4 | 🟢 Aktivno · v4.2.0 |
<!-- PROJECTS:END -->

> Legenda: 🟢 Aktivno · 🟡 Održavanje · 🔵 Eksperiment · ⚪ Arhivirano

---

## 🛠️ Tech

<!--
  TECH:START — agenti smeju da DODAJU badge za tehnologiju svog repo-a ako ne postoji.
  Ne uklanjati postojeće. Po jedan badge po tehnologiji.
-->
![Python](https://img.shields.io/badge/-Python-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/-FastAPI-009688?logo=fastapi&logoColor=white)
![TypeScript](https://img.shields.io/badge/-TypeScript-3178C6?logo=typescript&logoColor=white)
![Supabase](https://img.shields.io/badge/-Supabase-3FCF8E?logo=supabase&logoColor=white)
![Docker](https://img.shields.io/badge/-Docker-2496ED?logo=docker&logoColor=white)
<!-- TECH:END -->

---

## 📊 GitHub statistika

<p align="center">
  <img height="165" src="https://github-readme-stats.vercel.app/api?username=UnlimitedEdition&show_icons=true&hide_border=true&count_private=true" alt="stats"/>
  <img height="165" src="https://github-readme-stats.vercel.app/api/top-langs/?username=UnlimitedEdition&layout=compact&hide_border=true" alt="langs"/>
</p>

---

<!--
  ŽIVI DOKUMENT — ne dodavati „v1.0 final", ne brisati zone, ne zaključavati registry.
  Svaki repo ažurira svoj red. Vidi CONTRIBUTING-REGISTRY.md.
-->
<p align="center"><sub>🟢 Živi dokument — kontinuirano dopunjavan agentima iz pojedinačnih repozitorijuma.</sub></p>
```

---

## 7. SADRŽAJ ZA `CONTRIBUTING-REGISTRY.md` (upiši verbatim)

Ovaj fajl objašnjava svakom repo-agentu kako da dopuni registry. Sadrži i gotov prompt.

````markdown
# Kako se dopunjava profilni registry

Ovaj repo (`UnlimitedEdition/UnlimitedEdition`) drži živi profilni README.
Svaki drugi repo dopunjava SVOJ red u tabeli „Projekti" — prateći pravila niže.

## Pravila
- Dodaješ/ažuriraš TAČNO JEDAN red (svoj repo), unutar `<!-- PROJECTS:START/END -->`.
- Nikad ne brišeš/menjaš tuđe redove (ni pri konfliktu — zadrži oba).
- Idempotentno, alfabetski, bez „final/complete/closed".

## Prompt za agenta iz drugog repo-a (kopiraj i pokreni u tom repo-u)
```
ZADATAK: Dopuni profilni README (UnlimitedEdition/UnlimitedEdition, README.md)
jednim redom koji opisuje OVAJ repo. ŽIVI DOKUMENT — ne zatvarati.

1) Iz OVOG repo-a izvuci: ime (owner/name), opis (1 rečenica), stack (1-3),
   ⭐ broj ako znaš, status (🟢 Aktivno / 🟡 Održavanje / 🔵 Eksperiment / ⚪ Arhivirano)
   + verzija ako postoji.
2) git clone https://github.com/UnlimitedEdition/UnlimitedEdition.git && cd UnlimitedEdition
3) Između <!-- PROJECTS:START --> i <!-- PROJECTS:END --> upiši red:
   | [<ime>](<url>) | <šta radi> | <stack> | <⭐ ili prazno> | <emoji> <status> |
   - postoji red za ovaj repo → zameni; ne postoji → ubaci alfabetski.
   - zaglavlje i | --- | ne dirati.
4) git add README.md && git commit -m "chore(profile): update <ime> entry"
   for i in 1 2 3 4 5; do git pull --rebase origin HEAD && git push origin HEAD && break; sleep $((2**i)); done
5) Konflikt → zadrži OBA reda, pa rebase --continue. Nikad ne briši tuđi red.

NA KRAJU proveri: zaglavlje + svi stari redovi + tvoj red; markeri postoje;
nema duplikata; nema „final"; push prošao.
```
````

---

## 8. OPCIONO — Auto-update preko GitHub Actions

Da se red osvežava sam (bez ručnog agenta), u SVAKOM repo-u dodaj workflow koji na
push/release gura ažuriran red u profilni repo. Treba ti **PAT** (fine-grained token
sa `contents: write` na `UnlimitedEdition/UnlimitedEdition`) sačuvan kao secret
`PROFILE_REPO_TOKEN` u svakom repo-u.

`.github/workflows/update-profile-registry.yml`:
```yaml
name: Update profile registry
on:
  push: { branches: [ main, master ] }
  release: { types: [ published ] }
jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - name: Update my row in profile README
        env:
          GH_TOKEN: ${{ secrets.PROFILE_REPO_TOKEN }}
          REPO: ${{ github.repository }}
        run: |
          set -e
          git clone https://x-access-token:${GH_TOKEN}@github.com/UnlimitedEdition/UnlimitedEdition.git pr
          cd pr
          NAME="${REPO#*/}"
          URL="https://github.com/${REPO}"
          DESC="$(gh repo view "$REPO" --json description -q .description 2>/dev/null || echo '')"
          STARS="$(gh repo view "$REPO" --json stargazerCount -q .stargazerCount 2>/dev/null || echo '')"
          ROW="| [${NAME}](${URL}) | ${DESC} |  | ${STARS} | 🟢 Aktivno |"
          python3 - "$NAME" "$ROW" <<'PY'
          import re, sys
          name, row = sys.argv[1], sys.argv[2]
          f="README.md"; s=open(f, encoding="utf-8").read()
          a=s.index("<!-- PROJECTS:START"); a=s.index("\n", a)+1
          b=s.index("<!-- PROJECTS:END")
          head=s[:a]; block=s[a:b]; tail=s[b:]
          lines=block.rstrip("\n").split("\n")
          hdr=[l for l in lines if l.startswith("| Projekat") or set(l.strip())<=set("|- ")]
          rows=[l for l in lines if l.startswith("|") and l not in hdr]
          rows=[l for l in rows if f"[{name}]" not in l]   # ukloni stari svoj red
          rows.append(row)                                  # dodaj nov
          rows=sorted(rows, key=lambda l: l.lower())
          open(f,"w",encoding="utf-8").write(head+"\n".join(hdr+rows)+"\n"+tail)
          PY
          git config user.name "profile-bot"; git config user.email "bot@users.noreply.github.com"
          git add README.md
          git commit -m "chore(profile): auto-update ${NAME}" || exit 0
          for i in 1 2 3 4 5; do git pull --rebase origin HEAD && git push origin HEAD && break; sleep $((2**i)); done
```
> Napomena: za `gh` u workflow-u već postoji `GH_TOKEN`; za clone/push profilnog repo-a
> koristi se PAT iz `PROFILE_REPO_TOKEN`. Ako ne želiš PAT, ostani na agent-pristupu (sekcije 4–7).

---

## ▶️ TL;DR za agenta u profilnom repou
1. Napiši `README.md` (sekcija 6) i `CONTRIBUTING-REGISTRY.md` (sekcija 7).
2. Commit + push na default granu (sekcija 3, Korak C).
3. (Opciono) dodaj auto-update workflow predložak (sekcija 8) u dokumentaciju.
4. Dokument ostaje OTVOREN — registry rastu agenti iz drugih repo-a po protokolu iz sekcije 4.
