# Prompt za agenta — „Dopuni profilni README"

> Ovaj prompt daješ agentu **unutar svakog svog repozitorijuma**. Agent pročita
> taj repo i upiše/ažurira **samo svoj jedan red** u registry tabeli profilnog
> README-a (`UnlimitedEdition/UnlimitedEdition`). Dokument se NE zatvara i NE
> finalizuje — samo se dopunjava.

---

## 📋 Kopiraj ovo agentu (jedan repo = jedno pokretanje)

```
ZADATAK: Dopuni moj GitHub profilni README jednim redom koji opisuje OVAJ repozitorijum.
Profilni repo je: UnlimitedEdition/UnlimitedEdition (default grana, fajl README.md).

OVO JE ŽIVI DOKUMENT. Pravila su apsolutna:
- Dodaješ ili ažuriraš TAČNO JEDAN red — za repo iz kog si pokrenut.
- NIKADA ne brišeš, ne menjaš i ne preuređuješ tuđe redove.
- NE dodaješ "final", "v1.0", "complete" — ne zatvaraš poglavlje.
- NE diraš ništa van označenih zona (<!-- PROJECTS:START --> ... <!-- PROJECTS:END -->).

KORACI:
1. Pročitaj OVAJ repo i izvuci:
   - ime repo-a (owner/name)
   - kratak opis šta radi (1 rečenica, iz README/About)
   - glavni stack (1-3 tehnologije)
   - broj zvezdica (ako znaš; ako ne, ostavi prazno)
   - status: 🟢 Aktivno / 🟡 Održavanje / 🔵 Eksperiment / ⚪ Arhivirano
     (proceni po skorašnjim commit-ovima) + verzija ako postoji (npr. v1.2.0)

2. Kloniraj profilni repo i radi na default grani:
   git clone https://github.com/UnlimitedEdition/UnlimitedEdition.git
   cd UnlimitedEdition

3. U README.md, IZMEĐU markera <!-- PROJECTS:START --> i <!-- PROJECTS:END -->:
   - Format reda (5 kolona, tačno ovako):
     | [<ime>](<url>) | <šta radi> | <stack> | <⭐ ili prazno> | <status emoji> <opis> |
   - Ako red za ovaj repo VEĆ POSTOJI → zameni ga (idempotentno).
   - Ako NE postoji → ubaci ga tako da redovi ostanu ALFABETSKI sortirani po imenu repo-a.
   - Zaglavlje tabele i red sa | --- | NE diraj.

4. (Opciono) U zoni <!-- TECH:START --> ... <!-- TECH:END --> dodaj badge za
   tehnologiju koju ovaj repo koristi AKO već ne postoji. Ne uklanjaj postojeće.

5. Commit i push sa zaštitom od konflikta (jer više agenata gađa isti fajl):
   git add README.md
   git commit -m "chore(profile): update <ime-repo> entry in projects registry"
   # pre push-a povuci najnovije i rebase-uj, pa probaj ponovo ako neko pretekne:
   for i in 1 2 3 4 5; do
     git pull --rebase origin HEAD && git push origin HEAD && break
     sleep $((2**i))
   done

6. Ako posle rebase-a tvoj red i tuđi red kolidiraju — zadrži OBA reda
   (tvoj ažuriran + tuđi netaknut), reši konflikt tako što spojiš tabelu,
   pa nastavi rebase. Nikad ne brišeš tuđi red da bi rešio konflikt.

VERIFIKACIJA NA KRAJU:
- Tabela i dalje ima zaglavlje + sve postojeće redove + tvoj (ažuriran) red.
- Markeri PROJECTS:START/END i TECH:START/END i dalje postoje.
- Nema reči "final/complete/closed" niti obrisanih tuđih redova.
```

---

## 🔧 Napomene za tebe (operatera)

- **Idempotentno:** isti agent možeš da pokreneš više puta — uvek samo osvežava svoj red.
- **Paralelno bezbedno:** `pull --rebase` + retry petlja rešava trku kad više
  repo-agenata gura istovremeno. Marker-zone sprečavaju da agent „pojede" tuđe redove.
- **Skalira:** isti prompt radi za svih 35 repo-a — pokreni po jedan u svakom.
- **Seed:** README već ima red za `security-scanner` kao primer formata; ostali
  agenti samo dodaju svoje ispod/iznad po abecedi.
- **Dokument ostaje otvoren:** nigde nema „verzije koja zatvara poglavlje" — registry
  raste kako agenti stižu.

## ▶️ Prvi korak (ti, ručno, jednom)
1. Napravi repo **`UnlimitedEdition/UnlimitedEdition`** (public, isto ime kao username — to je „magični" profilni repo).
2. U njega ubaci `README.md` (scaffold koji sam ti spremio).
3. Onda pokreni agente sa promptom iznad — po jedan u svakom repo-u.
