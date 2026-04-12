# VERSION TRACKING — Web Security Scanner

> **Trenutna verzija: `2026-04-12-v3`**
>
> Ovaj fajl postoji da bi svaki agent/developer znao GDE SVE treba da
> promeni verziju kad se politika ili uslovi azuriraju.

## Kad se verzija menja?

Verzija se menja kad se azurira:
- Politika privatnosti (privacy.html)
- Uslovi koriscenja (terms.html)
- Prava korisnika (user-rights.html)
- Bilo koji pravni tekst koji korisnik potvrdjuje checkbox-om

## Format verzije

```
YYYY-MM-DD-vN
```
- `YYYY-MM-DD` = datum promene
- `vN` = redni broj verzije tog dana (v1, v2, v3...)

Primer: `2026-04-12-v3` = treca verzija od 12. aprila 2026.

## SVA MESTA gde se verzija pojavljuje

Kad menjas verziju, MORAS da azuriras SVA ova mesta:

### 1. Backend (api.py)
- `consent_version` string u POST /scan endpoint (~linija gde je `consent_version: "2026-04-12-v3"`)
- `consent_version` string u wizard execute endpoint

### 2. Frontend (index.html)
- `consent_version` u JavaScript `startScan()` funkciji
- Consent checkbox tekst — `(verzija 2026-04-12-v3)` link

### 3. Politika privatnosti (privacy.html)
- Subtitle SR: `Verzija <strong>2026-04-12-v3</strong>`
- Subtitle EN: `Version <strong>2026-04-12-v3</strong>`
- Sekcija 10 SR: `Trenutna verzija politike: 2026-04-12-v3`
- Sekcija 10 EN: `Current policy version: 2026-04-12-v3`
- Sekcija 14 SR: tabela — novi red sa statusom AKTIVNA, stari red zameni status
- Sekcija 14 EN: tabela — novi red sa statusom ACTIVE, stari red zameni status

### 4. Uslovi koriscenja (terms.html)
- Subtitle SR + EN: `Version 2026-04-12-v3`

### 4b. Politika refundacije (refund-policy.html)
- Subtitle SR + EN: `Verzija/Version 2026-04-12-v3`

### 4c. Prava korisnika (user-rights.html)
- Subtitle SR + EN: `Verzija/Version 2026-04-12-v3`

### 4d. Prijava zloupotrebe (abuse-report.html)
- Subtitle SR + EN: `Verzija/Version 2026-04-12-v3`

### 5. Header sajta (blog-common.js)
- `verBadge.textContent = 'v3'` — kratka oznaka u navbar-u
- `verBadge.title = '2026-04-12-v3'` — puna verzija na hover

### 6. Ovaj fajl (VERSION.md)
- Gornji red: `Trenutna verzija: 2026-04-12-v3`

## Procedura za promenu verzije

1. Odluci novu verziju (npr. `2026-05-15-v4`)
2. Azuriraj SVIH 6 lokacija iznad
3. U privacy.html §14 dodaj NOVI red u tabelu sa statusom AKTIVNA
4. Stari red promeni status iz AKTIVNA u "zamenjeno vN"
5. Commit sa porukom: `Bump consent version to YYYY-MM-DD-vN`
6. Push na oba remote-a

## Istorija verzija

| Verzija | Datum | Opis |
|---|---|---|
| `2026-04-12-v3` | 12. apr 2026 | ZZPL uskladjenost, cookie consent V2, kontakt email, data breach |
| `2026-04-10-v2` | 10. apr 2026 | Lemon Squeezy sub-processor, Pro plan, scan_requests |
| `2026-04-10-v1` | 10. apr 2026 | Prva verzija — PII hash, audit_log, backup |
