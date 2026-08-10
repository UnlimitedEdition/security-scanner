# ⚠️ DRAFT — NIJE PRIMENJENO — NIJE PRAVNI SAVET

> ## 🛑 PROČITAJ PRE BILO ČEGA
>
> - **Ovo je PREDLOG teksta, ne primenjen tekst.** `privacy.html` i `terms.html` **nisu dirani** i neće biti dirani bez tvoje eksplicitne odluke.
> - **Ovo NIJE pravni savet.** Napisao ga je AI agent na osnovu čitanja izvornog koda, ne pravnik. Delovi koji zahtevaju pravnu procenu (retencija, pravni osnov, jurisdikcija, potrošačko pravo) su **označeni i namerno nedovršeni** — vidi §8.
> - **Ništa odavde ne kopiraj u produkciju bez pregleda.** Tekst opisuje obradu podataka koja je pravno obavezujuća prema korisnicima; greška u opisu je greška u izjavi rukovaoca.
> - **Verzija pravnih akata je i dalje `2026-04-13-v4`.** Bump na `2026-08-09-v5` je predložen u §7, ali **nije izvršen**.
>
> Datum izrade drafta: **2026-08-09**
> Osnov: čitanje koda u `F:\security-scanner\security-scanner\` (grane `master`, poslednji commit 2026-04-19)

---

## 1. Zašto ovaj draft postoji

Malware skener je u produkciji **od aprila 2026**, a pravni akti ga **nigde ne pominju**:

```
grep -ci malware privacy.html  →  0
grep -ci malware terms.html    →  0
```

Konkretno, sledeće se dešava u produkciji a nije pokriveno objavljenim aktima:

| # | Činjenica iz koda | Gde je (ne)pokrivena |
|---|---|---|
| 1 | Ciljni domen/URL se šalje **8+ novih trećih strana** van EU | `privacy.html` §7 lista sub-procesora — nema nijednu od njih |
| 2 | Tri nove tabele (`malware_scans`, `malware_credits`, `license_activations`) | `privacy.html` §5 retencija — ne pominje nijednu |
| 3 | Za malware sken **fingerprint je OBAVEZAN** (403 bez njega) | `privacy.html` §2 kaže „**opcioni** fingerprint_hash" |
| 4 | `license_activations.user_agent` čuva **SIROV User-Agent** | `privacy.html` §2 tvrdi: „Ono što NE čuvamo: … raw User-Agent stringove" — **ova rečenica je danas netačna** |
| 5 | `license_activations` **nema RLS** | `privacy.html` §6 tvrdi: „svaka tabela ima RLS uključen sa default-deny politikom" — **netačno** |
| 6 | Malware pack je **plaćena usluga** ($3), sa limitom od 5 uređaja po ključu | `terms.html` §11-14 opisuju samo Pro pretplatu |
| 7 | `malware.js` šalje `consent_version: 'v1'` | Ne odgovara nijednoj postojećoj verziji akata — dokaz pristanka je **bezvredan** |
| 8 | Malware consent checkbox **nema link** ka ToS/Privacy | `index.html` checkbox ih ima (linija 1808-1809) |

Tačke 4, 5, 7 i 8 nisu samo „nedostaje tekst" — to su **postojeće izjave u aktima koje su danas neistinite** ili dokaz pristanka koji ne drži vodu. Vidi §9.

---

## 2. Šta kod stvarno radi — utvrđeno čitanjem

Sve dole je pročitano iz koda, ne pretpostavljeno. Reference su `fajl:linija` na dan 2026-08-09.

### 2.1. Malware skener — SAFE mod (11 provera, besplatno, bez verifikacije)

Pokreće se sa `malware.html` → `POST /malware-scan` sa `mode: 'safe'`.

| Primalac podataka | Šta se konkretno šalje | Jurisdikcija (procena, **potvrditi**) | Kod |
|---|---|---|---|
| **abuse.ch — URLhaus** | **Ceo ciljni URL** (`POST` sa `data={"url": url}`) | Švajcarska (ZHAW/Bern) | `malware_scanner/config.py:39`, `safe_checks/blacklist.py:79-83` |
| **OpenPhish** | **Ništa o cilju.** Preuzimamo `feed.txt` i poređenje radimo lokalno; OpenPhish vidi samo IP našeg backend-a | Irska/SAD | `config.py:40`, `safe_checks/blacklist.py:51-52` |
| **Spamhaus DBL** | Ciljni domen kao DNS upit `<domen>.dbl.spamhaus.org` | Švajcarska/UK | `config.py:48`, `safe_checks/blacklist.py:104-107` |
| **SURBL** | Ciljni domen kao DNS upit `<domen>.multi.surbl.org` | SAD | `config.py:49` |
| **Barracuda** | Ciljni domen kao DNS upit `<domen>.b.barracudacentral.org` | SAD | `config.py:50` |
| **Cloudflare (1.1.1.1)** | **Svaki** DNS upit malware skenera, uključujući gornja tri RBL upita → domen | SAD | `malware_scanner/utils.py:106,120` |
| **Google (8.8.8.8)** | isto | SAD | `malware_scanner/utils.py:106,120` |
| **Quad9 (9.9.9.9)** | isto | Švajcarska | `malware_scanner/utils.py:106,120` |
| Ciljni sajt | `GET` homepage (jedan zahtev) | — | `malware_scanner/main.py` |

> **Bitno za tekst politike:** resolveri su **hardkodovani na javni DNS** (`_PUBLIC_RESOLVERS`), nije sistemski resolver. To znači da Cloudflare/Google/Quad9 vide **svaki domen koji iko skenira**, uključujući besplatni tier bez verifikacije vlasništva.

### 2.2. Malware skener — FULL mod (+7 provera, samo posle verifikacije vlasništva)

| Primalac podataka | Šta se konkretno šalje | Kod |
|---|---|---|
| **abuse.ch — URLhaus (host endpoint)** | Ciljni domen (`POST data={"host": domain}`) — vraća **istoriju infekcija** | `full_checks/blacklist_history.py:32` |
| **Internet Archive (web.archive.org)** | Ciljni URL kroz CDX API + preuzimanje istorijskog snapshot-a. **Preko običnog HTTP-a, ne HTTPS** | `full_checks/wayback_analysis.py:33`, `full_checks/content_modification.py:41,42` |
| **crt.sh (Sectigo)** | Upit `%.<domen>` — svi CT sertifikati domena i poddomena | `full_checks/ssl_compromise.py:36` |
| **Spamhaus ZEN** | **IP adrese MX servera** ciljnog domena | `full_checks/email_reputation.py:45`, `config.py:54` |
| **SpamCop** | isto | `full_checks/email_reputation.py:46`, `config.py:56` |
| **Barracuda BRBL** | isto | `full_checks/email_reputation.py:47`, `config.py:55` |
| Javni DNS resolveri | MX / A / TXT / NS zapisi domena | `full_checks/reputation_score.py`, `email_reputation.py` |
| Ciljni sajt | `GET` robots.txt i sitemap.xml + **`HEAD` probe** na standardne backdoor putanje | `full_checks/index_contamination.py:16-19` |

### 2.3. Osnovni (240+) skener — treće strane koje takođe NISU u §7

Ovo je zaseban gap, zatečen usput:

| Primalac | Šta se šalje | Kod |
|---|---|---|
| **crt.sh (Sectigo)** | Ciljni domen | `checks/ct_check.py:18` |
| **Mozilla HTTP Observatory** | Ciljni domen (`POST host=<domen>`, uz `hidden=true` → rezultat se ne objavljuje javno na Observatory listi) | `checks/observatory_check.py:12,22` |
| **hstspreload.org (Google/Chromium)** | Ciljni domen | `checks/ssl_check.py:32` |
| **WHOIS registri** (Verisign, PIR, RNIDS, DENIC, Google Registry, Afilias, Nominet…) | Ciljni domen, preko sirovog TCP socket-a | `checks/whois_check.py:15-29,33-36` |
| Sistemski DNS resolver HF Spaces-a | DNS upiti | `checks/dns_check.py`, `checks/email_security_check.py`, `checks/subdomain_check.py` |

> **KOREKCIJA polazne pretpostavke:** u zadatku je navedeno da osnovni skener koristi „DNS RBL". **Ne koristi.** `grep -niE "rbl|dnsbl|spamhaus|barracuda|spamcop|surbl" checks/*.py` → 0 rezultata. RBL upiti postoje **isključivo** u `malware_scanner/`. Umesto RBL-a, osnovni skener otkriva `hstspreload.org` i WHOIS registre koji u polaznoj listi nisu bili.

### 2.4. Nove tabele — šta se upisuje

**`malware_scans`** (`migrations/020_malware_scans.sql:95-130`)

| Kolona | Sadržaj | PII? |
|---|---|---|
| `id`, `url`, `domain` | ID skena, ceo URL, normalizovan domen | — |
| `status`, `progress`, `step`, `error` | stanje skena | — |
| `scan_mode` | `safe` / `full` | — |
| `ip_hash` | SHA-256(IP + salt) | pseudonimizovano |
| `ua_hash` | SHA-256(UA + salt) | pseudonimizovano |
| `fingerprint_hash` | canvas/WebGL otisak iz browsera — **OBAVEZAN**, bez njega HTTP 403 (`api.py`, blok „Fingerprint required") | pseudonimizovano, ali **obavezno** |
| `credit_id` | FK na plaćeni paket | veza ka kupovini |
| `consent_accepted`, `consent_version` | dokaz pristanka | — |
| `result` (JSONB) | **kompletan nalaz** — sve provere + Damage Report + skor | osetljivo o cilju |
| `created_at`, `completed_at` | vremenski pečati | — |

**`malware_credits`** (`migrations/020_malware_scans.sql:41-80`, `migrations/022:88-90`)
`lemon_order_id`, `pack_kind`, `buyer_ip_hash`, `buyer_fingerprint`, `buyer_email`, `credits_total`, `credits_remaining`, `amount_usd`, `created_at`, `expires_at`, `subscription_id`.

**`license_activations`** (`migrations/023_license_activations.sql`)
`subscription_id`, `fingerprint`, **`user_agent` (SIROV, do 500 karaktera — `db.py:1711,1744`)**, `last_seen_at`, `created_at`.
Maks. **5 uređaja** po ključu (`db.py:1686`, provera u `api.py:3521-3532`).

**Retencija:** ⚠️ **NIJEDNA od tri tabele nema cron za brisanje.** `grep -i "malware\|license_activations" migrations/005_cron_jobs.sql` → 0. Migracije 020/022/023 ne dodaju nijedan `cron.schedule`. Podaci trenutno stoje **neograničeno**. Vidi §8, pitanje P1.

---

## 3. PREDLOG A — nova sekcija 16 u `privacy.html` (malware skener)

> **Stil:** postojeći `privacy.html` piše srpski **bez dijakritike** (ASCII latinica: „cuvamo", „azuriranje"). Predlog ispod prati taj stil da bi se uklopio. Sekcije su numerisane 1-15, pa je nova **16**, sa `id="pp16"` (SR) i `id="pp16e"` (EN) — `blog-common.js` gradi timeline iz `h2` elemenata, tako da će se sekcija automatski pojaviti u sadržaju.
>
> **Mesto za SR:** posle linije 251 (`</p>` na kraju §15), pre `</div>` na liniji 252.
> **Mesto za EN:** posle linije 470, pre `</div>` na liniji 471.

### 3.1. SR verzija

```html
    <h2 id="pp16">16. Malware skener — posebna obrada podataka</h2>
    <p>Od aprila 2026. nudimo <strong>Malware skener</strong> kao zaseban proizvod (stranica <a href="/malware.html">/malware.html</a>). To je odvojen tok obrade od osnovnog bezbednosnog skenera, sa sopstvenim tabelama, sopstvenim listama trecih strana i sopstvenim kvotama. Ova sekcija opisuje samo taj tok.</p>

    <p><strong>Dva moda:</strong></p>
    <ul>
      <li><strong>Brza provera (SAFE)</strong> — 11 provera, bez verifikacije vlasnistva, 1 besplatna provera na 24 sata po hash-u IP adrese</li>
      <li><strong>Puna provera (FULL)</strong> — dodatnih 7 provera plus Damage Report, iskljucivo posle uspesne verifikacije vlasnistva domena kroz wizard (isti postupak kao za puni sken osnovnog skenera — videti <a href="./terms.html#tos7">Uslove koriscenja, sekcija 7</a>)</li>
    </ul>

    <p><strong>Sta cuvamo u tabeli <code>malware_scans</code></strong> (jedan red po skeniranju):</p>
    <ul>
      <li><strong>URL i normalizovani domen</strong> koji ste zadali</li>
      <li><strong>Ceo rezultat provere</strong> (JSONB: svi nalazi, Damage Report, reputacioni skor)</li>
      <li><strong>Hash IP adrese</strong> i <strong>hash User-Agent stringa</strong> (SHA-256 sa server-side salt-om) — NE sirove vrednosti</li>
      <li><strong>Fingerprint hash</strong> (canvas/WebGL otisak pregledaca). <strong>Za malware skener ovaj otisak je obavezan</strong> — bez njega zahtev se odbija sa HTTP 403. Razlog je tehnicki: fingerprint je jedina odbrana protiv skripti i botova koji bi u suprotnom trosili besplatnu kvotu i pretvorili servis u masovni OSINT alat nad tudjim domenima. Ako ne zelite da se otisak pregledaca racuna, ne mozete koristiti Malware skener; osnovni skener i dalje radi</li>
      <li><strong>Mod skeniranja</strong> (safe / full), <strong>flag i verzija pristanka</strong>, <strong>vremenski pecati</strong></li>
      <li><strong>Veza ka plaćenom paketu</strong> (<code>credit_id</code>), ako je provera potrosila kredit</li>
    </ul>

    <p><strong>Sta cuvamo ako kupite paket</strong> (tabela <code>malware_credits</code>): ID porudzbine kod Lemon Squeezy-ja, vrstu paketa, hash IP adrese kupca, fingerprint kupca, email kupca, broj ukupnih i preostalih kredita, iznos u USD, i vremenske pecate. Email dolazi od Lemon Squeezy-ja i koristi se da vam se paket moze povezati sa license key-em i da mozete povratiti pristup ako izgubite kljuc.</p>

    <p><strong>Sta cuvamo o uredjajima</strong> (tabela <code>license_activations</code>): license key sme biti aktiviran na najvise <strong>5 uredjaja</strong>. Za svaki uredjaj cuvamo fingerprint pregledaca, vreme poslednjeg koriscenja, i <!-- ⚠️ VIDI §9-N1: uskladiti sa kodom pre objave --> podatke o pregledacu koje saljete u zahtevu. Aktivacije mozete pregledati i ukloniti na stranici <a href="./account.html">Moj nalog</a>.</p>

    <p><strong>Trece strane kojima se salje ciljni domen.</strong> Malware provera po prirodi posla znaci konsultovanje javnih baza reputacije. To znaci da <strong>domen koji skenirate saznaju i sledece organizacije</strong>, svaka pod svojom politikom privatnosti:</p>
    <ul>
      <li><strong>abuse.ch / URLhaus</strong> (Svajcarska) — saljemo ceo URL koji skenirate. Brza provera i puna provera.</li>
      <li><strong>Spamhaus (DBL, ZEN)</strong>, <strong>SURBL</strong>, <strong>Barracuda</strong>, <strong>SpamCop</strong> — saljemo domen (i, u punoj proveri, IP adrese vasih mail servera) kao DNS upit ka njihovim zonama.</li>
      <li><strong>Cloudflare (1.1.1.1)</strong>, <strong>Google (8.8.8.8)</strong>, <strong>Quad9 (9.9.9.9)</strong> — svi DNS upiti Malware skenera idu kroz ove javne resolvere, pa oni vide svaki domen koji se proverava.</li>
      <li><strong>Internet Archive (web.archive.org)</strong> (SAD) — samo u punoj proveri; saljemo URL da bismo uporedili danasnji sadrzaj sa arhiviranim snimkom.</li>
      <li><strong>crt.sh / Sectigo</strong> — samo u punoj proveri; saljemo domen radi pregleda Certificate Transparency logova.</li>
      <li><strong>OpenPhish</strong> — <em>ne saljemo im nista o vama ni o cilju</em>. Preuzimamo njihovu javnu listu i poredjenje radimo lokalno kod nas.</li>
    </ul>
    <p>Nijednoj od ovih organizacija ne saljemo vasu IP adresu, User-Agent, email, niti bilo koji podatak o vama licno — saljemo iskljucivo <strong>domen ili URL koji ste sami uneli u polje za skeniranje</strong>, sa naseg servera. Sa njihove strane, upit dolazi sa IP adrese naseg backend-a, ne sa vase.</p>

    <p><strong>Retencija:</strong> <!-- ⚠️ NEDOVRSENO — VIDI §8 PITANJE P1. Ne objavljivati dok se ne odluci rok I ne implementira cron. --></p>

    <p><strong>Pravni osnov:</strong> <!-- ⚠️ NEDOVRSENO — VIDI §8 PITANJE P2. --></p>
```

### 3.2. EN verzija

```html
    <h2 id="pp16e">16. Malware scanner — separate processing</h2>
    <p>Since April 2026 we offer a <strong>Malware scanner</strong> as a separate product (page <a href="/malware.html">/malware.html</a>). It is a distinct processing flow from the main security scanner, with its own tables, its own third-party recipients, and its own quotas. This section covers that flow only.</p>

    <p><strong>Two modes:</strong></p>
    <ul>
      <li><strong>Quick scan (SAFE)</strong> — 11 checks, no ownership verification, 1 free scan per 24 hours per IP hash</li>
      <li><strong>Full scan (FULL)</strong> — 7 additional checks plus a Damage Report, only after successful domain ownership verification through the wizard (same procedure as the main scanner's full scan — see <a href="./terms.html#tos7e">Terms of Service, section 7</a>)</li>
    </ul>

    <p><strong>What we store in the <code>malware_scans</code> table</strong> (one row per scan):</p>
    <ul>
      <li><strong>The URL and normalized domain</strong> you submitted</li>
      <li><strong>The full check result</strong> (JSONB: all findings, Damage Report, reputation score)</li>
      <li><strong>Hash of your IP address</strong> and <strong>hash of your User-Agent</strong> (SHA-256 with a server-side salt) — never the raw values</li>
      <li><strong>Fingerprint hash</strong> (canvas/WebGL browser fingerprint). <strong>For the Malware scanner this fingerprint is mandatory</strong> — without it the request is rejected with HTTP 403. The reason is technical: the fingerprint is the only defence against scripts and bots that would otherwise burn the free quota and turn the service into a mass OSINT tool against third-party domains. If you do not want a browser fingerprint computed, you cannot use the Malware scanner; the main scanner still works</li>
      <li><strong>Scan mode</strong> (safe / full), <strong>consent flag and consent version</strong>, <strong>timestamps</strong></li>
      <li><strong>Link to a paid pack</strong> (<code>credit_id</code>) if the scan consumed a credit</li>
    </ul>

    <p><strong>What we store if you buy a pack</strong> (<code>malware_credits</code> table): the Lemon Squeezy order ID, pack type, buyer IP hash, buyer fingerprint, buyer email, total and remaining credits, the USD amount, and timestamps. The email comes from Lemon Squeezy and is used to tie the pack to a license key so you can recover access if you lose the key.</p>

    <p><strong>What we store about devices</strong> (<code>license_activations</code> table): a license key may be activated on at most <strong>5 devices</strong>. For each device we store the browser fingerprint, the time it was last used, and <!-- ⚠️ SEE §9-N1: align with code before publishing --> the browser information sent with the request. You can review and remove activations on the <a href="./account.html">My account</a> page.</p>

    <p><strong>Third parties that learn the scanned domain.</strong> Malware checking inherently means consulting public reputation databases. That means the <strong>domain you scan is also disclosed to the following organizations</strong>, each under its own privacy policy:</p>
    <ul>
      <li><strong>abuse.ch / URLhaus</strong> (Switzerland) — we send the full URL you scan. Both quick and full scans.</li>
      <li><strong>Spamhaus (DBL, ZEN)</strong>, <strong>SURBL</strong>, <strong>Barracuda</strong>, <strong>SpamCop</strong> — we send the domain (and, in a full scan, the IP addresses of your mail servers) as DNS queries against their zones.</li>
      <li><strong>Cloudflare (1.1.1.1)</strong>, <strong>Google (8.8.8.8)</strong>, <strong>Quad9 (9.9.9.9)</strong> — all Malware scanner DNS queries go through these public resolvers, so they see every domain that gets checked.</li>
      <li><strong>Internet Archive (web.archive.org)</strong> (USA) — full scan only; we send the URL to compare today's content against an archived snapshot.</li>
      <li><strong>crt.sh / Sectigo</strong> — full scan only; we send the domain to review Certificate Transparency logs.</li>
      <li><strong>OpenPhish</strong> — <em>we send them nothing about you or the target</em>. We download their public list and match locally on our side.</li>
    </ul>
    <p>We send none of these organizations your IP address, User-Agent, email, or any data about you personally — we send only the <strong>domain or URL you typed into the scan field</strong>, from our server. From their perspective the query originates from our backend's IP, not yours.</p>

    <p><strong>Retention:</strong> <!-- ⚠️ INCOMPLETE — SEE §8 QUESTION P1. Do not publish until a period is decided AND a cron job implemented. --></p>

    <p><strong>Legal basis:</strong> <!-- ⚠️ INCOMPLETE — SEE §8 QUESTION P2. --></p>
```

---

## 4. PREDLOG B — ažurirana lista sub-procesora / trećih strana (`privacy.html` §7)

Postojeća lista (SR linije 121-129, EN 340-348) navodi 7 provajdera i tvrdi da je Lemon Squeezy **jedini** van EU. To više nije tačno. Predlog: **zadržati postojeću listu kao „Infrastruktura"** i **dodati drugu listu „Baze reputacije i javni servisi"**, jer to nisu sub-procesori u istom smislu (njima ne poveravamo lične podatke — šaljemo im domen cilja).

> **⚠️ Ovo razlikovanje („obrađivač" vs. „primalac") je pravno pitanje — vidi §8, P3.** Nemoj objaviti podelu bez potvrde pravnika.

### 4.1. Predlog za SR (zamena bloka `privacy.html:120-131`)

```html
    <p>Koristimo sledece servise trecih strana. Delimo ih u dve grupe jer se pravno bitno razlikuju.</p>
    <p><strong>A. Infrastruktura</strong> — provajderi koji obradjuju podatke u nase ime:</p>
    <ul>
      <li><strong>Supabase</strong> (EU region) — primarna PostgreSQL baza + Edge Functions + Vault</li>
      <li><strong>Cloudflare R2</strong> — offsite backup storage (enkriptovano)</li>
      <li><strong>Hugging Face Spaces</strong> — backend API hosting</li>
      <li><strong>Vercel</strong> — frontend hosting</li>
      <li><strong>Google AdSense</strong> — prikazivanje oglasa</li>
      <li><strong>Google Fonts</strong> — ucitavanje fontova</li>
      <li><strong>Lemon Squeezy</strong> (SAD, Merchant of Record) — obrada placanja za Pro pretplate i Malware pakete. Ako kupite Pro plan ili Malware paket, vasa kartica i personalni podaci za placanje se salju <strong>direktno Lemon Squeezy-ju</strong>, ne nama. Mi od njih primamo samo: email adresu, iznos, status pretplate/porudzbine, i license_key. Njihova politika privatnosti: <a href="https://www.lemonsqueezy.com/privacy" target="_blank" rel="noopener">lemonsqueezy.com/privacy</a></li>
    </ul>

    <p><strong>B. Javne baze reputacije i javni servisi</strong> — njima <strong>ne saljemo vase licne podatke</strong>; saljemo im iskljucivo <strong>domen ili URL koji ste sami uneli za skeniranje</strong>, sa IP adrese naseg servera:</p>
    <ul>
      <li><strong>abuse.ch — URLhaus</strong> (Svajcarska) — ceo skenirani URL &middot; <em>malware skener, brza i puna provera</em></li>
      <li><strong>Spamhaus</strong> (DBL i ZEN zone) — domen; u punoj proveri i IP adrese mail servera &middot; <em>malware skener</em></li>
      <li><strong>SURBL</strong> — domen &middot; <em>malware skener, brza provera</em></li>
      <li><strong>Barracuda Central</strong> — domen; u punoj proveri i IP mail servera &middot; <em>malware skener</em></li>
      <li><strong>SpamCop</strong> — IP adrese mail servera &middot; <em>malware skener, puna provera</em></li>
      <li><strong>Cloudflare DNS (1.1.1.1)</strong>, <strong>Google Public DNS (8.8.8.8)</strong>, <strong>Quad9 (9.9.9.9)</strong> — svi DNS upiti malware skenera, ukljucujuci gornje upite ka reputacionim zonama &middot; <em>malware skener</em></li>
      <li><strong>Internet Archive — Wayback Machine</strong> (SAD) — skenirani URL &middot; <em>malware skener, puna provera</em></li>
      <li><strong>crt.sh (Sectigo)</strong> — domen &middot; <em>malware skener (puna provera) i osnovni skener (Certificate Transparency provera)</em></li>
      <li><strong>Mozilla HTTP Observatory</strong> — domen, uz oznaku <code>hidden=true</code> tako da se rezultat ne objavljuje na javnoj Observatory listi &middot; <em>osnovni skener</em></li>
      <li><strong>hstspreload.org</strong> (Google/Chromium projekat) — domen &middot; <em>osnovni skener</em></li>
      <li><strong>WHOIS registri</strong> (Verisign, PIR, RNIDS, DENIC, Google Registry, Afilias, Nominet i drugi, zavisno od TLD-a) — domen &middot; <em>osnovni skener</em></li>
      <li><strong>OpenPhish</strong> — <strong>ne saljemo im nista</strong>; preuzimamo njihov javni feed i poredjenje radimo lokalno &middot; <em>malware skener</em></li>
    </ul>

    <p><strong>Napomena o prenosu podataka van EU:</strong> <!-- ⚠️ NEDOVRSENO — VIDI §8 PITANJE P4. Postojeca recenica "Lemon Squeezy je jedini provajder u nasem stack-u koji je van EU" VISE NIJE TACNA i mora se zameniti ili obrisati. --></p>
    <p><strong>Napomena o tome sta ovo znaci za vas:</strong> ako skenirate domen preko naseg servisa, taj domen postaje poznat gore navedenim organizacijama. Ako je to za vas neprihvatljivo — na primer ako je domen interni ili poverljiv — nemojte ga skenirati preko ovog servisa.</p>
```

### 4.2. EN verzija

```html
    <p>We use the following third-party services. We split them into two groups because they differ in a legally material way.</p>
    <p><strong>A. Infrastructure</strong> — providers that process data on our behalf:</p>
    <ul>
      <li><strong>Supabase</strong> (EU region) — primary PostgreSQL database + Edge Functions + Vault</li>
      <li><strong>Cloudflare R2</strong> — offsite backup storage (encrypted)</li>
      <li><strong>Hugging Face Spaces</strong> — backend API hosting</li>
      <li><strong>Vercel</strong> — frontend hosting</li>
      <li><strong>Google AdSense</strong> — ad display</li>
      <li><strong>Google Fonts</strong> — font loading</li>
      <li><strong>Lemon Squeezy</strong> (USA, Merchant of Record) — payment processing for Pro subscriptions and Malware packs. If you buy a Pro plan or a Malware pack, your card and personal payment information goes <strong>directly to Lemon Squeezy</strong>, not to us. From them we receive only: email address, amount, subscription/order status, and license_key. Their privacy policy: <a href="https://www.lemonsqueezy.com/privacy" target="_blank" rel="noopener">lemonsqueezy.com/privacy</a></li>
    </ul>

    <p><strong>B. Public reputation databases and public services</strong> — we send them <strong>none of your personal data</strong>; we send only the <strong>domain or URL you submitted for scanning</strong>, from our server's IP address:</p>
    <ul>
      <li><strong>abuse.ch — URLhaus</strong> (Switzerland) — the full scanned URL &middot; <em>malware scanner, quick and full</em></li>
      <li><strong>Spamhaus</strong> (DBL and ZEN zones) — the domain; in a full scan also mail server IPs &middot; <em>malware scanner</em></li>
      <li><strong>SURBL</strong> — the domain &middot; <em>malware scanner, quick scan</em></li>
      <li><strong>Barracuda Central</strong> — the domain; in a full scan also mail server IPs &middot; <em>malware scanner</em></li>
      <li><strong>SpamCop</strong> — mail server IPs &middot; <em>malware scanner, full scan</em></li>
      <li><strong>Cloudflare DNS (1.1.1.1)</strong>, <strong>Google Public DNS (8.8.8.8)</strong>, <strong>Quad9 (9.9.9.9)</strong> — all malware scanner DNS queries, including the reputation-zone lookups above &middot; <em>malware scanner</em></li>
      <li><strong>Internet Archive — Wayback Machine</strong> (USA) — the scanned URL &middot; <em>malware scanner, full scan</em></li>
      <li><strong>crt.sh (Sectigo)</strong> — the domain &middot; <em>malware scanner (full scan) and main scanner (Certificate Transparency check)</em></li>
      <li><strong>Mozilla HTTP Observatory</strong> — the domain, submitted with <code>hidden=true</code> so the result is not published on the public Observatory list &middot; <em>main scanner</em></li>
      <li><strong>hstspreload.org</strong> (Google/Chromium project) — the domain &middot; <em>main scanner</em></li>
      <li><strong>WHOIS registries</strong> (Verisign, PIR, RNIDS, DENIC, Google Registry, Afilias, Nominet and others depending on TLD) — the domain &middot; <em>main scanner</em></li>
      <li><strong>OpenPhish</strong> — <strong>we send them nothing</strong>; we download their public feed and match locally &middot; <em>malware scanner</em></li>
    </ul>

    <p><strong>Note on transfers outside the EU:</strong> <!-- ⚠️ INCOMPLETE — SEE §8 QUESTION P4. The existing sentence "Lemon Squeezy is the only provider in our stack outside the EU" IS NO LONGER TRUE and must be replaced or removed. --></p>
    <p><strong>What this means for you:</strong> if you scan a domain through our service, that domain becomes known to the organizations listed above. If that is unacceptable to you — for example if the domain is internal or confidential — do not scan it through this service.</p>
```

---

## 5. PREDLOG C — nova sekcija 16 u `terms.html` (malware skener kao plaćena usluga)

> Postojeće sekcije su 1-15. Nova je **16**, `id="tos16"` / `id="tos16e"`.
> **Mesto za SR:** posle linije 194, pre `</div>` na 195.
> **Mesto za EN:** posle linije 356, pre `</div>` na 357.

### 5.1. SR verzija

```html
    <h2 id="tos16">16. Malware skener (zaseban proizvod)</h2>
    <p><strong>Malware skener</strong> je odvojen proizvod od osnovnog bezbednosnog skenera, dostupan na stranici <a href="./malware.html">/malware.html</a>. Ne ulazi u Pro pretplatu i ne troši Pro kvotu — ima sopstveni model naplate.</p>

    <h3>16.1. Šta radi</h3>
    <p>Malware skener proverava da li je sajt <strong>kompromitovan</strong> — ubačen malver, phishing stranica, cryptojacking skripta, SEO spam, web shell, sumnjivi redirekti. Nudi dva moda:</p>
    <ul>
      <li><strong>Brza provera</strong> — 11 provera. Pasivne: čita se javno dostupan HTML početne strane i konsultuju se javne baze reputacije. Ne šalje se nijedan probe ka privatnoj infrastrukturi sajta.</li>
      <li><strong>Puna provera</strong> — 11 + 7 provera i <strong>Damage Report</strong> (procena štete, prioritetne akcije, procena vremena oporavka). Puna provera <strong>zahteva verifikaciju vlasništva domena</strong> kroz isti wizard opisan u sekciji 7.2, i uključuje <code>HEAD</code> probe ka standardnim backdoor putanjama na vašem sajtu. To je aktivno ispitivanje — pokrećete ga na sopstvenu pravnu odgovornost, isto kao i puni sken osnovnog skenera.</li>
    </ul>

    <h3>16.2. Besplatna kvota</h3>
    <p><strong>Jedna besplatna brza provera na 24 sata</strong>, po hash-u IP adrese i po fingerprint-u pregledača. Malware skener <strong>zahteva fingerprint pregledača</strong> — zahtevi bez njega (curl, skripte, automatizacija) se odbijaju sa HTTP 403. To je namerno: bez te mere besplatna kvota bi bila trivijalna za zloupotrebu.</p>

    <h3>16.3. Plaćeni paket</h3>
    <p><strong>Malware 5-Pack</strong> — jednokratna kupovina, <strong>$3 USD</strong>, daje <strong>5 punih provera</strong>. Nije pretplata i <strong>ne obnavlja se automatski</strong>.</p>
    <ul>
      <li><strong>Rok važenja kredita:</strong> <!-- ⚠️ NEDOVRŠENO — VIDI §8 PITANJE P5. Kod i marketing se NE SLAŽU (36500 dana vs. 30 dana vs. "nikad ne ističu"). Ne objavljivati dok se ne odluči i uskladi. --></li>
      <li><strong>License key:</strong> posle kupovine dobijate license key kojim se prijavljujete na stranici <a href="./account.html">Moj nalog</a> i vidite koliko vam je kredita ostalo. Ako kupite ponovo istim email-om, koristi se isti ključ i krediti se dodaju.</li>
      <li><strong>Ograničenje na 5 uređaja:</strong> jedan license key može biti aktivan na najviše <strong>5 uređaja</strong> istovremeno. Aktivirani uređaji se vide i mogu se ukloniti na stranici Moj nalog. Šesti uređaj biva odbijen dok ne uklonite jedan postojeći.</li>
      <li><strong>Merchant of Record:</strong> naplatu obrađuje Lemon Squeezy Inc., pod istim uslovima opisanim u sekciji 11.</li>
    </ul>

    <h3>16.4. Refundacija</h3>
    <p><!-- ⚠️ NEDOVRŠENO — VIDI §8 PITANJE P6. refund-policy.html trenutno pokriva SAMO mesečnu i godišnju pretplatu; jednokratna kupovina digitalnog sadržaja sa trenutnim izvršenjem ima drugačiji režim po EU pravu. --></p>

    <h3>16.5. Ograničenje odgovornosti specifično za malware proveru</h3>
    <p>Pored opšteg ograničenja iz sekcije 8, za Malware skener izričito važi:</p>
    <ul>
      <li><strong>Rezultat „čisto" NIJE garancija da sajt nije zaražen.</strong> Skener proverava javno vidljive tragove i javne baze reputacije. Malver koji je serverski (u PHP fajlovima, bazi, cron zadacima), uslovni malver koji se prikazuje samo određenim posetiocima, ili infekcija mlađa od ažuriranja javnih baza — neće biti otkriveni.</li>
      <li><strong>Rezultat „zaraženo" nije pravni ni forenzički nalaz.</strong> Javne baze reputacije imaju lažno pozitivne unose. Nalaz je indikacija koju treba proveriti, ne dokaz.</li>
      <li><strong>Damage Report je procena, ne merenje.</strong> Reputacioni skor, procena štete i procena vremena oporavka su heuristike izračunate iz nalaza; ne predstavljaju finansijsku, pravnu ni osiguravajuću procenu.</li>
      <li><strong>Ne uklanjamo malver.</strong> Servis samo detektuje i preporučuje. Sanacija je vaša odgovornost ili odgovornost vašeg izvođača.</li>
      <li><strong>Zavisnost od trećih strana.</strong> Provera se oslanja na spoljne baze (URLhaus, Spamhaus, SURBL, Barracuda, SpamCop, Internet Archive, crt.sh). Ako je neka od njih nedostupna, ta provera se preskače i to se u rezultatu jasno označava. Nedostupnost treće strane nije osnov za refundaciju kredita.</li>
    </ul>

    <h3>16.6. Podaci i treće strane</h3>
    <p>Malware provera po prirodi posla znači slanje domena koji skenirate javnim bazama reputacije, uključujući organizacije van EU. Pun spisak, šta se tačno kome šalje, i šta se čuva u našoj bazi — u <a href="./privacy.html#pp16">Politici privatnosti, sekcija 16</a>. <strong>Pokretanjem malware provere prihvatate to slanje.</strong></p>
```

### 5.2. EN verzija

```html
    <h2 id="tos16e">16. Malware scanner (separate product)</h2>
    <p>The <strong>Malware scanner</strong> is a separate product from the main security scanner, available at <a href="./malware.html">/malware.html</a>. It is not part of the Pro subscription and does not consume Pro quota — it has its own billing model.</p>

    <h3>16.1. What it does</h3>
    <p>The Malware scanner checks whether a site is <strong>compromised</strong> — injected malware, phishing pages, cryptojacking scripts, SEO spam, web shells, suspicious redirects. Two modes:</p>
    <ul>
      <li><strong>Quick scan</strong> — 11 checks. Passive: it reads the publicly available homepage HTML and consults public reputation databases. No probe is sent against the site's private infrastructure.</li>
      <li><strong>Full scan</strong> — 11 + 7 checks and a <strong>Damage Report</strong> (impact assessment, priority actions, estimated recovery time). The full scan <strong>requires domain ownership verification</strong> through the same wizard described in section 7.2, and includes <code>HEAD</code> probes against standard backdoor paths on your site. That is active probing — you run it under your own legal responsibility, exactly as with the main scanner's full scan.</li>
    </ul>

    <h3>16.2. Free quota</h3>
    <p><strong>One free quick scan per 24 hours</strong>, per IP hash and per browser fingerprint. The Malware scanner <strong>requires a browser fingerprint</strong> — requests without one (curl, scripts, automation) are rejected with HTTP 403. This is deliberate: without it the free quota would be trivial to abuse.</p>

    <h3>16.3. Paid pack</h3>
    <p><strong>Malware 5-Pack</strong> — one-time purchase, <strong>$3 USD</strong>, grants <strong>5 full scans</strong>. It is not a subscription and does <strong>not auto-renew</strong>.</p>
    <ul>
      <li><strong>Credit validity:</strong> <!-- ⚠️ INCOMPLETE — SEE §8 QUESTION P5. Code and marketing DISAGREE (36500 days vs 30 days vs "never expire"). Do not publish until decided and reconciled. --></li>
      <li><strong>License key:</strong> after purchase you receive a license key to sign in on the <a href="./account.html">My account</a> page and see your remaining credits. If you buy again with the same email, the same key is reused and credits are added.</li>
      <li><strong>5-device limit:</strong> one license key may be active on at most <strong>5 devices</strong> at a time. Activated devices are visible and removable on the My account page. A sixth device is rejected until you remove an existing one.</li>
      <li><strong>Merchant of Record:</strong> billing is handled by Lemon Squeezy Inc. under the same terms described in section 11.</li>
    </ul>

    <h3>16.4. Refunds</h3>
    <p><!-- ⚠️ INCOMPLETE — SEE §8 QUESTION P6. refund-policy.html currently covers ONLY monthly and yearly subscriptions; a one-time purchase of digital content with immediate performance has a different regime under EU law. --></p>

    <h3>16.5. Limitation of liability specific to malware checking</h3>
    <p>In addition to the general limitation in section 8, the following applies expressly to the Malware scanner:</p>
    <ul>
      <li><strong>A "clean" result is NOT a guarantee that the site is uninfected.</strong> The scanner checks publicly visible traces and public reputation databases. Server-side malware (in PHP files, the database, cron jobs), conditional malware shown only to certain visitors, or an infection newer than the public feeds — will not be detected.</li>
      <li><strong>An "infected" result is not a legal or forensic finding.</strong> Public reputation databases contain false positives. A finding is an indication to verify, not proof.</li>
      <li><strong>The Damage Report is an estimate, not a measurement.</strong> The reputation score, impact assessment, and estimated recovery time are heuristics computed from the findings; they are not a financial, legal, or insurance assessment.</li>
      <li><strong>We do not remove malware.</strong> The service only detects and recommends. Remediation is your responsibility or your contractor's.</li>
      <li><strong>Third-party dependency.</strong> The scan relies on external databases (URLhaus, Spamhaus, SURBL, Barracuda, SpamCop, Internet Archive, crt.sh). If one is unavailable, that check is skipped and clearly marked as such in the result. Third-party unavailability is not a basis for refunding a credit.</li>
    </ul>

    <h3>16.6. Data and third parties</h3>
    <p>Malware checking inherently means sending the domain you scan to public reputation databases, including organizations outside the EU. The full list, what exactly is sent to whom, and what we store in our database — see <a href="./privacy.html#pp16e">Privacy Policy, section 16</a>. <strong>By starting a malware scan you accept that disclosure.</strong></p>
```

---

## 6. PREDLOG D — dopune postojećih sekcija (obavezno uz A/B/C)

Nova sekcija bez ovih ispravki ostavlja **kontradikciju unutar istog dokumenta**.

| Fajl:linija | Postojeći tekst | Predlog | Zašto |
|---|---|---|---|
| `privacy.html:51` / `:270` | „Opcioni fingerprint_hash (canvas/WebGL fingerprint ako ga frontend proslijedi)" | dodati: „…; **za Malware skener je obavezan** — videti sekciju 16" | Za `/malware-scan` je 403 bez njega |
| `privacy.html:56` / `:275` | „…raw IP adrese, raw User-Agent stringove…" | **MORA se rešiti** — vidi §9-N1. Ili ispraviti kod, ili dodati izuzetak | Danas netačno zbog `license_activations.user_agent` |
| `privacy.html:88-96` / `:307-315` (§5 retencija) | lista tabela | dodati `malware_scans`, `malware_credits`, `license_activations` | Tri tabele nisu navedene |
| `privacy.html:103` / `:322` (§6 RLS) | „svaka tabela ima RLS uključen sa default-deny politikom" | **MORA se rešiti** — vidi §9-N2 | Danas netačno za `license_activations` |
| `privacy.html:130` / `:349` | „Lemon Squeezy je jedini provajder u našem stack-u koji je van EU" | zameniti — vidi §4.1, P4 | Danas netačno (abuse.ch, Spamhaus, SURBL, Barracuda, SpamCop, Archive, crt.sh, Cloudflare/Google/Quad9 DNS) |
| `privacy.html:131` / `:350` | „Svi ostali provajderi su odabrani tako da primarno čuvaju podatke u EU/EEA regionu" | isto | isto |
| `privacy.html:174` / `:393` (§11) | „NE koristi automatizovano odlučivanje" | proveriti — Damage Report daje reputacioni skor i procenu štete | Verovatno i dalje stoji (informativno), ali je **pitanje za pravnika**, §8-P7 |
| `terms.html:44-50` / `:206-212` (§2) | „Servis izvršava **pasivne** bezbednosne provere" | dodati napomenu da malware puna provera šalje `HEAD` probe | `full_checks/index_contamination.py:16-19` |
| `terms.html:141-147` / `:303-309` (§11) | lista Pro pogodnosti | dodati rečenicu „Malware skener nije uključen u Pro — vidi sekciju 16" | Odvojen proizvod, odvojena naplata |
| `privacy.html` §14 / `terms.html` subtitle | istorija verzija | dodati red za `2026-08-09-v5` — vidi §7 korak 9 | Procedura iz `VERSION.md` |
| `refund-policy.html` | nema pomena jednokratne kupovine | dodati sekciju — §8-P6 | `grep -ci malware refund-policy.html` → 0 |

---

## 7. Checklist za bump verzije `2026-04-13-v4` → `2026-08-09-v5`

Izvedeno iz `VERSION.md` §26-73, **provereno grep-om na dan 2026-08-09**.

> ⚠️ **`api.py` se AKTIVNO MENJA dok ovo pišem** (mtime `2026-08-09 14:36`, `git status` → ` M api.py`). Njegov broj linije će se pomeriti. Za `api.py` **koristi grep anchor, ne broj linije.** Svi ostali fajlovi su netaknuti od aprila i brojevi linija važe.

### 7.1. Tačne lokacije

| # | Fajl:linija | Trenutni sadržaj | Napomena |
|---|---|---|---|
| 1 | `api.py:2073` ⚠️ | `consent_version="2026-04-13-v4",` | **Anchor:** `grep -n '2026-04-13-v4' api.py`. Jedino mesto sa hardkodovanom verzijom u backend-u |
| 2 | `index.html:3040` | `consent_version: "2026-04-13-v4",` | `startScan()` payload |
| 3 | `index.html:1808` | `…(<a href="./privacy.html#pp14" …>verzija 2026-04-13-v4</a>)` | SR tekst consent checkbox-a |
| 4 | `index.html:1809` | `…(<a href="./privacy.html#pp14e" …>version 2026-04-13-v4</a>)` | EN tekst consent checkbox-a |
| 5 | `privacy.html:38` | `Verzija <strong>2026-04-13-v4</strong> · Poslednje azuriranje: 13. april 2026. · <em>v4: …</em>` | SR subtitle + opis izmene |
| 6 | `privacy.html:162` | `Trenutna verzija politike: <code>2026-04-13-v4</code>` | SR §10 |
| 7 | `privacy.html:198` | `<code …>2026-04-13-v4</code>` + badge `AKTIVNA` | SR §14 — postaje „zamenjeno v5" |
| 8 | `privacy.html:257` | `Version <strong>2026-04-13-v4</strong> · Last updated: April 13, 2026 · <em>v4: …</em>` | EN subtitle |
| 9 | `privacy.html:381` | `Current policy version: <code>2026-04-13-v4</code>` | EN §10 |
| 10 | `privacy.html:417` | `<code …>2026-04-13-v4</code>` + badge `ACTIVE` | EN §14 — postaje „replaced by v5" |
| 11 | `terms.html:38` | `Verzija 2026-04-13-v4 · Poslednje azuriranje: 13. april 2026. · <em>v4: …</em>` | SR subtitle |
| 12 | `terms.html:200` | `Version 2026-04-13-v4 · Last updated: April 13, 2026 · <em>v4: …</em>` | EN subtitle |
| 13 | `refund-policy.html:38` | `Verzija 2026-04-13-v4 · Poslednje azuriranje: 13. april 2026.` | SR subtitle |
| 14 | `refund-policy.html:130` | `Version 2026-04-13-v4 · Last updated: April 13, 2026` | EN subtitle |
| 15 | `user-rights.html:38` | `Verzija 2026-04-13-v4 · …` | SR subtitle |
| 16 | `user-rights.html:135` | `Version 2026-04-13-v4 · …` | EN subtitle |
| 17 | `abuse-report.html:197` | `Verzija 2026-04-13-v4 · …` | SR subtitle |
| 18 | `abuse-report.html:276` | `Version 2026-04-13-v4 · …` | EN subtitle |
| 19 | `blog-common.js:5` | `Version: 2026-04-13-v4 (public gallery opt-in — section 15 in privacy)` | header komentar fajla |
| 20 | `blog-common.js:212` | `verBadge.textContent = 'v4';` | **`'v4'` → `'v5'`** |
| 21 | `blog-common.js:213` | `verBadge.title = '2026-04-13-v4';` | hover tooltip |
| 22 | `VERSION.md:3` | `> **Trenutna verzija: \`2026-04-13-v4\`**` | |
| 23 | `VERSION.md:78` | red u tabeli „Istorija verzija" | dodati novi red **iznad** |

### 7.2. Lokacije koje `VERSION.md` NE navodi (propust u samoj proceduri)

| # | Fajl:linija | Sadržaj | Problem |
|---|---|---|---|
| 24 | **`malware.js:136`** | `consent_version: 'v1',` | 🔴 **Ne odgovara nijednoj verziji akata.** Format je `YYYY-MM-DD-vN`. Svi malware skenovi od aprila imaju pravno bezvredan zapis pristanka. Mora `'2026-08-09-v5'` |
| 25 | `VERSION.md:31,36,39-42,47,50,53,56,60,63` | sami primeri u proceduri | tekstualni primeri, ažurirati radi konzistentnosti |
| 26 | `VERSION.md` §26-63 | spisak lokacija | 🔴 **`malware.js` nije na spisku.** Dodati kao „### 7. Malware frontend (malware.js)" |
| 27 | `malware.html:650-656` | consent checkbox | 🔴 **Nema link ka `terms.html` / `privacy.html` ni oznaku verzije** — za razliku od `index.html:1808-1809`. Dodati po istom obrascu |
| 28 | `api.py` (malware wizard `/execute`) | `malware_scanner.scan_malware(url, mode="full")` | Wizard-ov puni malware sken **ne upisuje red u `malware_scans`** i ne beleži `consent_version`. Vidi §9-N5 |

### 7.3. Redosled koraka

1. Odluči odgovore na sva pitanja iz §8 (**bez toga se ne kreće**).
2. Reši §9-N1 i §9-N2 (kod ili tekst) — inače nova verzija objavljuje netačne tvrdnje.
3. Primeni PREDLOG A (privacy §16 SR+EN) uz popunjena polja retencije i pravnog osnova.
4. Primeni PREDLOG B (privacy §7 SR+EN).
5. Primeni PREDLOG C (terms §16 SR+EN) uz popunjena polja roka važenja i refundacije.
6. Primeni PREDLOG D (ispravke postojećih kontradikcija).
7. Ažuriraj `refund-policy.html` (§8-P6).
8. Zameni verziju na **svih 28 lokacija** iz §7.1 + §7.2.
9. `privacy.html` §14: dodaj **novi blok** iznad postojećeg (SR posle linije 195 `<div style="display:flex…">`, EN posle 414), sa badge-om `AKTIVNA`/`ACTIVE`, datumom „9. avgust 2026." / „August 9, 2026", i opisom: „Malware skener — nova sekcija 16 (obrada podataka, obavezni fingerprint, retencija), prosirena lista trecih strana (sekcija 7), uslovi za placeni Malware paket." Postojeći v4 blok: badge `AKTIVNA` → tekst `zamenjeno v5` i uklanjanje zelene pozadine (kopiraj stil v3 bloka sa linije 204/423).
10. `VERSION.md`: novi red u tabeli + `malware.js` na spisak lokacija.
11. Provera: `grep -rn "2026-04-13-v4" --include=*.py --include=*.html --include=*.js --include=*.md .` mora vratiti **samo** redove istorije verzija.
12. Provera: `grep -n "consent_version" malware.js` mora vratiti `'2026-08-09-v5'`.
13. **Commit/push/deploy — samo na tvoj eksplicitan nalog.** Ovaj draft ništa ne pušta u produkciju.

---

## 8. ⚖️ PRAVNA PITANJA — ovde ja NE MOGU da odgovorim, treba pravnik

Ova pitanja su namerno ostavljena kao `<!-- NEDOVRŠENO -->` u predlozima iznad. Nisam pravnik i odgovor na njih nije tehnička činjenica nego pravna odluka.

### P1 — Retencija (RETENCIJA) 🔴 blokira objavu
Tri nove tabele **nemaju nikakav rok čuvanja ni cron za brisanje**. Podaci stoje neograničeno.
Odluke koje neko sa pravnim znanjem mora doneti:
- Koliko se čuva `malware_scans`? (`result` JSONB sadrži kompletnu mapu ranjivosti tuđeg sajta — to je osetljiv sadržaj i po sebi, nezavisno od GDPR-a.)
- `malware_credits` sadrži `buyer_email` i `amount_usd` → verovatno pada pod istu **10-godišnju poresko-računovodstvenu obavezu** koja je već navedena za `subscriptions` (`privacy.html:60`). Potvrditi.
- `license_activations` — koliko se čuva aktivacija uređaja posle isteka/potrošnje paketa?
- Da li rok mora biti **implementiran** (pg_cron) pre nego što se objavi u politici? Objaviti rok koji tehnički ne postoji = netačna izjava rukovaoca.

### P2 — Pravni osnov (PRAVNI OSNOV) 🔴 blokira objavu
- Koji je osnov za obradu u malware toku: **saglasnost** (čl. 12 st. 1 tač. 1 ZZPL / GDPR 6(1)(a)), **izvršenje ugovora** (za plaćeni paket), ili **legitimni interes** (za rate limiting i anti-abuse)? Verovatno kombinacija — ko šta pokriva?
- **Fingerprint pregledača je obavezan.** Canvas/WebGL fingerprinting se pod ePrivacy direktivom tretira slično kolačiću (pristup informacijama na terminalnoj opremi). Ako je pravni osnov saglasnost, a servis ne radi bez fingerprint-a, da li je ta saglasnost **slobodno data** u smislu GDPR 7(4)? Ovo je ozbiljno pitanje, ne formalnost.
- Fingerprint se trenutno računa **pre** bilo kakve saglasnosti (`malware.js:14-66`, poziva se pri učitavanju). Da li to samo po sebi zahteva prethodnu saglasnost?

### P3 — Kvalifikacija trećih strana
Da li su abuse.ch, Spamhaus, SURBL, Barracuda, SpamCop, Internet Archive, crt.sh i javni DNS resolveri:
- **obrađivači** (sub-procesori, treba im ugovor po čl. 28 GDPR / čl. 45 ZZPL), ili
- **samostalni rukovaoci / primaoci** kojima se prosleđuje podatak, ili
- **uopšte ne obrađuju lične podatke** jer se šalje samo domen?

Moj argument u §4 je da domen sam po sebi nije lični podatak korisnika koji skenira. **Ali:** ako korisnik skenira sopstveni domen (a to je primarni use-case, ToS to i traži!), onda je „koji domen je skeniran" praktično podatak **o tom korisniku**. To ruši argument. **Treba pravnik.**

### P4 — Prenos van EU
Postojeća rečenica „Lemon Squeezy je jedini provajder van EU" **je danas netačna**. Šta je zamenjuje?
- Da li je potrebna procena adekvatnosti / SCC za svaki od novih primalaca?
- Švajcarska ima adequacy decision; SAD (Barracuda, SpamCop, SURBL, Internet Archive, Google DNS) nemaju automatski — Data Privacy Framework važi samo za sertifikovane subjekte.
- Realno: ne možeš sklopiti SCC sa Spamhaus-om preko besplatnog DNS upita. Verovatno je pravilan pristup transparentnost + jasno upozorenje korisniku, ne fikcija ugovora. **Potvrditi sa pravnikom.**

### P5 — Rok važenja plaćenih kredita 🔴 tri različite tvrdnje u produkciji
| Izvor | Tvrdnja |
|---|---|
| `malware_scanner/config.py:136-137` | `PAID_PACK_VALIDITY_DAYS = 30` |
| `subscription.py:440-441` | `{"credits": 5, "days": 36500}` (~100 godina = praktično nikad) |
| `pricing.html:355,362` | „5 skenova · ne istice" / „Krediti nikad ne isticu" |
| `api.py` (429 poruka) | „Plaćeni paket: 5 skeniranja za $3, **važi 30 dana**" |

**Kod koji se stvarno izvršava pri kupovini je `subscription.py` → 36500 dana.** Znači kupac plaća, dobija „nikad ne ističe", ali mu servis u error poruci kaže „30 dana", a `config.py` konstanta kaže 30. **Odluka je poslovna + pravna** (obećanje kupcu je obavezujuće), i mora se **prvo uskladiti u kodu**, pa tek onda upisati u ToS.

### P6 — Refundacija jednokratne digitalne kupovine
`refund-policy.html` pominje **samo** mesečnu i godišnju pretplatu (`grep -ci malware refund-policy.html` → 0). Malware 5-Pack je jednokratna kupovina digitalne usluge sa trenutnim izvršenjem.
- EU Consumer Rights Directive: pravo na odustanak od 14 dana, **osim** ako potrošač izričito pristane na trenutno izvršenje i potvrdi da time gubi pravo na odustanak. Da li checkout to hvata?
- Šta ako je od 5 kredita potrošen 1? Delimična refundacija?
- ToS §16.4 i `refund-policy.html` moraju reći **isto**.

### P7 — Automatizovano odlučivanje
`privacy.html` §11 tvrdi da servis ne koristi automatizovano odlučivanje. Malware skener proizvodi **Damage Report**: nivo štete, reputacioni skor 0-100, ocena A-F, „procena vremena oporavka", „pogođene oblasti".
Moja procena: i dalje informativno, ne proizvodi pravno dejstvo po korisnika → §11 verovatno ostaje. **Ali ako se rezultat ikad koristi kao ulaz za nečiju odluku** (npr. hosting provajder gasi sajt na osnovu našeg izveštaja), slika se menja. **Pitanje za pravnika.**

### P8 — Odgovornost za lažno pozitivan nalaz
Ako naš izveštaj kaže da je tuđi sajt zaražen (na osnovu lažno pozitivnog unosa u Spamhaus/URLhaus), a korisnik to prosledi klijentu ili objavi — koja je naša izloženost? Predlog teksta u §5.1 (16.5) pokušava da to pokrije, ali **formulaciju mora potvrditi pravnik**, posebno u odnosu na srpski Zakon o obligacionim odnosima i eventualnu odgovornost za štetu ugledu trećeg lica.

### P9 — Jurisdikcija
`terms.html:138` / `:300`: sporovi po pravu Republike Srbije. Da li to ostaje za **plaćeni** proizvod prodat EU potrošačima preko Merchant of Record-a u Delaware-u? Brussels I bis obično daje potrošaču pravo na sud u sopstvenoj državi bez obzira na klauzulu. Treba proveriti da li klauzula uopšte drži i da li je treba preformulisati.

---

## 9. 🔧 NALAZI U KODU koji uslovljavaju pravni tekst (prijava, NISU ispravljeni)

Po pravilu „vladaš samo svojim fajlom" — **ništa od ovoga nisam dirao.** Prijavljujem.

### N1 🔴 `license_activations.user_agent` čuva SIROV User-Agent
- `migrations/023_license_activations.sql:6` — kolona `user_agent TEXT`
- `db.py:1711` i `db.py:1744` — upisuje se `user_agent[:500]`, **bez hashovanja**, dok se svuda drugde koristi `db.hash_ua()`
- **Direktno protivreči** `privacy.html:56` („Ono što NE čuvamo: … raw User-Agent stringove") i `privacy.html:275` (EN)
- **Izbor:** (a) hashovati u kodu → tekst ostaje tačan, ili (b) priznati izuzetak u §2. Opcija (a) je i tehnički trivijalna i pravno čistija.

### N2 🔴 `license_activations` nema RLS
- `migrations/023_license_activations.sql` — nema `ALTER TABLE … ENABLE ROW LEVEL SECURITY`, nema `REVOKE`, nema deny politika. Jedina tabela u šemi bez toga (uporedi `020_malware_scans.sql:155-170`)
- **Protivreči** `privacy.html:103` / `:322` („svaka tabela ima RLS uključen sa default-deny politikom")
- Potrebna nova migracija (npr. `024_license_activations_rls.sql`). **Nisam je napravio** — nije moj fajl.

### N3 🔴 `malware.js:136` šalje `consent_version: 'v1'`
Ne odgovara nijednoj objavljenoj verziji akata i ne poštuje format `YYYY-MM-DD-vN`. Svi malware skenovi od aprila imaju zapis pristanka koji **ne može da posluži kao dokaz** — a `terms.html:75` se izričito poziva na te zapise kao dokaz u sporu.

### N4 🟠 `malware.html:650-656` — consent bez linkova
Checkbox kaže „Potvrđujem da sam vlasnik sajta ili imam pismenu dozvolu vlasnika za skeniranje." — **bez linka** na ToS/Privacy i **bez oznake verzije**. `index.html:1808-1809` to ima. Footer (koji `blog-common.js:345-355` ubacuje) ima linkove, ali to nije isto što i informisani pristanak na mestu radnje.

### N5 🟠 Malware wizard `/execute` ne persistuje sken
U `api.py`, grana `if scan_kind == "malware":` poziva `malware_scanner.scan_malware(url, mode="full")` i vraća rezultat, ali **ne upisuje red u `malware_scans`** i ne beleži `consent_version`. Postoje samo `audit_log` zapisi. Rezultat: puni malware skenovi kroz wizard nemaju trag u tabeli koju politika (i ovaj draft) opisuje.

### N6 🟠 Wayback pozivi idu preko čistog HTTP-a
`full_checks/wayback_analysis.py:33` i `content_modification.py:41,42` koriste `http://web.archive.org/…` (ne HTTPS). Ciljni URL korisnika putuje **nešifrovano** — vidi ga svaki posrednik na putanji, ne samo Internet Archive. Ako se u politici tvrdi „svi podaci se prenose kroz HTTPS" (`privacy.html:101` / `:320`), **i ta tvrdnja je danas netačna** za odlazni saobraćaj.

### N7 🟠 „Isti license key za sve uređaje" vs. limit od 5
`pricing.html:362` obećava „Isti license key za sve uredjaje" / „Same license key for all devices", a `db.py:1686` (`MAX_DEVICES_PER_LICENSE = 5`) i `api.py:3521-3532` odbijaju šesti uređaj. Marketinško obećanje koje proizvod ne ispunjava — kod plaćenog proizvoda to je materijalna tvrdnja, ne sitnica.

### N8 🟡 `PAID_PACK_VALIDITY_DAYS` je mrtva konstanta
`malware_scanner/config.py:137` kaže 30 dana; `subscription.py:441` koristi 36500. Konstanta ne utiče ni na šta osim što obmanjuje čitaoca koda. Vidi §8-P5.

### N9 🟡 Korekcija polazne pretpostavke
U zadatku je navedeno da osnovni skener koristi „DNS RBL". **Ne koristi** — RBL postoji samo u `malware_scanner/`. Umesto toga, osnovni skener ima dve treće strane koje u polaznoj listi nisu bile: **`hstspreload.org`** (`checks/ssl_check.py:32`) i **WHOIS registri** (`checks/whois_check.py:15-29`). Obe su uključene u PREDLOG B.

### N10 ⚠️ `api.py` se menja u paraleli
`mtime` = `2026-08-09 14:36`, `git status` → ` M api.py` (uz `malware.html`, `malware_scanner/main.py`, `pricing.html`, `README.md`, `CHANGELOG.md`, `ARCHITECTURE.md`, `Dockerfile`, `LEMON-SQUEEZY-SETUP.md`, `.gitignore`). Brojevi linija za `api.py` u §7.1 su tačni **u trenutku pisanja** i treba ih pre primene ponovo proveriti grep-om. Ostali fajlovi (`privacy.html`, `terms.html`, `index.html`, `blog-common.js`, `malware.js`, `VERSION.md`) su netaknuti od aprila.

---

## 10. Šta NIJE dirano i zašto

| Fajl | Status | Razlog |
|---|---|---|
| `privacy.html` | **netaknut** | Pravno obavezujući dokument. Eksplicitna zabrana u zadatku. Predlog je u §3, §4, §6 |
| `terms.html` | **netaknut** | isto. Predlog u §5, §6 |
| `refund-policy.html`, `user-rights.html`, `abuse-report.html` | netaknuti | Pravni akti. Potrebne im izmene su samo popisane u §6/§7 |
| `api.py`, `db.py`, `malware.js`, `malware.html`, `blog-common.js`, `index.html` | netaknuti | Nisu moj fajl. Nalazi N1-N8 su prijavljeni, ne popravljeni |
| `migrations/*` | netaknute | Migracija za RLS (N2) je potrebna ali je nisam napravio |
| `VERSION.md` | netaknut | Bump nije izvršen; checklist je u §7 |
| `.env` | **nije čitan** | Zabranjeno. Za env varijable korišćena su samo imena iz koda (`PII_HASH_SALT`, `LEMON_BUY_URL_MALWARE_5_PACK`, `PHISHTANK_API_KEY`) |
| Git | **ništa** | Bez `commit`, `push`, `merge`, deploy-a |

---

**Kraj drafta.** Sledeći korak je tvoj: odgovori na §8 (ili ih prosledi pravniku), odluči N1/N2/N3, pa tek onda primena §3-§7.
