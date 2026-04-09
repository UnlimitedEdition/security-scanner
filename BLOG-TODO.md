# Blog Stranice — TODO Lista sa Specifikacijama

## STANJE PROJEKTA (ažurirano 9. april 2026.)
- ✅ blog-common.css + blog-common.js — globalni header, footer, timeline
- ✅ index.html — header/footer iz blog-common, result tabs ispod skenera
- ✅ 8/8 SECURITY clanaka + hub stranica + timeline fix (EN h2 id-jevi)
- ✅ 7/7 SEO clanaka + hub stranica (meta, schema, sitemap, local, opengraph, headings, mobile)
- ✅ 0/6 PERFORMANCE clanaka + hub stranica gotova (clanci preostali)
- ✅ 0/5 GDPR clanaka + hub stranica gotova (clanci preostali)
- ✅ privacy.html
- ❌ 11 novih blog clanaka preostalo (6 Perf + 5 GDPR)
- ✅ sitemap.xml (31 URL-ova, buduci clanci ukljuceni)
- ✅ api.py (blog-common.css/js rute + wildcard + GZip + /index.html ruta)
- ✅ scanner.py fix: SSL retry verify=False, bot detection false-positive fix, Vercel challenge retry
- ✅ GDPR check fix: fundingchoicesmessages detekcija, privacy.html pattern
- ✅ index.html fix: h3→h2, static footer, semantic tags, ARIA, 110+ count
- ❌ PAID MULTI-PAGE SCANNING SYSTEM (nova faza — detalji ispod)
- ❌ deploy Vercel radi ali challenge blokira — 3 IP-a allowovana u firewall

---

## PAID MULTI-PAGE SCANNING — PLAN IMPLEMENTACIJE

### Koncept
Crawler vec pronalazi do 20 stranica. Free korisnik dobija SAMO homepage analizu.
Crawled stranice se prikazuju kao teaser → "Zelite analizu svih XX stranica? Izaberite paket."

### Paketi (jednokratno placanje)
- 5 stranica — starter
- 10 stranica — popular
- 30 stranica — pro
- 50 stranica — enterprise

### Queue sistem (round-robin)
4 korisnika sa 50 stranica: a1,b1,c1,d1,a2,b2,c2,d2...
Niko ne ceka da drugi zavrsi. Progresivni rezultati.

### Boost opcija
- Parallel obrada (3-5 concurrent) = brze ali skuplje
- Prepaid krediti: 10/100/1000 zahteva unapred

### Rate limit
- Free: 2 skeniranja / 2 sata (smanjiti sa trenutnih 5/30min)
- Paid: bez limita dok traje paket

### Faze implementacije
1. Smanjiti free rate limit + crawler teaser (prikaži listu stranica)
2. Stripe payment integration
3. Multipage scan backend (POST /scan/multipage, round-robin queue)
4. Frontend: paketi, progress, rezultati po stranici
5. Boost opcija + prepaid krediti
6. Agregatni izvestaj ("15/30 stranica ima SEO probleme")

### Tech stack za paid
- Payment: Stripe Checkout
- Database: Supabase (ili SQLite za pocetak)
- Queue: Python asyncio queue sa round-robin
- Auth: payment token (ne zahteva registraciju — plati i koristi)

## PRAVILA ZA SVAKI FAJL:
- Minimum 300 linija, idealno 400-700
- SR + EN jezici sa toggle-om
- Schema.org: Article + FAQPage (3-5 pitanja)
- OG + Twitter meta tagovi
- Canonical URL + hreflang sr/en
- Table of Contents na pocetku
- Stat cards (3-4 statistike)
- Code primeri gde je relevantno
- Callout boksovi za vazne informacije
- Tabele za poredjenja
- Reference sa linkovima (OWASP, MDN, RFC)
- Internal linkovi na ostale blog stranice
- CTA dugme "Skeniraj svoj sajt"
- Dark tema (#0a0c15 bg, #6c63ff accent)
- Inter font, isti CSS kao ostale blog stranice

---

## HUB STRANICE — ✅ SVE GOTOVO
- blog-security.html ✅ (337 linija, 8 kartica pod-clanaka, FAQPage, stat cards)
- blog-seo.html ✅ (343 linije, 7 kartica pod-clanaka, FAQPage, stat cards)
- blog-performance.html ✅ (267 linija, 6 kartica pod-clanaka, FAQPage, stat cards)
- blog-gdpr.html ✅ (242 linije, 5 kartica pod-clanaka, FAQPage, stat cards)
- privacy.html ✅ (header/footer/timeline)

---

## SECURITY (8 fajlova) — ✅ SVE GOTOVO

### 1. blog-security-ssl.html ✅ (725 linija, header/footer/timeline)
### 2. blog-security-headers.html ✅ (724 linije, header/footer/timeline)
### 3. blog-security-xss.html ✅ (~585 linija, header/footer/timeline)
### 4. blog-security-sql.html ✅ (~860 linija, header/footer/timeline)
### 5. blog-security-csrf.html ✅ (~575 linija, header/footer/timeline)
### 6. blog-security-dns.html ✅ (~520 linija, header/footer/timeline)
### 7. blog-security-ports.html ✅ (~615 linija, header/footer/timeline)
### 8. blog-security-api.html ✅ (~670 linija, header/footer/timeline)

---

## SEO (7 fajlova) — ✅ SVE GOTOVO

### 9. blog-seo-meta.html ✅ (528 linija)
### 10. blog-seo-schema.html ✅ (585 linija)
### 11. blog-seo-sitemap.html ✅ (521 linija)
### 12. blog-seo-local.html ✅ (480 linija)
### 13. blog-seo-opengraph.html ✅ (447 linija)
### 14. blog-seo-headings.html ✅ (451 linija)
### 15. blog-seo-mobile.html ✅ (429 linija)

---

## PERFORMANCE (6 fajlova)

### 16. blog-perf-cwv.html
**Title:** "Core Web Vitals — LCP, CLS, INP vodic | Web Security Scanner"
**Keywords:** Core Web Vitals, LCP, CLS, INP, FID, Google ranking, page speed
**Sadrzaj MORA da sadrzi:**
- Sta su Core Web Vitals (Google, maj 2020)
- 3 metrike detaljno:
  - LCP (Largest Contentful Paint): sta meri, dobar <2.5s, los >4s, kako optimizovati
  - CLS (Cumulative Layout Shift): sta meri, dobar <0.1, los >0.25, uzroci i resenja
  - INP (Interaction to Next Paint): zamenio FID u martu 2024, sta meri, dobar <200ms
- Kako Core Web Vitals uticu na Google ranking (Page Experience Update)
- Alati za merenje: PageSpeed Insights, Chrome DevTools, Search Console, web-vitals.js
- Field data vs Lab data razlika
- Optimizacija za svaku metriku (konkretni koraci)
- Statistike: Sajtovi koji prodje CWV imaju 24% manje napustanja
- Reference: web.dev/vitals, Google Search Central, Chrome UX Report
- FAQPage: "Sta su Core Web Vitals?", "Da li uticu na rangiranje?", "Koji je najvazniji?"

### 17. blog-perf-images.html
**Title:** "Optimizacija slika za web — Formati, kompresija, lazy loading | Web Security Scanner"
**Keywords:** optimizacija slika, WebP, AVIF, lazy loading, kompresija, srcset
**Sadrzaj MORA da sadrzi:**
- Zasto su slike najveci problem za performanse (prosecno 50% tezine stranice)
- Formati: JPEG, PNG, WebP, AVIF — poredjenje kvaliteta i velicine
- Kompresija: lossy vs lossless, optimalni kvalitet (80% JPEG)
- Responsive images: srcset i sizes atributi (sa primerom)
- Art direction: <picture> element
- Lazy loading: loading="lazy" atribut, Intersection Observer
- Width i height atributi (sprecavaju CLS)
- CDN za slike: Cloudinary, imgix, Cloudflare Images
- Alati: Squoosh, TinyPNG, ImageOptim
- Statistike: WebP je 25-35% manji od JPEG pri istom kvalitetu
- Reference: web.dev Image Optimization, MDN <picture> docs
- FAQPage: "Koji format koristiti?", "Sta je lazy loading?", "Kako smanjiti slike bez gubitka kvaliteta?"

### 18. blog-perf-cache.html
**Title:** "HTTP Caching — Cache-Control, ETag, CDN vodic | Web Security Scanner"
**Keywords:** cache, Cache-Control, ETag, CDN, browser cache, HTTP caching
**Sadrzaj MORA da sadrzi:**
- Sta je HTTP caching i zasto je bitan
- Cache-Control header:
  - max-age, s-maxage, no-cache, no-store, public, private
  - Primeri za razlicite tipove resursa (HTML, CSS, JS, slike)
- ETag: sta je, kako radi, weak vs strong
- Last-Modified / If-Modified-Since
- Cache-busting strategije: hash u filename-u, query string
- Browser cache vs CDN cache vs Server cache
- Service Worker cache (offline podrska)
- CDN objasnjenje: Cloudflare, AWS CloudFront, Vercel Edge
- Cache invalidation — "najtezi problem u CS"
- Statistike: Pravilno kesirani sajt se ucitava 5-10x brze za ponovne posete
- Reference: MDN HTTP Caching, web.dev Caching guide, RFC 7234
- FAQPage: "Sta je Cache-Control?", "Koliko dugo kesirati?", "Sta je CDN?"

### 19. blog-perf-compression.html
**Title:** "Gzip i Brotli kompresija — Kako smanjiti velicinu sajta | Web Security Scanner"
**Keywords:** Gzip, Brotli, kompresija, Content-Encoding, transfer size
**Sadrzaj MORA da sadrzi:**
- Sta je HTTP kompresija i kako radi (Accept-Encoding, Content-Encoding)
- Gzip: istorija, kako radi, nivo kompresije (1-9)
- Brotli: Google-ov algoritam, 15-25% bolji od Gzip
- Poredjenje: Gzip vs Brotli vs Deflate (tabela sa benchmarks)
- Koji fajlovi se kompresuju: HTML, CSS, JS, JSON, SVG, XML
- Koji se NE kompresuju: JPEG, PNG, WOFF2 (vec kompresovani)
- Konfiguracija: Nginx, Apache, Express.js, Vercel, Cloudflare
- Pre-kompresija vs dinamicka kompresija
- Statistike: Brotli stedI 15-25% bandwidth-a u poredjenju sa Gzip
- Reference: RFC 7932 (Brotli), Google Brotli GitHub, MDN Content-Encoding
- FAQPage: "Sta je bolje Gzip ili Brotli?", "Da li kompresija usporava server?", "Kako proveriti da li je ukljucena?"

### 20. blog-perf-cdn.html
**Title:** "CDN — Sta je Content Delivery Network i zasto vam treba | Web Security Scanner"
**Keywords:** CDN, Content Delivery Network, Cloudflare, performanse, latencija
**Sadrzaj MORA da sadrzi:**
- Sta je CDN i kako radi (edge servers, POP lokacije)
- Zasto je bitan: latencija, brzina, DDoS zastita, SSL
- Popularne CDN usluge:
  - Cloudflare (besplatan tier) — setup, DNS, SSL, WAF
  - AWS CloudFront
  - Fastly
  - Vercel Edge Network
  - Bunny.net (jeftina alternativa)
- CDN za staticke sajtove vs dinamicke
- Push vs Pull CDN
- Cache invalidation na CDN-u
- CDN i SEO: brzina = bolji rang
- Kako podesiti Cloudflare za besplatno (korak po korak)
- Statistike: CDN smanjuje latenciju za 50-70%
- Reference: Cloudflare docs, AWS CloudFront docs, Web Almanac
- FAQPage: "Da li mi treba CDN?", "Koliko kosta?", "Da li Cloudflare usporava sajt?"

### 21. blog-perf-lazy.html
**Title:** "Lazy Loading — Odlozeno ucitavanje resursa | Web Security Scanner"
**Keywords:** lazy loading, loading=lazy, Intersection Observer, performanse
**Sadrzaj MORA da sadrzi:**
- Sta je lazy loading i zasto je bitan
- Native lazy loading: loading="lazy" atribut (slike i iframe-ovi)
- Browser podrska za loading="lazy" (99%+ modernih browsera)
- Intersection Observer API za custom lazy loading
- Lazy loading za JavaScript module (dynamic import)
- Code splitting u React/Next.js/Vue
- Above-the-fold vs Below-the-fold pravilo
- Fetchpriority atribut za kriticne slike
- Najcesce greske: lazy loading hero slike (NE), nedostaje width/height
- Statistike: Lazy loading moze smanjiti initial page load za 40-60%
- Reference: web.dev Lazy Loading, MDN loading attribute, Chrome docs
- FAQPage: "Sta je lazy loading?", "Da li usporava sajt?", "Koje slike NE lazy loadovati?"

---

## GDPR (5 fajlova)

### 22. blog-gdpr-cookies.html
**Title:** "Cookie Consent — GDPR vodic za kolacice | Web Security Scanner"
**Keywords:** cookies, cookie consent, GDPR, kolacici, cookie banner, ePrivacy
**Sadrzaj MORA da sadrzi:**
- Sta su kolacici i tipovi: session, persistent, first-party, third-party
- ePrivacy Directive (Cookie Law) — EU regulativa
- GDPR zahtevi za kolacice:
  - Informed consent (jasno objasnjenje)
  - Prior consent (pre postavljanja non-essential cookies)
  - Granular consent (kategorije: necessary, analytics, marketing)
  - Easy withdrawal (lako povlacenje saglasnosti)
- Implementacija cookie banera:
  - CookieConsent (open source)
  - OneTrust
  - Cookiebot
  - Google Consent Mode
- Tehnicka implementacija: blokiranje skripti pre consent-a
- Najcesce greske: dark patterns, pre-checked boxes, "cookie wall"
- Kazne: Planet49 presuda (CJEU, 2019)
- Statistike: 60% EU sajtova i dalje nema validan consent
- Reference: GDPR Recital 30, ePrivacy Directive, CNIL cookie guidelines
- FAQPage: "Da li mi treba cookie baner?", "Koji cookies su essential?", "Sta ako ignorisuem GDPR?"

### 23. blog-gdpr-policy.html
**Title:** "Privacy Policy — Kako napisati politiku privatnosti | Web Security Scanner"
**Keywords:** privacy policy, politika privatnosti, GDPR, obavezne informacije
**Sadrzaj MORA da sadrzi:**
- Zasto je Privacy Policy obavezan (GDPR clan 13 i 14)
- Sta MORA da sadrzi:
  - Identitet kontrolora podataka
  - Kontakt DPO (Data Protection Officer) ako postoji
  - Svrhe obrade podataka
  - Pravni osnov za svaku svrhu
  - Primaoci podataka (trece strane)
  - Transfer podataka van EU
  - Period cuvanja podataka
  - Prava korisnika (pristup, brisanje, prenosivost)
  - Pravo na zalbu nadleznom organu
- Primeri po sekcijama (template)
- Privacy Policy generatori: Termly, Iubenda, GetTerms
- Gde postaviti na sajtu (footer link, obavezan)
- Azuriranje: kada i kako obavestiti korisnike
- Srpski zakon: Zakon o zastiti podataka o licnosti (ZZPL)
- Reference: GDPR clanci 13-14, ICO Privacy Policy checklist
- FAQPage: "Da li mi treba Privacy Policy?", "Moze li biti na srpskom?", "Ko pise Privacy Policy?"

### 24. blog-gdpr-trackers.html
**Title:** "Third-Party Trackeri — Google Analytics, Facebook Pixel i GDPR | Web Security Scanner"
**Keywords:** trackeri, Google Analytics, Facebook Pixel, GDPR, praćenje korisnika
**Sadrzaj MORA da sadrzi:**
- Sta su third-party trackeri i kako rade
- Najcesci trackeri:
  - Google Analytics (GA4) — sta prikuplja, GDPR implikacije
  - Google Tag Manager — container za skripte
  - Facebook Pixel / Meta Pixel — sta prikuplja
  - Hotjar / Microsoft Clarity — session recording
  - LinkedIn Insight Tag
- Schrems II presuda i Google Analytics (2022):
  - Austrija, Francuska, Italija zabranile GA
  - Google-ov odgovor: server-side processing u EU
- GDPR-compliant alternative:
  - Plausible Analytics (EU, open source)
  - Matomo (self-hosted)
  - Fathom Analytics
  - Simple Analytics
- Consent Mode v2 (Google, mart 2024)
- Server-side tracking kao resenje
- Statistike: 86% sajtova koristi Google Analytics
- Reference: CNIL GA odluka, EDPB preporuke, Google Consent Mode docs
- FAQPage: "Da li je Google Analytics legalan?", "Koja je alternativa?", "Sta je server-side tracking?"

### 25. blog-gdpr-rights.html
**Title:** "Prava korisnika po GDPR — Pristup, brisanje, prenosivost | Web Security Scanner"
**Keywords:** GDPR prava, pravo na brisanje, pravo na pristup, data portability
**Sadrzaj MORA da sadrzi:**
- 8 prava korisnika po GDPR-u:
  1. Pravo na informisanje (clan 13-14)
  2. Pravo na pristup (clan 15) — SAR (Subject Access Request)
  3. Pravo na ispravku (clan 16)
  4. Pravo na brisanje / "Right to be forgotten" (clan 17)
  5. Pravo na ogranicenje obrade (clan 18)
  6. Pravo na prenosivost podataka (clan 20)
  7. Pravo na prigovor (clan 21)
  8. Prava u vezi automatizovanog odlucivanja (clan 22)
- Za svako pravo: objasnjenje, primer, izuzeci
- Rokovi za odgovor: 30 dana (moze se produziti na 90)
- Kako implementirati: DSAR (Data Subject Access Request) proces
- Tehnicka implementacija: export korisnickih podataka, soft delete
- Srpski ZZPL: uporedba sa GDPR
- Statistike: 67% EU gradjana zna za GDPR prava (Eurobarometer 2023)
- Reference: GDPR clanci 12-22, EDPB Guidelines, ICO Individual Rights
- FAQPage: "Kako da zatrazim brisanje?", "Koliko treba da cekam?", "Moze li firma da odbije?"

### 26. blog-gdpr-fines.html
**Title:** "GDPR Kazne — Najvece kazne i kako ih izbeci | Web Security Scanner"
**Keywords:** GDPR kazne, GDPR fines, penali, compliance, zastita podataka
**Sadrzaj MORA da sadrzi:**
- Struktura kazni po GDPR-u:
  - Nizi nivo: do 10M EUR ili 2% globalnog prometa
  - Visi nivo: do 20M EUR ili 4% globalnog prometa
- Top 10 najvecih GDPR kazni (sa iznosima i razlozima):
  1. Meta (Ireland) — 1.2B EUR (2023) — transfer podataka u SAD
  2. Amazon (Luxembourg) — 746M EUR (2021) — targeting bez consent-a
  3. WhatsApp (Ireland) — 225M EUR (2021) — transparentnost
  4. Google (France) — 150M EUR (2022) — cookie consent
  5. H&M (Germany) — 35.3M EUR (2020) — nadzor zaposlenih
  6. British Airways — 22M EUR (2020) — data breach (XSS napad!)
  7. Marriott — 20M EUR (2020) — data breach
  8. Google (France) — 50M EUR (2019) — transparentnost
  9. TikTok (Ireland) — 345M EUR (2023) — deca
  10. Criteo (France) — 40M EUR (2023) — consent
- Kako nadlezni organi odlucuju o visini kazne (11 faktora)
- Male firme i GDPR: da li i za njih vaze kazne (DA)
- Srpski Poverenik: ovlascenja i kazne po ZZPL
- Kako izbeci kazne: 10 konkretnih koraka
- Statistike: Preko 4B EUR ukupno naplaceno od 2018 (GDPR Enforcement Tracker)
- Reference: GDPR Enforcement Tracker, EDPB Annual Report, CMS GDPR Portal
- FAQPage: "Kolika je najveca GDPR kazna?", "Da li male firme mogu biti kaznjene?", "Kako izbeci kaznu?"

---

## GLOBALNI SISTEM — ✅ SVE GOTOVO

### 27. blog-common.css + blog-common.js ✅
### 28. Primena na svih 13 postojecih fajlova ✅ (8 security + 4 hub + privacy)
### 29. index.html integracija ✅ (header/footer iz blog-common, result tabs ispod skenera)
### Putanje: ./index.html za pocetnu, ./blog-*.html za sve (file:// + Vercel cleanUrls)

---

## DEPLOY TASKOVI

### 30. Azurirati sitemap.xml ✅
- 31 URL-ova: glavna + 4 hub + 8 security + 7 seo + 6 perf + 5 gdpr + privacy
- Cisti URL-ovi (bez .html) jer Vercel cleanUrls: true
- Buduci clanci vec ukljuceni (fajlovi ce se kreirati)

### 31. Azurirati api.py ✅
- blog-common.css ruta dodana (text/css)
- blog-common.js ruta dodana (application/javascript)
- blog-{page}.html wildcard: uklonjena hardkodirana allowed lista, servira svaki blog-*.html sa diska

### 32. Navigacija ✅ GOTOVO (blog-common.js header/footer + hub kartice)

### 33. Deploy na Vercel + HF ❌ (kad bude spremno)
- git add + commit + push space + vercel deploy --prod
