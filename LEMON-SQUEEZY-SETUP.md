# Lemon Squeezy — Kompletan Setup Playbook

**Za Web Security Scanner (main) + Malware Scanner.** Operativno uputstvo —
tačno šta kreirati na Lemon Squeezy i šta preneti u HF Space env.

> Otvori Lemon dashboard: https://app.lemonsqueezy.com/
> Sve cene su u USD (Lemon je globalni, ne EUR/RSD).

---

## 1. STORE — napravi jedan

Dashboard → **Stores → New Store**

| Polje | Vrednost |
|---|---|
| Store name | `Web Security Scanner` |
| Store URL slug | `web-security-scanner` (URL postaje `web-security-scanner.lemonsqueezy.com`) |
| Currency | `USD` |
| Country | Srbija |
| Tax mode | *Lemon Squeezy as Merchant of Record* (default — oni plaćaju PDV) |

**Pokupi:** `Store ID` (broj, vidljiv u URL-u dashboard-a posle kreiranja).

---

## 2. PROIZVODI — kreiraj 3 komada

Dashboard → **Products → New Product**. Svaki proizvod ima jednu ili više
**varijanti** (varijanta = konkretna cena / billing plan).

---

### Proizvod A — **Pro Monthly**

| Polje | Vrednost |
|---|---|
| Product name | `Pro Monthly` |
| Description | `Monthly subscription — 240+ security checks, unlimited scans, PDF reports, priority support.` |
| Type | **Subscription** |
| Status | Published |

**Varijanta (jedna):**

| Polje | Vrednost |
|---|---|
| Variant name | `Monthly` |
| Price | `9.00` USD |
| Billing interval | `Every 1 month` |
| Trial | — (bez trial-a, ili 7 dana ako hoćeš akviziciju) |

**Pokupi posle publish-a:**
- `Product ID`
- `Variant ID` (za monthly)
- `Share / Buy link` → **Overview → Share** dugme → URL oblika `https://web-security-scanner.lemonsqueezy.com/buy/<uuid>`

---

### Proizvod B — **Pro Yearly**

| Polje | Vrednost |
|---|---|
| Product name | `Pro Yearly` |
| Description | `Annual subscription — save 27% vs monthly. All Pro Monthly features + yearly billing.` |
| Type | **Subscription** |
| Status | Published |

**Varijanta (jedna):**

| Polje | Vrednost |
|---|---|
| Variant name | `Yearly` |
| Price | `79.00` USD |
| Billing interval | `Every 1 year` |

**Pokupi:**
- `Product ID` (Yearly)
- `Variant ID` (za yearly)
- `Buy link`

> Napomena: Pro Monthly i Pro Yearly mogu biti **jedan proizvod sa 2 varijante**
> umesto 2 odvojena proizvoda. Ako ih spojiš, u env imaš jedan `LEMON_PRODUCT_ID`
> ali i dalje dva različita `LEMON_VARIANT_*`. Kôd radi oba načina.

---

### Proizvod C — **Malware Scanner 5-Pack** *(NOVO — Faza 7)*

| Polje | Vrednost |
|---|---|
| Product name | `Malware Scanner 5-Pack` |
| Description | `5 full malware scans with Damage Report. 30-day validity. One-time payment — no subscription.` |
| Type | **Single payment** (NIJE subscription) |
| Status | Published |

**Varijanta (jedna):**

| Polje | Vrednost |
|---|---|
| Variant name | `5-Pack` |
| Price | `3.00` USD |
| Billing interval | — (single payment) |

**Pokupi:**
- `Product ID` (malware)
- `Variant ID` (5-pack)
- `Buy link`

---

## 3. WEBHOOK — jedan, zajednički za sve

Dashboard → **Settings → Webhooks → + New Webhook**

| Polje | Vrednost |
|---|---|
| Callback URL | `https://unlimitededition-web-security-scanner.hf.space/webhooks/lemon` |
| Signing secret | (Lemon generiše — **kopiraj odmah**, ne pokazuje se ponovo) |
| Events (čekiraj sve dole) | → vidi listu |

**Čekiraj ove eventove:**

Subscription (Pro Monthly/Yearly):
- [x] `subscription_created`
- [x] `subscription_updated`
- [x] `subscription_cancelled`
- [x] `subscription_resumed`
- [x] `subscription_expired`
- [x] `subscription_payment_success`
- [x] `subscription_payment_failed`

License keys (ako ikad dodaš offline licence):
- [x] `license_key_created`
- [x] `license_key_updated`

One-time order (Malware 5-Pack — Faza 7):
- [x] `order_created`

**Pokupi:** `Signing secret` (HEX string, ~64 karaktera) — ide kao
`LEMON_WEBHOOK_SECRET` u HF Secrets.

---

## 4. API KEY

Dashboard → **Settings → API → + Create API key**

| Polje | Vrednost |
|---|---|
| Name | `hf-space-backend` |
| Scope | Default (full access) |

**Pokupi:** API key string (`lsk_...`) — ide kao `LEMON_API_KEY` u HF Secrets.

> Ovaj kôd ga ne koristi aktivno u ovom trenutku (sve radi kroz webhooks),
> ali mora biti postavljen da `/api/subscription/config` ne vraća da je Lemon
> nekonfigurisan.

---

## 5. ŠTA SVE POKUPITI — finalna checklist

Kada završiš sve iznad, imaćeš u rukama ove vrednosti:

| # | Vrednost | Odakle | Primer |
|---|---|---|---|
| 1 | **Store ID** | Dashboard URL posle kreiranja store-a | `12345` |
| 2 | **Pro Monthly — Product ID** | Product → Overview | `567890` |
| 3 | **Pro Monthly — Variant ID** | Product → Variants | `678901` |
| 4 | **Pro Monthly — Buy URL** | Product → Share | `https://web-security-scanner.lemonsqueezy.com/buy/abc-uuid` |
| 5 | **Pro Yearly — Product ID** | Product → Overview | `567891` |
| 6 | **Pro Yearly — Variant ID** | Product → Variants | `678902` |
| 7 | **Pro Yearly — Buy URL** | Product → Share | `https://.../buy/def-uuid` |
| 8 | **Malware 5-Pack — Variant ID** | Product → Variants | `678903` |
| 9 | **Malware 5-Pack — Buy URL** | Product → Share | `https://.../buy/ghi-uuid` |
| 10 | **API Key** | Settings → API | `lsk_...` |
| 11 | **Webhook Signing Secret** | Settings → Webhooks → click on webhook | HEX string |

> Stavke 2 i 5 mogu biti isti broj ako si Monthly+Yearly spojio u jedan
> proizvod. Tada koristiš taj jedan `LEMON_PRODUCT_ID`.

---

## 6. GDE ŠTA IDE U HF SPACE

HF Space dashboard → **Settings → Variables and secrets**

### 🔒 SECRETS (šifrovano — NE vidi se u UI posle snimanja)

```
LEMON_API_KEY                     = lsk_...
LEMON_WEBHOOK_SECRET              = <HEX string>
```

### 📋 VARIABLES (plain text — sme da se vidi)

```
LEMON_STORE_ID                    = 12345
LEMON_PRODUCT_ID                  = 567890
LEMON_VARIANT_MONTHLY             = 678901
LEMON_VARIANT_YEARLY              = 678902
LEMON_BUY_URL_MONTHLY             = https://web-security-scanner.lemonsqueezy.com/buy/<uuid>
LEMON_BUY_URL_YEARLY              = https://web-security-scanner.lemonsqueezy.com/buy/<uuid>
LEMON_VARIANT_MALWARE_5_PACK      = 678903
LEMON_BUY_URL_MALWARE_5_PACK      = https://web-security-scanner.lemonsqueezy.com/buy/<uuid>
```

> Posle snimanja → **Factory reboot Space** (Settings → Factory rebuild).
> Inače env se ne učita.

---

## 7. TESTIRANJE

### Pre-flight (bez pravog kupovanja):

```bash
curl https://unlimitededition-web-security-scanner.hf.space/api/subscription/config
```

Očekivano:
```json
{
  "lemon_api_key_set": true,
  "lemon_webhook_secret_set": true,
  "lemon_store_id": "12345",
  "lemon_product_id": "567890",
  "lemon_variant_monthly": "678901",
  "lemon_variant_yearly": "678902"
}
```

Ako bilo koje polje kaže `<unset>` ili `false` → env nije učitan. Proveri
Secrets/Variables i factory reboot-uj.

### Test kupovine (Lemon test mode):

Dashboard → **Settings → Advanced → Test mode: ON**

Kliknu pravi Buy URL → na checkout stranici unese test karticu:

```
Card: 4242 4242 4242 4242
CVC:  bilo koje 3 cifre
Date: bilo koja buduća
ZIP:  bilo koja 5 cifara
```

Kupovina prolazi, webhook se okida, u `lemon_webhook_events` tabeli (Supabase)
pojavljuje se nov red. Posle testa → **Test mode: OFF** pre produkcije.

---

## 8. REDOSLED KORAKA (operativno)

1. [ ] Kreiraj Store → pokupi Store ID
2. [ ] Kreiraj Proizvod A (Pro Monthly) → pokupi 3 stvari
3. [ ] Kreiraj Proizvod B (Pro Yearly) → pokupi 3 stvari
4. [ ] Kreiraj Proizvod C (Malware 5-Pack) → pokupi 3 stvari
5. [ ] Kreiraj API Key → pokupi `lsk_...`
6. [ ] Kreiraj Webhook → pokupi Signing Secret
7. [ ] Unesi sve u HF Space (Secrets + Variables iz sekcije 6)
8. [ ] Factory reboot HF Space
9. [ ] `curl /api/subscription/config` → verifikuj
10. [ ] Test mode ON → test kupovina sa test karticom
11. [ ] Proveri da li se pojavio red u `lemon_webhook_events` Supabase tabeli
12. [ ] Test mode OFF → produkcija

---

## 9. ŠTA KÔD RADI AUTOMATSKI (samo informativno)

- **Subscription kupovina** → `subscription_created` webhook → `subscription.py._handle_subscription_event` → INSERT u `subscriptions` tabelu → user od sada ima Pro.
- **Subscription otkazana** → `subscription_cancelled` webhook → flip `status='cancelled'`, user gubi Pro na kraju plaćenog perioda.
- **Malware 5-Pack kupovina** *(Faza 7 u izradi)* → `order_created` webhook → `subscription.py._handle_order_created` → INSERT u `malware_credits` tabelu sa `credits_remaining=5`, `expires_at=NOW()+30 dana`.
- **FULL malware scan** → api.py → `db.consume_malware_credit(ip_hash)` → atomic decrement → ako ima kredit, dozvoli `mode='full'` bez verifikacije domena.

---

## 10. RIZICI / ČESTE GREŠKE

| Greška | Simptom | Popravka |
|---|---|---|
| Zaboraviš Factory reboot | API vraća `"<unset>"` za env | Settings → Factory rebuild |
| Staviš Secret u Variables | Key vidljiv svima u UI | Briši i stavi u Secrets |
| Pogrešan Webhook URL | Webhooks Dashboard → Logs pokazuje 404 | Mora biti `/webhooks/lemon` (ne `/webhook` singular) |
| Test mode ostane ON | Prave kupovine ne dolaze | Settings → Advanced → Test mode OFF |
| Varijanta ID umesto Product ID | Subscription ne mapira se na plan | `LEMON_VARIANT_*` su varijante, `LEMON_PRODUCT_ID` je proizvod — ne mešaj |
| Webhook secret drift | Svi webhooks vraćaju 401 | Ako regenerišeš secret na Lemon-u, moraš ažurirati HF Secret + reboot |

---

## 11. KRATAK REZIME (TL;DR)

**Kreiraš na Lemon:**
- 1 Store
- 3 Proizvoda (Pro Monthly, Pro Yearly, Malware 5-Pack)
- 1 Webhook (na `/webhooks/lemon`)
- 1 API Key

**Šalješ mi / unosiš u HF Space:** 11 vrednosti iz tabele u sekciji 5.

Kada to imaš, reci mi i nastavljam Fazu 7 (kôd za webhook handler +
credit consumption).
