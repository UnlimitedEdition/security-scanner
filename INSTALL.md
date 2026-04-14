# Installation & Deployment

Self-hosting guide for Web Security Scanner. The canonical deployment
is Vercel (frontend) + HuggingFace Spaces (backend) + Supabase
(database), but any stack that runs Python 3.11+ and PostgreSQL 15+
works.

## Prerequisites

- Python 3.11 or newer
- PostgreSQL 15+ (Supabase recommended — RLS, `pg_cron`, Vault all
  used by the project)
- A domain you control (for frontend + backend CORS)
- Optional: Cloudflare R2 bucket (for encrypted backups)
- Optional: Lemon Squeezy account (for Pro tier payments)

## 1. Clone & install

```bash
git clone https://github.com/UnlimitedEdition/security-scanner.git
cd security-scanner
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Environment

```bash
cp .env.example .env
```

Fill in values. Required minimum:

- `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `SUPABASE_ANON_KEY`,
  `SUPABASE_DB_URL`
- `SERVER_SALT` (32+ random bytes, base64 — used for PII hashing)
- `FRONTEND_ORIGIN` (e.g. `https://your-domain.com`)

Optional (Pro tier, backups, BI):
- `LEMON_SQUEEZY_API_KEY`, `LEMON_SQUEEZY_WEBHOOK_SECRET`
- `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET`
- `GA4_MEASUREMENT_ID`

See `.env.example` for the full list with inline documentation.

## 3. Database

Apply migrations in order:

```bash
ls migrations/*.sql | sort | while read f; do
  psql "$SUPABASE_DB_URL" -f "$f"
done
```

Or paste each file into Supabase Dashboard → SQL Editor in sequence.
Migrations are numbered `001` through `019` as of v4.1.

## 4. Backend (HuggingFace Spaces)

Create a Docker Space, push this repo as `main`:

```bash
git remote add space https://huggingface.co/spaces/<user>/<space>
git push space master:main
```

Set environment variables as **Space Secrets**
(Settings → Variables). The Dockerfile is production-ready — HF
builds on push. Wait ~2 min for image build.

**Self-hosted alternative** (any server with Docker):

```bash
docker build -t security-scanner .
docker run -p 7860:7860 --env-file .env security-scanner
```

## 5. Frontend (Vercel)

```bash
npm i -g vercel
vercel login
vercel --prod
```

Vercel auto-detects the static site (no build step). The
`vercel.json` already has rewrites for `/public/:id`, security
headers, and cleanUrls.

**Force redeploy** when changing `vercel.json` (CDN cache is sticky):

```bash
vercel --prod --force
```

## 6. Configure API_BASE

In `index.html`, `gallery.html`, `public-scan.html`, `account.html`
look for the `API_BASE` constant and replace the HF Space URL with
your backend URL.

## 7. Smoke test

```bash
curl https://<your-backend>/health
# → {"status":"ok","version":"4.1.0"}
```

Then open `https://<your-domain>/` and run a scan against any
public site.

## 8. Optional: Pro tier

1. Create a Lemon Squeezy store + product
2. Set up webhook: `https://<backend>/api/lemon/webhook`
3. Configure the webhook secret as `LEMON_SQUEEZY_WEBHOOK_SECRET`
4. Update `PRICE_ID` / `STORE_ID` in `api.py`

See `PRIRUCNIK.md` (Serbian) for the operator handbook.

## Troubleshooting

- **CORS errors**: `FRONTEND_ORIGIN` must exactly match (no trailing
  slash, correct scheme)
- **Supabase `PGRST205`**: migration not applied — check
  `migrations/` folder against current DB state
- **Vercel 404 after rewrite change**: `vercel --prod --force`
- **HF Space cold start**: first request after idle takes ~30s; the
  backend auto-wakes on any inbound request
