# supabase/ — Supabase Edge Functions

Edge funkcije koje se deploy-uju na Supabase infrastrukturu.

## Struktura

```
supabase/
  functions/
    backup/
      index.ts          — glavni handler za backup edge function
      crypto.ts         — AES-256-GCM enkripcija backup podataka
      db_export.ts      — export kriticnih tabela iz baze
      r2_upload.ts      — upload enkriptovanog blob-a na Cloudflare R2
```

## Backup Edge Function

Automatski backup kriticnih tabela, pokrenut pg_cron-om svaki dan u 04:00 UTC.

Pipeline:
1. Verifikuje X-Webhook-Secret header (odbija bez validnog secret-a)
2. Ucitava R2 kredencijale i encryption key iz Vault-a
3. Exportuje podatke iz kriticnih tabela
4. JSON → gzip → AES-256-GCM enkripcija
5. Upload na Cloudflare R2
6. Loguje rezultat u backup_log tabelu

## Deploy

Edge funkcije se deploy-uju kroz Supabase Dashboard ili CLI.
