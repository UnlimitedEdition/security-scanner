# scripts/ — Utility Scripts

Pomocne skripte za administraciju i disaster recovery.

## Sadrzaj

| Fajl | Namena |
|------|--------|
| restore_backup.py | Download, decrypt i restore backup-a sa R2 storage-a |
| dr_drill_bootstrap.sql | DR drill skripta — sve migracije (001-010) u jednom SQL fajlu za FRESH Supabase projekat |

## Koriscenje

```bash
# Lista dostupnih backup-ova na R2
python scripts/restore_backup.py --list

# Download i decrypt konkretnog backup-a
python scripts/restore_backup.py --restore <backup-id>
```

DR drill SQL se paste-uje direktno u Supabase SQL Editor na novom projektu.
