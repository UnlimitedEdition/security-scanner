# tests/ — Test Suite

Testovi za Web Security Scanner.

## Pokretanje

```bash
cd security-scanner
python -m pytest tests/ -v
```

## Sadrzaj

| Fajl | Sta testira |
|------|------------|
| test_strictness.py | Scoring profili (minimal, standard, strict, paranoid) — regression gate |
| bench_strictness.py | Performance benchmark za scoring |
| test_public_gallery.py | Public gallery API endpoint-i |
| benchmark_results.json | Sacuvani benchmark rezultati |

Malware scanner ima svoje testove u `malware_scanner/tests/`.

## Konvencije

- Sinteticki input (nema network poziva, nema fixtures na disku)
- Standard profil MORA reprodukovati V3 scoring — svaka promena u scoringu mora proci regression test
- Pokreni pre svakog deploy-a
