# Web Security Scanner - Claude Code Project Config

## Project
- Backend: Python FastAPI (api.py, scanner.py, checks/)
- Frontend: Single HTML (index.html) + blog pages (blog-*.html)
- Deploy: Vercel (frontend) + HF Spaces (backend)

## Workflow Rules
- TODO lista SAMO kao plan — NE pokreci nista automatski
- Korisnik komanduje kad se sta radi
- Pisi fajlove DIREKTNO sa Edit/Write, ne preko agenata
- 1 agent = 1 fajl, maksimalno 1 jednostavan task
- NIKAD Write za fajlove 300+ linija — koristi Edit parcijalno
- Ako hook blokira Write, odmah prebaci na Edit

## Auto-Plugin Triggers
- /commit — koristi commit-commands plugin za git workflow
- /revise-claude-md — koristi claude-md-management za azuriranje ovog fajla
- /session-report — generisi HTML izvestaj o potrosnji tokena
- /hookify — kreiraj ili edituj hooks
- Python fajlovi (.py) — pyright-lsp automatski radi type checking

## Git
- Main branch: main
- Working branch: master
- Remote za HF: space
- Ne push-uj bez eksplicitne dozvole

## Code Style
- Python: FastAPI async, type hints
- HTML: 2-space indent, dark tema (#0a0c15), Inter font
- Blog: SR+EN toggle, Schema.org, OG tags, min 300 linija
