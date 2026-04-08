#!/bin/bash
echo "============================================"
echo "  Web Security Scanner - Pokretanje..."
echo "============================================"
echo

pip install -r requirements.txt -q
echo "API pokrenut na: http://localhost:8000"
echo "Otvori index.html u browseru!"
echo

python -m uvicorn api:app --host 127.0.0.1 --port 8000 --reload
