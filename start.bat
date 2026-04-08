@echo off
title Web Security Scanner
color 0A
echo.
echo  ============================================
echo   Web Security Scanner - Pokretanje...
echo  ============================================
echo.

cd /d "%~dp0"

set PYTHON=C:\Python313\python.exe

REM FIX: PostgreSQL kvari SSL - cistimo pre svega
set OPENSSL_CONF=
set SSL_CERT_FILE=
set REQUESTS_CA_BUNDLE=

REM Proveri da li su paketi vec instalirani
"%PYTHON%" -c "import fastapi, uvicorn, requests, dns, pydantic" >nul 2>&1
if %errorlevel% == 0 (
    echo  [1/2] Zavisnosti OK - preskacemo instalaciju
    goto START_SERVER
)

REM Instaliraj samo ako nedostaju
echo  [1/2] Instaliram zavisnosti...
set OPENSSL_CONF=
"%PYTHON%" -m pip install fastapi uvicorn requests dnspython "pydantic>=2" beautifulsoup4 certifi --quiet --trusted-host pypi.org --trusted-host files.pythonhosted.org

:START_SERVER
echo  [2/2] Pokrecem server...
echo.
echo  ============================================
echo   SPREMAN: http://localhost:8000
echo   Otvori index.html u browseru!
echo   Zaustavi: CTRL+C
echo  ============================================
echo.

set OPENSSL_CONF=
set SSL_CERT_FILE=
set REQUESTS_CA_BUNDLE=
"%PYTHON%" -m uvicorn api:app --host 127.0.0.1 --port 8000 --reload

pause
