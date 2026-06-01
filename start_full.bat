@echo off
TITLE EasyProxy Full Mode - Auto Setup
SETLOCAL EnableDelayedExpansion

echo Starting EasyProxy FULL Auto-Setup...
echo =====================================

set "FLARESOLVERR_PORT=8191"
:: --- 1. Set Environment ---
:: Clean __pycache__ folders to prevent import issues
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d"

:: Force PYTHONPATH to current directory
set PYTHONPATH=%CD%
set PYTHONUNBUFFERED=1

:: --- 2. EasyProxy Main Dependencies ---
echo Checking EasyProxy dependencies...
python -m pip install -r requirements.txt --quiet
python -m pip install pycryptodome --quiet
python -m playwright install chromium

:: --- 3. FlareSolverr Setup ---
echo Checking FlareSolverr...
IF NOT EXIST "flaresolverr\" (
    echo Downloading FlareSolverr...
    git clone https://github.com/FlareSolverr/FlareSolverr.git flaresolverr
    echo Installing FlareSolverr dependencies...
    pushd flaresolverr
    python -m pip install -r requirements.txt --quiet
    popd
) ELSE (
    :: FlareSolverr already installed, starts lazily on demand
    echo [OK] FlareSolverr installed, will start on demand
)

:: --- 4. FlareSolverr is LAZY (starts via Python code when first needed) ---

:: --- 5. Start EasyProxy ---
echo.
echo Starting EasyProxy Main App...
echo -------------------------------------
:: Reset PORT for main app
set PORT=7860
set FLARESOLVERR_URL=http://localhost:%FLARESOLVERR_PORT%

python app.py
pause
