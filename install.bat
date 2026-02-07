@echo off
REM ═══════════════════════════════════════════════════════════════
REM  VaultSecureCLI — Windows Installer (Batch)
REM  Installs dependencies and links the `vault` command globally.
REM ═══════════════════════════════════════════════════════════════

setlocal EnableDelayedExpansion

echo.
echo   ╔═══════════════════════════════════════════════╗
echo   ║       🔐  VaultSecureCLI  Installer          ║
echo   ╚═══════════════════════════════════════════════╝
echo.

REM ── Check Node.js ───────────────────────────────────────────
where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo   [ERROR] Node.js is not installed.
    echo   Please install Node.js 16+ from https://nodejs.org
    echo.
    pause
    exit /b 1
)

for /f "tokens=1 delims=." %%a in ('node -v') do set NODE_VER=%%a
set NODE_VER=%NODE_VER:v=%
if %NODE_VER% LSS 16 (
    echo   [ERROR] Node.js 16+ required. Please upgrade.
    pause
    exit /b 1
)

for /f %%v in ('node -v') do echo   [OK] Node.js %%v detected

REM ── Check npm ───────────────────────────────────────────────
where npm >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo   [ERROR] npm is not installed.
    pause
    exit /b 1
)

for /f %%v in ('npm -v') do echo   [OK] npm %%v detected

REM ── Install ─────────────────────────────────────────────────
echo.
echo   [..] Installing dependencies...
cd /d "%~dp0"
call npm install --production
if %ERRORLEVEL% neq 0 (
    echo   [ERROR] npm install failed.
    pause
    exit /b 1
)
echo   [OK] Dependencies installed

echo.
echo   [..] Linking 'vault' command globally...
call npm link
if %ERRORLEVEL% neq 0 (
    echo   [WARN] npm link failed. Try running as Administrator.
    echo   You can still run: node "%~dp0bin\vault.js"
) else (
    echo   [OK] Global link created
)

REM ── Done ────────────────────────────────────────────────────
echo.
echo   ─────────────────────────────────────────────
echo   Installation complete!
echo.
echo     vault          — Launch the vault
echo     vault --quick  — Skip boot animation
echo   ─────────────────────────────────────────────
echo.
pause
