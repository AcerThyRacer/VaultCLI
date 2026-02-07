# ═══════════════════════════════════════════════════════════════
#  VaultSecureCLI — Windows PowerShell Installer
#  Installs dependencies and links the `vault` command globally.
# ═══════════════════════════════════════════════════════════════

$ErrorActionPreference = "Stop"

function Write-Banner {
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║       🔐  VaultSecureCLI  Installer          ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step($Status, $Message, $Color) {
    Write-Host "  [$Status] " -ForegroundColor $Color -NoNewline
    Write-Host $Message
}

# ── Banner ────────────────────────────────────────────────────
Write-Banner

# ── Check Node.js ─────────────────────────────────────────────
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    Write-Step "ERROR" "Node.js is not installed. Please install Node.js 16+ from https://nodejs.org" Red
    exit 1
}

$nodeVersion = (node -v) -replace 'v', ''
$nodeMajor = [int]($nodeVersion.Split('.')[0])
if ($nodeMajor -lt 16) {
    Write-Step "ERROR" "Node.js 16+ required (found v$nodeVersion). Please upgrade." Red
    exit 1
}
Write-Step "OK" "Node.js v$nodeVersion detected" Green

# ── Check npm ─────────────────────────────────────────────────
$npmCmd = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npmCmd) {
    Write-Step "ERROR" "npm is not installed. It should come with Node.js." Red
    exit 1
}
$npmVersion = npm -v
Write-Step "OK" "npm v$npmVersion detected" Green

# ── Install ───────────────────────────────────────────────────
Write-Host ""
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $scriptDir

try {
    Write-Step ".." "Installing dependencies..." Yellow
    npm install --production 2>&1 | ForEach-Object { Write-Host "    $_" }
    Write-Step "OK" "Dependencies installed" Green

    Write-Host ""
    Write-Step ".." "Linking 'vault' command globally..." Yellow
    npm link 2>&1 | ForEach-Object { Write-Host "    $_" }
    Write-Step "OK" "Global link created" Green
} catch {
    Write-Step "ERROR" $_.Exception.Message Red
    Write-Host ""
    Write-Host "  Try running PowerShell as Administrator." -ForegroundColor Yellow
    Write-Host "  You can still run: node `"$scriptDir\bin\vault.js`"" -ForegroundColor DarkGray
}

Pop-Location

# ── Done ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "    vault         " -ForegroundColor Cyan -NoNewline
Write-Host " — Launch the vault"
Write-Host "    vault --quick " -ForegroundColor Cyan -NoNewline
Write-Host " — Skip boot animation"
Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""
