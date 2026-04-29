# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  IRVES — One-Command Installer (Windows)                                   ║
# ║  Usage (PowerShell as Administrator):                                      ║
# ║    Set-ExecutionPolicy -Scope Process Bypass; .\install.ps1                ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$IrvesDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $IrvesDir "backend"
$ToolsDir   = Join-Path $env:USERPROFILE ".irves\bin"
$JadxVersion    = "1.5.5"
$ApktoolVersion = "2.9.3"

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Ok($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Info($m) { Write-Host "  [ > ] $m" -ForegroundColor Cyan }
function Write-Warn($m) { Write-Host "  [ ! ] $m" -ForegroundColor Yellow }
function Write-Step($m) { Write-Host "`n$m" -ForegroundColor White }
function Write-Fail($m) { Write-Host "  [ERR] $m" -ForegroundColor Red; exit 1 }

function Test-Command($cmd) {
    $null -ne (Get-Command $cmd -ErrorAction SilentlyContinue)
}

function Get-FileFromUrl($url, $dest) {
    Write-Info "Downloading $(Split-Path $dest -Leaf)..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ██╗██████╗ ██╗   ██╗███████╗███████╗" -ForegroundColor Cyan
Write-Host "  ██║██╔══██╗██║   ██║██╔════╝██╔════╝" -ForegroundColor Cyan
Write-Host "  ██║██████╔╝╚██╗ ██╔╝█████╗  ███████╗" -ForegroundColor Cyan
Write-Host "  ██║██╔══██╗ ╚████╔╝ ██╔══╝  ╚════██║" -ForegroundColor Cyan
Write-Host "  ██║██║  ██║  ╚██╔╝  ███████╗███████║" -ForegroundColor Cyan
Write-Host "  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Intelligent Reverse Engineering & Vulnerability Evaluation System" -ForegroundColor White
Write-Host "  Windows Installer`n"
Write-Host "  ──────────────────────────────────────────────────────────────────"

New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null

# ══════════════════════════════════════════════════════════════════════════════
Write-Step "[ 1 / 7 ]  Java"
# ══════════════════════════════════════════════════════════════════════════════
$JavaOk = $false
try {
    $jOut = & java -version 2>&1
    if ($jOut -match '"(\d+)') {
        $jVer = [int]$Matches[1]
        if ($jVer -ge 11) { Write-Ok "Java $jVer already installed"; $JavaOk = $true }
    }
} catch {}

if (-not $JavaOk) {
    Write-Info "Installing Java 21 via winget..."
    $wingetAvailable = Test-Command "winget"
    if ($wingetAvailable) {
        try {
            winget install --id Microsoft.OpenJDK.21 --silent `
                --accept-package-agreements --accept-source-agreements
            # Refresh PATH
            $env:PATH = [Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                        [Environment]::GetEnvironmentVariable("PATH","User")
            Write-Ok "Java 21 installed"
            $JavaOk = $true
        } catch {
            Write-Warn "winget install failed: $_"
        }
    }
    if (-not $JavaOk) {
        Write-Warn "Automatic Java install failed."
        Write-Warn "Download Temurin JDK 21 from: https://adoptium.net/temurin/releases/?version=21"
        Write-Warn "Install it, then re-run this script."
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# ══════════════════════════════════════════════════════════════════════════════
Write-Step "[ 2 / 7 ]  Python 3.12+"
# ══════════════════════════════════════════════════════════════════════════════
$PythonBin = ""
foreach ($cmd in @("python", "python3", "py -3.12", "py")) {
    try {
        $ver = & $cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
        if ($ver -match "3\.(\d+)" -and [int]$Matches[1] -ge 12) {
            $PythonBin = $cmd
            Write-Ok "Python $ver found"
            break
        }
    } catch {}
}

if (-not $PythonBin) {
    Write-Info "Installing Python 3.12 via winget..."
    $wingetAvailable = Test-Command "winget"
    if ($wingetAvailable) {
        try {
            winget install --id Python.Python.3.12 --silent `
                --accept-package-agreements --accept-source-agreements
            $env:PATH = [Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                        [Environment]::GetEnvironmentVariable("PATH","User")
            $PythonBin = "python"
            Write-Ok "Python 3.12 installed"
        } catch {
            Write-Fail "Python install failed. Download from https://python.org/downloads (3.12+)"
        }
    } else {
        Write-Fail "winget not available. Download Python 3.12+ from https://python.org/downloads"
    }
}

# ══════════════════════════════════════════════════════════════════════════════
Write-Step "[ 3 / 7 ]  Python virtual environment & dependencies"
# ══════════════════════════════════════════════════════════════════════════════
$VenvDir = Join-Path $BackendDir ".venv"
if (-not (Test-Path $VenvDir)) {
    Write-Info "Creating virtual environment..."
    & $PythonBin -m venv $VenvDir
    Write-Ok "Created .venv"
} else {
    Write-Ok ".venv already exists — skipping creation"
}

$Pip     = Join-Path $VenvDir "Scripts\pip.exe"
$Python  = Join-Path $VenvDir "Scripts\python.exe"
$ReqFile = Join-Path $BackendDir "requirements.txt"

Write-Info "Installing Python packages (Frida, mitmproxy, androguard, …)"
& $Pip install -q --upgrade pip
& $Pip install -q -r $ReqFile
Write-Ok "Python dependencies installed"

# ══════════════════════════════════════════════════════════════════════════════
Write-Step "[ 4 / 7 ]  APKTool $ApktoolVersion"
# ══════════════════════════════════════════════════════════════════════════════
$ApktoolJar = Join-Path $ToolsDir "apktool.jar"
$ApktoolBat = Join-Path $ToolsDir "apktool.bat"

if (Test-Command "apktool") {
    Write-Ok "APKTool already installed"
} else {
    Get-FileFromUrl `
        "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${ApktoolVersion}.jar" `
        $ApktoolJar

    # Create .bat wrapper
    @"
@echo off
java -jar "$ApktoolJar" %*
"@ | Out-File -FilePath $ApktoolBat -Encoding ascii
    Write-Ok "APKTool $ApktoolVersion installed"
}

# ══════════════════════════════════════════════════════════════════════════════
Write-Step "[ 5 / 7 ]  JADX $JadxVersion"
# ══════════════════════════════════════════════════════════════════════════════
$JadxDir = Join-Path $ToolsDir "jadx"
$JadxBin = Join-Path $JadxDir "bin"

if (Test-Command "jadx") {
    Write-Ok "JADX already installed"
} else {
    $JadxZip = Join-Path $ToolsDir "jadx.zip"
    Get-FileFromUrl `
        "https://github.com/skylot/jadx/releases/download/v${JadxVersion}/jadx-${JadxVersion}.zip" `
        $JadxZip
    Write-Info "Extracting JADX..."
    Expand-Archive -Path $JadxZip -DestinationPath $JadxDir -Force
    Remove-Item $JadxZip
    Write-Ok "JADX $JadxVersion installed → $JadxBin"
}

# ══════════════════════════════════════════════════════════════════════════════
Write-Step "[ 6 / 7 ]  PATH configuration"
# ══════════════════════════════════════════════════════════════════════════════
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$PathsToAdd = @($ToolsDir, $JadxBin)

foreach ($p in $PathsToAdd) {
    if ($UserPath -notlike "*$p*") {
        $UserPath += ";$p"
        [Environment]::SetEnvironmentVariable("PATH", $UserPath, "User")
        $env:PATH += ";$p"
        Write-Ok "Added to PATH: $p"
    } else {
        Write-Ok "Already in PATH: $p"
    }
}

# ══════════════════════════════════════════════════════════════════════════════
Write-Step "[ 7 / 7 ]  Environment configuration"
# ══════════════════════════════════════════════════════════════════════════════
$EnvFile     = Join-Path $BackendDir ".env"
$EnvExample  = Join-Path $BackendDir ".env.example"

if (-not (Test-Path $EnvFile)) {
    Copy-Item $EnvExample $EnvFile
    Write-Ok "Created backend\.env from .env.example"
    Write-Warn "Open backend\.env and set at least one AI API key (e.g. ANTHROPIC_API_KEY)"
} else {
    Write-Ok "backend\.env already exists — skipping"
}

# ── Final summary ─────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ══════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "    IRVES is ready!" -ForegroundColor Green
Write-Host "  ══════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "  Start the server:" -ForegroundColor White
Write-Host "    cd backend" -ForegroundColor Cyan
Write-Host "    .venv\Scripts\Activate.ps1" -ForegroundColor Cyan
Write-Host "    python main.py" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Open in browser:  http://127.0.0.1:8765" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Next: Edit backend\.env with your AI API key." -ForegroundColor Yellow
Write-Host ""
