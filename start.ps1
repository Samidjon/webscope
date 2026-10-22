$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $Root

Write-Host ''
Write-Host '  WebScope - Web Security Workbench' -ForegroundColor Magenta
Write-Host '  ---------------------------------' -ForegroundColor DarkGray

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host 'Python was not found. Install Python 3.12 (64-bit) and enable Add Python to PATH.' -ForegroundColor Red
    exit 1
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host 'Node.js/npm was not found. Install Node.js 20+ and reopen PowerShell.' -ForegroundColor Red
    exit 1
}

if (-not (Test-Path (Join-Path $Root '.venv\Scripts\python.exe'))) {
    Write-Host '[1/4] Creating Python virtual environment...' -ForegroundColor Cyan
    python -m venv .venv
}
$Python = Join-Path $Root '.venv\Scripts\python.exe'
$Mitmdump = Join-Path $Root '.venv\Scripts\mitmdump.exe'

if (-not (Test-Path $Mitmdump)) {
    Write-Host '[2/4] Installing Python dependencies (first run may take a few minutes)...' -ForegroundColor Cyan
    & $Python -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw 'Could not upgrade pip.' }
    & $Python -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed.' }
}

if (-not (Test-Path (Join-Path $Root 'frontend\node_modules'))) {
    Write-Host '[3/4] Installing frontend dependencies (first run requires internet)...' -ForegroundColor Cyan
    Push-Location (Join-Path $Root 'frontend')
    try { npm install; if ($LASTEXITCODE -ne 0) { throw 'npm install failed.' } }
    finally { Pop-Location }
} else {
    Write-Host '[3/4] Frontend dependencies already installed.' -ForegroundColor DarkGray
}

Write-Host '[4/4] Opening the API and proxy in separate PowerShell windows...' -ForegroundColor Cyan
$backendScript = Join-Path $Root 'scripts\run-backend.ps1'
$proxyScript = Join-Path $Root 'scripts\run-proxy.ps1'
Start-Process -FilePath 'powershell.exe' -WorkingDirectory $Root -ArgumentList @('-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$backendScript`"")
Start-Sleep -Milliseconds 800
Start-Process -FilePath 'powershell.exe' -WorkingDirectory $Root -ArgumentList @('-NoExit', '-ExecutionPolicy', 'Bypass', '-File', "`"$proxyScript`"")
Start-Sleep -Seconds 2
Write-Host ''
Write-Host 'Starting the WebScope UI. Keep this terminal open.' -ForegroundColor Green
Write-Host 'UI:     http://127.0.0.1:5173' -ForegroundColor Green
Write-Host 'API:    http://127.0.0.1:8000/api/health' -ForegroundColor Green
Write-Host 'Proxy:  127.0.0.1:8080' -ForegroundColor Green
Write-Host 'Close the API and proxy PowerShell windows when finished; press Ctrl+C here to stop the UI.' -ForegroundColor Yellow
Push-Location (Join-Path $Root 'frontend')
try { npm run dev -- --host 127.0.0.1 }
finally { Pop-Location }
