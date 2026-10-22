$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
$Python = Join-Path $Root '.venv\Scripts\python.exe'
Write-Host 'Starting WebScope API on http://127.0.0.1:8000' -ForegroundColor Cyan
& $Python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
