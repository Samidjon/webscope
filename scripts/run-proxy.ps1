$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
$Mitmdump = Join-Path $Root '.venv\Scripts\mitmdump.exe'
Write-Host 'Starting WebScope proxy on 127.0.0.1:8080' -ForegroundColor Cyan
Write-Host 'Only point this proxy at traffic you own or are authorized to test.' -ForegroundColor Yellow
& $Mitmdump --listen-host 127.0.0.1 --listen-port 8080 -s (Join-Path $Root 'backend\proxy_addon.py')
