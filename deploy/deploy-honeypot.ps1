# Kurukshetra — Windows local deploy script (points to Render backend)
# Usage: .\deploy\deploy-honeypot.ps1

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "=== Kurukshetra Honeypot Deploy ===" -ForegroundColor Cyan

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example" -ForegroundColor Yellow
}

Write-Host "Building Docker honeypot..." -ForegroundColor Green
docker compose up -d --build

Write-Host ""
Write-Host "Honeypot running:" -ForegroundColor Green
Write-Host "  SSH:  ssh root@localhost -p 2222"
Write-Host "  Web:  http://localhost:8080/login"
Write-Host "  API:  http://localhost:8080/api/clone/status"
Write-Host "  Backend: https://kurukshetra-backend.onrender.com"
Write-Host ""
Write-Host "Run demo: python demo_launcher.py --target 127.0.0.1"
Write-Host "Run attack: python attack.py --target 127.0.0.1 --scenario mixed --loop"
