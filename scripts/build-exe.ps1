$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

python -m PyInstaller `
  --onefile `
  --console `
  --name BrowserJanitor `
  --clean `
  browser_janitor_launcher.py

Write-Host "Built dist\BrowserJanitor.exe"
