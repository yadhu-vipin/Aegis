# Aegis — Release Build & Packaging Script
# Compiles aegis-host in release mode and packages shipping zip bundle.

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir = Split-Path -Parent $ScriptDir
$DistDir = "$RepoDir\dist"

Write-Host "Building Aegis Host in release mode..." -ForegroundColor Cyan

Set-Location "$RepoDir\aegis-host"
cargo build --release

Write-Host "Preparing release package in $DistDir..." -ForegroundColor Cyan

if (Test-Path $DistDir) {
    Remove-Item $DistDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path "$DistDir\aegis-host" | Out-Null
New-Item -ItemType Directory -Force -Path "$DistDir\extension" | Out-Null

Copy-Item "$RepoDir\aegis-host\target\release\aegis-host.exe" "$DistDir\aegis-host\" -ErrorAction SilentlyContinue
Copy-Item "$RepoDir\aegis.toml" "$DistDir\aegis-host\"
Copy-Item "$RepoDir\extension\*" "$DistDir\extension\" -Recurse
Copy-Item "$RepoDir\scripts\install_native_host.ps1" "$DistDir\"

Compress-Archive -Path "$DistDir\*" -DestinationPath "$RepoDir\aegis-v1.0.0-windows.zip" -Force

Write-Host "✅ Release bundle created: $RepoDir\aegis-v1.0.0-windows.zip" -ForegroundColor Green
