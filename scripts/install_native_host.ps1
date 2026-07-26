# Aegis — Windows Native Messaging Host Installer
# Registers com.aegis.sandbox Native Host for Google Chrome via Windows Registry.

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir = Split-Path -Parent $ScriptDir
$HostName = "com.aegis.sandbox"

$InstallDir = "$env:LOCALAPPDATA\Aegis"
$HostBinary = "$InstallDir\aegis-host.exe"
$ManifestPath = "$InstallDir\$HostName.json"

Write-Host "Installing Aegis Native Host to $InstallDir..." -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Copy binary & config
$ReleaseBinary = "$RepoDir\aegis-host\target\release\aegis-host.exe"
if (Test-Path $ReleaseBinary) {
    Copy-Item $ReleaseBinary $HostBinary -Force
} else {
    Write-Warning "Release binary not found at $ReleaseBinary. Please run cargo build --release first."
}

if (Test-Path "$RepoDir\aegis.toml") {
    Copy-Item "$RepoDir\aegis.toml" "$InstallDir\aegis.toml" -Force
}

# Create Manifest
$ManifestContent = @{
    name = $HostName
    description = "Aegis Host Sandbox Native Messaging Host"
    path = $HostBinary
    type = "stdio"
    allowed_origins = @(
        "chrome-extension://aegisdownloadguardextensionid/"
    )
} | ConvertTo-Json -Depth 3

Set-Content -Path $ManifestPath -Value $ManifestContent -Encoding UTF8

# Register in Windows Registry
$RegKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
New-Item -Path $RegKey -Force | Out-Null
Set-ItemProperty -Path $RegKey -Name "(default)" -Value $ManifestPath

Write-Host "Registered registry key: $RegKey -> $ManifestPath" -ForegroundColor Green
Write-Host "✅ Installation complete." -ForegroundColor Green
