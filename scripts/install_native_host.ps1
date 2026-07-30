# Aegis — Windows Native Messaging Host Installer
# Registers com.aegis.sandbox as a Chrome Native Messaging host.
#
# Usage:
#   .\install_native_host.ps1                          # auto-detect extension ID
#   .\install_native_host.ps1 -ExtensionId abcdef...   # supply it explicitly
#
# The extension ID must be the REAL id Chrome assigned to the unpacked
# extension. Load extension/ via chrome://extensions (Developer mode ->
# "Load unpacked") first, then either pass -ExtensionId or let this script
# read it out of Chrome's Preferences file.

[CmdletBinding()]
param(
    [string]$ExtensionId,
    [switch]$Debug_Build
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoDir   = Split-Path -Parent $ScriptDir
$HostName  = "com.aegis.sandbox"
$ExtDir    = Join-Path $RepoDir "extension"

$InstallDir   = Join-Path $env:LOCALAPPDATA "Aegis"
$HostBinary   = Join-Path $InstallDir "aegis-host.exe"
$ManifestPath = Join-Path $InstallDir "$HostName.json"

# ---------------------------------------------------------------------------
# Resolve the extension ID
# ---------------------------------------------------------------------------
# Chrome extension IDs are exactly 32 characters drawn from 'a'-'p' (a
# base-16 alphabet shifted into letters). The previous placeholder,
# "aegisdownloadguardextensionid", is 29 chars and contains r/s/t/u/w/x/z, so
# it could never match a real extension and connectNative() always failed.
function Test-ExtensionId([string]$id) {
    return $id -cmatch '^[a-p]{32}$'
}

function Find-ExtensionIdFromChrome([string]$unpackedPath) {
    $prefsCandidates = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 1\Preferences"
    )
    $target = (Resolve-Path $unpackedPath -ErrorAction SilentlyContinue).Path
    if (-not $target) { return $null }

    foreach ($prefs in $prefsCandidates) {
        if (-not (Test-Path $prefs)) { continue }
        try {
            $json = Get-Content $prefs -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch { continue }
        $settings = $json.extensions.settings
        if (-not $settings) { continue }
        foreach ($prop in $settings.PSObject.Properties) {
            $p = $prop.Value.path
            if (-not $p) { continue }
            # Unpacked extensions store an absolute path here.
            if ($p -and (Test-Path $p -ErrorAction SilentlyContinue)) {
                $resolved = (Resolve-Path $p -ErrorAction SilentlyContinue).Path
                if ($resolved -eq $target -and (Test-ExtensionId $prop.Name)) {
                    Write-Host "  Auto-detected extension ID from $prefs" -ForegroundColor DarkGray
                    return $prop.Name
                }
            }
        }
    }
    return $null
}

if (-not $ExtensionId) {
    Write-Host "No -ExtensionId given; attempting auto-detection..." -ForegroundColor Cyan
    $ExtensionId = Find-ExtensionIdFromChrome $ExtDir
}

if (-not $ExtensionId -or -not (Test-ExtensionId $ExtensionId)) {
    Write-Host ""
    Write-Host "ERROR: no valid Chrome extension ID." -ForegroundColor Red
    Write-Host ""
    Write-Host "  A Chrome extension ID is exactly 32 characters, all in a-p." -ForegroundColor Yellow
    if ($ExtensionId) {
        Write-Host "  Got: '$ExtensionId' ($($ExtensionId.Length) chars)" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  To fix:" -ForegroundColor Yellow
    Write-Host "    1. Open chrome://extensions and enable Developer mode"
    Write-Host "    2. 'Load unpacked' -> select: $ExtDir"
    Write-Host "    3. Copy the ID shown on the extension card"
    Write-Host "    4. Re-run: .\install_native_host.ps1 -ExtensionId <id>"
    Write-Host ""
    Write-Host "  Registering with a wrong ID fails SILENTLY at runtime -" -ForegroundColor Yellow
    Write-Host "  connectNative() just never connects. Refusing to do that." -ForegroundColor Yellow
    exit 1
}

Write-Host "Installing Aegis Native Host to $InstallDir..." -ForegroundColor Cyan
Write-Host "  Extension ID: $ExtensionId" -ForegroundColor DarkGray

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# ---------------------------------------------------------------------------
# Copy binary + config
# ---------------------------------------------------------------------------
$Profile_ = if ($Debug_Build) { "debug" } else { "release" }
$SourceBinary = Join-Path $RepoDir "aegis-host\target\$Profile_\aegis-host.exe"

if (Test-Path $SourceBinary) {
    Copy-Item $SourceBinary $HostBinary -Force
    Write-Host "  Copied $Profile_ binary" -ForegroundColor DarkGray
} else {
    Write-Host ""
    Write-Host "ERROR: host binary not found at:" -ForegroundColor Red
    Write-Host "  $SourceBinary"
    Write-Host ""
    Write-Host "  Build it first:  cargo build --$Profile_" -ForegroundColor Yellow
    Write-Host "  (or pass -Debug_Build to install a debug build)" -ForegroundColor Yellow
    exit 1
}

$SourceConfig = Join-Path $RepoDir "aegis.toml"
if (Test-Path $SourceConfig) {
    Copy-Item $SourceConfig (Join-Path $InstallDir "aegis.toml") -Force
    Write-Host "  Copied aegis.toml" -ForegroundColor DarkGray
} else {
    Write-Host "ERROR: aegis.toml not found at $SourceConfig" -ForegroundColor Red
    Write-Host "  The host fails fast without it and will not start." -ForegroundColor Yellow
    exit 1
}

# ---------------------------------------------------------------------------
# Write the host manifest
# ---------------------------------------------------------------------------
$Manifest = [ordered]@{
    name            = $HostName
    description     = "Aegis download sandbox native messaging host"
    path            = $HostBinary
    type            = "stdio"
    allowed_origins = @("chrome-extension://$ExtensionId/")
}

$Json = $Manifest | ConvertTo-Json -Depth 3

# Write WITHOUT a BOM. PowerShell 5.1's `Set-Content -Encoding UTF8` and
# `Out-File -Encoding utf8` both emit a UTF-8 BOM, and Chrome's manifest
# parser can reject the file outright when one is present - another failure
# that surfaces only as "connectNative() silently does nothing".
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ManifestPath, $Json, $Utf8NoBom)

# Verify no BOM actually got written.
$firstBytes = [System.IO.File]::ReadAllBytes($ManifestPath) | Select-Object -First 3
if ($firstBytes.Count -ge 3 -and $firstBytes[0] -eq 0xEF -and $firstBytes[1] -eq 0xBB -and $firstBytes[2] -eq 0xBF) {
    Write-Host "ERROR: manifest was written with a BOM; Chrome may reject it." -ForegroundColor Red
    exit 1
}
Write-Host "  Wrote manifest (UTF-8, no BOM)" -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# Register in the Windows registry
# ---------------------------------------------------------------------------
# Per Chrome's native messaging docs the key is either
#   HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts\<name>   (all users)
#   HKCU\Software\Google\Chrome\NativeMessagingHosts\<name>   (current user)
# and its DEFAULT value is the full path to the manifest. HKCU needs no admin.
$RegKey = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
New-Item -Path $RegKey -Force | Out-Null
Set-ItemProperty -Path $RegKey -Name "(default)" -Value $ManifestPath

# Read it back rather than trusting the write.
$readBack = (Get-ItemProperty -Path $RegKey)."(default)"
if ($readBack -ne $ManifestPath) {
    Write-Host "ERROR: registry verification failed." -ForegroundColor Red
    Write-Host "  expected: $ManifestPath"
    Write-Host "  got     : $readBack"
    exit 1
}

Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
Write-Host "  Registry : $RegKey" -ForegroundColor DarkGray
Write-Host "  Manifest : $ManifestPath" -ForegroundColor DarkGray
Write-Host "  Binary   : $HostBinary" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Restart Chrome for the registration to take effect." -ForegroundColor Yellow
