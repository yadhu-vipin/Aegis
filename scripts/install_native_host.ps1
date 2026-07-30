# Aegis - Windows Native Messaging Host Installer
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

# Chromium-family browsers. Each looks ONLY in its own registry path for
# native messaging hosts, so registering under Google\Chrome alone silently
# fails on every other browser: connectNative() reports "host not found", no
# host process is ever spawned, and there is nothing in any log to explain it.
$Browsers = @(
    @{ Name = "Chrome";   Reg = "HKCU:\Software\Google\Chrome\NativeMessagingHosts";                UserData = "$env:LOCALAPPDATA\Google\Chrome\User Data";              Exe = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe" }
    @{ Name = "Chromium"; Reg = "HKCU:\Software\Chromium\NativeMessagingHosts";                     UserData = "$env:LOCALAPPDATA\Chromium\User Data";                   Exe = "$env:ProgramFiles\Chromium\Application\chrome.exe" }
    @{ Name = "Brave";    Reg = "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts";  UserData = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"; Exe = "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe" }
    @{ Name = "Edge";     Reg = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts";               UserData = "$env:LOCALAPPDATA\Microsoft\Edge\User Data";             Exe = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" }
    @{ Name = "Vivaldi";  Reg = "HKCU:\Software\Vivaldi\NativeMessagingHosts";                      UserData = "$env:LOCALAPPDATA\Vivaldi\User Data";                    Exe = "$env:LOCALAPPDATA\Vivaldi\Application\vivaldi.exe" }
)

function Get-InstalledBrowsers {
    # Presence of the user-data directory is the reliable signal: it exists
    # once the browser has been run, regardless of install location, and it is
    # also where we look up the extension ID.
    $Browsers | Where-Object { (Test-Path $_.UserData) -or (Test-Path $_.Exe) }
}

function Find-ExtensionIdFromChrome([string]$unpackedPath) {
    $prefsCandidates = @()
    foreach ($b in Get-InstalledBrowsers) {
        if (-not (Test-Path $b.UserData)) { continue }
        Get-ChildItem $b.UserData -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq "Default" -or $_.Name -like "Profile *" } |
            ForEach-Object { $prefsCandidates += (Join-Path $_.FullName "Preferences") }
    }

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
# Register in the Windows registry - for EVERY installed Chromium browser
# ---------------------------------------------------------------------------
# The key's DEFAULT value is the full path to the manifest. HKCU needs no admin.
# Each browser reads only its own hive, so registering under Google\Chrome
# alone leaves Brave/Edge/Vivaldi users with a connectNative() that fails and
# no diagnostic anywhere.
$installed = Get-InstalledBrowsers
if (-not $installed) {
    Write-Host "ERROR: no Chromium-family browser found." -ForegroundColor Red
    Write-Host "  Looked for Chrome, Chromium, Brave, Edge and Vivaldi." -ForegroundColor Yellow
    exit 1
}

$registered = @()
foreach ($b in $installed) {
    $RegKey = "$($b.Reg)\$HostName"
    New-Item -Path $RegKey -Force | Out-Null
    Set-ItemProperty -Path $RegKey -Name "(default)" -Value $ManifestPath

    # Read back rather than trusting the write.
    $readBack = (Get-ItemProperty -Path $RegKey)."(default)"
    if ($readBack -ne $ManifestPath) {
        Write-Host "ERROR: registry verification failed for $($b.Name)." -ForegroundColor Red
        Write-Host "  expected: $ManifestPath"
        Write-Host "  got     : $readBack"
        exit 1
    }
    $registered += $b.Name
    Write-Host "  Registered for $($b.Name)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Installation complete." -ForegroundColor Green
Write-Host "  Browsers : $($registered -join ', ')" -ForegroundColor DarkGray
Write-Host "  Manifest : $ManifestPath" -ForegroundColor DarkGray
Write-Host "  Binary   : $HostBinary" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Fully quit and reopen your browser for this to take effect." -ForegroundColor Yellow
Write-Host "(Closing the window is not enough - the registry is read at startup.)" -ForegroundColor Yellow
