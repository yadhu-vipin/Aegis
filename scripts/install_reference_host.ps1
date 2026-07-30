# Aegis - install the MINIMAL REFERENCE HOST (diagnostic only)
#
# Installs a trivial Python native messaging host under the name
# `com.aegis.echo`, alongside (not replacing) the real Aegis host.
#
# WHY: Edge has never launched the Aegis host. It reports "Can't find manifest"
# for a manifest that exists at a path the registry points to, and the Aegis
# binary - which logs on its very first statement - has never written a log.
# Every part of the registration verifies correct when inspected directly.
#
# This partitions the problem:
#   echo host LAUNCHES -> native messaging works; the fault is in the Aegis
#                         registration, and diffing the two manifests will
#                         show what.
#   echo host DOES NOT -> native messaging is broken for this Edge install
#                         generally. Nothing in Aegis is at fault and the fix
#                         is machine/browser configuration.
#
# It differs from Aegis in every dimension that could matter: Python not Rust,
# a .bat wrapper (so Edge goes through cmd.exe) not a direct .exe, its own host
# name and registry key, and no config file to fail on.
#
# Usage: .\install_reference_host.ps1 -ExtensionId <32-char id>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExtensionId
)

$ErrorActionPreference = "Stop"

if ($ExtensionId -notmatch '^[a-p]{32}$') {
    Write-Host "ERROR: '$ExtensionId' is not a valid extension ID (32 chars, a-p)." -ForegroundColor Red
    exit 1
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcPy     = Join-Path $ScriptDir "reference_host\echo_host.py"
$InstallDir = "C:\Aegis"
$HostName  = "com.aegis.echo"

if (-not (Test-Path $SrcPy)) {
    Write-Host "ERROR: $SrcPy not found." -ForegroundColor Red
    exit 1
}

# --- locate a real Python (not the Microsoft Store alias stub) -------------
$Python = $null
foreach ($c in @(
    "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
    "$env:ProgramFiles\Python312\python.exe"
)) { if (Test-Path $c) { $Python = $c; break } }

if (-not $Python) {
    $g = Get-ChildItem "$env:LOCALAPPDATA\Programs\Python" -Filter python.exe -Recurse -ErrorAction SilentlyContinue |
         Select-Object -First 1
    if ($g) { $Python = $g.FullName }
}
if (-not $Python) {
    Write-Host "ERROR: no real Python found (the WindowsApps alias is a stub, not an interpreter)." -ForegroundColor Red
    exit 1
}
Write-Host "Using Python: $Python" -ForegroundColor DarkGray

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $SrcPy (Join-Path $InstallDir "echo_host.py") -Force

# --- .bat wrapper: makes Edge launch us through cmd.exe --------------------
# This is deliberate. If Edge is failing to launch .exe hosts directly (there
# is a documented Edge policy that toggles exactly this behaviour), a .bat host
# would still work - and that difference is itself the diagnosis.
$BatPath = Join-Path $InstallDir "echo-host.bat"
$bat = @"
@echo off
"$Python" "$InstallDir\echo_host.py" %*
"@
[System.IO.File]::WriteAllText($BatPath, $bat, (New-Object System.Text.ASCIIEncoding))
Write-Host "  wrote $BatPath" -ForegroundColor DarkGray

# --- native messaging host manifest ---------------------------------------
$ManifestPath = Join-Path $InstallDir "$HostName.json"
$Manifest = [ordered]@{
    name            = $HostName
    description     = "Aegis minimal reference host (diagnostic)"
    path            = $BatPath
    type            = "stdio"
    allowed_origins = @("chrome-extension://$ExtensionId/")
}
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ManifestPath, ($Manifest | ConvertTo-Json -Depth 3), $Utf8NoBom)
Write-Host "  wrote $ManifestPath (UTF-8, no BOM)" -ForegroundColor DarkGray

# --- register for every installed Chromium browser ------------------------
$Hives = @(
    @{ Name = "Chrome";   Reg = "HKCU:\Software\Google\Chrome\NativeMessagingHosts";               UserData = "$env:LOCALAPPDATA\Google\Chrome\User Data" }
    @{ Name = "Brave";    Reg = "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts"; UserData = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
    @{ Name = "Edge";     Reg = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts";              UserData = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }
)
foreach ($h in $Hives) {
    if (-not (Test-Path $h.UserData)) { continue }
    $key = "$($h.Reg)\$HostName"
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name "(default)" -Value $ManifestPath
    $back = (Get-ItemProperty -Path $key)."(default)"
    if ($back -ne $ManifestPath) {
        Write-Host "ERROR: registry verification failed for $($h.Name)" -ForegroundColor Red
        exit 1
    }
    Write-Host "  registered for $($h.Name)" -ForegroundColor DarkGray
}

Remove-Item (Join-Path $InstallDir "echo-host.log") -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Reference host installed." -ForegroundColor Green
Write-Host "  name     : $HostName"
Write-Host "  manifest : $ManifestPath"
Write-Host "  launcher : $BatPath"
Write-Host ""
Write-Host "Next: edge://restart, then open the Aegis popup." -ForegroundColor Yellow
Write-Host "The banner tests BOTH hosts and reports each result." -ForegroundColor Yellow
Write-Host "Evidence file: $InstallDir\echo-host.log" -ForegroundColor Yellow
