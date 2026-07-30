# Aegis - capture what the browser ACTUALLY says about native messaging
#
# Chromium only writes native-messaging failures to its debug log, and that log
# is off by default. Without it you get the extension's second-hand view
# ("host not found") with no indication of which link broke. This turns that
# into first-hand evidence.
#
# Two phases, because you have to reproduce the failure in between:
#
#   .\diagnose_native_messaging.ps1            # phase 1: relaunch with logging
#   ...reproduce (open the Aegis popup, or download something)...
#   .\diagnose_native_messaging.ps1 -Analyze   # phase 2: extract the verdict
#
# Phase 1 closes the browser. Tabs are restored on relaunch, but save anything
# unsaved first.

[CmdletBinding()]
param(
    [switch]$Analyze,
    [ValidateSet("Edge", "Brave")][string]$Browser = "Edge"
)

$Config = @{
    Edge  = @{ Proc = "msedge"; Exe = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"; UserData = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }
    Brave = @{ Proc = "brave";  Exe = "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe"; UserData = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" }
}[$Browser]

$LogPath = Join-Path $Config.UserData "chrome_debug.log"

# ---------------------------------------------------------------------------
# Phase 2 - analyse
# ---------------------------------------------------------------------------
if ($Analyze) {
    if (-not (Test-Path $LogPath)) {
        Write-Host "No log at $LogPath" -ForegroundColor Red
        Write-Host "Run this script WITHOUT -Analyze first, then reproduce." -ForegroundColor Yellow
        exit 1
    }

    $size = [math]::Round((Get-Item $LogPath).Length / 1MB, 1)
    Write-Host "Reading $LogPath (${size} MB)..." -ForegroundColor Cyan
    Write-Host ""

    # Only lines that bear on native messaging. The debug log is overwhelmingly
    # unrelated noise (telemetry, page metadata, wallet), so filter hard.
    $patterns = @(
        'native.messaging',
        'native_message',
        'launch_context',
        'NativeMessag',
        'com\.aegis',
        '\[Aegis\]'
    )
    $rx = ($patterns -join '|')

    $hits = Select-String -Path $LogPath -Pattern $rx -AllMatches -ErrorAction SilentlyContinue

    if (-not $hits) {
        Write-Host "NO native-messaging lines at all." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "That means the extension never called connectNative during this" -ForegroundColor Yellow
        Write-Host "session - so the service worker probably did not start. Open the" -ForegroundColor Yellow
        Write-Host "Aegis popup (that wakes it) and re-run with -Analyze." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "=== native-messaging lines ($($hits.Count) found) ===" -ForegroundColor Cyan
    Write-Host ""
    foreach ($h in $hits) {
        $line = $h.Line
        if ($line.Length -gt 300) { $line = $line.Substring(0, 300) + "..." }

        $colour = "Gray"
        if ($line -match "Can't find manifest")          { $colour = "Red" }
        elseif ($line -match "ERROR|Failed|forbidden")   { $colour = "Red" }
        elseif ($line -match "ECHO_PONG|PONG|reachable") { $colour = "Green" }
        elseif ($line -match "WARNING")                  { $colour = "Yellow" }

        Write-Host $line -ForegroundColor $colour
    }

    Write-Host ""
    Write-Host "=== interpretation ===" -ForegroundColor Cyan
    $all = ($hits | ForEach-Object { $_.Line }) -join "`n"

    if ($all -match "com\.aegis\.echo" -and $all -notmatch "Can't find manifest for native messaging host com\.aegis\.echo") {
        Write-Host "  The REFERENCE host was reached." -ForegroundColor Green
        Write-Host "  Native messaging works here - the fault is specific to the" -ForegroundColor Green
        Write-Host "  Aegis registration. Diff the two manifests in C:\Aegis\." -ForegroundColor Green
    }
    elseif ($all -match "Can't find manifest") {
        Write-Host "  'Can't find manifest' for a manifest that provably exists at a" -ForegroundColor Red
        Write-Host "  path the registry provably points to." -ForegroundColor Red
        Write-Host ""
        Write-Host "  Chromium reports this when it does not consult the registry" -ForegroundColor Yellow
        Write-Host "  location we wrote - which happens when user-level native hosts" -ForegroundColor Yellow
        Write-Host "  are disabled by policy. HKCU is skipped entirely and only HKLM" -ForegroundColor Yellow
        Write-Host "  is searched." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Next: register under HKLM (needs admin), or switch the host to" -ForegroundColor Yellow
        Write-Host "  a 127.0.0.1 HTTP transport, which policy cannot block." -ForegroundColor Yellow
    }
    elseif ($all -match "forbidden") {
        Write-Host "  'Forbidden' - the manifest WAS found but the extension's origin" -ForegroundColor Yellow
        Write-Host "  is not in allowed_origins. Re-run install_native_host.ps1 with" -ForegroundColor Yellow
        Write-Host "  the ID shown on the extension's card." -ForegroundColor Yellow
    }
    elseif ($all -match "Failed to start") {
        Write-Host "  'Failed to start' - manifest found, binary refused to launch." -ForegroundColor Yellow
        Write-Host "  Check antivirus and application-control policy for the exe." -ForegroundColor Yellow
    }
    exit 0
}

# ---------------------------------------------------------------------------
# Phase 1 - relaunch with logging
# ---------------------------------------------------------------------------
if (-not (Test-Path $Config.Exe)) {
    Write-Host "ERROR: $Browser not found at $($Config.Exe)" -ForegroundColor Red
    exit 1
}

$running = @(Get-Process $Config.Proc -ErrorAction SilentlyContinue)
if ($running.Count) {
    Write-Host "Closing $Browser ($($running.Count) processes)..." -ForegroundColor Yellow
    Write-Host "  Tabs are restored on relaunch." -ForegroundColor DarkGray
    $running | Stop-Process -Force -ErrorAction SilentlyContinue
    # Give the browser a moment to release its files before we delete the log.
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline -and @(Get-Process $Config.Proc -ErrorAction SilentlyContinue).Count) {
        Start-Sleep -Milliseconds 300
    }
}

Remove-Item $LogPath -Force -ErrorAction SilentlyContinue
Write-Host "Cleared $LogPath" -ForegroundColor DarkGray

# Clear host logs too, so anything present afterwards is unambiguous evidence.
Remove-Item "C:\Aegis\aegis-host.log", "C:\Aegis\echo-host.log" -Force -ErrorAction SilentlyContinue

Write-Host "Starting $Browser with logging enabled..." -ForegroundColor Cyan
Start-Process $Config.Exe -ArgumentList "--enable-logging", "--v=1"

Write-Host ""
Write-Host "Now reproduce the failure:" -ForegroundColor Yellow
Write-Host "  1. Open the Aegis extension popup (this wakes the service worker)" -ForegroundColor Yellow
Write-Host "  2. Optionally download any file" -ForegroundColor Yellow
Write-Host "  3. Wait ~10 seconds" -ForegroundColor Yellow
Write-Host ""
Write-Host "Then run:" -ForegroundColor Cyan
Write-Host "  .\scripts\diagnose_native_messaging.ps1 -Analyze" -ForegroundColor White
