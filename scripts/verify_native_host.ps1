# Aegis - Native Messaging Host Diagnostic
#
# Answers one question: can the browser actually launch the Aegis host?
#
# "Specified native messaging host not found" gives no detail about WHICH link
# in the chain broke, and the extension's fail-closed policy turns that single
# failure into "every download is blocked" - a symptom that looks nothing like
# its cause. This walks the whole chain the way the browser does and names the
# broken link.
#
# Usage:  .\verify_native_host.ps1 [-ExtensionId <id>]

[CmdletBinding()]
param([string]$ExtensionId)

$HostName = "com.aegis.sandbox"

$Browsers = @(
    @{ Name = "Chrome";   Reg = "HKCU:\Software\Google\Chrome\NativeMessagingHosts";               UserData = "$env:LOCALAPPDATA\Google\Chrome\User Data";               Proc = "chrome" }
    @{ Name = "Chromium"; Reg = "HKCU:\Software\Chromium\NativeMessagingHosts";                    UserData = "$env:LOCALAPPDATA\Chromium\User Data";                    Proc = "chrome" }
    @{ Name = "Brave";    Reg = "HKCU:\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts"; UserData = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"; Proc = "brave" }
    @{ Name = "Edge";     Reg = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts";              UserData = "$env:LOCALAPPDATA\Microsoft\Edge\User Data";              Proc = "msedge" }
    @{ Name = "Vivaldi";  Reg = "HKCU:\Software\Vivaldi\NativeMessagingHosts";                     UserData = "$env:LOCALAPPDATA\Vivaldi\User Data";                     Proc = "vivaldi" }
)

function Say($ok, $msg) {
    if ($ok) { Write-Host "  [ ok ] $msg" -ForegroundColor Green }
    else     { Write-Host "  [FAIL] $msg" -ForegroundColor Red }
    return $ok
}

Write-Host "Aegis native messaging host diagnostic" -ForegroundColor Cyan
Write-Host ""

# --- 1. Which browsers are present, and is one holding stale state? ---------
Write-Host "Browsers detected:" -ForegroundColor Cyan
$present = @()
foreach ($b in $Browsers) {
    if (-not (Test-Path $b.UserData)) { continue }
    $present += $b
    $running = @(Get-Process $b.Proc -ErrorAction SilentlyContinue).Count
    $regOk = Test-Path "$($b.Reg)\$HostName"
    $state = if ($regOk) { "registered" } else { "NOT REGISTERED" }
    $run   = if ($running) { "$running process(es) running" } else { "not running" }
    Write-Host ("  {0,-10} {1,-16} {2}" -f $b.Name, $state, $run)
}
if (-not $present) {
    Write-Host "  none found" -ForegroundColor Red
    exit 1
}
Write-Host ""

# --- 2. Walk the chain for each registered browser --------------------------
$anyGood = $false
foreach ($b in $present) {
    $key = "$($b.Reg)\$HostName"
    if (-not (Test-Path $key)) { continue }

    Write-Host "$($b.Name):" -ForegroundColor Cyan
    $ok = $true

    $manifestPath = (Get-ItemProperty $key)."(default)"
    $ok = (Say ($null -ne $manifestPath) "registry key -> $manifestPath") -and $ok
    if (-not $manifestPath) { continue }

    if (-not (Say (Test-Path $manifestPath) "manifest file exists")) { Write-Host ""; continue }

    $bytes = [System.IO.File]::ReadAllBytes($manifestPath)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $ok = (Say (-not $hasBom) "no UTF-8 BOM (a BOM can make the parser reject it)") -and $ok

    try {
        $j = [System.IO.File]::ReadAllText($manifestPath) | ConvertFrom-Json
        $ok = (Say $true "valid JSON") -and $ok
    } catch {
        Say $false "JSON parse failed: $($_.Exception.Message)" | Out-Null
        Write-Host ""
        continue
    }

    $ok = (Say ($j.name -eq $HostName) "manifest name matches registry key") -and $ok
    $ok = (Say ($j.type -eq "stdio") "type is stdio") -and $ok
    $ok = (Say ($j.path -and (Test-Path $j.path)) "host binary exists: $($j.path)") -and $ok

    if ($ExtensionId) {
        $origin = "chrome-extension://$ExtensionId/"
        $ok = (Say ($j.allowed_origins -contains $origin) "allowed_origins contains $ExtensionId") -and $ok
    } else {
        Write-Host "  [info] allowed_origins: $($j.allowed_origins -join ', ')" -ForegroundColor DarkGray
    }

    # Config must be resolvable or the host exits at startup.
    $cfg = Join-Path (Split-Path -Parent $j.path) "aegis.toml"
    $ok = (Say (Test-Path $cfg) "aegis.toml next to the binary") -and $ok

    if ($ok) { $anyGood = $true }
    Write-Host ""
}

# --- 3. Did the host actually run? ------------------------------------------
Write-Host "Host activity:" -ForegroundColor Cyan
$log = Join-Path $env:LOCALAPPDATA "Aegis\aegis-host.log"
if (Test-Path $log) {
    $size = (Get-Item $log).Length
    Write-Host "  [ ok ] log exists ($size bytes) - the browser HAS launched the host" -ForegroundColor Green
    Write-Host "         $log" -ForegroundColor DarkGray
    Write-Host "  last 5 lines:" -ForegroundColor DarkGray
    Get-Content $log -Tail 5 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
} else {
    Write-Host "  [!!] NO LOG FILE - the browser has never launched the host." -ForegroundColor Yellow
    Write-Host "       If the chain above is all [ok], the browser simply has not" -ForegroundColor Yellow
    Write-Host "       re-read the registry yet. It is read at browser startup, and" -ForegroundColor Yellow
    Write-Host "       closing the window is NOT enough - Edge and Chrome keep" -ForegroundColor Yellow
    Write-Host "       background processes alive." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "       Fix: browse to  edge://restart  (or chrome://restart)." -ForegroundColor Cyan
    Write-Host "       That fully restarts the browser and keeps your tabs." -ForegroundColor Cyan
}

Write-Host ""
if ($anyGood) {
    Write-Host "Registration chain is intact for at least one browser." -ForegroundColor Green
} else {
    Write-Host "Registration is broken - re-run install_native_host.ps1." -ForegroundColor Red
    exit 1
}
