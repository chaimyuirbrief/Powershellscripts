#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Uninstall Microsoft Edge (Chromium) using its own setup.exe uninstaller.

.DESCRIPTION
    The old version of this script deleted the entire
    "C:\Program Files (x86)\Microsoft" folder, which also contains WebView2,
    EdgeUpdate, EdgeCore and other components many apps depend on. That could
    break Teams, Office add-ins, and any app that hosts WebView2.

    This version instead invokes Edge's own setup.exe with the documented
    --uninstall flags, which is the supported way to remove it. It does NOT
    touch WebView2 (a separate runtime that other software relies on).

    Note: on most consumer Windows SKUs Microsoft blocks Edge uninstallation
    and setup.exe will refuse. In that case this script reports it and stops -
    it will not fall back to force-deleting shared folders.

.PARAMETER RemoveWebView2
    Also uninstall the Edge WebView2 Runtime. Off by default because other
    applications embed it; only use this if you know nothing depends on it.
#>
[CmdletBinding()]
param(
    [switch]$RemoveWebView2
)

function Get-EdgeSetup {
    # setup.exe lives under a versioned Application\<version>\Installer folder
    foreach ($base in @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application",
        "$env:ProgramFiles\Microsoft\Edge\Application"
    )) {
        if (Test-Path $base) {
            $setup = Get-ChildItem -Path $base -Recurse -Filter 'setup.exe' -ErrorAction SilentlyContinue |
                     Where-Object { $_.FullName -match '\\Installer\\setup\.exe$' } |
                     Sort-Object -Property @{ Expression = {
                         # Sort as a real version, not lexicographically ("10.0.9" > "10.0.10" as strings)
                         $v = $null
                         if ([version]::TryParse($_.VersionInfo.ProductVersion, [ref]$v)) { $v } else { [version]'0.0.0.0' }
                     } } -Descending |
                     Select-Object -First 1
            if ($setup) { return $setup.FullName }
        }
    }
    return $null
}

$setup = Get-EdgeSetup
if (-not $setup) {
    Write-Host "Microsoft Edge setup.exe not found - Edge may already be removed." -ForegroundColor Yellow
    return
}

Write-Host "Closing Edge processes..." -ForegroundColor Cyan
Get-Process -Name 'msedge', 'msedgewebview2' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "Uninstalling Microsoft Edge via: $setup" -ForegroundColor Cyan
$args = '--uninstall --system-level --verbose-logging --force-uninstall'
$proc = Start-Process -FilePath $setup -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
if ($proc.ExitCode -eq 0) {
    Write-Host "Edge uninstaller completed." -ForegroundColor Green
} else {
    Write-Host "Edge uninstaller returned exit code $($proc.ExitCode)." -ForegroundColor Yellow
    Write-Host "On most consumer Windows editions Microsoft blocks Edge removal - this is expected." -ForegroundColor Yellow
}

if ($RemoveWebView2) {
    Write-Host "`nUninstalling Edge WebView2 Runtime (requested)..." -ForegroundColor Cyan
    $uninstallKeys = @(
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $wv = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName -like '*WebView2*' -and $_.UninstallString }
    # On Windows PowerShell 5.1 `foreach ($x in $null)` runs ONCE with $x = $null,
    # so guard with if/else rather than looping over a possibly-null $wv.
    if (-not $wv) {
        Write-Host "WebView2 uninstall entry not found." -ForegroundColor Yellow
    } else {
        foreach ($w in $wv) {
            $cmd = $w.UninstallString
            if ($cmd -notmatch 'force-uninstall') { $cmd += ' --force-uninstall' }
            Write-Host "  $($w.DisplayName)" -ForegroundColor Gray
            Start-Process -FilePath 'cmd.exe' -ArgumentList "/d /s /c `"$cmd`"" -Wait -WindowStyle Hidden
        }
    }
}

Write-Host "`nDone. A reboot is recommended." -ForegroundColor Green
