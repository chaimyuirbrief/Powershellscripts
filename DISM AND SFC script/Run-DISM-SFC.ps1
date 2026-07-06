#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Run the standard Windows image/system repair sequence:
    DISM ScanHealth -> CheckHealth -> RestoreHealth, then SFC /scannow.

.DESCRIPTION
    Each step runs with live output in the console (progress renders correctly).
    A timestamped summary with each step's exit code is written to the log.

    DISM and SFC keep their own detailed logs; this script points you at them:
      DISM : C:\Windows\Logs\DISM\dism.log
      SFC  : C:\Windows\Logs\CBS\CBS.log
#>
[CmdletBinding()]
param(
    [string]$LogPath = 'C:\Logs'
)

if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}
$logFile = Join-Path $LogPath 'dism_sfc_log.txt'

function Run-Step {
    param(
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$Label
    )

    $header = "`n===== $Label  ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) ====="
    Write-Host $header -ForegroundColor Cyan
    Add-Content -Path $logFile -Value $header

    # Run inheriting the console so DISM/SFC progress displays live and their
    # native Unicode output is not mangled by pipe redirection.
    & $FilePath @Arguments
    $code = $LASTEXITCODE

    $result = "Exit code: $code"
    if ($code -eq 0) { Write-Host $result -ForegroundColor Green }
    else             { Write-Host $result -ForegroundColor Yellow }
    Add-Content -Path $logFile -Value $result
    return $code
}

Add-Content -Path $logFile -Value "===== DISM/SFC run started $(Get-Date) ====="

Run-Step 'dism.exe' @('/online', '/cleanup-image', '/scanhealth')    'DISM: ScanHealth'    | Out-Null
Run-Step 'dism.exe' @('/online', '/cleanup-image', '/checkhealth')   'DISM: CheckHealth'   | Out-Null
$restore = Run-Step 'dism.exe' @('/online', '/cleanup-image', '/restorehealth') 'DISM: RestoreHealth'
Run-Step 'sfc.exe'  @('/scannow')                                    'SFC: System File Check' | Out-Null

Write-Host "`nAll steps completed. Summary log: $logFile" -ForegroundColor Green
Write-Host "Detailed logs: C:\Windows\Logs\DISM\dism.log  and  C:\Windows\Logs\CBS\CBS.log" -ForegroundColor Gray
if ($restore -ne 0) {
    Write-Host "DISM RestoreHealth did not report success (exit $restore). If it failed to find sources, retry with a mounted Windows ISO:" -ForegroundColor Yellow
    Write-Host "  dism /online /cleanup-image /restorehealth /source:ESD:X:\sources\install.esd:1 /limitaccess" -ForegroundColor Yellow
}
