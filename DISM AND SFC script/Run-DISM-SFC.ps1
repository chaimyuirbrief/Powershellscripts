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

    # Pipe to Out-Host so DISM/SFC output goes straight to the console (live,
    # correctly rendered) and does NOT flow into this function's output stream -
    # otherwise `return $code` would be preceded by every stdout line and the
    # caller's variable would be an object[], not the exit code.
    & $FilePath @Arguments | Out-Host
    $code = $LASTEXITCODE

    $result = "Exit code: $code"
    # 3010 = ERROR_SUCCESS_REBOOT_REQUIRED - a success, not a failure.
    if ($code -eq 0 -or $code -eq 3010) { Write-Host $result -ForegroundColor Green }
    else                                { Write-Host $result -ForegroundColor Yellow }
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
if ($restore -eq 3010) {
    Write-Host "DISM RestoreHealth succeeded but a reboot is required to finalize the repair (exit 3010). Please restart Windows." -ForegroundColor Yellow
}
elseif ($restore -ne 0) {
    Write-Host "DISM RestoreHealth did not report success (exit $restore). If it failed to find sources, retry with a mounted Windows ISO (adjust the file and index to match your media - use 'dism /Get-WimInfo' or '/Get-ImageInfo' to list them):" -ForegroundColor Yellow
    Write-Host "  dism /online /cleanup-image /restorehealth /source:ESD:X:\sources\install.esd:1 /limitaccess" -ForegroundColor Yellow
}
