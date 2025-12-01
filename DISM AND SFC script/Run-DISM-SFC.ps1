# Create log folder
$logPath = "C:\Logs"
$logFile = "$logPath\dism_sfc_log.txt"
if (-not (Test-Path $logPath)) {
    New-Item -ItemType Directory -Path $logPath | Out-Null
}

# Function to run command with live output and logging
function Run-Step {
    param (
        [string]$Command,
        [string]$Label
    )

    Write-Host "`n===== $Label =====" -ForegroundColor Cyan
    Add-Content -Path $logFile -Value "`n===== $Label =====`n"

    $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $Command" -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt" -NoNewWindow -PassThru
    $process.WaitForExit()

    Get-Content "stdout.txt" | Tee-Object -FilePath $logFile -Append
    Get-Content "stderr.txt" | Tee-Object -FilePath $logFile -Append

    Remove-Item "stdout.txt","stderr.txt" -ErrorAction SilentlyContinue
}

# Run DISM and SFC in order
Run-Step "dism /online /cleanup-image /scanhealth"     "DISM: ScanHealth"
Run-Step "dism /online /cleanup-image /checkhealth"    "DISM: CheckHealth"
Run-Step "dism /online /cleanup-image /restorehealth"  "DISM: RestoreHealth"
Run-Step "sfc /scannow"                                "SFC: System File Check"

Write-Host "`nAll steps completed. Log saved to $logFile." -ForegroundColor Green
