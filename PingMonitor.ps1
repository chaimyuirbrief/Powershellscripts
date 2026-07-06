<#
Continuous ping monitor with timestamped logging.

Usage:
    .\PingMonitor.ps1                                     # ping 8.8.8.8 every second
    .\PingMonitor.ps1 -Target 192.168.1.1 -IntervalSeconds 5
#>
param(
    [string]$Target = '8.8.8.8',

    [ValidateRange(1, 3600)]
    [int]$IntervalSeconds = 1,

    [string]$LogDir = 'C:\pinglogs'
)

# Create log folder if it doesn't exist
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir | Out-Null
}
$logFile = Join-Path $LogDir "$Target ping logs.txt"

Write-Host "Pinging $Target every $IntervalSeconds second(s). Logging to $logFile - Ctrl+C to stop." -ForegroundColor Cyan

while ($true) {
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # one ping per loop - the same reply drives both the up/down check and the latency
    $reply = Test-Connection -ComputerName $Target -Count 1 -ErrorAction SilentlyContinue

    # PowerShell 7+ returns a reply object even on timeout (with a Status),
    # Windows PowerShell 5.1 returns nothing on failure.
    $status = $null
    if ($reply -and $reply.PSObject.Properties['Status']) { $status = "$($reply.Status)" }
    $ok = ($null -ne $reply) -and (($null -eq $status) -or ($status -eq 'Success'))

    if ($ok) {
        # 5.1 exposes ResponseTime; 7+ exposes Latency
        $latency = $reply.ResponseTime
        if ($null -eq $latency) { $latency = $reply.Latency }
        $logLine = "$timestamp | True | ${latency}ms"
        Write-Host "$timestamp - Reply from ${Target}: time=${latency}ms" -ForegroundColor Green
    } else {
        $logLine = "$timestamp | False"
        Write-Host "$timestamp - Request timed out." -ForegroundColor Red
    }

    Add-Content -Path $logFile -Value $logLine
    Start-Sleep -Seconds $IntervalSeconds
}
