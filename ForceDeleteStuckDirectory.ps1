#Requires -RunAsAdministrator
$p = "pathofdirectory"
if (-not (Test-Path $p)) { Write-Host "Not found."; exit }

takeown /F "$p" /R /A /D Y 2>&1 | Out-Null
icacls "$p" /grant everyone:F /T /C /Q 2>&1 | Out-Null
Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path $p) { cmd /c rd /s /q "$p" }

if (Test-Path $p) {
    Write-Host "Still present - reboot and retry."
} else {
    Write-Host "Gone."
}
