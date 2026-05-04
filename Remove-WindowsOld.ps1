#Requires -RunAsAdministrator
$p = "C:\Windows.old"
if (-not (Test-Path $p)) { Write-Host "Not found."; exit }

takeown /F "$p" /R /A /D Y 2>&1 | Out-Null
icacls "$p" /grant everyone:F /T /C /Q 2>&1 | Out-Null

Remove-Item $p -Recurse -Force -EA SilentlyContinue
if (Test-Path $p) { cmd /c rd /s /q "$p" }

Write-Host (if (Test-Path $p) { "Still present — reboot and retry." } else { "Gone." })
