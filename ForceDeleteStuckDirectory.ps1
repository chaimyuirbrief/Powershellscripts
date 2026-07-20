#Requires -RunAsAdministrator
# Force-delete a stubborn folder or file.
# Set the path below, then run this in an ELEVATED PowerShell / ISE window.

$Target = 'C:\path\to\stuck\folder'      # <-- EDIT THIS, then run

if (-not (Test-Path -LiteralPath $Target)) {
    Write-Host "Not found - nothing to do." -ForegroundColor Yellow
    return
}

takeown /F "$Target" /R /A /D Y 2>&1 | Out-Null
icacls  "$Target" /grant "*S-1-5-32-544:(OI)(CI)F" /T /C /Q 2>&1 | Out-Null   # *S-1-5-32-544 = Administrators
Remove-Item -LiteralPath $Target -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $Target) { cmd /d /c "rd /s /q `"$Target`"" 2>&1 | Out-Null }

if (Test-Path -LiteralPath $Target) {
    Write-Host "Still present - something has it open. Reboot and run again." -ForegroundColor Yellow
} else {
    Write-Host "Gone." -ForegroundColor Green
}
