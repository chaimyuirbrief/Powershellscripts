#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Force-delete a stubborn directory or file, escalating through takeown /
    icacls and finally queueing locked items for deletion at next reboot.

.EXAMPLE
    .\ForceDeleteStuckDirectory.ps1 -Path 'C:\Some\Stuck\Folder'
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

if (-not (Test-Path -LiteralPath $Path)) {
    Write-Host "Not found: $Path" -ForegroundColor Yellow
    return
}

$full = (Get-Item -LiteralPath $Path -Force).FullName.TrimEnd('\')

# Safety: never operate on a drive root or a top-level system folder.
$protected = @(
    $env:SystemDrive, $env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)},
    $env:ProgramData, (Join-Path $env:SystemDrive 'Users')
) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }
if ((($full -split '\\').Count -lt 3) -or ($protected -contains $full)) {
    Write-Host "Refusing to delete protected path: $full" -ForegroundColor Red
    return
}

$isDir = Test-Path -LiteralPath $full -PathType Container

# Take ownership + grant full control. *S-1-1-0 is the Everyone SID, which
# works on non-English Windows where the name "everyone" doesn't resolve.
if ($isDir) {
    takeown.exe /F "$full" /R /A /D Y 2>&1 | Out-Null
    icacls.exe "$full" /grant '*S-1-1-0:(OI)(CI)F' /T /C /Q 2>&1 | Out-Null
} else {
    takeown.exe /F "$full" /A 2>&1 | Out-Null
    icacls.exe "$full" /grant '*S-1-1-0:F' /C /Q 2>&1 | Out-Null
}

Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
if (-not (Test-Path -LiteralPath $full) -and $isDir) {
    cmd.exe /d /c "rd /s /q `"$full`"" 2>&1 | Out-Null
}

if (-not (Test-Path -LiteralPath $full)) {
    Write-Host "Gone." -ForegroundColor Green
    return
}

# Still here - it's locked by a running process. Queue for reboot deletion.
Add-Type -Namespace Win32 -Name PendingDelete -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
$targets = @()
if ($isDir) {
    $targets += @(Get-ChildItem -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue |
                  Sort-Object { $_.FullName.Length } -Descending |
                  Select-Object -ExpandProperty FullName)
}
$targets += $full
$queued = 0
foreach ($t in $targets) {
    if ([Win32.PendingDelete]::MoveFileEx($t, $null, 4)) { $queued++ }  # MOVEFILE_DELAY_UNTIL_REBOOT
}
if ($queued -gt 0) {
    Write-Host "Locked - $queued item(s) queued for deletion at next reboot. Reboot to finish." -ForegroundColor Yellow
} else {
    Write-Host "Still present and could not be queued for deletion: $full" -ForegroundColor Red
}
