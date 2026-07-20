#Requires -RunAsAdministrator
# =====================================================================
#  Force-delete a stubborn folder or file.
#    1) Put the path you want gone on the $Target line below.
#    2) Run the whole script in an ELEVATED PowerShell / ISE window.
# =====================================================================

$Target = 'C:\path\to\stuck\folder'          # <-- EDIT THIS, then run

# ---- nothing below needs editing ------------------------------------

if (-not (Test-Path -LiteralPath $Target)) {
    Write-Host "Not found - nothing to do: $Target" -ForegroundColor Yellow
    return
}
$full = (Get-Item -LiteralPath $Target -Force).FullName.TrimEnd('\')

# Guard: a typo on the $Target line must not wipe a drive root or a system tree.
$protected = @("$env:SystemDrive\", $env:windir, $env:ProgramData,
               "$env:SystemDrive\Users", $env:ProgramFiles, ${env:ProgramFiles(x86)}) |
             Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() }
if (($full -split '\\').Count -lt 3 -or $protected -contains $full.ToLower()) {
    Write-Host "Refusing to delete protected path: $full" -ForegroundColor Red
    return
}

function Test-IsLink($p) {
    try { ([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -ne 0 } catch { $false }
}

# A junction/symlink is UNLINKED, never followed - otherwise Windows PowerShell
# 5.1 deletes the real data it points at. Handle the target itself first...
if (Test-IsLink $full) {
    cmd /d /c "rd /q `"$full`"" 2>&1 | Out-Null
    if (Test-Path -LiteralPath $full) { try { [IO.File]::Delete($full) } catch {} }
    if (Test-Path -LiteralPath $full) { Write-Host "Could not remove link: $full" -ForegroundColor Red }
    else { Write-Host "Removed the link; its target was left untouched." -ForegroundColor Green }
    return
}

# ...then any links nested inside, so the ownership/permission/delete passes
# below can't walk a junction out into unrelated data.
function Clear-NestedLinks($dir) {
    foreach ($c in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
        if (Test-IsLink $c.FullName) {
            cmd /d /c "rd /q `"$($c.FullName)`"" 2>&1 | Out-Null
            if (Test-Path -LiteralPath $c.FullName) { try { [IO.File]::Delete($c.FullName) } catch {} }
        } elseif ($c.PSIsContainer) { Clear-NestedLinks $c.FullName }
    }
}
$isDir = Test-Path -LiteralPath $full -PathType Container
if ($isDir) { Clear-NestedLinks $full }

# Take ownership + grant Administrators (NOT Everyone) full control. The grant is
# by SID so it resolves on any locale, and Administrators-only so a locked
# survivor is never left world-writable.
if ($isDir) {
    takeown /F "$full" /R /A /D Y 2>&1 | Out-Null
    icacls  "$full" /grant "*S-1-5-32-544:(OI)(CI)F" /T /C /Q 2>&1 | Out-Null
} else {
    takeown /F "$full" /A 2>&1 | Out-Null
    icacls  "$full" /grant "*S-1-5-32-544:F" /C /Q 2>&1 | Out-Null
}

# Delete: PowerShell first, then cmd's rd with a \\?\ long-path prefix as backup.
Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
if ((Test-Path -LiteralPath $full) -and $isDir) {
    $rd = if ($full -match '^[A-Za-z]:\\') { '\\?\' + $full } else { $full }
    cmd /d /c "rd /s /q `"$rd`"" 2>&1 | Out-Null
}

if (Test-Path -LiteralPath $full) {
    icacls "$full" /reset /T /C /Q 2>&1 | Out-Null   # don't leave our permission change behind
    Write-Host "Still present - something has it open. Reboot and run this again." -ForegroundColor Yellow
} else {
    Write-Host "Gone." -ForegroundColor Green
}
