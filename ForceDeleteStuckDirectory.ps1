#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Force-delete a stubborn directory or file, escalating through takeown /
    icacls and finally queueing locked items for deletion at next reboot.

.DESCRIPTION
    Safety features:
      - Refuses drive roots, protected system trees (Windows, ProgramData) and
        the immediate children of Program Files / user-profile roots.
      - Never follows a junction/symlink: a link target (or a link nested in the
        tree) is unlinked, never deleted through.
      - Grants Administrators (not Everyone) full control, so a file that can't
        be deleted is never left world-writable.

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

$item = Get-Item -LiteralPath $Path -Force
$full = $item.FullName.TrimEnd('\')

# --- Safety guard: containment check, not just an exact-match list ----------
function Test-AtOrUnder([string]$child, [string]$root) {
    if ([string]::IsNullOrEmpty($root)) { return $false }
    $root = $root.TrimEnd('\')
    return $child.Equals($root, [System.StringComparison]::OrdinalIgnoreCase) -or
           $child.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)
}

# Off-limits: these paths AND everything beneath them.
$hardRoots = @($env:windir, $env:ProgramData) |
    Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }

# Protected root + its immediate children only; deeper stuck folders are allowed
# so the tool stays useful (C:\Users\Bob\proj\locked is fine; C:\Users\Bob is not).
$shallowRoots = @(
    (Join-Path $env:SystemDrive 'Users'), $env:ProgramFiles, ${env:ProgramFiles(x86)}
) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }

$blocked = $false
if (($full -split '\\').Count -lt 3) { $blocked = $true }   # drive root / 2-segment path
foreach ($r in $hardRoots) { if (Test-AtOrUnder $full $r) { $blocked = $true; break } }
if (-not $blocked) {
    foreach ($r in $shallowRoots) {
        if (Test-AtOrUnder $full $r) {
            $rel = $full.Substring($r.Length).Trim('\')
            if ($rel -eq '' -or ($rel -split '\\').Count -le 1) { $blocked = $true }
            break
        }
    }
}
if ($blocked) {
    Write-Host "Refusing to delete protected path: $full" -ForegroundColor Red
    return
}

# --- Reparse-point handling -------------------------------------------------
function Test-IsReparsePoint([string]$p) {
    try { return (([System.IO.File]::GetAttributes($p) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) }
    catch { return $false }
}
function Remove-LinkOnly([string]$p) {
    if (Test-Path -LiteralPath $p -PathType Container) {
        cmd.exe /d /c "rd /q `"$p`"" 2>&1 | Out-Null    # unlink junction; does NOT touch target
        if (Test-Path -LiteralPath $p) { try { [System.IO.Directory]::Delete($p, $false) } catch { } }
    } else {
        try { [System.IO.File]::Delete($p) } catch { }
    }
}
function Remove-NestedReparsePoints([string]$dir) {
    foreach ($child in @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)) {
        if (Test-IsReparsePoint $child.FullName) { Remove-LinkOnly $child.FullName }
        elseif ($child.PSIsContainer) { Remove-NestedReparsePoints $child.FullName }
    }
}

# If the target itself is a link, unlink it only - never delete its target.
if (Test-IsReparsePoint $full) {
    Remove-LinkOnly $full
    if (-not (Test-Path -LiteralPath $full)) { Write-Host "Removed link (target untouched)." -ForegroundColor Green }
    else { Write-Host "Could not remove link: $full" -ForegroundColor Red }
    return
}

$isDir = Test-Path -LiteralPath $full -PathType Container

# Strip nested links first so takeown /R, icacls /T and Remove-Item -Recurse
# below can't traverse a junction into unrelated data (they follow them on 5.1).
if ($isDir) { Remove-NestedReparsePoints $full }

# Take ownership + grant Administrators (*S-1-5-32-544, SID-based for non-English
# Windows) full control. Not Everyone (*S-1-1-0): a surviving locked file must
# not be left world-writable. takeown /A makes Administrators the owner, so
# Administrators:F is enough for this elevated process to delete the tree.
if ($isDir) {
    takeown.exe /F "$full" /R /A /D Y 2>&1 | Out-Null
    icacls.exe "$full" /grant '*S-1-5-32-544:(OI)(CI)F' /T /C /Q 2>&1 | Out-Null
} else {
    takeown.exe /F "$full" /A 2>&1 | Out-Null
    icacls.exe "$full" /grant '*S-1-5-32-544:F' /C /Q 2>&1 | Out-Null
}

Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
if ((Test-Path -LiteralPath $full) -and $isDir) {
    cmd.exe /d /c "rd /s /q `"$full`"" 2>&1 | Out-Null
}

if (-not (Test-Path -LiteralPath $full)) {
    Write-Host "Gone." -ForegroundColor Green
    return
}

# Still here - locked by a running process. Queue for deletion at next reboot.
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
    # restore inherited ACLs so the ACE we added does not linger on a survivor
    icacls.exe "$full" /reset /T /C /Q 2>&1 | Out-Null
    Write-Host "Still present and could not be queued for deletion: $full" -ForegroundColor Red
}
