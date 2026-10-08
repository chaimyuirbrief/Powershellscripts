#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    ScreenConnect (ConnectWise Control) total removal - uninstall, wipe files,
    registry, services, and sweep the entire C: drive.

.DESCRIPTION
    Removes every trace of ScreenConnect / ConnectWise Control:

      1. Runs every ScreenConnect uninstaller registered in the registry
      2. Kills any related processes still running
      3. Stops and deletes ScreenConnect services
      4. Removes related scheduled tasks
      5. Force-deletes known ScreenConnect folders, escalating through
         takeown/icacls and queueing locked files for reboot deletion
      6. Deletes ScreenConnect registry keys and autorun entries
      7. Sweeps the entire system drive for anything named *screenconnect*
         and permanently deletes it - no backup, no exceptions

    A transcript is written to %TEMP% (path printed at the end).

.PARAMETER Force
    Skip the confirmation prompt and the reboot question (for unattended use).

.EXAMPLE
    .\UninstallScreenConnect.ps1

.EXAMPLE
    .\UninstallScreenConnect.ps1 -Force
#>

[CmdletBinding()]
param(
    [switch]$Force
)

$ErrorActionPreference = 'Continue'

# ------------------------------------------------------------------ setup ----

$script:RebootNeeded = $false
$script:Resistant    = New-Object System.Collections.Generic.List[string]

$LogFile = Join-Path $env:TEMP ("SC-Removal-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $LogFile -Force | Out-Null } catch { }

function Write-Step { param([string]$Text) Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) Write-Host "  [+] $Text" -ForegroundColor Green }
function Write-Bad  { param([string]$Text) Write-Host "  [!] $Text" -ForegroundColor Yellow }

if (-not ('Win32.PendingDelete' -as [type])) {
    Add-Type -Namespace Win32 -Name PendingDelete -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
}

$MatchPattern = 'screenconnect|connectwise.+control'

function Test-IsReparsePoint {
    param([string]$Path)
    try {
        $attr = [System.IO.File]::GetAttributes($Path)
        return (($attr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    } catch { return $false }
}

function Remove-LinkOnly {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path -PathType Container) {
        cmd.exe /d /c "rd /q `"$Path`"" 2>&1 | Out-Null
        if (Test-Path -LiteralPath $Path) {
            try { [System.IO.Directory]::Delete($Path, $false) } catch { }
        }
    } else {
        try { [System.IO.File]::Delete($Path) } catch { }
    }
}

function Remove-NestedReparsePoints {
    param([string]$Dir)
    foreach ($child in @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue)) {
        if (Test-IsReparsePoint $child.FullName) {
            Remove-LinkOnly $child.FullName
        } elseif ($child.PSIsContainer) {
            Remove-NestedReparsePoints -Dir $child.FullName
        }
    }
}

function Remove-ItemForcefully {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $full = $item.FullName

    $normalized = $full.TrimEnd('\')
    $protected = @(
        $env:SystemDrive, $env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)},
        $env:CommonProgramFiles, ${env:CommonProgramFiles(x86)}, $env:ProgramData,
        (Join-Path $env:SystemDrive 'Users')
    ) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }
    if ((($normalized -split '\\').Count -lt 3) -or ($protected -contains $normalized)) {
        Write-Bad "REFUSING to delete protected path: $full"
        $script:Resistant.Add($full)
        return
    }

    if (Test-IsReparsePoint $full) {
        Remove-LinkOnly $full
        if (-not (Test-Path -LiteralPath $full)) { Write-Ok "Removed link (target untouched): $full" }
        else { $script:Resistant.Add($full); Write-Bad "Could not remove link: $full" }
        return
    }

    $isDir = Test-Path -LiteralPath $full -PathType Container

    if ($isDir) { Remove-NestedReparsePoints -Dir $full }

    # 1) plain delete
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $full)) { Write-Ok "Removed: $full"; return }

    # 2) take ownership and retry
    if ($isDir) {
        takeown.exe /F "$full" /R /A /D Y 2>&1 | Out-Null
        icacls.exe "$full" /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /T /C /Q 2>&1 | Out-Null
    } else {
        takeown.exe /F "$full" /A 2>&1 | Out-Null
        icacls.exe "$full" /grant '*S-1-5-32-544:F' '*S-1-5-18:F' /C /Q 2>&1 | Out-Null
    }
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $full)) { Write-Ok "Removed after taking ownership: $full"; return }

    # 3) cmd fallback
    if ($isDir) { cmd.exe /d /c "rd /s /q `"$full`"" 2>&1 | Out-Null }
    else        { cmd.exe /d /c "del /f /q `"$full`"" 2>&1 | Out-Null }
    if (-not (Test-Path -LiteralPath $full)) { Write-Ok "Removed via cmd: $full"; return }

    # 4) queue locked items for reboot deletion
    $targets = @()
    if ($isDir) {
        $targets += @(Get-ChildItem -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue |
                      Sort-Object { $_.FullName.Length } -Descending |
                      Select-Object -ExpandProperty FullName)
    }
    $targets += $full
    $queued = 0
    foreach ($target in $targets) {
        if ([Win32.PendingDelete]::MoveFileEx($target, $null, 4)) { $queued++ }
    }
    if ($queued -gt 0) {
        $script:RebootNeeded = $true
        Write-Bad "Locked - $queued item(s) queued for deletion at next reboot: $full"
    } else {
        icacls.exe "$full" /reset /T /C /Q 2>&1 | Out-Null
        $script:Resistant.Add($full)
        Write-Bad "Still resistant: $full"
    }
}

# -------------------------------------------------------- inventory + go? ----

Write-Host "`nScreenConnect / ConnectWise Control - Total Removal" -ForegroundColor Yellow
Write-Host "Log: $LogFile" -ForegroundColor Gray

$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$products = @(Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
    Where-Object { "$($_.DisplayName) $($_.Publisher) $($_.PSChildName)" -match $MatchPattern -and $_.UninstallString })

if ($products.Count -gt 0) {
    Write-Host "`nInstalled ScreenConnect products:" -ForegroundColor Cyan
    $products | ForEach-Object { Write-Host "   $($_.DisplayName)" }
} else {
    Write-Host "`nNo ScreenConnect products registered in the registry (will still sweep for leftovers)." -ForegroundColor Gray
}

if (-not $Force) {
    Write-Host "`nThis will PERMANENTLY remove ALL ScreenConnect / ConnectWise Control software," -ForegroundColor Yellow
    Write-Host "services, files, and registry keys. No backup will be made." -ForegroundColor Yellow
    $confirm = Read-Host 'Type YES to continue'
    if ($confirm -cne 'YES') {
        Write-Host 'Aborted - nothing was changed.' -ForegroundColor Green
        try { Stop-Transcript | Out-Null } catch { }
        exit 1
    }
}

# ----------------------------------------- 1) official uninstallers first ----

if ($products.Count -gt 0) {
    Write-Step 'Running official uninstallers'
    foreach ($p in $products) {
        $cmd = $null
        $quiet = $true
        if ($p.QuietUninstallString) {
            $cmd = $p.QuietUninstallString
        } elseif ($p.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {
            $cmd = "msiexec.exe /x $($p.PSChildName) /qn /norestart"
        } else {
            $cmd = $p.UninstallString
            $quiet = $false
        }
        Write-Host "  Uninstalling: $($p.DisplayName)" -ForegroundColor Gray
        try {
            $style = if ($quiet) { 'Hidden' } else { 'Normal' }
            $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList ('/d /s /c "' + $cmd + '"') `
                                  -WindowStyle $style -PassThru
            if (-not $proc.WaitForExit(300000)) {
                Start-Process -FilePath 'taskkill.exe' -ArgumentList "/PID $($proc.Id) /T /F" `
                              -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                Write-Bad "Timed out: $($p.DisplayName) (continuing with forced removal)"
            } elseif ($proc.ExitCode -in 0, 1605, 3010) {
                if ($proc.ExitCode -eq 3010) { $script:RebootNeeded = $true }
                Write-Ok "Uninstalled: $($p.DisplayName)"
            } else {
                Write-Bad "Uninstaller for $($p.DisplayName) returned $($proc.ExitCode)"
            }
        } catch {
            Write-Bad "Could not run uninstaller for $($p.DisplayName): $($_.Exception.Message)"
        }
        Start-Sleep -Seconds 2
    }
}

# ----------------------------------------------------- 2) kill processes ----

Write-Step 'Killing ScreenConnect processes'
$procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match $MatchPattern -or
    ($_.Path -and $_.Path -match $MatchPattern)
})
if ($procs.Count -eq 0) { Write-Host '  none running' -ForegroundColor Gray }
foreach ($p in $procs) {
    try {
        Stop-Process -Id $p.Id -Force -ErrorAction Stop
        Write-Ok "Killed: $($p.Name) (PID $($p.Id))"
    } catch {
        Write-Bad "Could not kill $($p.Name): $($_.Exception.Message)"
    }
}

# --------------------------------------------------- 3) services + drivers ----

Write-Step 'Removing ScreenConnect services'
$services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object {
    "$($_.Name) $($_.DisplayName) $($_.PathName)" -match $MatchPattern
})
if ($services.Count -eq 0) { Write-Host '  none found' -ForegroundColor Gray }
foreach ($svc in $services) {
    Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
    sc.exe config "$($svc.Name)" start= disabled 2>&1 | Out-Null
    sc.exe delete "$($svc.Name)" 2>&1 | Out-Null
    $deleteExit = $LASTEXITCODE
    if ($deleteExit -eq 0) {
        sc.exe query "$($svc.Name)" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 1060) {
            Write-Ok "Deleted service: $($svc.Name)"
        } else {
            $script:RebootNeeded = $true
            Write-Ok "Service marked for deletion at reboot: $($svc.Name)"
        }
    } elseif ($deleteExit -eq 1072) {
        $script:RebootNeeded = $true
        Write-Ok "Service marked for deletion at reboot: $($svc.Name)"
    } else {
        $script:Resistant.Add("service: $($svc.Name)")
        Write-Bad "Could not delete service $($svc.Name) (sc.exe exit code $deleteExit)"
    }
}

# ----------------------------------------------------- 4) scheduled tasks ----

Write-Step 'Removing ScreenConnect scheduled tasks'
$tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    "$($_.TaskName) $($_.TaskPath)" -match $MatchPattern
})
if ($tasks.Count -eq 0) { Write-Host '  none found' -ForegroundColor Gray }
foreach ($t in $tasks) {
    try {
        Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
        Write-Ok "Removed task: $($t.TaskPath)$($t.TaskName)"
    } catch {
        Write-Bad "Could not remove task $($t.TaskName): $($_.Exception.Message)"
    }
}

# ---------------------------------------------------- 5) known folder nuke ----

Write-Step 'Deleting known ScreenConnect folders'
$folders = New-Object System.Collections.Generic.List[string]
foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)) {
    if ($root) {
        foreach ($name in 'ScreenConnect', 'ScreenConnect Client', 'ConnectWise', 'ConnectWise Control',
                          'ConnectWise Control Client') {
            $folders.Add((Join-Path $root $name))
        }
    }
}
foreach ($userDir in @(Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue)) {
    foreach ($sub in 'AppData\Local\ScreenConnect',
                     'AppData\Local\ScreenConnect Client',
                     'AppData\Local\ConnectWise',
                     'AppData\Roaming\ScreenConnect',
                     'AppData\Roaming\ConnectWise') {
        $folders.Add((Join-Path $userDir.FullName $sub))
    }
}
# ScreenConnect also drops files here
$folders.Add((Join-Path $env:windir 'Temp\ScreenConnect'))

$found = $false
foreach ($f in $folders) {
    if (Test-Path -LiteralPath $f) { $found = $true; Remove-ItemForcefully -Path $f }
}
if (-not $found) { Write-Host '  none present' -ForegroundColor Gray }

# -------------------------------------------------------- 6) registry keys ----

Write-Step 'Cleaning ScreenConnect registry keys'
$regKeys = @(
    'HKLM:\SOFTWARE\ScreenConnect',
    'HKLM:\SOFTWARE\WOW6432Node\ScreenConnect',
    'HKLM:\SOFTWARE\ConnectWise',
    'HKLM:\SOFTWARE\WOW6432Node\ConnectWise',
    'HKCU:\SOFTWARE\ScreenConnect',
    'HKCU:\SOFTWARE\ConnectWise'
)

# Also nuke any per-instance uninstall keys that survived the official uninstaller
$regKeys += @(Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
    Where-Object { "$($_.DisplayName) $($_.Publisher) $($_.PSChildName)" -match $MatchPattern } |
    ForEach-Object { $_.PSPath })

foreach ($key in $regKeys) {
    if (Test-Path -LiteralPath $key) {
        try {
            Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Stop
            Write-Ok "Removed: $key"
        } catch {
            $script:Resistant.Add($key)
            Write-Bad "Could not remove ${key}: $($_.Exception.Message)"
        }
    }
}

# autorun entries
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($runKey in $runKeys) {
    if (-not (Test-Path -LiteralPath $runKey)) { continue }
    $entry = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue
    if (-not $entry) { continue }
    foreach ($prop in $entry.PSObject.Properties) {
        if ($prop.Name -in 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') { continue }
        if ("$($prop.Name) $($prop.Value)" -match $MatchPattern) {
            try {
                Remove-ItemProperty -Path $runKey -Name $prop.Name -Force -ErrorAction Stop
                Write-Ok "Removed autorun entry: $($prop.Name)"
            } catch {
                Write-Bad "Could not remove autorun $($prop.Name): $($_.Exception.Message)"
            }
        }
    }
}

# ---------------------------------------------------- 7) full drive sweep ----

Write-Step "Sweeping $env:SystemDrive\ for ALL remaining ScreenConnect traces"

$excludeRoots = @(
    (Join-Path $env:windir 'WinSxS'),
    (Join-Path $env:windir 'servicing'),
    (Join-Path $env:SystemDrive '$Recycle.Bin')
) | ForEach-Object { $_.TrimEnd('\') + '\' }
$excludeFiles = @($PSCommandPath, $LogFile) | Where-Object { $_ }

function Test-PathStartsWith {
    param([string]$Path, [string[]]$Prefixes)
    $normalized = $Path.TrimEnd('\') + '\'
    foreach ($prefix in $Prefixes) {
        if ($normalized.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

$hits = @(Get-ChildItem -Path "$env:SystemDrive\" -Filter '*screenconnect*' -Recurse -Force -ErrorAction SilentlyContinue)
Write-Host "  $($hits.Count) match(es) found" -ForegroundColor Gray

$dirs  = @($hits | Where-Object { $_.PSIsContainer } | Sort-Object { $_.FullName.Length })
$files = @($hits | Where-Object { -not $_.PSIsContainer })
foreach ($hit in ($dirs + $files)) {
    $full = $hit.FullName
    if (-not (Test-Path -LiteralPath $full)) { continue }
    if ($excludeFiles -contains $full) { continue }
    if (Test-PathStartsWith -Path $full -Prefixes $excludeRoots) { continue }
    Remove-ItemForcefully -Path $full
}

# Second pass for ConnectWise Control naming
$hits2 = @(Get-ChildItem -Path "$env:SystemDrive\" -Filter '*connectwise*control*' -Recurse -Force -ErrorAction SilentlyContinue)
if ($hits2.Count -gt 0) {
    Write-Host "  $($hits2.Count) ConnectWise Control match(es) found" -ForegroundColor Gray
    $dirs2  = @($hits2 | Where-Object { $_.PSIsContainer } | Sort-Object { $_.FullName.Length })
    $files2 = @($hits2 | Where-Object { -not $_.PSIsContainer })
    foreach ($hit in ($dirs2 + $files2)) {
        $full = $hit.FullName
        if (-not (Test-Path -LiteralPath $full)) { continue }
        if ($excludeFiles -contains $full) { continue }
        if (Test-PathStartsWith -Path $full -Prefixes $excludeRoots) { continue }
        Remove-ItemForcefully -Path $full
    }
}

# ---------------------------------------------------------------- summary ----

Write-Step 'Summary'
if ($script:Resistant.Count -gt 0) {
    Write-Host "  Could NOT be removed:" -ForegroundColor Yellow
    $script:Resistant | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
}
if ($script:Resistant.Count -eq 0) {
    Write-Host '  Clean - no resistant items.' -ForegroundColor Green
}
Write-Host "  Log saved to: $LogFile" -ForegroundColor Gray

try { Stop-Transcript | Out-Null } catch { }

if ($script:RebootNeeded) {
    Write-Host "`nA reboot is REQUIRED to finish removing locked files/services." -ForegroundColor Yellow
} else {
    Write-Host "`nDone. A reboot is recommended to confirm a clean state." -ForegroundColor Green
}
if (-not $Force) {
    $answer = Read-Host 'Reboot now? [y/N]'
    if ($answer -match '^(y|yes)$') { Restart-Computer -Force }
}
