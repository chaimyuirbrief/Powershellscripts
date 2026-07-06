#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    McAfee Search & Destroy - complete removal of McAfee products and leftovers.

.DESCRIPTION
    Removes McAfee the proper way first, then by force:

      1. Runs every McAfee uninstaller registered in the registry (silently when possible)
      2. Kills any McAfee processes still running
      3. Stops and deletes McAfee services and kernel drivers
      4. Unregisters McAfee scheduled tasks
      5. Removes McAfee AppX packages (installed + provisioned)
      6. Force-deletes known McAfee folders, escalating through takeown/icacls
         and finally queueing locked files for deletion at next reboot
      7. Deletes McAfee registry keys and autorun entries
      8. Optional: -DeepScan sweeps the whole system drive for anything named
         *mcafee* that survived

    A full transcript is written to %TEMP% (path is printed at the end).

    If anything survives even this, finish the job with McAfee's official MCPR
    removal tool: https://www.mcafee.com/support (search for "MCPR").

.PARAMETER Force
    Skip the confirmation prompt and the reboot question (for unattended use).

.PARAMETER DeepScan
    Scan the entire system drive for leftover *mcafee* files/folders. Matches
    inside program/system locations are deleted; matches anywhere else (e.g.
    your own documents) are listed for manual review, never auto-deleted.

.PARAMETER SkipUninstallers
    Skip step 1 (official uninstallers) and go straight to forced removal.

.EXAMPLE
    .\getridofmcafee.ps1

.EXAMPLE
    .\getridofmcafee.ps1 -Force -DeepScan
#>

[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$DeepScan,
    [switch]$SkipUninstallers
)

$ErrorActionPreference = 'Continue'

# ------------------------------------------------------------------ setup ----

$script:RebootNeeded = $false
$script:Resistant    = New-Object System.Collections.Generic.List[string]
$script:ReviewOnly   = New-Object System.Collections.Generic.List[string]

# Log name deliberately does not contain "mcafee" so -DeepScan never eats it
$LogFile = Join-Path $env:TEMP ("AV-Removal-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $LogFile -Force | Out-Null } catch { }

function Write-Step { param([string]$Text) Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) Write-Host "  [+] $Text" -ForegroundColor Green }
function Write-Bad  { param([string]$Text) Write-Host "  [!] $Text" -ForegroundColor Yellow }

# MoveFileEx lets us queue locked files (drivers, self-protected binaries)
# for deletion at next reboot - the last resort when nothing else works.
if (-not ('Win32.PendingDelete' -as [type])) {
    Add-Type -Namespace Win32 -Name PendingDelete -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
}

# Anything containing this substring is McAfee...
$McAfeeName = 'mcafee'
# ...plus McAfee service/driver/process names that don't contain "mcafee":
# mfe* (drivers + core services), enterprise agent services, consumer helpers.
$McAfeeExact = '^(mfe\w*|masvc|macmnsvc|macompatsvc|mctaskmanager|mcapexe|mcawfwk|mccspsvc|mccspservicehost|mcuicnt|mcpvtray|mcshield|mcsacore|mmsshost|modulecoreservice|pefservice|protectedmodulehost|qcshm)$'

function Test-PathStartsWith {
    param([string]$Path, [string[]]$Prefixes)
    $normalized = $Path.TrimEnd('\') + '\'
    foreach ($prefix in $Prefixes) {
        if ($normalized.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Remove-ItemForcefully {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $full = $item.FullName

    # Safety net: refuse to touch drive roots and top-level system folders,
    # no matter what the caller (or a bad wildcard match) hands us.
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

    # 1) plain delete
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $full)) { Write-Ok "Removed: $full"; return }

    # 2) take ownership and grant access, then retry.
    #    *S-1-1-0 is the Everyone SID - works on non-English Windows where
    #    the literal group name "Everyone" does not exist.
    $isDir = Test-Path -LiteralPath $full -PathType Container
    if ($isDir) {
        takeown.exe /F "$full" /R /A /D Y 2>&1 | Out-Null
        icacls.exe "$full" /grant '*S-1-1-0:(OI)(CI)F' /T /C /Q 2>&1 | Out-Null
    } else {
        takeown.exe /F "$full" /A 2>&1 | Out-Null
        icacls.exe "$full" /grant '*S-1-1-0:F' /C /Q 2>&1 | Out-Null
    }
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $full)) { Write-Ok "Removed after taking ownership: $full"; return }

    # 3) cmd fallback (handles some path/attribute cases PowerShell chokes on)
    if ($isDir) { cmd.exe /d /c "rd /s /q `"$full`"" 2>&1 | Out-Null }
    else        { cmd.exe /d /c "del /f /q `"$full`"" 2>&1 | Out-Null }
    if (-not (Test-Path -LiteralPath $full)) { Write-Ok "Removed via cmd: $full"; return }

    # 4) locked by a running driver/service: queue for deletion at next reboot
    #    (children first - a directory can only be reboot-deleted once empty)
    $targets = @()
    if ($isDir) {
        $targets += @(Get-ChildItem -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue |
                      Sort-Object { $_.FullName.Length } -Descending |
                      Select-Object -ExpandProperty FullName)
    }
    $targets += $full
    $queued = 0
    foreach ($target in $targets) {
        if ([Win32.PendingDelete]::MoveFileEx($target, $null, 4)) { $queued++ }  # 4 = MOVEFILE_DELAY_UNTIL_REBOOT
    }
    if ($queued -gt 0) {
        $script:RebootNeeded = $true
        Write-Bad "Locked - $queued item(s) queued for deletion at next reboot: $full"
    } else {
        $script:Resistant.Add($full)
        Write-Bad "Still resistant: $full"
    }
}

# -------------------------------------------------------- inventory + go? ----

Write-Host "`nMcAfee Search & Destroy" -ForegroundColor Yellow
Write-Host "Log: $LogFile" -ForegroundColor Gray

$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$products = @(Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
    Where-Object { "$($_.DisplayName) $($_.Publisher)" -match $McAfeeName -and $_.UninstallString })

if ($products.Count -gt 0) {
    Write-Host "`nInstalled McAfee products:" -ForegroundColor Cyan
    $products | ForEach-Object { Write-Host "   $($_.DisplayName)" }
} else {
    Write-Host "`nNo McAfee products registered in the registry (will still sweep for leftovers)." -ForegroundColor Gray
}

if (-not $Force) {
    Write-Host "`nThis will forcibly remove ALL McAfee software, services, drivers, tasks and files." -ForegroundColor Yellow
    $confirm = Read-Host 'Type YES to continue'
    if ($confirm -cne 'YES') {
        Write-Host 'Aborted - nothing was changed.' -ForegroundColor Green
        try { Stop-Transcript | Out-Null } catch { }
        exit 1
    }
}

# ------------------------------------------- 1) official uninstallers first ----
# Doing this before force-deleting files keeps Windows Installer state clean
# and lets McAfee's own uninstaller unhook drivers/WFP filters properly.

if (-not $SkipUninstallers -and $products.Count -gt 0) {
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
            $quiet = $false   # may show UI - let it, rather than hang hidden
        }
        Write-Host "  Uninstalling: $($p.DisplayName)" -ForegroundColor Gray
        try {
            $style = 'Normal'
            if ($quiet) { $style = 'Hidden' }
            $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList ('/d /s /c "' + $cmd + '"') `
                                  -WindowStyle $style -PassThru
            if (-not $proc.WaitForExit(600000)) {   # 10 min per product
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                Write-Bad "Timed out: $($p.DisplayName) (continuing with forced removal)"
            } elseif ($proc.ExitCode -in 0, 1605, 3010) {   # ok / already gone / ok-needs-reboot
                if ($proc.ExitCode -eq 3010) { $script:RebootNeeded = $true }
                Write-Ok "Uninstalled: $($p.DisplayName)"
            } else {
                Write-Bad "Uninstaller for $($p.DisplayName) returned $($proc.ExitCode)"
            }
        } catch {
            Write-Bad "Could not run uninstaller for $($p.DisplayName): $($_.Exception.Message)"
        }
        Start-Sleep -Seconds 2   # let msiexec settle between products
    }
}

# ----------------------------------------------------- 2) kill processes ----

Write-Step 'Killing remaining McAfee processes'
$procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match $McAfeeName -or $_.Name -match $McAfeeExact -or
    ($_.Path -and $_.Path -match $McAfeeName)
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

# ------------------------------------------- 3) services + kernel drivers ----

Write-Step 'Removing McAfee services and drivers'
$services = @()
foreach ($class in 'Win32_Service', 'Win32_SystemDriver') {
    $services += @(Get-CimInstance -ClassName $class -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match $McAfeeExact -or "$($_.DisplayName) $($_.PathName)" -match $McAfeeName
    })
}
if ($services.Count -eq 0) { Write-Host '  none found' -ForegroundColor Gray }
foreach ($svc in $services) {
    Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
    sc.exe config "$($svc.Name)" start= disabled 2>&1 | Out-Null
    sc.exe delete "$($svc.Name)" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Deleted service: $($svc.Name)"
    } elseif ($LASTEXITCODE -eq 1072) {   # already marked for deletion
        $script:RebootNeeded = $true
        Write-Ok "Service marked for deletion at reboot: $($svc.Name)"
    } else {
        $script:Resistant.Add("service: $($svc.Name)")
        Write-Bad "Could not delete service $($svc.Name) (sc.exe exit code $LASTEXITCODE)"
    }
}

# ------------------------------------------------------ 4) scheduled tasks ----

Write-Step 'Removing McAfee scheduled tasks'
$tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    "$($_.TaskName) $($_.TaskPath)" -match $McAfeeName
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

# --------------------------------------------------------- 5) AppX packages ----

Write-Step 'Removing McAfee Store/AppX packages'
try {
    $appx = @(Get-AppxPackage -AllUsers -Name '*mcafee*' -ErrorAction SilentlyContinue)
    if ($appx.Count -eq 0) { Write-Host '  none installed' -ForegroundColor Gray }
    foreach ($pkg in $appx) {
        try {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
            Write-Ok "Removed AppX: $($pkg.Name)"
        } catch {
            Write-Bad "AppX $($pkg.Name): $($_.Exception.Message)"
        }
    }
    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like '*mcafee*' } | ForEach-Object {
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction Stop | Out-Null
                Write-Ok "Deprovisioned: $($_.DisplayName)"
            } catch {
                Write-Bad "Provisioned $($_.DisplayName): $($_.Exception.Message)"
            }
        }
} catch {
    Write-Bad "AppX cleanup failed: $($_.Exception.Message)"
}

# ---------------------------------------------------- 6) known folder nuke ----

Write-Step 'Deleting known McAfee folders'
$folders = New-Object System.Collections.Generic.List[string]
foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:CommonProgramFiles,
                    ${env:CommonProgramFiles(x86)}, $env:ProgramData)) {
    if ($root) {
        foreach ($name in 'McAfee', 'McAfee.com', 'McAfee Security Scan') {
            $folders.Add((Join-Path $root $name))
        }
    }
}
foreach ($userDir in @(Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue)) {
    foreach ($sub in 'AppData\Local\McAfee', 'AppData\Roaming\McAfee', 'AppData\LocalLow\McAfee') {
        $folders.Add((Join-Path $userDir.FullName $sub))
    }
}
$found = $false
foreach ($f in $folders) {
    if (Test-Path -LiteralPath $f) { $found = $true; Remove-ItemForcefully -Path $f }
}
if (-not $found) { Write-Host '  none present' -ForegroundColor Gray }

# -------------------------------------------------------- 7) registry keys ----

Write-Step 'Cleaning McAfee registry keys'
$regKeys = @(
    'HKLM:\SOFTWARE\McAfee',
    'HKLM:\SOFTWARE\McAfee.com',
    'HKLM:\SOFTWARE\WOW6432Node\McAfee',
    'HKLM:\SOFTWARE\WOW6432Node\McAfee.com',
    'HKCU:\SOFTWARE\McAfee'
)
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

# autorun entries that launch McAfee
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
        if ("$($prop.Name) $($prop.Value)" -match $McAfeeName) {
            try {
                Remove-ItemProperty -Path $runKey -Name $prop.Name -Force -ErrorAction Stop
                Write-Ok "Removed autorun entry: $($prop.Name)"
            } catch {
                Write-Bad "Could not remove autorun $($prop.Name): $($_.Exception.Message)"
            }
        }
    }
}

# ------------------------------------------------- 8) optional deep scan ----

if ($DeepScan) {
    Write-Step "Deep-scanning $env:SystemDrive\ for leftovers (this can take a while)"

    # never touch these, even on a match
    $excludeRoots = @(
        (Join-Path $env:windir 'WinSxS'),
        (Join-Path $env:windir 'servicing'),
        (Join-Path $env:SystemDrive '$Recycle.Bin')
    ) | ForEach-Object { $_.TrimEnd('\') + '\' }
    $excludeFiles = @($PSCommandPath, $LogFile) | Where-Object { $_ }

    # matches under these roots are program/system data - safe to auto-delete
    $safeRoots = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:CommonProgramFiles,
                     ${env:CommonProgramFiles(x86)}, $env:ProgramData, (Join-Path $env:windir 'Temp'))) {
        if ($r) { $safeRoots.Add($r.TrimEnd('\') + '\') }
    }
    foreach ($userDir in @(Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue)) {
        $safeRoots.Add((Join-Path $userDir.FullName 'AppData').TrimEnd('\') + '\')
    }

    # single case-insensitive pass; NTFS wildcard matching ignores case anyway
    $hits = @(Get-ChildItem -Path "$env:SystemDrive\" -Filter '*mcafee*' -Recurse -Force -ErrorAction SilentlyContinue)
    Write-Host "  $($hits.Count) match(es) found" -ForegroundColor Gray

    # directories first (shortest path first, so children vanish with parents)
    $dirs  = @($hits | Where-Object { $_.PSIsContainer } | Sort-Object { $_.FullName.Length })
    $files = @($hits | Where-Object { -not $_.PSIsContainer })
    foreach ($hit in ($dirs + $files)) {
        $full = $hit.FullName
        if (-not (Test-Path -LiteralPath $full)) { continue }   # parent already removed
        if ($excludeFiles -contains $full) { continue }
        if (Test-PathStartsWith -Path $full -Prefixes $excludeRoots) { continue }
        if (Test-PathStartsWith -Path $full -Prefixes $safeRoots) {
            Remove-ItemForcefully -Path $full
        } else {
            $script:ReviewOnly.Add($full)   # user data - report, don't delete
        }
    }
}

# ---------------------------------------------------------------- summary ----

Write-Step 'Summary'
if ($script:Resistant.Count -gt 0) {
    Write-Host "  Could NOT be removed:" -ForegroundColor Yellow
    $script:Resistant | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
    Write-Host "  Finish these off with McAfee's MCPR tool: https://www.mcafee.com/support" -ForegroundColor Yellow
}
if ($script:ReviewOnly.Count -gt 0) {
    Write-Host "  Matches OUTSIDE program locations - review and delete manually if wanted:" -ForegroundColor Cyan
    $script:ReviewOnly | ForEach-Object { Write-Host "    $_" }
}
if ($script:Resistant.Count -eq 0 -and $script:ReviewOnly.Count -eq 0) {
    Write-Host '  Clean - no resistant items.' -ForegroundColor Green
}
Write-Host "  Log saved to: $LogFile" -ForegroundColor Gray

try { Stop-Transcript | Out-Null } catch { }

if ($script:RebootNeeded) {
    Write-Host "`nA reboot is REQUIRED to finish removing locked files/services." -ForegroundColor Yellow
} else {
    Write-Host "`nDone. A reboot is recommended." -ForegroundColor Green
}
if (-not $Force) {
    $answer = Read-Host 'Reboot now? [y/N]'
    if ($answer -match '^(y|yes)$') { Restart-Computer -Force }
}
