#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fully uninstall Microsoft Edge (Chromium) while leaving the components
    Windows itself relies on - WebView2, Windows Search, the Start menu and
    Widgets - working.

.DESCRIPTION
    Two things make "just uninstall Edge" go wrong, and this script avoids both:

    1. On most consumer Windows editions Microsoft blocks Edge removal, so a
       plain "setup.exe --uninstall" simply refuses. To get a *real* uninstall
       this script temporarily flips the "Edge is uninstallable." policy in
       %SystemRoot%\System32\IntegratedServicesRegionPolicySet.json - the same
       switch that lets EEA (European) users remove Edge - runs Edge's own
       supported uninstaller, and then restores the policy file exactly as it
       was. Nothing is force-deleted.

    2. Aggressive "Edge removers" break Windows by deleting shared pieces -
       the whole "Program Files (x86)\Microsoft" folder, or the WebView2
       runtime. WebView2 is what the Start menu, the taskbar Search box and
       the Widgets board use to render their content, so removing it is what
       leaves people with a dead search/Start menu. This script therefore:
         * keeps WebView2 by default,
         * never deletes shared folders, SystemApps, or any Windows Search /
           Start-menu component,
         * blocks Edge (only) from being silently reinstalled by Windows
           Update, while still letting WebView2 update normally.

    After a successful uninstall it sets the documented EdgeUpdate policies so
    Windows Update / Edge Update will not quietly bring Edge back.

.PARAMETER RemoveWebView2
    Also remove the Edge WebView2 Runtime and the Edge Update stack. OFF by
    default: many apps - and Windows shell surfaces like Search, Start and
    Widgets - embed WebView2, so removing it can break them. Only use this if
    you are certain nothing depends on it.

.EXAMPLE
    .\UninstallEdge.ps1
    Removes the Edge browser, keeps WebView2 and everything Windows needs.

.EXAMPLE
    .\UninstallEdge.ps1 -RemoveWebView2
    Also strips the WebView2 runtime and Edge Update (may break Search/Widgets).
#>
[CmdletBinding()]
param(
    [switch]$RemoveWebView2
)

$ErrorActionPreference = 'Continue'

# BUILTIN\Administrators - used as a SID so it works on non-English Windows too.
$AdminSid = 'S-1-5-32-544'

# Edge Update product code for Edge Stable (the consumer browser). WebView2 has
# its own separate code ({F3017226-...}) which we deliberately never block.
$EdgeStableGuid = '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'

function Get-SetupExe {
    <#
        Return the newest "...\Application\<version>\Installer\setup.exe" under
        any of the given base folders, or $null. setup.exe is Edge's own
        supported (un)installer.
    #>
    param([string[]]$BasePaths)

    foreach ($base in $BasePaths) {
        if (Test-Path -LiteralPath $base) {
            $setup = Get-ChildItem -LiteralPath $base -Recurse -Filter 'setup.exe' -ErrorAction SilentlyContinue |
                     Where-Object { $_.FullName -match '\\Installer\\setup\.exe$' } |
                     Sort-Object -Property @{ Expression = {
                         # Sort as a real version, not as text ("10.0.9" > "10.0.10" as strings).
                         $v = $null
                         if ([version]::TryParse($_.VersionInfo.ProductVersion, [ref]$v)) { $v } else { [version]'0.0.0.0' }
                     } } -Descending |
                     Select-Object -First 1
            if ($setup) { return $setup.FullName }
        }
    }
    return $null
}

function Unlock-EdgeUninstall {
    <#
        Temporarily flip "Edge is uninstallable." to "enabled" in the region
        policy file so setup.exe --uninstall is allowed on non-EEA machines.
        Backs the file up first and returns what to restore, or $null if no
        change was made / needed. Restore-EdgeUninstallUnlock undoes it.
    #>
    $policyFile = Join-Path $env:SystemRoot 'System32\IntegratedServicesRegionPolicySet.json'
    if (-not (Test-Path -LiteralPath $policyFile)) {
        Write-Verbose 'Region policy file not present - this build does not gate Edge removal by region.'
        return $null
    }

    try {
        $raw = Get-Content -LiteralPath $policyFile -Raw -ErrorAction Stop
    } catch {
        Write-Warning "Could not read region policy file: $($_.Exception.Message)"
        return $null
    }

    # Within the "Edge is uninstallable." policy object, turn its defaultState
    # from disabled to enabled. Non-greedy so it targets that policy's own field.
    $pattern = '("\$comment"\s*:\s*"Edge is uninstallable\."[\s\S]*?"defaultState"\s*:\s*")disabled(")'
    if ($raw -notmatch $pattern) {
        Write-Verbose 'Edge-uninstall policy is already enabled or uses an unexpected layout - leaving the file untouched.'
        return $null
    }

    # Keep the backup OUTSIDE System32 - Administrators can overwrite the
    # existing policy file (once we grant ourselves rights below) but usually
    # cannot create new files in the System32 directory itself.
    $backup = Join-Path $env:TEMP 'IntegratedServicesRegionPolicySet.json.edgeuninstall.bak'
    try {
        Copy-Item -LiteralPath $policyFile -Destination $backup -Force -ErrorAction Stop

        # The file is owned by TrustedInstaller; grant ourselves write access.
        & takeown.exe /f $policyFile /a *> $null
        & icacls.exe $policyFile /grant "*$($AdminSid):(F)" *> $null

        $patched = [regex]::Replace($raw, $pattern, '${1}enabled${2}',
                                    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

        # Write UTF-8 with NO BOM - the parser is picky and the original has none.
        [System.IO.File]::WriteAllText($policyFile, $patched, (New-Object System.Text.UTF8Encoding($false)))

        Write-Host '  Region policy temporarily set to allow Edge removal.' -ForegroundColor Gray
        return @{ File = $policyFile; Backup = $backup }
    } catch {
        Write-Warning "Could not unlock Edge uninstall: $($_.Exception.Message)"
        # Best-effort roll back if we already copied a backup.
        if (Test-Path -LiteralPath $backup) {
            Copy-Item -LiteralPath $backup -Destination $policyFile -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
        }
        return $null
    }
}

function Restore-EdgeUninstallUnlock {
    <# Put the region policy file (content + ownership) back the way it was. #>
    param($Unlock)
    if (-not $Unlock) { return }

    try {
        if (Test-Path -LiteralPath $Unlock.Backup) {
            Copy-Item -LiteralPath $Unlock.Backup -Destination $Unlock.File -Force -ErrorAction Stop
            Remove-Item -LiteralPath $Unlock.Backup -Force -ErrorAction SilentlyContinue
        }
        # Hand ownership back to TrustedInstaller and drop the grant we added.
        & icacls.exe $Unlock.File /setowner 'NT SERVICE\TrustedInstaller' *> $null
        & icacls.exe $Unlock.File /remove:g "*$AdminSid" *> $null
        Write-Host '  Region policy restored.' -ForegroundColor Gray
    } catch {
        Write-Warning "Could not fully restore $($Unlock.File): $($_.Exception.Message)"
        Write-Warning "A backup of the original remains at $($Unlock.Backup)."
    }
}

function Block-EdgeReinstall {
    <#
        Stop Windows Update / Edge Update from silently reinstalling the Edge
        browser - WITHOUT touching WebView2, which stays installable/updatable
        so the Start menu, Search and Widgets keep working.
    #>
    try {
        $eu = 'HKLM:\SOFTWARE\Microsoft\EdgeUpdate'
        if (-not (Test-Path $eu)) { New-Item -Path $eu -Force | Out-Null }
        Set-ItemProperty -Path $eu -Name 'DoNotUpdateToEdgeWithChromium' -Value 1 -Type DWord

        $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
        if (-not (Test-Path $pol)) { New-Item -Path $pol -Force | Out-Null }
        # Block ONLY the Edge browser product. We intentionally do not set
        # InstallDefault=0, so WebView2 (a different product code) is unaffected.
        Set-ItemProperty -Path $pol -Name "Install$EdgeStableGuid" -Value 0 -Type DWord
        Set-ItemProperty -Path $pol -Name "Update$EdgeStableGuid"  -Value 0 -Type DWord
        Write-Host '  Blocked Edge from being silently reinstalled (WebView2 left alone).' -ForegroundColor Gray
    } catch {
        Write-Warning "Could not write EdgeUpdate reinstall-block policies: $($_.Exception.Message)"
    }
}

function Remove-EdgeUpdateStack {
    <#
        Remove the Edge Update services and tasks. Only called with
        -RemoveWebView2, because otherwise Edge Update is what keeps WebView2
        updated and should stay.
    #>
    foreach ($svc in 'edgeupdate', 'edgeupdatem') {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            & sc.exe delete $svc *> $null
        }
    }
    Get-ScheduledTask -TaskName 'MicrosoftEdgeUpdate*' -ErrorAction SilentlyContinue |
        Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

    foreach ($euRoot in @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\EdgeUpdate'),
        (Join-Path $env:ProgramFiles          'Microsoft\EdgeUpdate')
    )) {
        if (Test-Path -LiteralPath $euRoot) {
            Remove-Item -LiteralPath $euRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host '  Removed the Edge Update stack.' -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# 1. Uninstall the Edge browser
# ---------------------------------------------------------------------------
$edgeBases = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application",
    "$env:ProgramFiles\Microsoft\Edge\Application"
)
$edgeSetup = Get-SetupExe -BasePaths $edgeBases

if (-not $edgeSetup) {
    Write-Host 'Microsoft Edge setup.exe not found - the Edge browser looks already removed.' -ForegroundColor Yellow
    $edgeGone = $true
} else {
    Write-Host 'Closing Microsoft Edge...' -ForegroundColor Cyan
    Get-Process -Name 'msedge' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    if ($RemoveWebView2) {
        Get-Process -Name 'msedgewebview2' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    $unlock = $null
    try {
        Write-Host 'Preparing to uninstall Microsoft Edge...' -ForegroundColor Cyan
        $unlock = Unlock-EdgeUninstall

        Write-Host "Uninstalling Microsoft Edge via: $edgeSetup" -ForegroundColor Cyan
        $edgeArgs = '--uninstall --system-level --verbose-logging --force-uninstall'
        $proc = Start-Process -FilePath $edgeSetup -ArgumentList $edgeArgs -Wait -PassThru -WindowStyle Hidden
    } finally {
        # Always put the region policy file back, even if the uninstall threw.
        Restore-EdgeUninstallUnlock -Unlock $unlock
    }

    # Verify by re-scanning for setup.exe rather than trusting the exit code.
    $edgeGone = -not (Get-SetupExe -BasePaths $edgeBases)

    if ($edgeGone) {
        Write-Host 'Microsoft Edge removed.' -ForegroundColor Green
    } else {
        Write-Host "Edge is still present (uninstaller exit code $($proc.ExitCode))." -ForegroundColor Yellow
        Write-Host 'If this is a managed/Enterprise device, Group Policy may be forcing Edge to stay.' -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 2. Keep it gone (only worth doing if Edge is actually removed)
# ---------------------------------------------------------------------------
if ($edgeGone) {
    Write-Host 'Preventing silent Edge reinstall...' -ForegroundColor Cyan
    Block-EdgeReinstall
}

# ---------------------------------------------------------------------------
# 3. Optional: remove WebView2 + Edge Update (may break Search/Start/Widgets)
# ---------------------------------------------------------------------------
if ($RemoveWebView2) {
    Write-Host "`nRemoving Edge WebView2 Runtime (requested with -RemoveWebView2)..." -ForegroundColor Cyan
    Write-Host 'Note: WebView2 backs the Start menu, taskbar Search and Widgets - these may stop working.' -ForegroundColor Yellow

    Get-Process -Name 'msedgewebview2' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    $wv2Setup = Get-SetupExe -BasePaths @(
        "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application",
        "$env:ProgramFiles\Microsoft\EdgeWebView\Application"
    )
    if ($wv2Setup) {
        $wv2Args = '--uninstall --msedgewebview --system-level --verbose-logging --force-uninstall'
        Start-Process -FilePath $wv2Setup -ArgumentList $wv2Args -Wait -WindowStyle Hidden
        Write-Host '  Ran the WebView2 uninstaller.' -ForegroundColor Gray
    } else {
        # Fall back to the registered uninstall string (e.g. per-user installs).
        $uninstallKeys = @(
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $wv = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
              Where-Object { $_.DisplayName -like '*WebView2*' -and $_.UninstallString }
        # On PowerShell 5.1 "foreach ($x in $null)" runs once with $x = $null,
        # so guard with if/else instead of looping over a possibly-null value.
        if (-not $wv) {
            Write-Host '  No WebView2 uninstall entry found.' -ForegroundColor Yellow
        } else {
            foreach ($w in $wv) {
                $cmd = $w.UninstallString
                if ($cmd -notmatch 'force-uninstall') { $cmd += ' --force-uninstall' }
                Write-Host "  $($w.DisplayName)" -ForegroundColor Gray
                Start-Process -FilePath 'cmd.exe' -ArgumentList "/d /s /c `"$cmd`"" -Wait -WindowStyle Hidden
            }
        }
    }

    Remove-EdgeUpdateStack
}

Write-Host "`nDone. A reboot is recommended." -ForegroundColor Green
