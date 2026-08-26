#Requires -RunAsAdministrator
<#
  Force-delete a stubborn folder or file.

  Whatever is holding it open is dealt with automatically:
    - normal apps      -> the process is killed
    - Windows services -> stopped through the SCM, not terminated
    - a loaded profile -> the user is logged off and BOTH of their registry
                          hives unloaded, because NTUSER.DAT / UsrClass.dat
                          are held by the kernel and no killable process
                          owns them

  Set $p below, then run this in an ELEVATED PowerShell / ISE window.
#>

$p = "pathofdirectory"        # <-- EDIT THIS, then run

# Killing any of these bluescreens Windows - backstop for what Restart Manager
# already flags as RmCritical.
$never = @('system','idle','smss','csrss','wininit','winlogon','services',
           'lsass','svchost','memory compression','registry','fontdrvhost','dwm')

$RmCritical = 1000    # RM_APP_TYPE: must never be shut down
$RmService  = 3       # RM_APP_TYPE: stop via the SCM instead of killing

if (-not (Test-Path -LiteralPath $p)) {
    Write-Host "Not found: $p" -ForegroundColor Yellow
    return
}

# Careful with the trailing slash: 'C:\'.TrimEnd('\') is 'C:', which means
# "current directory on C:" - not the drive root - and would silently retarget.
$full = (Get-Item -LiteralPath $p -Force).FullName
$driveRoot = [IO.Path]::GetPathRoot($full)
if ($full -ne $driveRoot) { $full = $full.TrimEnd('\') }

$blocked = @($driveRoot, $env:windir, $env:ProgramData,
             (Join-Path $env:SystemDrive 'Users'),
             $env:ProgramFiles, ${env:ProgramFiles(x86)}) |
           Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() }
if ($full -eq $driveRoot -or $blocked -contains $full.ToLower()) {
    Write-Host "Refusing to delete protected path: $full" -ForegroundColor Red
    return
}

# --- Ask Windows which processes hold a file open (Restart Manager API) ------
if (-not ('FileLocks' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class FileLocks
{
    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    private const int CCH_RM_MAX_APP_NAME = 255;
    private const int CCH_RM_MAX_SVC_NAME = 63;
    private const int ERROR_MORE_DATA = 234;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
        public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
        public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint pSessionHandle);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames,
        uint nApplications, RM_UNIQUE_PROCESS[] rgApplications, uint nServices, string[] rgsServiceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded,
        ref uint pnProcInfo, [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);

    // First element is always "RC=<code>" so the caller can tell an API failure
    // apart from "nothing is holding these files open".
    // Remaining elements: pid|apptype|restartable|startFileTime|serviceName|appName
    public static string[] Find(string[] files)
    {
        var found = new List<string>();
        uint session;
        int rc = RmStartSession(out session, 0, Guid.NewGuid().ToString("N"));
        if (rc != 0) { found.Add("RC=" + rc); return found.ToArray(); }
        try
        {
            rc = RmRegisterResources(session, (uint)files.Length, files, 0, null, 0, null);
            if (rc != 0) { found.Add("RC=" + rc); return found.ToArray(); }

            uint needed = 0, count = 0, reason = 0;
            rc = RmGetList(session, out needed, ref count, null, ref reason);
            if (rc == 0 && needed == 0) { found.Add("RC=0"); return found.ToArray(); }
            if (rc != ERROR_MORE_DATA)  { found.Add("RC=" + rc); return found.ToArray(); }

            var info = new RM_PROCESS_INFO[needed];
            count = needed;
            rc = RmGetList(session, out needed, ref count, info, ref reason);
            if (rc != 0) { found.Add("RC=" + rc); return found.ToArray(); }

            found.Add("RC=0");
            for (int i = 0; i < count; i++)
            {
                var pi = info[i];
                long ft = ((long)pi.Process.ProcessStartTime.dwHighDateTime << 32)
                          | (uint)pi.Process.ProcessStartTime.dwLowDateTime;
                found.Add(string.Join("|", new string[] {
                    pi.Process.dwProcessId.ToString(),
                    pi.ApplicationType.ToString(),
                    pi.bRestartable ? "1" : "0",
                    ft.ToString(),
                    pi.strServiceShortName == null ? "" : pi.strServiceShortName,
                    pi.strAppName == null ? "" : pi.strAppName
                }));
            }
        }
        finally { RmEndSession(session); }
        return found.ToArray();
    }
}
'@
}

function Get-Lockers([string[]]$paths) {
    $entries = @(); $failed = $false
    for ($i = 0; $i -lt $paths.Count; $i += 400) {
        $end = [Math]::Min($i + 399, $paths.Count - 1)
        try { $raw = [FileLocks]::Find($paths[$i..$end]) }
        catch {
            Write-Host "  could not query lock owners: $($_.Exception.Message)" -ForegroundColor Red
            $failed = $true; continue
        }
        foreach ($r in $raw) {
            if ($r -like 'RC=*') {
                if ([int]$r.Substring(3) -ne 0) { $failed = $true }
            } else { $entries += $r }
        }
    }
    [pscustomobject]@{ Failed = $failed; Entries = @($entries | Sort-Object -Unique) }
}

# Returns 'killed' | 'none' | 'failed' | 'protected'
function Stop-Lockers([string]$root) {
    if (Test-Path -LiteralPath $root -PathType Leaf) {
        $files = @($root)
    } else {
        $files = @(Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue |
                   Select-Object -ExpandProperty FullName)
    }

    $res = Get-Lockers $files
    # The folder itself is queried separately - a handle on the directory (an
    # Explorer window, a shell sitting inside it) is the usual last blocker, and
    # a bad path in this call must not poison the file results.
    $dirRes = Get-Lockers @($root)
    $entries = @(@($res.Entries) + @($dirRes.Entries) | Sort-Object -Unique)
    $failed  = $res.Failed -or $dirRes.Failed

    $killed = $false; $protectedSeen = $false
    foreach ($entry in $entries) {
        $f = $entry -split '\|'
        if ($f.Count -lt 6) { continue }
        $procId = [int]$f[0]; $appType = [int]$f[1]
        $startFt = [long]$f[3]; $svcName = $f[4]; $appName = $f[5]

        if ($procId -le 4 -or $procId -eq $PID) { $protectedSeen = $true; continue }
        if ($appType -eq $RmCritical) {
            Write-Host "  leaving system-critical process alone: $appName (PID $procId)" -ForegroundColor DarkYellow
            $protectedSeen = $true; continue
        }

        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if (-not $proc) { continue }
        if ($never -contains $proc.Name.ToLower()) {
            Write-Host "  leaving critical process alone: $($proc.Name) (PID $procId)" -ForegroundColor DarkYellow
            $protectedSeen = $true; continue
        }
        # Make sure this is still the process Restart Manager reported, not a
        # different one that inherited the PID in the meantime.
        if ($startFt -gt 0) {
            try {
                if ([Math]::Abs((($proc.StartTime) - [DateTime]::FromFileTime($startFt)).TotalSeconds) -gt 2) {
                    Write-Host "  PID $procId was reused - skipping" -ForegroundColor DarkYellow
                    continue
                }
            } catch { }
        }

        if ($appType -eq $RmService -and $svcName) {
            Write-Host "  stopping service $svcName (PID $procId)" -ForegroundColor Cyan
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            $killed = $true; continue
        }

        Write-Host "  killing $($proc.Name) (PID $procId)" -ForegroundColor Cyan
        try { $proc.Kill(); [void]$proc.WaitForExit(10000) } catch { }
        $killed = $true
    }

    if ($killed)        { return 'killed' }
    if ($failed)        { return 'failed' }
    if ($protectedSeen) { return 'protected' }
    return 'none'
}

function Test-ProfileLoaded([string]$sid) {
    $x = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'" -ErrorAction SilentlyContinue
    if ($x) { return [bool]$x.Loaded }
    return $false
}

# --- If the target is a user profile, unload it before touching the files ----
# NTUSER.DAT and UsrClass.dat are mapped by the kernel while the profile is
# loaded, so no process can be killed to release them.
$mySid     = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
$mySession = (Get-Process -Id $PID).SessionId

$prof = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -and $_.LocalPath.TrimEnd('\') -ieq $full }

if ($prof) {
    if ($prof.SID -eq $mySid) {
        Write-Host "That is the profile you are signed in with - refusing." -ForegroundColor Red
        Write-Host "Run this from a different administrator account." -ForegroundColor Yellow
        return
    }
    if ($prof.Loaded) {
        Write-Host "This is a LOADED user profile - signing that user out first..." -ForegroundColor Cyan
        try {
            $user = (New-Object Security.Principal.SecurityIdentifier $prof.SID).
                    Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
            foreach ($line in @(quser 2>$null | Select-Object -Skip 1)) {
                $f = @(($line -replace '^\s*>', ' ') -split '\s{2,}' | Where-Object { $_ })
                if ($f.Count -and $f[0].Trim() -ieq $user) {
                    $sessionId = @($f | Where-Object { $_ -match '^\d+$' })[0]
                    if ($sessionId -and [int]$sessionId -ne $mySession) {
                        Write-Host "  logging off $user (session $sessionId)" -ForegroundColor Cyan
                        logoff $sessionId 2>$null
                    }
                }
            }
        } catch { }

        # Wait for the hives to actually come out. A logoff takes far longer than
        # a fixed sleep allows, and UsrClass.dat is a SEPARATE hive from
        # NTUSER.DAT - unload "<SID>_Classes" as well or UsrClass.dat stays locked.
        $deadline = (Get-Date).AddSeconds(90)
        while ((Test-ProfileLoaded $prof.SID) -and (Get-Date) -lt $deadline) {
            reg unload "HKU\$($prof.SID)_Classes" 2>&1 | Out-Null
            reg unload "HKU\$($prof.SID)"         2>&1 | Out-Null
            Start-Sleep -Seconds 3
        }
        if (Test-ProfileLoaded $prof.SID) {
            Write-Host "Profile is STILL loaded - not deleting it half-way." -ForegroundColor Red
            Write-Host "Sign that user out completely (or reboot), then run this again." -ForegroundColor Yellow
            return
        }
        Write-Host "  profile unloaded." -ForegroundColor Green
    }
}

# --- Ownership + permissions ------------------------------------------------
# Administrators by SID (not Everyone) so anything that survives is not left
# writable by every account on the machine.
takeown /F "$full" /R /A /D Y 2>&1 | Out-Null
icacls  "$full" /grant "*S-1-5-32-544:(OI)(CI)F" /T /C /Q 2>&1 | Out-Null

# --- Delete, clearing whatever blocks it, up to 3 passes --------------------
$rdPath = if ($full -match '^[A-Za-z]:\\') { '\\?\' + $full } else { $full }
for ($pass = 1; $pass -le 3; $pass++) {
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $full) { cmd /d /c "rd /s /q `"$rdPath`"" 2>&1 | Out-Null }
    if (-not (Test-Path -LiteralPath $full)) { break }
    if ($pass -eq 3) { break }

    Write-Host "Still locked - finding what has it open (pass $pass)..." -ForegroundColor Yellow
    $status = Stop-Lockers $full
    if ($status -eq 'protected') {
        Write-Host "  only processes that must not be killed are holding it." -ForegroundColor Yellow
        break
    }
    if ($status -eq 'failed') { Write-Host "  lock query failed - retrying anyway." -ForegroundColor DarkYellow }
    if ($status -eq 'none')   { Write-Host "  nothing reported holding it - retrying." -ForegroundColor DarkYellow }
    Start-Sleep -Seconds 2
}

# --- Report -----------------------------------------------------------------
if (-not (Test-Path -LiteralPath $full)) {
    Write-Host "Gone." -ForegroundColor Green
    if ($prof) {
        try {
            $prof | Remove-CimInstance -ErrorAction Stop
            Write-Host "Profile registration removed from the registry too." -ForegroundColor Green
        } catch {
            Write-Host "Note: the profile's registry entry could not be removed - $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }
} else {
    $left = @(Get-ChildItem -LiteralPath $full -Recurse -Force -File -ErrorAction SilentlyContinue |
              Select-Object -ExpandProperty FullName)
    Write-Host "Still present - $($left.Count) file(s) visible:" -ForegroundColor Red
    $left | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

    if ($left -match '(NTUSER|UsrClass)\.dat') {
        Write-Host ""
        Write-Host "Those are registry hives - held open by the kernel, not by any process" -ForegroundColor Yellow
        Write-Host "you can kill, which means the profile is still loaded." -ForegroundColor Yellow
        Write-Host "Sign that user out completely (or just reboot), then run this again." -ForegroundColor Yellow
    } elseif ($left.Count -eq 0) {
        Write-Host "The folder itself is held open - usually an Explorer window or a" -ForegroundColor Yellow
        Write-Host "console sitting inside it. Close those and run this again." -ForegroundColor Yellow
    } else {
        Write-Host "Reboot and run this again." -ForegroundColor Yellow
    }
}
