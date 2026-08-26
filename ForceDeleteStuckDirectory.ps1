#Requires -RunAsAdministrator
<#
  Force-delete a stubborn folder or file.

  Anything holding a file open inside it is dealt with automatically:
    - normal apps  -> the process is killed
    - a loaded user profile (NTUSER.DAT / UsrClass.dat) -> the user is logged
      off and their registry hive unloaded, because those files are held by
      the kernel and no killable process owns them

  Set $p below, then run this in an ELEVATED PowerShell / ISE window.
#>

$p = "pathofdirectory"        # <-- EDIT THIS, then run

# Killing any of these bluescreens Windows or wrecks the session - never touch them.
$never = @('system','idle','smss','csrss','wininit','winlogon','services',
           'lsass','svchost','memory compression','registry','fontdrvhost','dwm')

if (-not (Test-Path -LiteralPath $p)) {
    Write-Host "Not found: $p" -ForegroundColor Yellow
    return
}
$full = (Get-Item -LiteralPath $p -Force).FullName.TrimEnd('\')

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

    // Returns "pid|name" for each process holding one of these files open.
    public static string[] Find(string[] files)
    {
        var found = new List<string>();
        uint session;
        if (RmStartSession(out session, 0, Guid.NewGuid().ToString("N")) != 0) return found.ToArray();
        try
        {
            if (RmRegisterResources(session, (uint)files.Length, files, 0, null, 0, null) != 0)
                return found.ToArray();

            uint needed = 0, count = 0, reason = 0;
            int rc = RmGetList(session, out needed, ref count, null, ref reason);
            if (rc == ERROR_MORE_DATA && needed > 0)
            {
                var info = new RM_PROCESS_INFO[needed];
                count = needed;
                if (RmGetList(session, out needed, ref count, info, ref reason) == 0)
                    for (int i = 0; i < count; i++)
                        found.Add(info[i].Process.dwProcessId + "|" + info[i].strAppName);
            }
        }
        finally { RmEndSession(session); }
        return found.ToArray();
    }
}
'@
}

function Stop-Lockers([string]$root) {
    if (Test-Path -LiteralPath $root -PathType Leaf) {
        $files = @($root)
    } else {
        $files = @(Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue |
                   Select-Object -ExpandProperty FullName)
    }
    if ($files.Count -eq 0) { return $false }

    # Restart Manager takes a limited batch at a time.
    $hits = @()
    for ($i = 0; $i -lt $files.Count; $i += 400) {
        $end = [Math]::Min($i + 399, $files.Count - 1)
        try { $hits += [FileLocks]::Find($files[$i..$end]) } catch { }
    }

    $killed = $false
    foreach ($entry in ($hits | Sort-Object -Unique)) {
        $procId = [int]($entry -split '\|')[0]
        if ($procId -le 4 -or $procId -eq $PID) { continue }
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if (-not $proc) { continue }
        if ($never -contains $proc.Name.ToLower()) {
            Write-Host "  leaving critical process alone: $($proc.Name) (PID $procId)" -ForegroundColor DarkYellow
            continue
        }
        Write-Host "  killing $($proc.Name) (PID $procId)" -ForegroundColor Cyan
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        $killed = $true
    }
    return $killed
}

# --- If the target is a user profile, unload it -----------------------------
# NTUSER.DAT / UsrClass.dat are held by the kernel while the profile is loaded.
# No process can be killed to release them; the user has to be logged off.
$prof = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -and $_.LocalPath.TrimEnd('\') -ieq $full }

if ($prof -and $prof.Loaded) {
    Write-Host "This is a LOADED user profile - logging the user off first..." -ForegroundColor Cyan
    try {
        $user = (New-Object Security.Principal.SecurityIdentifier $prof.SID).
                Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        foreach ($line in @(quser 2>$null | Select-Object -Skip 1)) {
            $f = @(($line -replace '^\s*>', ' ') -split '\s{2,}' | Where-Object { $_ })
            if ($f.Count -and $f[0].Trim() -ieq $user) {
                $sessionId = @($f | Where-Object { $_ -match '^\d+$' })[0]
                if ($sessionId) {
                    Write-Host "  logging off $user (session $sessionId)" -ForegroundColor Cyan
                    logoff $sessionId 2>$null
                }
            }
        }
    } catch { }
    Start-Sleep -Seconds 3
    reg unload "HKU\$($prof.SID)" 2>&1 | Out-Null
}

# --- Ownership + permissions ------------------------------------------------
# Administrators by SID (not Everyone) so a file that survives isn't left
# writable by every account on the machine.
takeown /F "$full" /R /A /D Y 2>&1 | Out-Null
icacls  "$full" /grant "*S-1-5-32-544:(OI)(CI)F" /T /C /Q 2>&1 | Out-Null

# --- Delete, killing whatever blocks it, up to 3 passes ---------------------
for ($pass = 1; $pass -le 3; $pass++) {
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $full) { cmd /d /c "rd /s /q `"$full`"" 2>&1 | Out-Null }
    if (-not (Test-Path -LiteralPath $full)) { break }
    if ($pass -eq 3) { break }

    Write-Host "Still locked - finding what has it open (pass $pass)..." -ForegroundColor Yellow
    if (-not (Stop-Lockers $full)) { break }    # nothing left that can be killed
    Start-Sleep -Seconds 2
}

# --- Report -----------------------------------------------------------------
if (-not (Test-Path -LiteralPath $full)) {
    Write-Host "Gone." -ForegroundColor Green
    if ($prof) {
        $prof | Remove-CimInstance -ErrorAction SilentlyContinue
        Write-Host "Profile registration removed from the registry too." -ForegroundColor Green
    }
} else {
    $left = @(Get-ChildItem -LiteralPath $full -Recurse -Force -File -ErrorAction SilentlyContinue |
              Select-Object -ExpandProperty FullName)
    Write-Host "Still present - $($left.Count) file(s) left:" -ForegroundColor Red
    $left | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }

    if ($left -match '(NTUSER|UsrClass)\.dat') {
        Write-Host ""
        Write-Host "Those are registry hives. They are held open by the kernel, not by any" -ForegroundColor Yellow
        Write-Host "process you can kill, which means the profile is still loaded." -ForegroundColor Yellow
        Write-Host "Sign that user out completely (or just reboot), then run this again." -ForegroundColor Yellow
    } else {
        Write-Host "Reboot and run this again." -ForegroundColor Yellow
    }
}
