#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Remote Access & RMM Sweep - find, uninstall and wipe remote-control /
    RMM software, hunt for a custom/unknown backdoor a hacker may have left,
    inspect inbound network access, and log everything for an IT professional.

.DESCRIPTION
    This is an incident-response / clean-handover tool. Run it on a machine you
    suspect a remote attacker (or an unwanted "tech support" remote session) has
    touched. It works in seven stages:

      1. INVENTORY     - scans installed programs, services, drivers, running
                         processes, scheduled tasks, autoruns and common install
                         folders against a built-in catalogue of ~70 popular RMM
                         and remote-access products (ConnectWise/ScreenConnect,
                         AnyDesk, TeamViewer, Atera, Splashtop, NinjaOne, Kaseya,
                         Datto, AnyDesk, RustDesk, ngrok/Cloudflare tunnels, VNC,
                         etc.).

      2. CUSTOM-RMM    - heuristics for a remote-access tool a hacker rolled
         HUNT            themselves (so it is in no catalogue): unsigned / oddly
                         signed programs that LISTEN for inbound connections,
                         services and autoruns whose binary lives in a
                         user-writable location (AppData/Temp/ProgramData/Users),
                         encoded-PowerShell run keys, etc. These are REPORTED for
                         human review - never auto-deleted - because the same
                         fingerprints also match legitimate software.

      3. NETWORK TRACE - lists endpoints the machine exposes to the outside
                         (listening sockets bound to all interfaces, live inbound
                         sessions with their foreign IPs), the RDP / WinRM state,
                         inbound firewall ALLOW rules, and who is in the local
                         Administrators group - so you can see any path a hacker
                         still has in.

      4. CONFIRM       - shows everything found and asks before changing anything
                         (unless -Force or -ScanOnly).

      5. UNINSTALL     - runs each product's own uninstaller (silently when it
                         can), kills processes, stops+deletes services/drivers,
                         removes scheduled tasks and autoruns.

      6. WIPE          - force-deletes leftover folders and registry keys
                         (escalating through takeown/icacls, then queueing locked
                         files for deletion at next reboot), then combs the WHOLE
                         system drive for anything still named after a product
                         that was found installed, and deletes it. Built-in
                         guards refuse to touch drive roots, Windows, Program
                         Files, ProgramData and the Users root.

      7. NETWORK       - for the products it removed, kills their listeners and
         REMEDIATION     disables any inbound firewall ALLOW rule that points at
                         their binaries. Suspicious/custom findings from stage 2-3
                         are only remediated with -RemoveSuspicious (or an
                         interactive yes), again because of false positives.

    A plain-text report is written to -LogDir and opened in Notepad at the end,
    with a prompt to send it to your IT professional for review.

    SAFETY: this script deletes software, files, services and registry keys.
    It is deliberately aggressive on CATALOGUED products that are actually
    installed, and deliberately cautious on heuristic guesses. Read it, make a
    backup / restore point, and prefer -ScanOnly for a first pass.

.PARAMETER ScanOnly
    Investigate and write the report, but change NOTHING. Best first run.

.PARAMETER Force
    Skip the confirmation prompt and the reboot question (unattended use).
    Implies removal of catalogued products. Does NOT by itself remove
    heuristic/custom findings - add -RemoveSuspicious for that.

.PARAMETER RemoveSuspicious
    Also act on stage 2/3 heuristic findings (kill the process, block it in the
    firewall). Off by default because these can be legitimate software.

.PARAMETER LogDir
    Folder for the report + transcript. Default C:\RemoteAccessAudit.

.EXAMPLE
    .\RemoveRemoteAccessAndRMM.ps1 -ScanOnly
    Audit only - see what is there before touching anything.

.EXAMPLE
    .\RemoveRemoteAccessAndRMM.ps1
    Interactive: audit, confirm, then uninstall + wipe catalogued products.

.EXAMPLE
    .\RemoveRemoteAccessAndRMM.ps1 -Force -RemoveSuspicious
    Unattended full clean, including blocking suspicious custom listeners.

.NOTES
    Catalogue drawn from the community LOLRMM project (lolrmm.io) plus common
    attacker tunnelling tools. Windows PowerShell 5.1+; run elevated.
#>

[CmdletBinding()]
param(
    [switch]$ScanOnly,
    [switch]$Force,
    [switch]$RemoveSuspicious,
    [string]$LogDir = (Join-Path $env:SystemDrive 'RemoteAccessAudit')
)

$ErrorActionPreference = 'Continue'

# =============================================================== logging ====

if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$stamp    = Get-Date -Format 'yyyyMMdd-HHmmss'
# Report/transcript names avoid every catalogue token so the drive sweep in
# stage 6 can never eat this script's own output.
$ReportFile  = Join-Path $LogDir ("Audit-Report-$stamp.log")
$Transcript  = Join-Path $LogDir ("Audit-Console-$stamp.log")
try { Start-Transcript -Path $Transcript -Force | Out-Null } catch { }

$script:Report      = New-Object System.Collections.Generic.List[string]
$script:RebootNeeded = $false
$script:Resistant    = New-Object System.Collections.Generic.List[string]

function Log {
    param([string]$Text, [string]$Color = 'Gray', [switch]$NoHost)
    $script:Report.Add($Text)
    if (-not $NoHost) { Write-Host $Text -ForegroundColor $Color }
}
function Section {
    param([string]$Text)
    $bar = '=' * 72
    Log ''
    Log $bar Cyan
    Log "  $Text" Cyan
    Log $bar Cyan
}
function Ok  { param([string]$t) Log "  [+] $t" Green }
function Bad { param([string]$t) Log "  [!] $t" Yellow }
function Note{ param([string]$t) Log "      $t" Gray }

Log ("Remote Access & RMM Sweep  -  {0}" -f (Get-Date)) White
Log ("Computer : {0}" -f $env:COMPUTERNAME)
Log ("User     : {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
Log ("Mode     : {0}" -f $(if ($ScanOnly) { 'SCAN ONLY (no changes)' } elseif ($Force) { 'FORCE (unattended removal)' } else { 'INTERACTIVE removal' }))
Log ("Report   : {0}" -f $ReportFile)

# =============================================== native force-delete help ====

if (-not ('Win32.PendingDelete' -as [type])) {
    Add-Type -Namespace Win32 -Name PendingDelete -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
}

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
        if (Test-Path -LiteralPath $Path) { try { [System.IO.Directory]::Delete($Path, $false) } catch { } }
    } else {
        try { [System.IO.File]::Delete($Path) } catch { }
    }
}
function Remove-NestedReparsePoints {
    param([string]$Dir)
    foreach ($child in @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction SilentlyContinue)) {
        if (Test-IsReparsePoint $child.FullName) { Remove-LinkOnly $child.FullName }
        elseif ($child.PSIsContainer) { Remove-NestedReparsePoints -Dir $child.FullName }
    }
}

# Paths the script will never delete, no matter what matched.
$script:ProtectedPaths = @(
    $env:SystemDrive, $env:windir, $env:ProgramFiles, ${env:ProgramFiles(x86)},
    $env:CommonProgramFiles, ${env:CommonProgramFiles(x86)}, $env:ProgramData,
    (Join-Path $env:SystemDrive 'Users'),
    (Join-Path $env:windir 'System32'), (Join-Path $env:windir 'SysWOW64')
) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() }

function Remove-ItemForcefully {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($ScanOnly) { Note "would delete: $Path"; return }
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $full = $item.FullName
    $normalized = $full.TrimEnd('\')

    if ((($normalized -split '\\').Count -lt 3) -or ($script:ProtectedPaths -contains $normalized.ToLower())) {
        Bad "REFUSING to delete protected path: $full"; $script:Resistant.Add($full); return
    }

    if (Test-IsReparsePoint $full) {
        Remove-LinkOnly $full
        if (-not (Test-Path -LiteralPath $full)) { Ok "Removed link (target untouched): $full" }
        else { $script:Resistant.Add($full); Bad "Could not remove link: $full" }
        return
    }

    $isDir = Test-Path -LiteralPath $full -PathType Container
    if ($isDir) { Remove-NestedReparsePoints -Dir $full }

    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $full)) { Ok "Removed: $full"; return }

    if ($isDir) {
        takeown.exe /F "$full" /R /A /D Y 2>&1 | Out-Null
        icacls.exe "$full" /grant '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /T /C /Q 2>&1 | Out-Null
    } else {
        takeown.exe /F "$full" /A 2>&1 | Out-Null
        icacls.exe "$full" /grant '*S-1-5-32-544:F' '*S-1-5-18:F' /C /Q 2>&1 | Out-Null
    }
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $full)) { Ok "Removed after taking ownership: $full"; return }

    if ($isDir) { cmd.exe /d /c "rd /s /q `"$full`"" 2>&1 | Out-Null }
    else        { cmd.exe /d /c "del /f /q `"$full`"" 2>&1 | Out-Null }
    if (-not (Test-Path -LiteralPath $full)) { Ok "Removed via cmd: $full"; return }

    $targets = @()
    if ($isDir) {
        $targets += @(Get-ChildItem -LiteralPath $full -Recurse -Force -ErrorAction SilentlyContinue |
                      Sort-Object { $_.FullName.Length } -Descending | Select-Object -ExpandProperty FullName)
    }
    $targets += $full
    $queued = 0
    foreach ($t in $targets) { if ([Win32.PendingDelete]::MoveFileEx($t, $null, 4)) { $queued++ } }
    if ($queued -gt 0) {
        $script:RebootNeeded = $true
        Bad "Locked - $queued item(s) queued for deletion at next reboot: $full"
    } else {
        icacls.exe "$full" /reset /T /C /Q 2>&1 | Out-Null
        $script:Resistant.Add($full); Bad "Still resistant: $full"
    }
}

# =============================================================== catalogue ====
# Tier  : Remove = uninstall + wipe when found.  Report = surface only (dual-use
#         admin tooling or a Windows built-in - deleting it would hurt the OS or
#         the admin, so an IT pro decides).
# Pattern: regex matched (case-insensitive) against installed-program display
#         names/publishers, service names/paths, process names/paths, task names
#         and folder names.
# Tokens : distinctive filename fragments swept for across the whole drive in
#         stage 6 - ONLY for products actually found. Kept collision-light.

function P { param($Name,$Cat,$Tier,$Pattern,$Tokens='') [pscustomobject]@{
    Name=$Name; Category=$Cat; Tier=$Tier; Pattern=$Pattern;
    Tokens=@($Tokens -split ';' | Where-Object { $_ }) } }

$Catalog = @(
    # ---- RMM platforms -----------------------------------------------------
    P 'ConnectWise ScreenConnect / Control' 'RMM' 'Remove' 'screenconnect|connectwise\s*control' 'screenconnect'
    P 'ConnectWise Automate (LabTech)'      'RMM' 'Remove' 'labtech|connectwise\s*automate|ltsvc|ltservice' 'labtech;ltsvc;ltservice'
    P 'ConnectWise ITSupport247'            'RMM' 'Remove' 'itsupport247|saazod|saazapsc' 'itsupport247;saazod'
    P 'Datto RMM (CentraStage)'             'RMM' 'Remove' 'datto\s*rmm|centrastage|aemagent' 'centrastage;aemagent'
    P 'NinjaOne (NinjaRMM)'                 'RMM' 'Remove' 'ninjarmm|ninja\s*rmm|ninjaone' 'ninjarmm;ninjaone'
    P 'Atera Agent'                         'RMM' 'Remove' 'atera' 'ateraagent;atera'
    P 'Syncro / Kabuto'                     'RMM' 'Remove' 'syncro|kabuto|repairtech' 'syncro;kabuto'
    P 'Kaseya VSA Agent'                    'RMM' 'Remove' 'kaseya|agentmon' 'kaseya;agentmon'
    P 'N-able N-central'                    'RMM' 'Remove' 'n-?able|n-?central|windowsagent' 'ncentral'
    P 'N-able Advanced Monitoring Agent'    'RMM' 'Remove' 'advanced\s*monitoring\s*agent|winagent' 'advancedmonitoringagent;winagent'
    P 'N-able Take Control / BeAnywhere'    'RMM' 'Remove' 'take\s*control|beanywhere|getsupportservice|bascsrv' 'beanywhere'
    P 'ManageEngine Endpoint/Desktop Central' 'RMM' 'Remove' 'manageengine|desktop\s*central|endpoint\s*central|dcagent' 'manageengine;dcagentservice'
    P 'Pulseway'                            'RMM' 'Remove' 'pulseway' 'pulseway'
    P 'Action1'                             'RMM' 'Remove' 'action1' 'action1'
    P 'Tactical RMM'                        'RMM' 'Remove' 'tactical\s*rmm|tacticalagent|tacticalrmm' 'tacticalrmm;tacticalagent'
    P 'Level.io'                            'RMM' 'Remove' 'level\.io|level-windows|level\s*rmm' 'level-windows'
    P 'Automox'                             'RMM' 'Remove' 'automox' 'automox'
    P 'Addigy'                              'RMM' 'Remove' 'addigy' 'addigy'
    P 'ImmyBot'                             'RMM' 'Remove' 'immybot' 'immybot'
    P 'SuperOps'                            'RMM' 'Remove' 'superops' 'superops'
    P 'Domotz'                              'RMM' 'Remove' 'domotz' 'domotz'
    P 'Auvik'                               'RMM' 'Remove' 'auvik' 'auvik'
    P 'PDQ Connect'                         'RMM' 'Remove' 'pdq\s*connect|pdqconnect' 'pdqconnect'
    P 'Itarian / Comodo RMM'                'RMM' 'Remove' 'itarian|comodo\s*rmm|rmmservice' 'itarian'
    P 'FleetDeck'                           'RMM' 'Remove' 'fleetdeck' 'fleetdeck'
    P 'Bluetrait MSP Agent'                 'RMM' 'Remove' 'bluetrait' 'bluetrait'

    # ---- Remote-access / support tools ------------------------------------
    P 'AnyDesk'                             'Remote' 'Remove' 'anydesk' 'anydesk'
    P 'TeamViewer'                          'Remote' 'Remove' 'teamviewer' 'teamviewer'
    P 'Splashtop'                           'Remote' 'Remove' 'splashtop' 'splashtop'
    P 'LogMeIn'                             'Remote' 'Remove' 'logmein' 'logmein'
    P 'GoTo (GoToAssist/MyPC/Resolve)'      'Remote' 'Remove' 'gotoassist|gotomypc|goto\s*resolve|gotoresolve|goto\s*opener' 'gotoassist;gotomypc;gotoresolve'
    P 'RemotePC'                            'Remote' 'Remove' 'remotepc' 'remotepc'
    P 'RustDesk'                            'Remote' 'Remove' 'rustdesk' 'rustdesk'
    P 'UltraViewer'                         'Remote' 'Remove' 'ultraviewer' 'ultraviewer'
    P 'Supremo'                             'Remote' 'Remove' 'supremo' 'supremo'
    P 'AeroAdmin'                           'Remote' 'Remove' 'aeroadmin' 'aeroadmin'
    P 'Ammyy Admin'                         'Remote' 'Remove' 'ammyy' 'ammyy'
    P 'Remote Utilities / RMS'              'Remote' 'Remove' 'remote\s*utilities|remoteutilities|rutserv|rfusclient|remote\s*manipulator|rmansys' 'rutserv;rfusclient;remoteutilities'
    P 'Radmin'                              'Remote' 'Remove' 'radmin|rserver3' 'radmin;rserver3'
    P 'DWService'                           'Remote' 'Remove' 'dwservice|dwagent' 'dwagent;dwservice'
    P 'Getscreen'                           'Remote' 'Remove' 'getscreen' 'getscreen'
    P 'HopToDesk'                           'Remote' 'Remove' 'hoptodesk' 'hoptodesk'
    P 'Zoho Assist'                         'Remote' 'Remove' 'zoho\s*assist|zohoassist|zaservice' 'zohoassist'
    P 'ISL Online / ISL Light'              'Remote' 'Remove' 'isl\s*online|isl\s*light|isllight' 'isllight;islonline'
    P 'BeyondTrust / Bomgar'                'Remote' 'Remove' 'beyondtrust|bomgar' 'bomgar;beyondtrust'
    P 'Chrome Remote Desktop'               'Remote' 'Remove' 'chrome\s*remote\s*desktop|remoting_host|chromoting' 'remoting_host;chromoting'
    P 'Parsec'                              'Remote' 'Remove' 'parsec' 'parsecd'
    P 'RealVNC'                             'Remote' 'Remove' 'realvnc|vncserver' 'realvnc;vncserver'
    P 'TightVNC'                            'Remote' 'Remove' 'tightvnc|tvnserver' 'tightvnc;tvnserver'
    P 'UltraVNC'                            'Remote' 'Remove' 'ultravnc|uvnc' 'ultravnc'
    P 'TigerVNC'                            'Remote' 'Remove' 'tigervnc' 'tigervnc'
    P 'NoMachine'                           'Remote' 'Remove' 'nomachine' 'nomachine'
    P 'Iperius Remote'                      'Remote' 'Remove' 'iperius\s*remote' 'iperius'
    P 'ShowMyPC'                            'Remote' 'Remove' 'showmypc' 'showmypc'
    P 'MeshCentral / MeshAgent'             'Remote' 'Remove' 'meshcentral|meshagent' 'meshagent;meshcentral'
    P 'AnyViewer'                           'Remote' 'Remove' 'anyviewer' 'anyviewer'
    P 'ToDesk'                              'Remote' 'Remove' 'todesk' 'todesk'
    P 'Sunlogin'                            'Remote' 'Remove' 'sunlogin' 'sunlogin'

    # ---- Tunnelling / overlay nets (classic attacker persistence) ----------
    P 'ngrok'                               'Tunnel' 'Remove' 'ngrok' 'ngrok'
    P 'Cloudflare Tunnel (cloudflared)'     'Tunnel' 'Remove' 'cloudflared|cloudflare\s*tunnel' 'cloudflared'
    P 'LocalXpose'                          'Tunnel' 'Remove' 'localxpose|loclx' 'localxpose;loclx'
    P 'PiTunnel'                            'Tunnel' 'Remove' 'pitunnel' 'pitunnel'
    P 'NetBird'                             'Tunnel' 'Remove' 'netbird' 'netbird'
    P 'ZeroTier'                            'Tunnel' 'Remove' 'zerotier' 'zerotier'
    P 'Tailscale'                           'Tunnel' 'Remove' 'tailscale' 'tailscale'

    # ---- Dual-use / built-in (REPORT only; never auto-deleted) -------------
    P 'Windows Quick Assist'                'Built-in' 'Report' 'quick\s*assist|quickassist' ''
    P 'RDP (mstsc / Remote Desktop)'        'Built-in' 'Report' '\bmstsc\b|remote\s*desktop\s*connection' ''
    P 'PsExec (Sysinternals)'               'Dual-use' 'Report' 'psexec|psexesvc' ''
    P 'PuTTY / KiTTY / plink (SSH)'          'Dual-use' 'Report' '\bputty\b|\bkitty\b|\bplink\b' ''
    P 'OpenSSH Server (sshd)'               'Dual-use' 'Report' 'openssh|sshd' ''
    P 'WinRM / PowerShell Remoting'         'Built-in' 'Report' 'winrm' ''
)

# =============================================================== inventory ====

Section 'STAGE 1 - Inventory: catalogued remote / RMM software'

$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$installed = @(Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName })
$services  = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)
$procs     = @(Get-Process -ErrorAction SilentlyContinue)
$tasks     = @(Get-ScheduledTask -ErrorAction SilentlyContinue)

# Folder roots to check for product folders.
$folderRoots = New-Object System.Collections.Generic.List[string]
foreach ($r in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)) {
    if ($r) { $folderRoots.Add($r) }
}
foreach ($u in @(Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue)) {
    foreach ($s in 'AppData\Local','AppData\Roaming') { $folderRoots.Add((Join-Path $u.FullName $s)) }
}
$childFolders = @(foreach ($root in $folderRoots) {
    Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue
})

$Detected = New-Object System.Collections.Generic.List[object]

foreach ($entry in $Catalog) {
    $rx = [regex]::new($entry.Pattern, 'IgnoreCase')
    $hitInstalled = @($installed | Where-Object { $rx.IsMatch("$($_.DisplayName) $($_.Publisher) $($_.PSChildName)") })
    $hitServices  = @($services  | Where-Object { $rx.IsMatch("$($_.Name) $($_.DisplayName) $($_.PathName)") })
    $hitProcs     = @($procs     | Where-Object { $rx.IsMatch("$($_.Name)") -or ($_.Path -and $rx.IsMatch($_.Path)) })
    $hitTasks     = @($tasks     | Where-Object { $rx.IsMatch("$($_.TaskName) $($_.TaskPath)") })
    $hitFolders   = @($childFolders | Where-Object { $rx.IsMatch($_.Name) } | Select-Object -ExpandProperty FullName)

    if ($hitInstalled.Count -or $hitServices.Count -or $hitProcs.Count -or $hitTasks.Count -or $hitFolders.Count) {
        $obj = [pscustomobject]@{
            Name      = $entry.Name
            Category  = $entry.Category
            Tier      = $entry.Tier
            Tokens    = $entry.Tokens
            Installed = $hitInstalled
            Services  = $hitServices
            Procs     = $hitProcs
            Tasks     = $hitTasks
            Folders   = $hitFolders
        }
        $Detected.Add($obj)
        $color = if ($entry.Tier -eq 'Remove') { 'Yellow' } else { 'Magenta' }
        Log ("  [FOUND] {0}  ({1}, tier={2})" -f $entry.Name, $entry.Category, $entry.Tier) $color
        if ($hitInstalled.Count) { Note ("installed : " + (($hitInstalled | ForEach-Object { $_.DisplayName }) -join '; ')) }
        if ($hitServices.Count)  { Note ("services  : " + (($hitServices  | ForEach-Object { $_.Name }) -join ', ')) }
        if ($hitProcs.Count)     { Note ("processes : " + (($hitProcs | ForEach-Object { $_.Name } | Sort-Object -Unique) -join ', ')) }
        if ($hitTasks.Count)     { Note ("tasks     : " + (($hitTasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }) -join ', ')) }
        if ($hitFolders.Count)   { Note ("folders   : " + ($hitFolders -join '; ')) }
    }
}
if ($Detected.Count -eq 0) { Ok 'No catalogued remote/RMM software found.' }

# ======================================================= custom-RMM hunt ====

Section 'STAGE 2 - Heuristic hunt for a custom / unknown remote tool'
Log '  (Reported for review - NOT auto-deleted; legit software can match too)' Gray

$script:Suspicious = New-Object System.Collections.Generic.List[object]
$userWritable = '(?i)\\(Users|AppData|Temp|ProgramData|Windows\\Temp|Public|Downloads|Recycle)'

function Get-Signature {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return 'NoFile' }
    try {
        $s = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($s.Status -ne 'Valid') { return "Unsigned/Invalid($($s.Status))" }
        $subj = $s.SignerCertificate.Subject
        if ($subj -match 'Microsoft (Windows|Corporation)') { return 'Microsoft' }
        return "Signed: $subj"
    } catch { return 'SigError' }
}
function Add-Suspicious {
    param($Kind,$Detail,$Path,$Why)
    $script:Suspicious.Add([pscustomobject]@{ Kind=$Kind; Detail=$Detail; Path=$Path; Why=$Why; Sig=(Get-Signature $Path) })
}

# 2a. Services whose binary lives in a user-writable location, or is unsigned.
foreach ($svc in $services) {
    $bin = $null
    if ($svc.PathName -match '"([^"]+\.exe)"') { $bin = $matches[1] }
    elseif ($svc.PathName -match '^\s*([^\s]+\.exe)') { $bin = $matches[1] }
    if (-not $bin) { continue }
    $sig = Get-Signature $bin
    $odd = ($bin -match $userWritable)
    $unsigned = ($sig -like 'Unsigned*' -or $sig -eq 'NoFile')
    if ($odd -or $unsigned) {
        Add-Suspicious 'Service' "$($svc.Name) ($($svc.State))" $bin ("binary " + $(if ($odd){'in user-writable path '}) + $(if ($unsigned){'and unsigned'}))
    }
}

# 2b. Run-key autoruns that are encoded PowerShell, point into user-writable
#     paths, or pull from the network.
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($rk in $runKeys) {
    if (-not (Test-Path -LiteralPath $rk)) { continue }
    $props = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
        $val = "$($p.Value)"
        if ($val -match '(?i)-enc(odedcommand)?\s|downloadstring|invoke-webrequest|iwr |frombase64|powershell.*hidden' -or
            $val -match $userWritable) {
            Add-Suspicious 'Autorun' "$rk :: $($p.Name) = $val" $null 'suspicious autorun command/location'
        }
    }
}

# 2c. Unknown programs that LISTEN for inbound connections (shown in stage 3,
#     correlated there). Here we just flag listeners from odd/unsigned binaries.
#     (Done in stage 3 where sockets are enumerated.)

if ($script:Suspicious.Count -eq 0) { Ok 'No obvious custom/unknown remote-tool fingerprints.' }
else {
    foreach ($s in $script:Suspicious) {
        Bad ("{0}: {1}" -f $s.Kind, $s.Detail)
        Note ("path: {0}" -f $(if ($s.Path) { $s.Path } else { 'n/a' }))
        Note ("sig : {0}  |  why: {1}" -f $s.Sig, $s.Why)
    }
}

# ============================================================ network trace ====

Section 'STAGE 3 - Inbound network exposure (how someone could still get in)'

# Build pid -> process-path map once.
$pidMap = @{}
foreach ($pr in $procs) { if (-not $pidMap.ContainsKey($pr.Id)) { $pidMap[$pr.Id] = $pr.Path } }

$conns = $null
try { $conns = @(Get-NetTCPConnection -ErrorAction Stop) } catch { $conns = $null }

$listenExposed = @()
$inbound       = @()
if ($conns) {
    $listenExposed = @($conns | Where-Object { $_.State -eq 'Listen' -and $_.LocalAddress -in '0.0.0.0','::','*' })
    $listenPorts   = @($listenExposed | ForEach-Object { $_.LocalPort } | Sort-Object -Unique)
    $inbound = @($conns | Where-Object {
        $_.State -eq 'Established' -and $_.LocalPort -in $listenPorts -and
        $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80|::$)'
    })
} else {
    Note 'Get-NetTCPConnection unavailable; falling back to netstat -ano.'
    $raw = netstat -ano 2>$null | Select-String '^\s+TCP'
    foreach ($line in $raw) {
        $f = ($line -replace '^\s+','') -split '\s+'
        if ($f.Count -lt 5) { continue }
        $local = $f[1]; $remote = $f[2]; $state = $f[3]; $opid = [int]$f[4]
        if ($state -eq 'LISTENING' -and ($local -match '^(0\.0\.0\.0|\[::\]):(\d+)$')) {
            $listenExposed += [pscustomobject]@{ LocalAddress=($local -split ':')[0]; LocalPort=($local -split ':')[-1]; OwningProcess=$opid; State='Listen' }
        } elseif ($state -eq 'ESTABLISHED' -and $remote -notmatch '^(127\.|\[::1\]|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)') {
            $inbound += [pscustomobject]@{ LocalAddress=($local -split ':')[0]; LocalPort=($local -split ':')[-1]; RemoteAddress=($remote -split ':')[0]; OwningProcess=$opid; State='Established' }
        }
    }
}

Log '  Listening sockets exposed to all interfaces:' White
if ($listenExposed.Count -eq 0) { Note 'none' }
foreach ($l in ($listenExposed | Sort-Object LocalPort -Unique)) {
    $opid = [int]$l.OwningProcess
    $path = $pidMap[$opid]
    $pname = ($procs | Where-Object { $_.Id -eq $opid } | Select-Object -First 1).Name
    $sig  = Get-Signature $path
    $flag = ''
    # Correlate with catalogue / suspicious.
    $catHit = $Detected | Where-Object { $_.Procs | Where-Object { $_.Id -eq $opid } } | Select-Object -First 1
    if ($catHit) { $flag = "  <= $($catHit.Name)" }
    elseif ($sig -like 'Unsigned*' -or ($path -and $path -match $userWritable)) {
        $flag = '  <= SUSPICIOUS (unsigned / user-writable path)'
        Add-Suspicious 'Listener' "port $($l.LocalPort) pid $opid ($pname)" $path 'listens for inbound from an unsigned/odd-path binary'
    }
    Note ("port {0,-6} pid {1,-6} {2,-22} sig={3}{4}" -f $l.LocalPort, $opid, $(if ($pname) { $pname } else { '?' }), $sig, $flag)
}

Log '  Live inbound sessions from non-local addresses:' White
if ($inbound.Count -eq 0) { Note 'none' }
foreach ($c in $inbound) {
    $opid = [int]$c.OwningProcess
    $pname = ($procs | Where-Object { $_.Id -eq $opid } | Select-Object -First 1).Name
    Bad ("from {0}  ->  local port {1}  pid {2} ({3})" -f $c.RemoteAddress, $c.LocalPort, $opid, $(if ($pname) { $pname } else { '?' }))
}

# Remote-access posture.
Log '  Remote-access posture:' White
$rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
Note ("RDP (Remote Desktop)      : " + $(if ($rdp -eq 0) { 'ENABLED  <= inbound RDP is allowed' } elseif ($rdp -eq 1) { 'disabled' } else { 'unknown' }))
$winrm = (Get-Service WinRM -ErrorAction SilentlyContinue)
Note ("WinRM (PowerShell remoting): " + $(if ($winrm -and $winrm.Status -eq 'Running') { 'RUNNING' } else { 'not running' }))
$sshd = (Get-Service sshd -ErrorAction SilentlyContinue)
Note ("OpenSSH server (sshd)     : " + $(if ($sshd -and $sshd.Status -eq 'Running') { 'RUNNING' } else { 'not present/stopped' }))

# Inbound firewall ALLOW rules.
Log '  Enabled inbound firewall ALLOW rules:' White
try {
    $fw = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)
    $appFilters = @{}
    try { Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | ForEach-Object { $appFilters[$_.InstanceID] = $_.Program } } catch {}
    Note ("{0} enabled inbound allow rule(s). Rules whose program is a detected tool are flagged in stage 7." -f $fw.Count)
} catch { Note 'Get-NetFirewallRule unavailable on this system.' }

# Local administrators.
Log '  Local Administrators group members:' White
try {
    $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop)
    foreach ($a in $admins) { Note ("{0}  ({1})" -f $a.Name, $a.ObjectClass) }
} catch {
    $admins = (net localgroup Administrators 2>$null)
    foreach ($line in $admins) { if ($line -and $line -notmatch '----|command completed|Alias name|Comment|Members|^\s*$') { Note $line } }
}

# ========================================================= decision / confirm ====

$removable = @($Detected | Where-Object { $_.Tier -eq 'Remove' })

Section 'SUMMARY BEFORE ANY CHANGES'
Log ("Catalogued tools found : {0}  (removable: {1}, report-only: {2})" -f $Detected.Count, $removable.Count, ($Detected.Count - $removable.Count))
Log ("Heuristic suspects     : {0}" -f $script:Suspicious.Count)
Log ("Live inbound sessions  : {0}" -f $inbound.Count)

if ($ScanOnly) {
    Log ''
    Ok 'SCAN-ONLY mode: nothing was changed.'
    # jump to report
} else {
    if ($removable.Count -eq 0 -and -not ($RemoveSuspicious -and $script:Suspicious.Count)) {
        Log ''
        Ok 'Nothing in the auto-removal tier. Review the report for anything flagged.'
    } else {
        if (-not $Force) {
            Log ''
            Log 'The following CATALOGUED tools will be UNINSTALLED and their files/keys WIPED:' Yellow
            $removable | ForEach-Object { Log ("   - {0}" -f $_.Name) Yellow }
            if ($RemoveSuspicious -and $script:Suspicious.Count) {
                Log 'Heuristic suspects will also be killed/blocked (-RemoveSuspicious):' Yellow
                $script:Suspicious | ForEach-Object { Log ("   - {0}: {1}" -f $_.Kind, $_.Detail) Yellow }
            }
            Log 'No backup is made. Protected system paths are never deleted.' Yellow
            $confirm = Read-Host 'Type YES to proceed with removal'
            if ($confirm -cne 'YES') {
                Log 'Aborted by user - nothing was changed.' Green
                $ScanOnly = $true   # fall through to report without acting
            }
        }
    }
}

# ================================================================ removal ====

if (-not $ScanOnly -and $removable.Count -gt 0) {

    Section 'STAGE 5 - Uninstall catalogued products'
    foreach ($d in $removable) {
        foreach ($p in $d.Installed) {
            $cmd = $null; $quiet = $true
            if ($p.QuietUninstallString) { $cmd = $p.QuietUninstallString }
            elseif ($p.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') { $cmd = "msiexec.exe /x $($p.PSChildName) /qn /norestart" }
            elseif ($p.UninstallString) { $cmd = $p.UninstallString; $quiet = $false }
            if (-not $cmd) { continue }
            Log ("  Uninstalling: {0}" -f $p.DisplayName) Gray
            try {
                $style = if ($quiet) { 'Hidden' } else { 'Normal' }
                $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList ('/d /s /c "' + $cmd + '"') -WindowStyle $style -PassThru
                if (-not $proc.WaitForExit(300000)) {
                    Start-Process taskkill.exe -ArgumentList "/PID $($proc.Id) /T /F" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                    Bad "Timed out: $($p.DisplayName) (continuing with forced removal)"
                } elseif ($proc.ExitCode -in 0,1605,3010) {
                    if ($proc.ExitCode -eq 3010) { $script:RebootNeeded = $true }
                    Ok "Uninstalled: $($p.DisplayName)"
                } else { Bad "Uninstaller for $($p.DisplayName) returned $($proc.ExitCode)" }
            } catch { Bad "Could not run uninstaller for $($p.DisplayName): $($_.Exception.Message)" }
            Start-Sleep -Seconds 2
        }
    }

    Section 'STAGE 5 - Kill processes'
    foreach ($d in $removable) {
        foreach ($pr in $d.Procs) {
            try { Stop-Process -Id $pr.Id -Force -ErrorAction Stop; Ok "Killed $($pr.Name) (PID $($pr.Id))" }
            catch { Bad "Could not kill $($pr.Name): $($_.Exception.Message)" }
        }
    }

    Section 'STAGE 5 - Stop & delete services / drivers'
    foreach ($d in $removable) {
        foreach ($svc in $d.Services) {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            sc.exe config "$($svc.Name)" start= disabled 2>&1 | Out-Null
            sc.exe delete "$($svc.Name)" 2>&1 | Out-Null
            $ex = $LASTEXITCODE
            if ($ex -eq 0) {
                sc.exe query "$($svc.Name)" 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 1060) { Ok "Deleted service: $($svc.Name)" }
                else { $script:RebootNeeded = $true; Ok "Service marked for deletion at reboot: $($svc.Name)" }
            } elseif ($ex -eq 1072) { $script:RebootNeeded = $true; Ok "Service marked for deletion at reboot: $($svc.Name)" }
            else { $script:Resistant.Add("service: $($svc.Name)"); Bad "Could not delete service $($svc.Name) (sc.exe $ex)" }
        }
    }

    Section 'STAGE 5 - Remove scheduled tasks'
    foreach ($d in $removable) {
        foreach ($t in $d.Tasks) {
            try { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
                  Ok "Removed task: $($t.TaskPath)$($t.TaskName)" }
            catch { Bad "Could not remove task $($t.TaskName): $($_.Exception.Message)" }
        }
    }

    Section 'STAGE 6 - Delete known folders'
    foreach ($d in $removable) {
        foreach ($f in $d.Folders) { if (Test-Path -LiteralPath $f) { Remove-ItemForcefully -Path $f } }
    }

    Section 'STAGE 6 - Delete registry keys & autorun entries'
    foreach ($d in $removable) {
        $rx = [regex]::new(($Catalog | Where-Object { $_.Name -eq $d.Name }).Pattern, 'IgnoreCase')
        # per-product software keys
        foreach ($hive in 'HKLM:\SOFTWARE','HKLM:\SOFTWARE\WOW6432Node','HKCU:\SOFTWARE') {
            foreach ($k in @(Get-ChildItem -LiteralPath $hive -ErrorAction SilentlyContinue | Where-Object { $rx.IsMatch($_.PSChildName) })) {
                if ($ScanOnly) { Note "would remove key: $($k.PSPath)"; continue }
                try { Remove-Item -LiteralPath $k.PSPath -Recurse -Force -ErrorAction Stop; Ok "Removed key: $($k.Name)" }
                catch { $script:Resistant.Add($k.Name); Bad "Could not remove key $($k.Name): $($_.Exception.Message)" }
            }
        }
        # surviving uninstall entries
        foreach ($p in $d.Installed) {
            if ($p.PSPath -and (Test-Path -LiteralPath $p.PSPath)) {
                try { Remove-Item -LiteralPath $p.PSPath -Recurse -Force -ErrorAction Stop; Ok "Removed uninstall key: $($p.DisplayName)" } catch {}
            }
        }
        # autorun values
        foreach ($rk in $runKeys) {
            if (-not (Test-Path -LiteralPath $rk)) { continue }
            $props = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { continue }
                if ($rx.IsMatch("$($p.Name) $($p.Value)")) {
                    if ($ScanOnly) { Note "would remove autorun: $($p.Name)"; continue }
                    try { Remove-ItemProperty -Path $rk -Name $p.Name -Force -ErrorAction Stop; Ok "Removed autorun: $($p.Name)" } catch {}
                }
            }
        }
    }

    # -------- whole-drive sweep for the names that were actually found --------
    Section 'STAGE 6 - Comb the whole drive for leftover files named after found tools'
    $tokens = @($removable | ForEach-Object { $_.Tokens } | Where-Object { $_ } | Sort-Object -Unique)
    if ($tokens.Count -eq 0) { Note 'No safe name tokens to sweep for.' }
    else {
        Log ("  Sweeping {0}\ for: {1}" -f $env:SystemDrive, ($tokens -join ', '))
        # Match a token only at a NAME-COMPONENT boundary (start of the name or
        # after a non-alphanumeric separator). This catches "AteraAgent.exe" and
        # "atera.log" but NOT unrelated files like "collateral" / "bilateral".
        $tokenRx = [regex]::new('(?i)(^|[^a-z0-9])(' + (($tokens | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')')
        $excludeRoots = @(
            (Join-Path $env:windir 'WinSxS'),
            (Join-Path $env:windir 'servicing'),
            (Join-Path $env:windir 'assembly'),
            (Join-Path $env:SystemDrive '$Recycle.Bin'),
            $LogDir
        ) | ForEach-Object { $_.TrimEnd('\') + '\' }
        $excludeFiles = @($PSCommandPath, $ReportFile, $Transcript) | Where-Object { $_ }

        $hits = @(Get-ChildItem -LiteralPath "$env:SystemDrive\" -Recurse -Force -ErrorAction SilentlyContinue |
                  Where-Object { $tokenRx.IsMatch($_.Name) })
        Log ("  {0} name match(es) found" -f $hits.Count)
        $dirs  = @($hits | Where-Object { $_.PSIsContainer } | Sort-Object { $_.FullName.Length })
        $files = @($hits | Where-Object { -not $_.PSIsContainer })
        foreach ($hit in ($dirs + $files)) {
            $full = $hit.FullName
            if (-not (Test-Path -LiteralPath $full)) { continue }
            if ($excludeFiles -contains $full) { continue }
            $norm = $full.TrimEnd('\') + '\'
            if ($excludeRoots | Where-Object { $norm.StartsWith($_, [System.StringComparison]::OrdinalIgnoreCase) }) { continue }
            Remove-ItemForcefully -Path $full
        }
    }

    # --------------------------- network remediation --------------------------
    Section 'STAGE 7 - Network remediation for removed tools'
    # Kill any remaining listeners owned by removed tools + block their binaries.
    foreach ($d in $removable) {
        foreach ($pr in $d.Procs) {
            if (Get-Process -Id $pr.Id -ErrorAction SilentlyContinue) {
                try { Stop-Process -Id $pr.Id -Force -ErrorAction Stop; Ok "Killed lingering $($pr.Name) (PID $($pr.Id))" } catch {}
            }
        }
    }
    try {
        $fwRules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop)
        $removedTokensRx = if ($tokens.Count) { [regex]::new('(?i)(^|[^a-z0-9])(' + (($tokens | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')') } else { $null }
        foreach ($r in $fwRules) {
            $prog = $null
            try { $prog = ($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program } catch {}
            $text = "$($r.DisplayName) $prog"
            if ($removedTokensRx -and $removedTokensRx.IsMatch($text)) {
                if ($ScanOnly) { Note "would disable inbound rule: $($r.DisplayName)"; continue }
                try { Disable-NetFirewallRule -Name $r.Name -ErrorAction Stop; Ok "Disabled inbound firewall allow rule: $($r.DisplayName)" } catch {}
            }
        }
    } catch { Note 'Firewall rule remediation skipped (cmdlets unavailable).' }
}

# -------- optional remediation of heuristic suspects ----------------------
if (-not $ScanOnly -and $RemoveSuspicious -and $script:Suspicious.Count) {
    Section 'STAGE 7 - Act on heuristic suspects (-RemoveSuspicious)'
    foreach ($s in ($script:Suspicious | Where-Object { $_.Kind -in 'Service','Listener' })) {
        $go = $Force
        if (-not $Force) {
            $ans = Read-Host ("Block/stop suspect '{0}' [{1}]? (y/N)" -f $s.Detail, $s.Sig)
            $go = ($ans -match '^(y|yes)$')
        }
        if (-not $go) { Note "skipped: $($s.Detail)"; continue }
        if ($s.Kind -eq 'Service') {
            $svcName = ($s.Detail -split ' ')[0]
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            sc.exe config "$svcName" start= disabled 2>&1 | Out-Null
            Ok "Disabled suspect service: $svcName (left on disk for IT review)"
        }
        if ($s.Path -and (Test-Path -LiteralPath $s.Path)) {
            try {
                New-NetFirewallRule -DisplayName ("BLOCK-suspect-" + (Split-Path $s.Path -Leaf)) -Direction Inbound -Action Block -Program $s.Path -ErrorAction Stop | Out-Null
                New-NetFirewallRule -DisplayName ("BLOCK-suspect-out-" + (Split-Path $s.Path -Leaf)) -Direction Outbound -Action Block -Program $s.Path -ErrorAction Stop | Out-Null
                Ok "Firewall-blocked suspect binary: $($s.Path)"
            } catch { Bad "Could not add firewall block for $($s.Path): $($_.Exception.Message)" }
        }
    }
    Note 'Suspect binaries are BLOCKED, not deleted - confirm with your IT pro before removing.'
}

# ================================================================= report ====

Section 'DONE - Summary'
if ($script:Resistant.Count -gt 0) {
    Log '  Could NOT be removed (needs manual / IT attention):' Yellow
    $script:Resistant | Sort-Object -Unique | ForEach-Object { Log "    $_" Yellow }
} elseif (-not $ScanOnly) { Ok 'No resistant items.' }

Log ''
Log '  NEXT STEPS / what to tell your IT professional:' White
Note '1. Review the "Live inbound sessions" and "Heuristic suspects" sections above.'
Note '2. If anything was queued for deletion, REBOOT to finish the wipe.'
Note '3. Rotate every password from a KNOWN-CLEAN device, and enable MFA.'
Note '4. If RDP/WinRM/sshd showed ENABLED/RUNNING and you did not set that up, have IT disable it.'
Note '5. Check the local Administrators list above for accounts you do not recognise.'
Note '6. Heuristic suspects may be legitimate - do not delete them without confirmation.'

Log ("`n  Full report : {0}" -f $ReportFile) Gray
Log   ("  Console log : {0}" -f $Transcript) Gray

try { Stop-Transcript | Out-Null } catch { }

# Write the clean report and open it.
try { $script:Report | Out-File -FilePath $ReportFile -Encoding UTF8 -Force } catch {}

if ($script:RebootNeeded) {
    Write-Host "`nA REBOOT is required to finish removing locked files/services." -ForegroundColor Yellow
}

# Open the log in Notepad for the user.
try { Start-Process notepad.exe -ArgumentList "`"$ReportFile`"" -ErrorAction SilentlyContinue | Out-Null } catch {}

# Prompt to send to IT.
Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' Please SEND THIS LOG TO YOUR IT PROFESSIONAL for review.' -ForegroundColor Cyan
Write-Host (" Log file: {0}" -f $ReportFile) -ForegroundColor Cyan
Write-Host ' It lists every remote tool found, what was removed, and any' -ForegroundColor Cyan
Write-Host ' way an attacker might still have access. A professional' -ForegroundColor Cyan
Write-Host ' should confirm the machine is clean before you trust it.' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan

if (-not $Force -and -not $ScanOnly) {
    $send = Read-Host 'Open your email client to send the log now? (y/N)'
    if ($send -match '^(y|yes)$') {
        $subject = "Remote Access & RMM audit - $env:COMPUTERNAME - $stamp"
        $body    = "Automated remote-access/RMM audit log attached (or at $ReportFile). Please review for any remaining attacker access."
        try {
            Start-Process ("mailto:?subject=" + [uri]::EscapeDataString($subject) + "&body=" + [uri]::EscapeDataString($body))
            Write-Host "Your email client should be open. Attach: $ReportFile" -ForegroundColor Green
        } catch { Write-Host "Could not open mail client. Attach manually: $ReportFile" -ForegroundColor Yellow }
    }
}

if (-not $Force -and -not $ScanOnly -and $script:RebootNeeded) {
    $answer = Read-Host 'Reboot now to finish the wipe? (y/N)'
    if ($answer -match '^(y|yes)$') { Restart-Computer -Force }
}
