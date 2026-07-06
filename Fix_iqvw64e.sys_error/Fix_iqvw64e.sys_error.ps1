# Clean-Dell-PCDoctor.ps1
# Removes Dell SupportAssist/PC-Doctor leftovers that trigger HVCI popups

[CmdletBinding()]
param()

function Assert-Admin {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error "Run this in an elevated PowerShell window."; exit 1
  }
}
Assert-Admin

# Setup logging
$logDir = 'C:\Logs'
New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue | Out-Null
$log = Join-Path $logDir 'Clean-Dell-PCDoctor.log'

# Write to console AND append to the log. Tee-Object gained -Append only in
# PowerShell 6; on Windows PowerShell 5.1 `Tee-Object -Append` throws and
# nothing is logged, so use this instead.
function Write-Log {
  param([Parameter(ValueFromPipeline = $true, Position = 0)][object]$Message)
  process {
    Write-Host $Message
    Add-Content -Path $log -Value $Message
  }
}

"=== $(Get-Date) Start Dell PC-Doctor cleanup ===" | Write-Log

# 1) Kill known processes (best-effort)
$procNames = @('SupportAssistAgent','pcdr','pcdrcui','pcdsrvc','pcdclr','AppUp.IntelUnifiedDCH','Dell.TechHub')
foreach($p in $procNames){
  Get-Process -Name $p -ErrorAction SilentlyContinue | ForEach-Object {
    "Killing process: $($_.Name)" | Write-Log
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
  }
}

# 2) Stop/delete services that look like SupportAssist / PC-Doctor
# NOTE: -or must sit at the END of each line. If it starts the next line,
# PowerShell ends the statement after the first -match and tries to run "-or"
# as a command, so the filter would only ever match on $_.Name.
# Win32_Service lists only user-mode services; the HVCI-blocked kernel driver
# (iqvw64e.sys / the PC-Doctor driver) is a SERVICE_KERNEL_DRIVER and shows up
# only under Win32_SystemDriver. Query both. @( ) tolerates null/single results.
$svcLike = @(
  Get-CimInstance Win32_Service      -ErrorAction SilentlyContinue
  Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue
) | Where-Object {
  $_.Name -match '(?i)(supportassist|pc-?doctor|pcdr|pcdsrvc|techhub|iqvw64e)' -or
  $_.DisplayName -match '(?i)(supportassist|pc-?doctor|pcdr|techhub)' -or
  $_.PathName -match '(?i)(supportassistagent|pcdr|pc-?doctor|iqvw64e)'
}

if($svcLike){
  "Services to remove:" | Write-Log
  ($svcLike | Select-Object Name, DisplayName, State, StartMode, PathName | Format-Table | Out-String) | Write-Log
  foreach($s in $svcLike){
    "Stopping/deleting service: $($s.Name)" | Write-Log
    sc.exe stop $s.Name 2>$null | Out-Null
    Start-Sleep -Milliseconds 400
    sc.exe delete $s.Name 2>$null | Out-Null
    $svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)"
    if(Test-Path $svcKey){
      New-ItemProperty -Path $svcKey -Name Start -PropertyType DWord -Value 4 -Force -ErrorAction SilentlyContinue | Out-Null
      Remove-Item -Path $svcKey -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
} else {
  "No matching services found." | Write-Log
}

# 3) Remove scheduled tasks under common Dell/PCDr paths.
# schtasks.exe /TN does NOT accept wildcards, so the old '\Dell\*' query matched
# nothing. Get-ScheduledTask -TaskPath does support wildcards.
$taskRoots = @('\Dell','\Dell\SupportAssistAgent','\PC-Doctor','\PCDr')
foreach($root in $taskRoots){
  try{
    $tasks = Get-ScheduledTask -TaskPath ($root + '\*') -ErrorAction SilentlyContinue
    if($tasks){
      "Deleting tasks under " + $root | Write-Log
      foreach($t in $tasks){
        ("  " + $t.TaskPath + $t.TaskName) | Write-Log
        Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction SilentlyContinue
      }
    }
  } catch {}
}

# 4) Force-remove leftover folders/files
$folders = @(
  'C:\Program Files\Dell\SupportAssistAgent\PCDr',
  'C:\Program Files\Dell\SupportAssistAgent',
  'C:\Program Files\PC-Doctor',
  'C:\ProgramData\PC-Doctor',
  'C:\ProgramData\Dell\SupportAssist',
  'C:\Program Files\Dell\SupportAssist'
)

foreach($f in $folders){
  if(Test-Path $f){
    "Removing folder: $f" | Write-Log
    try{
      takeown /f "$f" /r /d y | Out-Null
      # *S-1-5-32-544 is the built-in Administrators SID - resolves on any locale
      icacls "$f" /grant '*S-1-5-32-544:F' /t /c | Out-Null
      # remove any .pkms/.sys first (sometimes locked)
      Get-ChildItem -Path $f -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '(?i)\.(pkms|sys|dll|exe)$' } |
        ForEach-Object {
          "  Deleting file: $($_.FullName)" | Write-Log
          Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
      Remove-Item -Path $f -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
      "  Failed to remove: $f  ->  $($_.Exception.Message)" | Write-Log
    }
  }
}

# 5) Clean up installer caches referencing PC-Doctor/SupportAssist (optional sweep)
$uninstRoots = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)
foreach($root in $uninstRoots){
  Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
    try{
      $dn = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).DisplayName
      if($dn -and $dn -match '(?i)(PC-?Doctor|PCDr|SupportAssist)'){
        "Uninstall entry remains: " + $dn | Write-Log
      }
    }catch{}
  }
}

# 6) Clear Code Integrity log
wevtutil cl "Microsoft-Windows-CodeIntegrity/Operational" 2>$null

"`nDone. Log: $log" | Write-Log
Write-Host ("Done. Log saved to: " + $log)
Write-Warning "Reboot now. After reboot, rerun Code Integrity log check to confirm no new blocks."
