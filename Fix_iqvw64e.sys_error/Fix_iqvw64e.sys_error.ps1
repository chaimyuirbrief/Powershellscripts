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
"=== $(Get-Date) Start Dell PC-Doctor cleanup ===" | Tee-Object -FilePath $log -Append

# 1) Kill known processes (best-effort)
$procNames = @('SupportAssistAgent','pcdr','pcdrcui','pcdsrvc','pcdclr','AppUp.IntelUnifiedDCH','Dell.TechHub')
foreach($p in $procNames){
  Get-Process -Name $p -ErrorAction SilentlyContinue | ForEach-Object {
    "Killing process: $($_.Name)" | Tee-Object -FilePath $log -Append
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
  }
}

# 2) Stop/delete services that look like SupportAssist / PC-Doctor
$svcLike = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
  $_.Name -match '(?i)(supportassist|pc-?doctor|pcdr|pcdsrvc|techhub)'
    -or $_.DisplayName -match '(?i)(supportassist|pc-?doctor|pcdr|techhub)'
    -or $_.PathName -match '(?i)(supportassistagent|pcdr|pc-?doctor)'
}

if($svcLike){
  "Services to remove:" | Tee-Object -FilePath $log -Append
  ($svcLike | Select-Object Name, DisplayName, State, StartMode, PathName | Format-Table | Out-String) | Tee-Object -FilePath $log -Append
  foreach($s in $svcLike){
    "Stopping/deleting service: $($s.Name)" | Tee-Object -FilePath $log -Append
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
  "No matching services found." | Tee-Object -FilePath $log -Append
}

# 3) Remove scheduled tasks under common Dell/PCDr paths
$taskRoots = @('\Dell','\Dell\SupportAssistAgent','\PC-Doctor','\PCDr')
foreach($root in $taskRoots){
  try{
    $q = schtasks /Query /TN ($root + '\*') 2>&1
    if($LASTEXITCODE -eq 0 -and $q){
      "Deleting tasks under " + $root | Tee-Object -FilePath $log -Append
      schtasks /Delete /TN ($root + '\*') /F 2>&1 | Tee-Object -FilePath $log -Append | Out-Null
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
    "Removing folder: $f" | Tee-Object -FilePath $log -Append
    try{
      takeown /f "$f" /r /d y | Out-Null
      icacls "$f" /grant Administrators:F /t /c | Out-Null
      # remove any .pkms/.sys first (sometimes locked)
      Get-ChildItem -Path $f -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '(?i)\.(pkms|sys|dll|exe)$' } |
        ForEach-Object {
          "  Deleting file: $($_.FullName)" | Tee-Object -FilePath $log -Append
          Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        }
      Remove-Item -Path $f -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
      "  Failed to remove: $f  ->  $($_.Exception.Message)" | Tee-Object -FilePath $log -Append
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
        "Uninstall entry remains: " + $dn | Tee-Object -FilePath $log -Append
      }
    }catch{}
  }
}

# 6) Clear Code Integrity log
wevtutil cl "Microsoft-Windows-CodeIntegrity/Operational" 2>$null

"`nDone. Log: $log" | Tee-Object -FilePath $log -Append
Write-Host ("Done. Log saved to: " + $log)
Write-Warning "Reboot now. After reboot, rerun Code Integrity log check to confirm no new blocks."
