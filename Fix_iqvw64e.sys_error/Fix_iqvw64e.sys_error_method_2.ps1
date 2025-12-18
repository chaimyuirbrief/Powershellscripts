<# 
Fix-iqvw64e.ps1
Removes / quarantines iqvw64e.sys and its driver package to stop the “A driver cannot load on this device” prompt.

Usage:
  .\Fix-iqvw64e.ps1
  .\Fix-iqvw64e.ps1 -DisableMemoryIntegrity   # optional (reduces security)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [switch]$DisableMemoryIntegrity
)

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script in an elevated PowerShell (Run as Administrator)."
  }
}

function Write-Log {
  param([string]$Msg)
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  $line = "[$ts] $Msg"
  Write-Host $line
  Add-Content -Path $Global:LogPath -Value $line
}

Assert-Admin

$Global:LogPath = Join-Path $env:TEMP ("Fix-iqvw64e_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
Write-Log "Log: $LogPath"

$driverName = "iqvw64e.sys"
$sysPath    = Join-Path $env:WINDIR "System32\drivers\$driverName"

Write-Log "Checking for $driverName..."

# Find any services pointing at iqvw64e.sys (driver services show up here too)
$svcHits = Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
  Where-Object { $_.PathName -and $_.PathName -match [regex]::Escape($driverName) }

if ($svcHits) {
  foreach ($svc in $svcHits) {
    Write-Log "Found driver service: $($svc.Name)  (State=$($svc.State), StartMode=$($svc.StartMode))"
    try {
      if ($svc.State -eq "Running") {
        Write-Log "Stopping service $($svc.Name)..."
        sc.exe stop $svc.Name | Out-Null
        Start-Sleep -Seconds 2
      }
      Write-Log "Disabling service $($svc.Name)..."
      sc.exe config $svc.Name start= disabled | Out-Null
    } catch {
      Write-Log "WARN: Could not stop/disable service $($svc.Name): $($_.Exception.Message)"
    }
  }
} else {
  Write-Log "No service entries directly referencing $driverName were found."
}

# Enumerate driver store and find OEM*.inf that references iqvw64e
Write-Log "Searching driver store for packages that reference $driverName..."
$pnputil = & pnputil.exe /enum-drivers 2>$null
if (-not $pnputil) { throw "pnputil.exe failed to enumerate drivers." }

$blocks = ($pnputil -join "`n") -split "(\r?\n){2,}"
$oemInfs = @()

foreach ($b in $blocks) {
  if ($b -match "(?im)Published Name\s*:\s*(oem\d+\.inf)" -and $b -match "(?im)Original Name\s*:\s*([^\r\n]+)") {
    $pub = $Matches[1]
    if ($b -match "(?im)$([regex]::Escape($driverName))") {
      $oemInfs += $pub
    }
  }
}

$oemInfs = $oemInfs | Select-Object -Unique

if ($oemInfs.Count -gt 0) {
  foreach ($inf in $oemInfs) {
    Write-Log "Attempting removal of driver package: $inf"
    try {
      # /uninstall removes devices using it; /force forces removal if possible
      $out = & pnputil.exe /delete-driver $inf /uninstall /force 2>&1
      $out | ForEach-Object { Write-Log $_ }
    } catch {
      Write-Log "ERROR removing $inf: $($_.Exception.Message)"
    }
  }
} else {
  Write-Log "No OEM INF packages were found that explicitly mention $driverName via pnputil output."
}

# Quarantine the SYS file if present
if (Test-Path $sysPath) {
  $quarantineDir = Join-Path $env:ProgramData "DriverQuarantine"
  New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
  $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
  $dest  = Join-Path $quarantineDir ("{0}.{1}.bak" -f $driverName, $stamp)

  Write-Log "Quarantining $sysPath -> $dest"
  try {
    # Remove readonly/system attributes if set
    attrib.exe -R -S -H $sysPath 2>$null | Out-Null
    Move-Item -Path $sysPath -Destination $dest -Force
  } catch {
    Write-Log "ERROR: Could not move $sysPath. You may need to reboot and re-run. Details: $($_.Exception.Message)"
  }
} else {
  Write-Log "$sysPath not present."
}

# OPTIONAL: disable Memory Integrity (HVCI) – this reduces security
if ($DisableMemoryIntegrity) {
  Write-Log "Disabling Memory Integrity (HVCI) via registry (reduces security)."
  try {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    Set-ItemProperty -Path $key -Name "Enabled" -Type DWord -Value 0
    Write-Log "Set HVCI Enabled=0. Reboot required."
  } catch {
    Write-Log "ERROR setting HVCI registry value: $($_.Exception.Message)"
  }
} else {
  Write-Log "Memory Integrity was NOT changed. (Recommended)"
}

Write-Log "Done. Reboot your PC now to fully clear the blocked-driver popup."
Write-Host "`nReboot recommended. Log saved at: $LogPath`n"
