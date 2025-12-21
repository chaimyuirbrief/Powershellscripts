<# 
Removes ONLY Credential Manager entries whose Target contains "adobe" (case-insensitive).
Creates a before/after log alongside the script. Safe-guards ensure nothing else is touched.
#>

param(
  [string]$Match = 'adobe',            # substring to match in Target
  [switch]$WhatIf                      # preview-only mode
)

function Get-CredTargets {
  # Returns full Target strings from cmdkey /list (exact values needed for deletion)
  $raw = cmdkey /list 2>$null
  if (-not $raw) { return @() }
  $targets = @()
  foreach ($line in $raw) {
    if ($line -match '^\s*Target:\s*(.+)$') {
      $targets += $Matches[1].Trim()
    }
  }
  return $targets
}

# Collect all targets and filter to only those that contain the substring
$allTargets   = Get-CredTargets
$matched      = $allTargets | Where-Object { $_ -match [regex]::Escape($Match) }  # case-insensitive by default

# Write logs
$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$logBase = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Path) -ChildPath "AdobeCredCleanup-$stamp"
$newLog  = "$logBase.log"
$preLog  = "$logBase.pre.txt"
$posLog  = "$logBase.post.txt"

$allTargets | Set-Content -Encoding UTF8 $preLog

if (-not $matched) {
  Write-Host "[INFO] No credentials with `"$Match`" found. Nothing to do."
  Write-Host "[INFO] Inventory saved to: $preLog"
  return
}

Write-Host "[INFO] Found $($matched.Count) credential(s) containing `"$Match`":"
$matched | ForEach-Object { Write-Host " - $_" }

if ($WhatIf) {
  Write-Host "[PREVIEW] -WhatIf specified. No deletions performed."
  Write-Host "[PREVIEW] These would be deleted:" 
  $matched | ForEach-Object { Write-Host "  cmdkey /delete:`"$_`"" }
  return
}

# Extra safety: refuse to run unless the match is exactly "adobe" (user's requirement)
if ($Match -ne 'adobe') {
  Write-Error "Safety check: This script only runs real deletions when -Match is exactly 'adobe'. Use -WhatIf to preview other strings."
  return
}

# Perform deletions
$results = foreach ($t in $matched) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = 'cmdkey.exe'
  $psi.Arguments = "/delete:`"$t`""
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false
  $p = [System.Diagnostics.Process]::Start($psi)
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()

  [pscustomobject]@{
    Target   = $t
    ExitCode = $p.ExitCode
    Output   = $out.Trim()
    Error    = $err.Trim()
    Success  = ($p.ExitCode -eq 0 -and -not $err)
  }
}

# Log results
$results | ForEach-Object {
  if ($_.Success) {
    "[OK]  Deleted: $($_.Target)" | Add-Content -Encoding UTF8 $newLog
  } else {
    "[ERR] Target: $($_.Target)  ExitCode: $($_.ExitCode)  Output: $($_.Output)  Error: $($_.Error)" | Add-Content -Encoding UTF8 $newLog
  }
}

# Post-state inventory
(Get-CredTargets) | Set-Content -Encoding UTF8 $posLog

Write-Host "[DONE] Deleted $(@($results | Where-Object Success).Count) of $($matched.Count)."
Write-Host "Log:      $newLog"
Write-Host "Before:   $preLog"
Write-Host "After:    $posLog"
